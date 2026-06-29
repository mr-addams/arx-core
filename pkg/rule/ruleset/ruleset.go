// ========================== pkg/rule — RuleSet (Task E1) ===================================
//   RuleSet is the named, mutable, thread-safe collection of compiled rule expressions
//   built on top of the catalog / scheme / compiler pipeline (DECISION D13). It is the
//   runtime lifecycle owner of rules in arx-core: product plugins embed a RuleSet, Add
//   / Remove / Replace rules as their configuration changes, and call Match for every
//   event to obtain a predicate verdict (the engine never performs the action itself —
//   D12).
//
//   WHAT IS HERE:
//     - RuleInfo — public snapshot row: {Name, Expression}.
//     - RuleSet — the typed collection with New / Add / Remove / Replace / Match /
//       Rules / Stats.
//     - compiledRule — unexported slot holding Name, source text, immutable *Plan, and
//       a monotonically increasing atomic match counter.
//     - ErrRuleExists, ErrRuleNotFound — public error sentinels for Add / Replace.
//     - compileExpr — the locked, lex → parse → compile pipeline used by both
//       Add and Replace. NEVER split across locks (D13: "compile under lock").
//
//   WHAT IS NOT HERE:
//     - Builder helpers / fluent registration — owned by Task E2 (builder.go).
//     - HTTP/syslog/<custom> resolvers — owned by embedding plugins (D3).
//     - Action mapping (pass / drop / enrich) — plugin concern; RuleSet.Match returns
//       (name, matched bool) only (D12).
//     - Plan.Rev staleness detection at Match time — the engine surfaces a stale plan
//       by returning false; downstream detection (via Plan.Rev vs Scheme.Revision())
//       is the engine's responsibility, not RuleSet's (D13: "live Catalog mutations are
//       detected via Plan.Rev vs Scheme.Revision() at the engine level, NOT by RuleSet
//       auto-recompiling").
//
//   DEPENDENCY RULE (D2):
//     stdlib only, plus sibling pkg/rule (parent — for Catalog, Scheme, FieldResolver,
//     Value), sibling pkg/rule/compiler (Plan, Compiler, CompileError), sibling
//     pkg/rule/parser (Parse → AST), and sibling pkg/plugin (Event boundary, used
//     by Match). The lexer is encapsulated inside parser.Parse — the RuleSet never
//     imports pkg/rule/lexer directly.
//
//   LOCATION — note for reviewers:
//     RuleSet lives in the subpackage `pkg/rule/ruleset` rather than directly in
//     `pkg/rule` for the same reason compiler.go is in a subpackage: pkg/rule/
//     compiler imports pkg/rule (for Kind, FieldType, Scheme), and pkg/rule/parser
//     also imports pkg/rule (for Value). Putting RuleSet inside pkg/rule would
//     require pkg/rule to import pkg/rule/compiler and pkg/rule/parser, closing
//     the cycle. As with the compiler subpackage, a future cleanup that lifts
//     Value/Kind to a stdlib-only leaf package can hoist RuleSet back to pkg/rule;
//     the public API is package-agnostic via type aliases declared in the parent
//     package (RuleSet = ruleset.RuleSet, etc.), so consumers see a single name
//     either way.
//
//   CONCURRENCY (D13):
//     The internal `rules` slice is guarded by a sync.RWMutex:
//       - Match / Rules / Stats hold the read lock for the duration of the operation.
//       - Add / Remove / Replace compile the expression WITHOUT holding the lock,
//         then acquire the write lock only for the duplicate-check and slice mutation.
//
//     Why compile outside the write lock:
//       Compile is pure and read-only against the immutable Scheme, so it is safe to
//       run concurrently with other Adds or concurrent Matches. The write lock is
//       taken only for the brief publish step, minimising contention on the hot path.
//       Atomicity is preserved: if compileExpr returns an error, the lock is never
//       taken and the existing rules slice is untouched (bad expression leaves the set
//       unchanged; bad Replace expression leaves the old rule in place). If profiling
//       later shows contention on the publish step itself, a per-slot CAS is the next
//       logical optimisation; the public API does not change.
//
//     Match increments the matched rule's counter via sync/atomic.Uint64.Add. The
//     counter lives on the compiledRule slot, accessed through the slice head pointer
//     loaded under the read lock. Read lock + atomic add is race-free: the slice head
//     is stable across the RLock, and the counter is a separate atomic word.
//
//     Compile path: RuleSet caches a single *compiler.Compiler constructed once from
//     the captured Scheme. The Compiler is immutable (DECISION Group C, C1) and safe
//     for concurrent use, but every Add / Replace also takes the write lock, so the
//     cached Compiler is used in series with no parallelism pressure on it.

package ruleset

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/compiler"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== Public errors ==================================================

var (
	// ErrRuleExists is returned by Add when a rule with the same name is already in
	// the RuleSet. Add never silently overwrites — that would let a configuration
	// flip drop the old expression's compiled Plan on the floor. Callers that want
	// upsert semantics must Remove first (or use Replace on an existing rule).
	ErrRuleExists = errors.New("rule: rule with that name already exists")

	// ErrRuleNotFound is returned by Replace when the target name is not present in
	// the RuleSet. Replace is defined as an atomic swap (D13 — "old rule stays on
	// error"), which only has meaning when there IS an old rule. Silently turning
	// Replace into Add on a missing name would hide configuration mistakes (e.g.
	// typos in the rule name) and violate the swap semantics. If you want Add-or-
	// Replace semantics, call Has(name) (or check via Rules()) and choose Add or
	// Replace based on the result — keeping the intent explicit at the call site.
	ErrRuleNotFound = errors.New("rule: no rule with that name to replace")
)

// ========================== RuleInfo — public snapshot row =================================

// RuleInfo is the row type returned by Rules(): the rule's unique name and the source
// expression string that produced its Plan. The Plan itself is intentionally NOT part
// of the snapshot — introspection surfaces source text for audit, debugging, and rule
// management UIs, not the compiled plan (which has its own Rev / lifetime story).
type RuleInfo struct {
	// Name is the unique identifier of the rule within the RuleSet. Set by the
	// caller at Add / Replace time. Never empty for a loaded rule.
	Name string

	// Expression is the source expression string that was compiled into the rule's
	// current Plan. For Replace: this is the LATEST expression (not the one the
	// current slot started with), reflecting the post-swap state. Returned exactly
	// as supplied by the caller so logging round-trips.
	Expression string
}

// ========================== compiledRule — internal slot ===================================

// compiledRule is one slot in the RuleSet's internal rule slice. Name and source text
// are immutable once written (under the write lock); the *compiler.Plan is also
// immutable (C1) and so safe for concurrent Eval from many goroutines while the slot
// is alive. The matches counter is the only mutable field on a live slot and is
// touched only via its atomic API.
//
// Why a per-slot atomic counter rather than a per-RuleSet mutex around the map:
// counters are updated on every Match (a hot path), while rule-list membership
// changes only at lifecycle boundaries (cold). Keeping the counter lock-free avoids
// serializing Eval against administrative operations like introspection or live
// config reloads.
//
// Why the counter is *atomic.Uint64 (pointer) rather than atomic.Uint64 (value):
// value-typed atomic.Uint64 has an internal sync/atomic.noCopy marker; any struct
// copy of compiledRule (e.g. during slice append in Remove) trips `go vet`'s
// passlock checker. Holding the counter by pointer keeps Move operations safe
// without forking the struct — the counter outlives any given slot's slice
// memory because it's heap-allocated at slot creation in New / Replace.
type compiledRule struct {
	name    string
	source  string
	plan    *compiler.Plan
	matches *atomic.Uint64
}

// ========================== RuleSet — public type ==========================================

// RuleSet is the public, mutable, thread-safe collection of compiled rules bound to a
// specific profile's Scheme projection (DECISION D6, D9, D13).
//
// Lifetime model:
//   - The Scheme is captured at New and never re-projected. Subsequent Catalog
//     registrations do NOT change the RuleSet's view of available fields (D13:
//     compile-once / eval-many). Stale-plan detection between the live Catalog and
//     a Plan bound to this Scheme is the engine's job (Plan.Rev vs Scheme.Revision()),
//     not RuleSet's.
//   - The *compiler.Compiler is cached at New and reused across every Add / Replace
//     call. A fresh Compiler on every Add would re-build the field-index map needlessly;
//     the cached one is immutable and safe.
//   - The rules slice grows with Add and shrinks with Remove. Replace keeps the slot
//     in place (preserving the matches counter for the swap; see Replace docs).
//
// Concurrency:
//   - New is safe to call from multiple goroutines, but typically called once at
//     startup by the embedding plugin.
//   - Add, Remove, Replace, Match, Rules, Stats are all safe to call concurrently.
//     There is no allocator-level sequence point required between them; see the file
//     header for the full concurrency rationale.
type RuleSet struct {
	// catalog is retained for introspection consistency at the type level — the
	// RuleSet does not consult the Catalog at runtime (D13: Scheme captured at
	// construction). Stored here so a future API surface can re-project a live
	// scheme on demand without changing the public New signature.
	catalog *rule.Catalog

	// scheme is the captured projection. Immutable for the lifetime of the RuleSet.
	scheme *rule.Scheme

	// compiler is cached at New from the captured scheme. Compiler is immutable
	// per C1 and safe for concurrent use, so Add / Replace can call Compile on it
	// from many goroutines — but the RuleSet still serializes them under the write
	// lock for the transactional compile-and-publish semantics.
	compiler *compiler.Compiler

	// profile is the namespace projection key passed to New. Stored for future
	// introspection (e.g. "which profile did this RuleSet bind to?") and as a
	// diagnostic breadcrumb if someone debug-dumps a RuleSet. Not consulted by
	// Add / Replace / Match directly.
	profile string

	// mu guards rules. Read paths (Match / Rules / Stats) hold the RLock for the
	// duration of the operation; write paths (Add / Remove / Replace) hold the
	// full Lock including the compile step (D13).
	mu sync.RWMutex

	// rules holds compiledRule slots in registration order. Match walks left-to-
	// right and returns the first true verdict (DECISION D12's predicate-only
	// surface; first-match-wins is the natural rule semantics).
	rules []compiledRule
}

// ========================== New ====================================================================

// New constructs a RuleSet bound to the Catalog's current projection for the named
// profile. The profile is the namespace projection key (DECISION D9): "waf",
// "syslog-anomaly", "rate-anomaly", "generic", etc. — semantically, the namespace
// the rules in this RuleSet are allowed to reference. Every RuleSet also implicitly
// includes the `core` namespace (the Envelope: timestamp, stream, source, source_type,
// level), because core.* fields are Core-owned and always meaningful to any pipeline.
//
// Construction semantics:
//   - The Scheme is captured ONCE here as `Project(profile, "core")`. Subsequent
//     Catalog.Register calls do NOT re-project onto this RuleSet, and new fields
//     added to those namespaces after New returns are invisible to rules compiled
//     by this RuleSet (D13: compile-once / eval-many). This is the deliberate
//     trade-off that makes a compiled Plan self-contained and safely
//     concurrency-shared.
//   - The Compiler is constructed once from the captured Scheme and cached. A
//     nil-catalog Scheme failure (NewCompiler returns *CompileError on nil scheme)
//     is unwrapped into a plain error so New's contract stays the simple
//     (*RuleSet, error) pattern — but the error is returned synchronously so
//     configuration bugs surface at startup, not at the first Add.
//   - profile must be a valid namespace identifier (lowercase, non-empty, no dots);
//     this matches the Catalog.Register's namespace rules. An invalid profile
//     string yields a Scheme that lacks the profile's namespace but still
//     includes `core` — a caller that misspells a profile gets a "field not in
//     scheme" compile error on the first Add (D6 compile-time field gating),
//     not a silent miss.
//
// The returned RuleSet is empty and ready for Add.
func New(catalog *rule.Catalog, profile string) (*RuleSet, error) {
	if catalog == nil {
		// A nil catalog means the caller skipped the A3 step. Fail fast: a
		// RuleSet constructed against a nil catalog cannot compile anything
		// because the Scheme would also be nil, but more importantly, we don't
		// want downstream code to silently treat "empty rule set" as success.
		return nil, errors.New("rule: New requires a non-nil catalog")
	}

	// Project the profile namespace plus `core` (the Envelope namespace every
	// pipeline has access to). Project() with no namespaces would yield a Scheme
	// with zero fields; with both it carries the profile's fields plus envelope
	// fields, which is the smallest sensible "open profile" rule engine.
	scheme := catalog.Project(profile, "core")

	comp, cerr := compiler.NewCompiler(scheme)
	if cerr != nil {
		// The only NewCompiler failure mode today is CodeNilScheme. Project() on a
		// non-nil catalog never returns nil, so this branch is reachable only via
		// a future change to NewCompiler.
		return nil, fmt.Errorf("rule: build compiler: %w", cerr)
	}

	return &RuleSet{
		catalog:  catalog,
		scheme:   scheme,
		compiler: comp,
		profile:  profile,
	}, nil
}

// ========================== compileExpr — internal locked helper ================================

// compileExpr runs the lex → parse → compile pipeline on expression and returns a
// fresh *compiler.Plan, or an error tagged with the pipeline stage that failed.
//
// Called from Add and Replace BEFORE the write lock is acquired. The compile
// step is pure and read-only against the immutable Scheme, so it is safe to run
// concurrently. The write lock is taken by the caller only after compileExpr
// returns successfully, covering only the duplicate-check and slice mutation.
//
// Why a single helper, not three inlined calls: keeping the pipeline in one place
// makes the error-wrapping policy consistent (every error is annotated with its
// stage so Add callers see "parse error: ..." vs "compile error: ..." and can
// distinguish configuration bugs from scheme bugs).
func (r *RuleSet) compileExpr(expression string) (*compiler.Plan, error) {
	// Stage 1: parse (includes lex internally).
	ast, err := parser.Parse(expression)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	if ast == nil {
		// parser.Parse documents "empty input is a parse error"; this defensive
		// check is a harness against future parser changes relaxing that policy.
		return nil, errors.New("parse error: parser returned nil AST")
	}

	// Stage 2: compile against the cached Compiler (constructed once at New).
	plan, err := r.compiler.Compile(ast)
	if err != nil {
		return nil, fmt.Errorf("compile error: %w", err)
	}
	return plan, nil
}

// ========================== Add ====================================================================

// Add compiles expression and appends it to the RuleSet under name. On compile
// success, the rule is live and visible to subsequent Matches. On compile failure
// the rule is NOT stored (atomicity: a bad rule never poisons RuleSet state) and
// the error is returned to the caller — never panicked.
//
// Add returns ErrRuleExists when a rule with the same name is already present.
// Duplicate names are a configuration error; silently overwriting would let a
// configuration flip drop the old expression's compiled Plan on the floor without
// any observability hook. Callers that want upsert semantics should Remove first,
// or use Replace for the existing-name path.
//
// Concurrency: holds the write lock for the full lex → parse → compile + append
// cycle (DECISION D13). See the file header for the rationale on compile-under-lock.
func (r *RuleSet) Add(name, expression string) error {
	if name == "" {
		return errors.New("rule: Add requires a non-empty name")
	}

	plan, err := r.compileExpr(expression)
	if err != nil {
		// Atomicity invariant: a bad expression must not mutate the rules slice.
		// compileExpr happens BEFORE the lock-protected append; returning here
		// leaves r.rules untouched.
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.rules {
		if r.rules[i].name == name {
			return ErrRuleExists
		}
	}

	// New per-slot counter. Heap-allocated via &atomic.Uint64{} so the counter
	// outlives any given slice element's memory (see the compiledRule doc-comment
	// for the noCopy-pointer rationale).
	r.rules = append(r.rules, compiledRule{
		name:    name,
		source:  expression,
		plan:    plan,
		matches: &atomic.Uint64{},
	})
	return nil
}

// ========================== Remove ===============================================================

// Remove deletes the rule with the given name from the RuleSet. No-op if no rule
// with that name exists — Remove has no error return by design (idempotent
// administration: "delete if present" is the natural semantics for a rule management
// API). A missing name is not considered an error condition.
//
// Concurrency: holds the write lock for the duration of the linear scan + slice
// rebuild. The slot's atomic counter is dropped along with the rest of the slot
// (D13: counters are per-slot, reset on Remove — the new slot starts at zero).
//
// Build cost: removes a single slot by allocating a new slice of len-1 and copying
// non-matching slots. For the cardinality RuleSet operates at (dozens to hundreds
// of rules, not millions), this is cheaper than a linked-list or map structure and
// keeps Match's linear walk as the fast path.
func (r *RuleSet) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Single-pass rebuild. compiledRule carries a *atomic.Uint64 pointer, so
	// append copies a struct of pure-data + one machine-word pointer — no
	// passlock violation. The counter outlives any given slot's slice memory
	// because it's heap-allocated at slot creation; once a slot is dropped
	// (Remove), the counter becomes unreachable and is collected. Replace
	// preserves counters because the slot is the same slot — only the data
	// fields swap, and the *matches pointer stays put.
	n := len(r.rules)
	if n == 0 {
		return
	}
	out := make([]compiledRule, 0, n)
	found := false
	for i := 0; i < n; i++ {
		if !found && r.rules[i].name == name {
			found = true
			continue
		}
		out = append(out, r.rules[i])
	}
	if !found {
		return
	}
	r.rules = out
}

// ========================== Replace ==============================================================

// Replace atomically swaps the expression of an existing rule. The new expression is
// compiled FIRST, under the write lock; on compile failure, the existing rule stays
// in place and continues to fire (atomicity: a bad expression never disables a live
// rule). On compile success, the slot's Plan and source text are swapped; the slot's
// matches counter is preserved.
//
// Why counter preservation (not reset): Replace is a swap, not a Remove+Add. The
// counter reflects "how many times did this slot match"; the slot is the same slot,
// so its history is continuous. From the operator's perspective, "edit a rule,
// keep observability of its match frequency since installation" is the intuitive
// behaviour. A counter reset would surprise every monitoring panel that uses Stats().
//
// Replace returns ErrRuleNotFound when the named rule is absent. See ErrRuleNotFound's
// doc comment for why we don't silently turn Replace into Add on a missing name.
//
// Concurrency: holds the write lock for the full lex → parse → compile + swap cycle
// (D13). Same rationale as Add.
func (r *RuleSet) Replace(name, expression string) error {
	if name == "" {
		return errors.New("rule: Replace requires a non-empty name")
	}

	// Compile before taking the write lock — compile is pure/read-only against
	// the immutable Scheme and safe to run concurrently with ongoing Matches.
	// A bad expression returns early here, leaving the existing rule untouched.
	plan, err := r.compileExpr(expression)
	if err != nil {
		// Atomicity: bad expression leaves the existing rule unchanged. Caller
		// sees the compile error; the live rule keeps firing for any concurrent
		// Match that already loaded its slot under the read lock.
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.rules {
		if r.rules[i].name == name {
			// Atomic slot update: swap plan + source in place, leave the
			// counter alone.
			r.rules[i].plan = plan
			r.rules[i].source = expression
			return nil
		}
	}
	// Compiled a good expression but the rule didn't exist when we took the
	// lock — the caller asked for a non-existent name, or it was removed by a
	// concurrent Remove between our compile and lock acquisition. Either way,
	// the compilation result is discarded and ErrRuleNotFound returned.
	return ErrRuleNotFound
}

// ========================== Match ================================================================

// Match evaluates every loaded rule against event + resolver, in registration order,
// and returns the name of the first rule whose Plan.Eval is true. If no rule
// matches, Match returns ("", false).
//
// Predicate-only contract (DECISION D12): Match does NOT execute any action on the
// event — it only reports which rule (if any) produced the verdict. The embedding
// plugin decides what to do with the verdict (drop, enrich, alert, etc.).
//
// Concurrency:
//   - Holds the read lock for the duration of the walk (so the rule slice is stable
//     across the iteration).
//   - For the matching rule, the counter is incremented via atomic.Uint64.Add —
//     lock-free, race-free with concurrent Matches from other goroutines. The
//     counter is owned by the slot, not by the slice; the slice head pointer is
//     captured under the RLock, the slot reference is then dereferenced outside
//     the lock, but here we still increment INSIDE the read lock because the
//     slot reference is only stable while the read lock is held — the slot could
//     be replaced by a concurrent Replace and the new Plan would shadow the old
//     counter reference (Replace keeps the same slot, so this is safe; we keep
//     the increment under the RLock for clarity).
//   - Early termination: Match returns as soon as the first true verdict is
//     found, never walking the rest of the rules. This is what makes
//     "first-match-wins" the natural semantics of the linear walk.
//
// Resolver contract: Match passes the caller-supplied resolver through to Eval
// unchanged. The RuleSet does not inject a core.* resolver — the caller is
// responsible for providing a resolver that covers every namespace the rules
// reference (typically a chain of EnvelopeResolver + plugin resolvers). RuleSet
// is engine-agnostic about where field values come from; that's a resolver
// concern.
func (r *RuleSet) Match(event *plugin.Event, resolver rule.FieldResolver) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Linear walk in registration order. First true wins. We iterate by index
	// rather than ranging with a local copy because ranging would copy the slice
	// header on each iteration (cheap, but using an index keeps the optimizer's
	// view simple).
	for i := range r.rules {
		if r.rules[i].plan.Eval(resolver, event) {
			// Increment the per-rule match counter atomically. The counter is
			// separate from the rule slice (per-slot atomic.Uint64), so this
			// races safely with concurrent Stats() loads via atomic.Load on the
			// same word.
			r.rules[i].matches.Add(1)
			return r.rules[i].name, true
		}
	}
	return "", false
}

// ========================== Rules ================================================================

// Rules returns a freshly-allocated snapshot of every loaded rule's name and source
// expression. The result is owned by the caller — RuleSet retains no reference and
// does not alias future Add / Remove / Replace calls into the returned slice. This
// is the explicit "snapshot, not live ref" semantics called out in D13's inspection
// surface.
//
// Snapshot is taken under the read lock for consistency with concurrent Add /
// Remove / Replace. The strings returned (Name, Expression) are immutable (Add and
// Replace never mutate an existing slot's name; source is replaced by Replace, not
// aliased). So a Rules() result is safe to retain across RuleSet mutations even
// though it's not the same slice.
func (r *RuleSet) Rules() []RuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.rules) == 0 {
		return []RuleInfo{} // non-nil empty slice — caller can range without a guard
	}
	out := make([]RuleInfo, 0, len(r.rules))
	for i := range r.rules {
		out = append(out, RuleInfo{
			Name:       r.rules[i].name,
			Expression: r.rules[i].source,
		})
	}
	return out
}

// ========================== Stats ================================================================

// Stats returns a snapshot of per-rule match counts since the rule was Added
// (or last Replace-d for the same slot). The returned map is freshly allocated and
// owned by the caller.
//
// Semantics (DECISION D13):
//   - Counters are monotonic since the rule was Added (or the slot was newly created
//     via Replace — which keeps the slot, so counter continuity is preserved).
//   - Replacing a rule does NOT reset its counter (Replace is a swap, not a
//     Remove+Add; see Replace docs).
//   - Removing a rule does reset its counter (the slot is gone).
//   - The returned map only contains entries for rules currently loaded. A rule
//     that was Added, matched, and then Removed does NOT appear — its counter is
//     garbage-collected along with the slot.
//
// The walk reads each counter via atomic.Uint64.Load so concurrent Match+Stats
// callers do not race. Counts observed by Stats are best-effort "as of this read";
// a Match that completes after Stats starts walking may or may not be visible in
// the snapshot, but the snapshot itself is internally consistent (a single Load per
// rule, no torn reads).
func (r *RuleSet) Stats() map[string]uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]uint64, len(r.rules))
	for i := range r.rules {
		out[r.rules[i].name] = r.rules[i].matches.Load()
	}
	return out
}
