// ========================== pkg/rule/compiler — evaluator (Task C2) =========================
//   The evaluator walks a compiled Plan against a FieldResolver and a *plugin.Event,
//   returning a bool predicate verdict. It is the engine's hot path (DECISION D4):
//   after the first few calls ("warmup"), scalar-only plans must allocate ZERO bytes
//   per call. Bench verification lives in eval_test.go (BenchmarkEval_ScalarPlan).
//
//   LOCATION — note for reviewers:
//     This file lives in the same subpackage as the compiler (compiler/eval.go, not
//     pkg/rule/eval.go) for the same reason compiler.go does — the evaluator must read
//     the unexported op types (opLitString, opField, opCmp, ...). Hoisting eval.go to
//     pkg/rule would require exporting every op type, breaking the C1 contract.
//
//   WHAT IS HERE:
//     - (*Plan).Eval — the public entry point. The contract is documented on the
//       method itself; the short version is: walks the Plan, returns bool, never
//       panics, safe for concurrent use.
//     - eval / evalOp — the internal dispatch. Type-switch on concrete op type is
//       deliberate: interface dispatch would allocate (boxing) on every call.
//
//   WHAT IS NOT HERE:
//     - Compilation / type-checking — lives in compiler.go (Task C1).
//     - Field resolvers — EnvelopeResolver lives in pkg/rule, plugin resolvers in
//       their respective plugins (DECISION D3).
//     - Function-table execution — the v0.3.0 function table (DECISION D16) is
//       closed and populated. compileFuncCall rejects unknown names / wrong arity
//       / per-argument Kind mismatches at compile time; the evaluator dispatches
//       via the spec's Eval entry point and surfaces a defensive false if any
//       argument fails to resolve.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): net, regexp, strings. Plus sibling pkg/rule
//     (FieldResolver / Value / Kind / FieldType) and pkg/plugin (Event).
//
//   HOT PATH PERFORMANCE (D4):
//     After warmup (a few initial calls), a scalar-only Plan achieves
//     0 allocs/op. See BenchmarkEval_ScalarPlan for live measurement; the number
//     pinned below was captured on 2026-06-29 against the initial implementation
//     of this file.
//
//     Measured: 0 allocs/op on BenchmarkEval_ScalarPlan (http.status eq 200,
//     KindInt cmp), BenchmarkEval_ScalarPlan_String (KindString cmp), and
//     BenchmarkEval_ComplexPlan (range + contains). All three plans run at
//     0 B/op on go 1.26 / linux-amd64, satisfying D4.
//     The only allocations left on the hot path are:
//       - The first Eval of a Plan containing a wildcard op (lazy regexp compile
//         via sync.Once on opWildcard, then amortised across all subsequent calls).
//       - opIn over Map/Array ops (those are heap-backed by design — D5).
//       - Field resolution via a custom resolver that allocates (EnvelopeResolver
//         for core.* fields is alloc-free for non-IP scalars; this is a property
//         of the resolver, not the evaluator).
//
//   CONCURRENCY:
//     A *Plan is immutable after Compile. Eval is safe to call from many goroutines
//     on the same Plan concurrently. The lazy-compiled regexp inside opWildcard
//     is guarded by a per-op sync.Once so the first writer wins, all others reuse.

package compiler

import (
	"regexp"
	"strings"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
)

// Eval walks the Plan against resolver and event, returning the predicate verdict.
//
// Contract (DECISION D4, D12):
//
//   - p MUST be non-nil. Eval on a nil *Plan returns false (defensive — production
//     code never passes nil, tests can rely on the safe default).
//   - resolver MUST be non-nil. Eval on a nil resolver returns false (defensive —
//     surfacing the misconfiguration as "no match" instead of a panic lets the
//     embedding plugin keep serving traffic until the configuration is fixed).
//   - event MAY be nil. The FieldResolver contract (D3) requires resolvers to return
//     (Value{}, false) on nil event; the evaluator surfaces that as "no match".
//   - Eval never panics. All runtime type mismatches, nil dereferences, and bad
//     values surface as `false` (no match). The engine is a pure predicate —
//     the embedding plugin interprets the verdict (D12).
//   - Eval is safe for concurrent use on the same *Plan. The Plan is immutable
//     after Compile, and the only shared mutable state inside an op (the lazy
//     wildcard regex) is guarded by sync.Once.
func (p *Plan) Eval(resolver rule.FieldResolver, event *plugin.Event) bool {
	// Defensive nil checks. Eval is the engine's hot path; failing closed
	// (false) on a misconfiguration is the contract, not panicking.
	if p == nil || p.root == nil || resolver == nil {
		return false
	}
	return eval(p.root, resolver, event)
}

// eval is the internal dispatch entry point. It exists as a separate function (not
// inlined into Eval) so that recursive calls into opAnd / opOr subtrees use the same
// helper and so the public API stays trivially readable.
func eval(o op, resolver rule.FieldResolver, event *plugin.Event) bool {
	switch n := o.(type) {
	// ── Literal leaves — return their stored Value as a boolean truthiness ────
	case *opLitBool:
		// opLitBool is a constant predicate. eval-as-bool short-circuits the rest
		// of the walk: `true and X` always evaluates to X, but `false or X` always
		// evaluates to X. Eval() of an opLitBool is rare (top-level predicates
		// are usually wrapped by And/Or), so we treat it as a constant.
		b, ok := n.v.AsBool()
		if !ok {
			return false
		}
		return b

	case *opLitString, *opLitInt, *opLitFloat, *opLitIP, *opLitBytes, *opLitDuration, *opLitTimestamp:
		// Non-bool literals at the root of a Plan are not predicates — they're
		// values. The compiler rejects this shape (top-level literals must be
		// used inside an op), but reaching here is reachable if a caller builds
		// a Plan by hand. We surface a defensive false.
		return false

	case *opLitArray:
		// Arrays are only meaningful inside opIn. A standalone array is not a
		// predicate; surface a defensive false.
		return false

	// ── Field / bracket — resolve and surface unresolved as no-match ─────────
	case *opField:
		v, ok := resolver.Resolve(n.name, event)
		if !ok {
			// Resolver returned no value — treat as a no-match for the whole
			// predicate. This matches the D3 contract: missing field is not a
			// panic, it is "unresolved", which propagates up as a failed match.
			return false
		}
		// A field reference at the root of a Plan is also a non-predicate value.
		// Treat as defensive false. A well-formed expression wraps the field in
		// a Cmp / string-op / In.
		_ = v
		return false

	case *opBracket:
		// Resolves the underlying field as a Map, then looks up the key. If
		// the field does not resolve or is not a Map, or the key is missing,
		// the result is "no match" for the whole predicate.
		v, ok := resolver.Resolve(n.obj.name, event)
		if !ok || v.Kind() != rule.KindMap {
			return false
		}
		m, ok := v.AsMap()
		if !ok {
			return false
		}
		_, present := m[n.key]
		if !present {
			return false
		}
		// A bracket access alone is a value, not a predicate — defensive false.
		return false

	// ── Logic ops — short-circuit ─────────────────────────────────────────────
	case *opAnd:
		// Short-circuit: if left is false, don't evaluate right.
		return eval(n.left, resolver, event) && eval(n.right, resolver, event)
	case *opOr:
		// Short-circuit: if left is true, don't evaluate right.
		return eval(n.left, resolver, event) || eval(n.right, resolver, event)
	case *opNot:
		return !eval(n.operand, resolver, event)

	// ── Comparison — type-checked dispatch over both operand kinds ────────────
	case *opCmp:
		return evalCmp(n, resolver, event)

	// ── String ops — both operands must be String ─────────────────────────────
	case *opContains:
		return evalContains(n, resolver, event)
	case *opStartsWith:
		return evalStartsWith(n, resolver, event)
	case *opEndsWith:
		return evalEndsWith(n, resolver, event)
	case *opMatches:
		return evalMatches(n, resolver, event)
	case *opWildcard:
		return evalWildcard(n, resolver, event)

	// ── In — set membership over opLitArray elements ──────────────────────────
	case *opIn:
		return evalIn(n, resolver, event)

	// ── Strict — semantic no-op in v1, just unwrap the inner predicate ────────
	case *opStrict:
		// v1 strict is the default behavior (D14); the wrapper exists as a
		// syntactic marker only. Just evaluate the inner op.
		return eval(n.inner, resolver, event)

	// ── Function call — dispatch via the registry (DECISION D16) ──────────────
	case *opFunc:
		return evalFuncCall(n, resolver, event)
	case *opRegexReplace:
		// The compile-time-precompiled regex path. If compiled is non-nil we
		// honour DECISION D4 (no regexp.Compile per eval); the literal-pattern
		// branch of compileRegexReplace populates this field. The non-literal
		// branch leaves compiled nil and the evaluator compiles per call.
		return evalRegexReplace(n, resolver, event)
	}
	// Unreachable for any Plan produced by the compiler (every concrete op type
	// is handled above). Defensive false.
	return false
}

// evalCmp dispatches the six comparison operators over the resolved left/right
// Values. Type mismatches return false rather than panicking.
func evalCmp(n *opCmp, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	right, rok := evalValue(n.right, resolver, event)
	if !lok || !rok {
		// Either side failed to resolve (e.g. a field lookup returned false).
		// Treat as no-match.
		return false
	}

	// Special case: IP `eq` / `ne` CIDR — if right is a CIDR literal, the
	// comparison becomes IP-in-CIDR membership (left's IP against right's
	// network). The compiler pre-resolves the *net.IPNet at compile time
	// (DECISION D17); eval just calls ipnet.Contains(left) — no ParseCIDR
	// on the hot path.
	if left.Kind() == rule.KindIP && right.Kind() == rule.KindIP {
		if ipLit, ok := n.right.(*opLitIP); ok && ipLit.cidr {
			leftIP, _ := left.AsIP()
			if ipLit.ipnet == nil {
				return false
			}
			switch n.op {
			case opCmpEq:
				return ipLit.ipnet.Contains(leftIP)
			case opCmpNe:
				return !ipLit.ipnet.Contains(leftIP)
			default:
				// Ordering comparisons against a CIDR are meaningless; the compiler
				// only accepts eq / ne for IP-vs-CIDR, so reaching any other branch
				// is a defensive false.
				return false
			}
		}
	}

	// General case: strict same-Kind comparison. Kind mismatch surfaces as
	// no-match per the runtime type-mismatch contract.
	if left.Kind() != right.Kind() {
		return false
	}

	switch n.op {
	case opCmpEq:
		return left.Equal(right)
	case opCmpNe:
		return !left.Equal(right)
	case opCmpLt:
		return compareLess(left, right)
	case opCmpLe:
		return compareLess(left, right) || left.Equal(right)
	case opCmpGt:
		return compareLess(right, left)
	case opCmpGe:
		return compareLess(right, left) || left.Equal(right)
	}
	return false
}

// compareLess reports whether left is strictly less than right under the natural
// ordering of their shared Kind. Timestamp and Duration share a single underlying
// representation (int64 nanoseconds) so they share a comparison path; Int uses the
// same path. String is lexicographic. Float is IEEE-754 (NaN propagates the
// standard "comparison is false" semantics — both lt and gt return false for NaN).
//
// Both sides MUST share the same Kind; the caller enforces this via evalCmp's
// Kind-mismatch guard.
func compareLess(left, right rule.Value) bool {
	switch left.Kind() {
	case rule.KindInt:
		li, _ := left.AsInt()
		ri, _ := right.AsInt()
		return li < ri
	case rule.KindFloat:
		lf, _ := left.AsFloat()
		rf, _ := right.AsFloat()
		return lf < rf
	case rule.KindString:
		ls, _ := left.AsString()
		rs, _ := right.AsString()
		return ls < rs
	case rule.KindTimestamp:
		lt, _ := left.AsTimestamp()
		rt, _ := right.AsTimestamp()
		return lt.Before(rt)
	case rule.KindDuration:
		ld, _ := left.AsDuration()
		rd, _ := right.AsDuration()
		return ld < rd
	}
	// Non-orderable kinds (IP, Bool, Bytes, Array, Map) — caller enforces
	// orderability at compile time, so this branch is unreachable on a Plan
	// produced by Compile. Defensive false.
	return false
}

// evalContains implements `left contains right` for two String values.
func evalContains(n *opContains, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	right, rok := evalValue(n.right, resolver, event)
	if !lok || !rok || left.Kind() != rule.KindString || right.Kind() != rule.KindString {
		return false
	}
	ls, _ := left.AsString()
	rs, _ := right.AsString()
	return strings.Contains(ls, rs)
}

// evalStartsWith implements `left starts_with right` for two String values.
func evalStartsWith(n *opStartsWith, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	right, rok := evalValue(n.right, resolver, event)
	if !lok || !rok || left.Kind() != rule.KindString || right.Kind() != rule.KindString {
		return false
	}
	ls, _ := left.AsString()
	rs, _ := right.AsString()
	return strings.HasPrefix(ls, rs)
}

// evalEndsWith implements `left ends_with right` for two String values.
func evalEndsWith(n *opEndsWith, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	right, rok := evalValue(n.right, resolver, event)
	if !lok || !rok || left.Kind() != rule.KindString || right.Kind() != rule.KindString {
		return false
	}
	ls, _ := left.AsString()
	rs, _ := right.AsString()
	return strings.HasSuffix(ls, rs)
}

// evalMatches implements `left matches pattern` for left=String or left=Bytes.
// The *regexp.Regexp is pre-compiled at compile time (D4) by compileMatches.
func evalMatches(n *opMatches, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	if !lok || n.regex == nil {
		return false
	}
	switch left.Kind() {
	case rule.KindString:
		s, _ := left.AsString()
		return n.regex.MatchString(s)
	case rule.KindBytes:
		b, _ := left.AsBytes()
		return n.regex.Match(b)
	}
	return false
}

// evalWildcard implements `left wildcard pattern`. The pattern's grammar is `?`
// (one character) and `*` (any sequence); other characters match literally. The
// evaluator compiles the pattern to a *regexp.Regexp on first use (sync.Once)
// and reuses it on every subsequent Eval call.
//
// Why lazy compile (sync.Once) instead of compile-time:
// The compiler (C1) stores the pattern as a plain string, not as a pre-compiled
// regex. Making compile-time compile happen would require extending C1's contract
// (the brief from C2 explicitly flags this as an architect-level change). Lazy
// compile keeps C1 untouched and amortises the regex.Compile cost across every
// call after the first.
func evalWildcard(n *opWildcard, resolver rule.FieldResolver, event *plugin.Event) bool {
	left, lok := evalValue(n.left, resolver, event)
	if !lok || left.Kind() != rule.KindString {
		return false
	}
	// Compile the pattern lazily. sync.Once guarantees a single compilation
	// across goroutines; subsequent Eval calls reuse the cached regex.
	n.compileOnce.Do(func() {
		n.regex = compileWildcardPattern(n.pattern)
	})
	if n.regex == nil {
		// Pattern was empty or contained only illegal sequences that produced
		// an unmatchable regex — treat as no-match.
		return false
	}
	s, _ := left.AsString()
	return n.regex.MatchString(s)
}

// compileWildcardPattern converts a wildcard pattern (`?` = any single char,
// `*` = any sequence of chars) into a regexp pattern string. Any regex meta-
// characters in the user pattern are escaped by QuoteMeta first, then `*` and
// `?` are restored as their regex equivalents (.* and .).
//
// Examples:
//
//	"foo*"      → "^foo.*$"
//	"a?c"       → "^a.c$"
//	"*.log"     → "^.*\\.log$"  (the dot is escaped by QuoteMeta)
//	"10.0.0.1"  → "^10\\.0\\.0\\.1$"
//
// The full-string anchors (^ and $) match the brief's interpretation: the
// pattern must match the entire string, not just a substring.
func compileWildcardPattern(pattern string) *regexp.Regexp {
	if pattern == "" {
		// Empty pattern matches nothing (an empty string would match any
		// zero-length target, which is not the intent of a wildcard filter).
		return nil
	}
	// QuoteMeta escapes regex meta-chars; the only chars it leaves untouched
	// (in the printable ASCII range we care about) are letters, digits and a
	// handful of punctuation marks including `?` and `*`. We then expand `*`
	// → `.*` and `?` → `.`.
	quoted := regexp.QuoteMeta(pattern)
	// QuoteMeta turns `*` into `\*` and `?` into `\?`. Walk the quoted string
	// and expand them back.
	var b strings.Builder
	b.Grow(len(quoted) + 4)
	b.WriteByte('^')
	for i := 0; i < len(quoted); i++ {
		c := quoted[i]
		if c == '\\' && i+1 < len(quoted) {
			next := quoted[i+1]
			if next == '*' {
				b.WriteString(".*")
				i++
				continue
			}
			if next == '?' {
				b.WriteByte('.')
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		// Should be unreachable — QuoteMeta + controlled `*` / `?` expansion
		// always yields a valid regex. Defensive: fall back to no-match.
		return nil
	}
	return re
}

// evalIn implements `element in {set}`. The set must be a *opLitArray (the
// compiler enforces this). For IP elements, set members that are CIDR literals
// produce IP-in-CIDR membership rather than plain equality. The *net.IPNet for
// each CIDR literal was pre-resolved at compile time (DECISION D17), so the
// array branch uses ipnet.Contains directly with no runtime ParseCIDR.
func evalIn(n *opIn, resolver rule.FieldResolver, event *plugin.Event) bool {
	elem, eok := evalValue(n.element, resolver, event)
	if !eok {
		return false
	}
	arr, ok := n.set.(*opLitArray)
	if !ok {
		return false
	}
	if len(arr.elements) == 0 {
		// The compiler rejects empty arrays with CodeTypeMismatch, so reaching
		// here on a compiler-produced Plan is unreachable. A hand-built Plan
		// with an empty array evaluates to false (no element can be a member).
		return false
	}
	// Iterate the set. For IP elements we dispatch per-member: plain IP uses
	// Equal, CIDR uses membership (via the pre-resolved *net.IPNet on the
	// opLitIP). For non-IP elements every member must share the same Kind
	// (the compiler enforces this); Kind-mismatch surfaces as "not this
	// member", and if no member matches we return false.
	switch elem.Kind() {
	case rule.KindIP:
		leftIP, _ := elem.AsIP()
		for _, e := range arr.elements {
			ipLit, ok := e.(*opLitIP)
			if !ok {
				continue
			}
			// Branch on cidr first so we never call right.AsIP() on CIDR
			// members — the CIDR branch uses ipnet.Contains(leftIP) and
			// does not need the right-side IP at all. Hoisting the cidr
			// check avoids one wasted defensive-copy per matched/missed
			// CIDR member (the IP-vs-CIDR eval path is hot).
			if ipLit.cidr {
				if ipLit.ipnet != nil && ipLit.ipnet.Contains(leftIP) {
					return true
				}
				continue
			}
			rightIP, _ := ipLit.v.AsIP()
			if leftIP.Equal(rightIP) {
				return true
			}
		}
		return false
	default:
		for _, e := range arr.elements {
			// Compute the array member as a Value. For literal members this
			// is zero-cost (returns the stored Value). For non-literal members
			// (rejected by the compiler, so unreachable here) we'd recurse.
			mv, ok := evalValue(e, resolver, event)
			if !ok {
				continue
			}
			if mv.Kind() == elem.Kind() && elem.Equal(mv) {
				return true
			}
		}
		return false
	}
}

// ========================== Function dispatch ===============================================

// evalFuncCall is the eval-side dispatch for *opFunc in predicate position (the root
// of a Plan). The compile-time signature check (compileFuncCall, DECISION D16 §2)
// has already verified the function name, arity, and per-argument Kinds — at eval
// time we resolve each argument to a Value via evalValue and invoke the spec's
// Eval entry point.
//
// If any argument fails to resolve (e.g. a field reference whose resolver returned
// no value), the call is surfaced as "no match" (false) rather than panicking —
// the same defensive contract as every other op in the evaluator.
//
// A function that returns a non-Bool Kind is misused at the root of a Plan (the
// language expects a predicate). Defensive false.
func evalFuncCall(n *opFunc, resolver rule.FieldResolver, event *plugin.Event) bool {
	v, ok := evalFuncCallValue(n, resolver, event)
	if !ok {
		return false
	}
	b, ok := v.AsBool()
	if !ok {
		return false
	}
	return b
}

// evalFuncCallValue is the value-returning counterpart of evalFuncCall. It is used
// by evalValue when the function appears in value position (e.g. inside a Cmp
// operand: `lower(field) eq "abc"`). Returns the function's result Value plus an
// ok flag — false if any argument failed to resolve.
func evalFuncCallValue(n *opFunc, resolver rule.FieldResolver, event *plugin.Event) (rule.Value, bool) {
	args := make([]rule.Value, len(n.args))
	for i, a := range n.args {
		v, ok := evalValue(a, resolver, event)
		if !ok {
			return rule.Value{}, false
		}
		args[i] = v
	}
	return n.spec.Eval(args), true
}

// evalRegexReplace is the predicate-position dispatch for *opRegexReplace. The
// function returns a string, so a predicate-position call (the function at the
// root of a Plan) is a misuse. The engine's defensive contract surfaces this
// as "no match" — same as every other op with the wrong return kind at root.
//
// We keep the function for symmetry with evalFuncCall; the value-returning
// counterpart below is what value-position call sites use.
func evalRegexReplace(n *opRegexReplace, resolver rule.FieldResolver, event *plugin.Event) bool {
	v, ok := evalRegexReplaceValue(n, resolver, event)
	if !ok {
		return false
	}
	b, ok := v.AsBool()
	if !ok {
		return false
	}
	return b
}

// evalRegexReplaceValue resolves subject, repl, and (when the pattern was not
// precompiled) the pattern itself, then performs the replacement.
//
// DECISION D4 fast path: when n.compiled is non-nil, the regex is reused across
// every Eval call — no per-eval regexp.Compile. This is the case for literal
// patterns and the dominant case for compiled Plans.
//
// Non-literal patterns compile per call (regexp.Compile on a runtime-
// supplied string). The function Eval signature returns a Value, not an error,
// so a malformed per-eval pattern surfaces as the subject unchanged — the same
// defensive contract as the registry entry's evalRegexReplaceFallback.
func evalRegexReplaceValue(n *opRegexReplace, resolver rule.FieldResolver, event *plugin.Event) (rule.Value, bool) {
	subjectV, ok := evalValue(n.subject, resolver, event)
	if !ok {
		return rule.Value{}, false
	}
	subject, _ := subjectV.AsString()

	replV, ok := evalValue(n.repl, resolver, event)
	if !ok {
		return rule.Value{}, false
	}
	repl, _ := replV.AsString()

	if n.compiled != nil {
		return rule.NewString(n.compiled.ReplaceAllString(subject, repl)), true
	}

	// Non-literal pattern: compile per call from the resolved pattern value.
	patternV, ok := evalValue(n.patternOp, resolver, event)
	if !ok {
		return rule.Value{}, false
	}
	pattern, _ := patternV.AsString()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return rule.NewString(subject), true
	}
	return rule.NewString(re.ReplaceAllString(subject, repl)), true
}

// evalValue walks an op and returns the Value it produces, plus an "ok" flag.
// Used by the comparison / string / In ops to get the operand values, and by
// evalFuncCallValue to resolve function arguments.
//
// For literal ops the Value is stored directly and returned without any resolver
// involvement. For field / bracket ops the resolver is consulted. For function
// calls the args are resolved and the spec's Eval entry point produces the result.
// For nested composite ops (Cmp, Contains, In, ...) we surface a defensive
// failure: a comparison / membership op expects scalar operands, never another
// predicate. The compiler rejects this shape, so reaching here is unreachable
// on a compiler-produced Plan; we keep the guard for hand-built plans.
func evalValue(o op, resolver rule.FieldResolver, event *plugin.Event) (rule.Value, bool) {
	switch n := o.(type) {
	// ── Literals — return the stored Value directly (zero alloc) ─────────────
	case *opLitBool:
		return n.v, true
	case *opLitString:
		return n.v, true
	case *opLitInt:
		return n.v, true
	case *opLitFloat:
		return n.v, true
	case *opLitIP:
		return n.v, true
	case *opLitBytes:
		return n.v, true
	case *opLitDuration:
		return n.v, true
	case *opLitTimestamp:
		return n.v, true

	// ── Field resolution — the only place the resolver is consulted here ──────
	case *opField:
		return resolver.Resolve(n.name, event)

	// ── Bracket access — Map field + string key → resolved Value ──────────────
	case *opBracket:
		v, ok := resolver.Resolve(n.obj.name, event)
		if !ok || v.Kind() != rule.KindMap {
			return rule.Value{}, false
		}
		m, ok := v.AsMap()
		if !ok {
			return rule.Value{}, false
		}
		mv, present := m[n.key]
		if !present {
			return rule.Value{}, false
		}
		return mv, true

	// ── Strict wrapper — unwrap and recurse ────────────────────────────────────
	case *opStrict:
		return evalValue(n.inner, resolver, event)

	// ── Function call — resolve args and dispatch via the spec (D16) ───────────
	case *opFunc:
		return evalFuncCallValue(n, resolver, event)

	// ── regex_replace — value-position (Group D3) ─────────────────────────────
	case *opRegexReplace:
		// Returns a string. The eval-side resolution of subject / repl / pattern
		// (for non-literal patterns) lives in evalRegexReplace. We can reuse it
		// here because its value-returning shape matches.
		return evalRegexReplaceValue(n, resolver, event)

	// ── Defensive — predicate ops are not Values ───────────────────────────────
	case *opLitArray, *opAnd, *opOr, *opNot, *opCmp,
		*opContains, *opStartsWith, *opEndsWith, *opMatches, *opWildcard,
		*opIn:
		return rule.Value{}, false
	}
	return rule.Value{}, false
}

// compile-time conformance: Plan.Eval signature must stay stable for downstream
// callers (the embedding plugin). The assignment below is a no-op at runtime;
// it fails at build time if the Eval method signature drifts.
var _ = func(p *Plan, r rule.FieldResolver, e *plugin.Event) bool {
	return p.Eval(r, e)
}
