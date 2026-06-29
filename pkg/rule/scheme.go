// ========================== pkg/rule — Scheme / Catalog ===================================
//   Catalog is the runtime registry of every field known to the engine. It is append-only
//   after startup (DECISION D6, "Catalog is the global, all-loaded-plugins registry"):
//   once a field is registered it stays for the lifetime of the process — there is no
//   Unregister. A plan compiled against an older Catalog revision stays valid until the
//   plan itself is recompiled (D13).
//
//   Scheme is the per-use-case projection of a Catalog (D6, D9). It is an immutable
//   snapshot: the fields known at the moment of Project(...) are frozen, and subsequent
//   Register calls into the source Catalog have no effect on a Scheme created before
//   them. Multiple Schemes can coexist — one per profile ("waf", "syslog-anomaly", ...)
//   each carrying the FieldInfo set the profile is allowed to reference.
//
//   WHAT IS HERE:
//     - FieldType — string-typed mirror of the Value Kind enum (D5). Keeps pkg/rule
//       field types self-describing and stable across versions without dragging the
//       Kind numeric values into the field contract.
//     - FieldInfo — Namespace + Name + Type triple, the unit of registration and
//       projection.
//     - Catalog — thread-safe Registry (D6, D13): Register / Fields / Has / Revision.
//     - Scheme — immutable snapshot, the unit of compilation (D9).
//
//   WHAT IS NOT HERE:
//     - Parser / compiler that consumes Scheme (Group B / C).
//     - RuleSet built on top of Scheme (E1).
//     - Builder glue for ergonomic registration from a Manifest (E2).
//     - HTTP / syslog / <custom> resolvers — owned by their plugins, not Core (D3, D7).
//     - Any non-stdlib dependency (D2).
//
//   DEPENDENCY RULE:
//     pkg/rule → stdlib only, plus sibling arx-core/pkg/plugin for the Event boundary
//     referenced by FieldResolver (resolver.go). Catalog and Scheme themselves never
//     touch pkg/plugin — they are pure data.
//
//   CONCURRENCY:
//     - Register holds the write lock and bumps an atomic Revision counter, so
//       concurrent Readers (Fields / Has / Revision) never block on the lock just to
//       read the counter.
//     - Fields() / Has() / Revision() / Project(...) hold the read lock.
//     - Scheme is constructed under the read lock and is immutable thereafter — it
//       may be passed across goroutines without coordination.

package rule

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
)

// ========================== FieldType — typed mirror of Kind ===============================

// FieldType is the stable, version-independent name of a field's value kind. It mirrors
// the Kind enum (DECISION D5) as a string constant so the field contract — what a
// downstream plugin manifest and the rule-language type-checker exchange — stays textual
// rather than dependent on the underlying numeric Kind values.
//
// KindInvalid (the "absent field" sentinel) is intentionally NOT represented: it is a
// runtime sentinel, not a declared field type. A future Kind added without a
// corresponding FieldType constant will be rejected by Register with ErrUnknownFieldType.
type FieldType string

// Field type constants. The string value is part of the engine's diagnostic surface
// (rule-language type names, error messages, Manifest exports) — treat changes as
// breaking.
const (
	TypeString    FieldType = "string"
	TypeInt       FieldType = "int"
	TypeFloat     FieldType = "float"
	TypeBool      FieldType = "bool"
	TypeIP        FieldType = "ip"
	TypeBytes     FieldType = "bytes"
	TypeTimestamp FieldType = "timestamp"
	TypeDuration  FieldType = "duration"
	TypeArray     FieldType = "array"
	TypeMap       FieldType = "map"
)

// ========================== FieldInfo — registration unit =================================

// FieldInfo describes a single field known to the engine. Namespace is the dot-prefix
// owner of the field ("core", "http", "syslog", "<custom>"); Name is the unqualified
// field name within that namespace. FullName returns the canonical dotted form used as
// the key in the Catalog's index and as the spelling the parser and FieldResolver.
//
// FieldInfo values are immutable once published via Fields() or Project(): callers may
// compare them by value, pass them across goroutines, and build maps keyed by them
// without synchronization.
type FieldInfo struct {
	// Namespace is the dot-prefix owner of the field (DECISION D7). For a field
	// declared as "http.method", Namespace == "http". Never empty.
	Namespace string

	// Name is the unqualified field name within the namespace. For a field
	// declared as "http.method", Name == "method". Never empty.
	Name string

	// Type is the FieldType mirror of the field's Value Kind. Stable across versions.
	Type FieldType
}

// FullName returns the canonical dotted form of the field — "<namespace>.<name>". This
// is the spelling the rule language uses for field references, and the key the Catalog
// indexes by.
func (f FieldInfo) FullName() string { return f.Namespace + "." + f.Name }

// Equal reports whether two FieldInfo values describe the same field (same namespace,
// name, and type). Comparison is exact — different namespaces with same name, or same
// namespace/name with different type, both report false.
func (f FieldInfo) Equal(other FieldInfo) bool {
	return f.Namespace == other.Namespace && f.Name == other.Name && f.Type == other.Type
}

// ========================== Public errors ==================================================

var (
	// ErrEmptyNamespace is returned by Register when a field name is supplied without a
	// "<namespace>." prefix. Every field in the engine MUST be namespaced (D7); a bare
	// name is a configuration error.
	ErrEmptyNamespace = errors.New("rule: field name has no namespace prefix")

	// ErrInvalidNamespace is returned when the namespace portion of a field name is
	// empty or contains characters that would break the rule-language grammar (a dot,
	// whitespace, or a non-lowercase letter).
	ErrInvalidNamespace = errors.New("rule: invalid namespace")

	// ErrInvalidName is returned when the unqualified field name is empty, contains a
	// dot, whitespace, or a non-lowercase letter.
	ErrInvalidName = errors.New("rule: invalid field name")

	// ErrFieldExists is returned when Register is called for a field that is already
	// registered with the same type. Idempotent re-registration with the same type is
	// NOT silently accepted — a duplicate name in the namespace is a programming error
	// (D7: each namespace owns its field spellings), and silently accepting it would
	// hide the duplication.
	ErrFieldExists = errors.New("rule: field already registered")

	// ErrFieldTypeMismatch is returned when Register is called for a field that is
	// already registered with a different type. A type re-declaration is a programming
	// error — namespaces are supposed to own disjoint field names (D7) and types.
	ErrFieldTypeMismatch = errors.New("rule: field type mismatch on re-registration")

	// ErrUnknownFieldType is returned when Register is called with a FieldType value
	// that does not correspond to any declared constant. Catches typos like
	// TypeInteher instead of TypeInt at registration time rather than at compile time.
	ErrUnknownFieldType = errors.New("rule: unknown field type")
)

// ========================== internal validation ============================================

// validNamespace reports whether ns is a usable namespace per DECISION D7. The rules are
// non-empty, no dot (so it can be combined with a name unambiguously), no whitespace,
// and lowercase. The lowercase convention keeps dotted spellings canonical across logs,
// config, and Manifest exports — the parser (Group B) will not have to normalise at
// every call site.
func validNamespace(ns string) bool {
	if ns == "" {
		return false
	}
	for i := 0; i < len(ns); i++ {
		if !validIdentByte(ns[i]) {
			return false
		}
	}
	return true
}

// validName reports whether n is a usable unqualified field name per DECISION D7. The
// rules match validNamespace; the two helpers are kept apart because we may want to
// relax the rules asymmetrically (e.g. allow hyphens in names but not in namespaces)
// later.
func validName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !validIdentByte(n[i]) {
			return false
		}
	}
	return true
}

// validIdentByte reports whether c is a byte allowed in a field identifier component.
// The set is deliberately narrow: lowercase ASCII letters, digits, and underscore /
// hyphen. Dots and whitespace would break the dotted grammar of <namespace>.<name>.
func validIdentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_' || c == '-':
		return true
	}
	return false
}

// isKnownFieldType reports whether t corresponds to one of the declared FieldType
// constants. Closed set — adding a new Kind to types.go without adding a FieldType
// here is a deliberate decision, and registering such a field fails fast.
func isKnownFieldType(t FieldType) bool {
	switch t {
	case TypeString, TypeInt, TypeFloat, TypeBool, TypeIP,
		TypeBytes, TypeTimestamp, TypeDuration, TypeArray, TypeMap:
		return true
	}
	return false
}

// ========================== Catalog ========================================================

// Catalog is the process-wide registry of every field known to the rule engine
// (DECISION D6, "the global, all-loaded-plugins registry"). It is append-only after
// startup: there is no Unregister. Every successful Register call increments a
// monotonic revision counter (DECISION D13) so that compiled plans can detect when the
// field surface they were compiled against has changed.
//
// The zero value of Catalog is NOT usable — construct one with NewCatalog.
type Catalog struct {
	mu sync.RWMutex

	// rev is incremented on every successful Register call. Read without the lock via
	// atomic.Load — faster than a mutex acquisition on the hot path. The atomic also
	// publishes a happens-before edge so a goroutine that observed a new Revision()
	// value can rely on the new Fields() state.
	rev atomic.Uint64

	// fields is the index keyed by FullName(). Guarded by mu.
	fields map[string]FieldInfo
}

// NewCatalog returns an empty Catalog ready to accept Register calls.
func NewCatalog() *Catalog {
	return &Catalog{fields: make(map[string]FieldInfo)}
}

// Register records (namespace, name) → typ in the Catalog. The field becomes visible to
// future Fields() / Has() / Project(...) calls and bumps Revision(). Once a field is
// registered for a given (namespace, name), re-registering:
//
//   - with the SAME Type        → ErrFieldExists (the registration already happened;
//     the caller is registering twice, which is a bug — see D7 namespace ownership).
//   - with a DIFFERENT Type     → ErrFieldTypeMismatch (same root cause: conflicting
//     declarations of the same field).
//
// Inputs are validated BEFORE any mutation: an empty namespace, a malformed name, or
// an unknown FieldType all return their respective error and do NOT touch the Catalog
// or the revision counter. A bad Register must not bump the revision and invalidate
// every compiled plan in the process.
//
// Register is safe for concurrent use with Fields / Has / Revision.
func (c *Catalog) Register(namespace, name string, typ FieldType) error {
	if !validNamespace(namespace) {
		if namespace == "" {
			return ErrEmptyNamespace
		}
		return ErrInvalidNamespace
	}
	if !validName(name) {
		return ErrInvalidName
	}
	if !isKnownFieldType(typ) {
		return ErrUnknownFieldType
	}

	full := namespace + "." + name

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.fields[full]; ok {
		if existing.Type == typ {
			return ErrFieldExists
		}
		return ErrFieldTypeMismatch
	}

	c.fields[full] = FieldInfo{Namespace: namespace, Name: name, Type: typ}
	// Order matters: bump the revision only after the field is durably visible to
	// readers. atomic Add is sequentially consistent on every supported architecture,
	// so a subsequent Revision() ≥ the bumped value implies the new Fields() state is
	// observable to that caller.
	c.rev.Add(1)
	return nil
}

// Fields returns a snapshot of every FieldInfo currently in the Catalog, sorted by
// FullName(). The returned slice is freshly allocated and owned by the caller; the
// Catalog retains its own copy, so the caller may sort, retain, or modify the result
// independently of future Register calls.
//
// Snapshot semantics: a call observing Revision() == N sees exactly the Fields() at
// that revision. A subsequent successful Register() bumps revision to N+1 and adds a
// new field to the snapshot. The previous Fields() slice is NOT mutated.
//
// Fields is safe for concurrent use with Register and other readers.
func (c *Catalog) Fields() []FieldInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]FieldInfo, 0, len(c.fields))
	for _, fi := range c.fields {
		out = append(out, fi)
	}
	sortFieldInfos(out)
	return out
}

// Has reports whether the Catalog knows about the given fully-qualified field name. It
// is a thin convenience for callers (e.g. the future compiler) that only need existence.
//
// Has is safe for concurrent use with Register and other readers.
func (c *Catalog) Has(fullName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.fields[fullName]
	return ok
}

// Revision returns the current monotonic revision of the Catalog. It starts at 0 for a
// freshly constructed Catalog and is incremented by 1 for every successful Register.
//
// Revision is loaded without acquiring the Catalog's lock: the atomic guarantees
// monotonicity and visibility on every platform arx-core targets.
//
// Revision is safe for concurrent use with Register and other readers.
func (c *Catalog) Revision() uint64 {
	return c.rev.Load()
}

// Project builds an immutable Scheme containing every field of the Catalog whose
// Namespace appears in namespaces. An empty namespaces slice yields a Scheme with no
// fields (still well-formed). The result is detached from the Catalog: future
// Register calls do NOT change Scheme.Fields().
//
// Rationale (D9): each profile declares the namespaces it knows about ("waf" →
// {core, http}, "syslog-anomaly" → {core, syslog}, ...) and Project(...) is what
// translates that declaration into a frozen Scheme the compiler validates against
// without racing with global Catalog mutations.
//
// Malformed namespace arguments are silently dropped — a profile with one typo is not
// allowed to either fail loudly (Compile-once/eval-many invariants, D4) or to silently
// produce a wrong Scheme. We opt for the safe side: nothing matches a malformed
// namespace, so the projection simply omits those fields.
//
// Project is safe for concurrent use with Register and other readers. It holds the
// read lock for the duration of the copy so the snapshot is internally consistent.
func (c *Catalog) Project(namespaces ...string) *Scheme {
	nsSet := make(map[string]struct{}, len(namespaces))
	for _, ns := range namespaces {
		if validNamespace(ns) {
			nsSet[ns] = struct{}{}
		}
	}

	c.mu.RLock()
	rev := c.rev.Load()
	snap := make([]FieldInfo, 0, len(nsSet))
	if len(nsSet) > 0 {
		for _, fi := range c.fields {
			if _, ok := nsSet[fi.Namespace]; ok {
				snap = append(snap, fi)
			}
		}
	}
	sortFieldInfos(snap)
	c.mu.RUnlock()

	return &Scheme{fields: snap, rev: rev}
}

// ========================== Scheme =========================================================

// Scheme is an immutable projection of a Catalog, frozen for use by the compiler and
// matched at evaluation time (DECISION D6, D9). Once constructed via
// (*Catalog).Project, its Fields() set does not change.
//
// Concurrency: a Scheme is immutable; it may be passed across goroutines without
// synchronization.
type Scheme struct {
	// fields is sorted by FullName() at construction. The slice is owned by the Scheme
	// and never mutated after Project returns.
	fields []FieldInfo

	// rev is the Catalog.Revision() observed at Project time. Subsequent Register
	// calls on the source Catalog increment the source's revision; the Scheme retains
	// the revision it was built against so a plan compiled from this Scheme can detect
	// a stale-base problem (D13: "compiled plans carry the revision they were compiled
	// against").
	rev uint64
}

// Fields returns the projection's field snapshot as a freshly allocated, independently
// owned slice. The caller may sort, retain, or modify the result without affecting
// the Scheme or any other caller.
func (s *Scheme) Fields() []FieldInfo {
	if s == nil {
		return nil
	}
	out := make([]FieldInfo, len(s.fields))
	copy(out, s.fields)
	return out
}

// Revision returns the Catalog revision this Scheme was projected against. Combined
// with the source Catalog's Revision(), a caller can determine whether the Scheme is
// still in sync with the live Catalog state.
//
// A nil receiver returns 0 so callers don't need a guard before calling.
func (s *Scheme) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.rev
}

// Has reports whether the Scheme knows about the given fully-qualified field name.
// Useful as a compile-time gate ("is this field valid in this profile?") before the
// compiler commits to an op node.
//
// A nil receiver returns false so callers don't need a guard before calling.
func (s *Scheme) Has(fullName string) bool {
	if s == nil {
		return false
	}
	// fields is sorted by FullName(); linear scan beats the alternatives for the
	// per-profile cardinality typical of WAF / syslog use cases (a few dozen entries).
	// A map-based secondary index would dwarf the actual projection data.
	for i := range s.fields {
		if s.fields[i].FullName() == fullName {
			return true
		}
	}
	return false
}

// ========================== internal helpers ===============================================

// sortFieldInfos sorts a slice in place by FullName(). Insertion sort for tiny slices —
// the common per-profile cardinality — falls through to sort.Slice for larger ones.
// The FullName key uniquely identifies a field, so we don't need a stable sort.
func sortFieldInfos(s []FieldInfo) {
	if len(s) < 32 {
		// Insertion sort: allocation-free, predictable, and faster than sort.Slice for
		// the dozens-of-entries regime that Schemes operate in.
		for i := 1; i < len(s); i++ {
			for j := i; j > 0 && s[j-1].FullName() > s[j].FullName(); j-- {
				s[j-1], s[j] = s[j], s[j-1]
			}
		}
		return
	}
	sort.Slice(s, func(i, j int) bool {
		return s[i].FullName() < s[j].FullName()
	})
}
