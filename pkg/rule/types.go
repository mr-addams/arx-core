// ========================== pkg/rule — Value type system =================================
//   The Value type is the universal, payload-agnostic value carrier used throughout the
//   rule engine. It represents the result of resolving a field at evaluation time, the
//   operands of literal sub-expressions, and the intermediate results of operator
//   evaluation. Every operator, function, and comparison in the rule language operates
//   on Values — never on plugin-specific payload types.
//
//   WHAT IS HERE:
//     - Kind — typed enum identifying the storage variant of a Value
//     - Value — union struct with one private storage slot per Kind
//     - AsXxx() — kind-checked accessors returning (T, bool) where bool == false means
//       "kind mismatch" (caller MUST check before using T)
//     - Constructors (NewString / NewInt / …) — defensive copies so the resulting
//       Value is immutable-by-convention
//     - String() / Kind.String() — stable, human-readable formatters for logs/errors
//     - Equal / IsZero — semantic equality and zero-state checks
//
//   WHAT IS NOT HERE:
//     - FieldResolver interface (resolver.go, Group A — Task A2)
//     - Catalog / Scheme (scheme.go, Group A — Task A3)
//     - Lexer / Parser / AST (parser/, Group B)
//     - Compiler / Evaluator (Group C)
//     - RuleSet / Builder (Group E)
//     - Any non-stdlib dependency
//
//   DEPENDENCY RULE:
//     pkg/rule → stdlib only, plus sibling arx-core/pkg/plugin for the Event boundary
//     referenced by FieldResolver (resolver.go). The Value system itself has no plugin
//     dependency — it is pure data.
//
//   CONCURRENCY:
//     Value is a value-type. All New* constructors copy their inputs; the resulting
//     Value may be shared across goroutines without further synchronization, matching
//     the immutability requirement of compiled plans (DECISION D4) and Event itself.

package rule

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

// ========================== Kind — typed enum =============================================

// Kind enumerates the storage variants of a Value. It is a typed uint8 wrapper so the
// type system catches accidental mixing with raw integers (compare with Kind.String()
// rather than with a magic number).
//
// KindInvalid is the zero value: a freshly-declared Value (without a constructor) reads
// as IsZero() == true and its AsXxx() accessors all return (zero, false). Callers MUST
// check Kind() before reading the underlying value or before invoking AsXxx() that
// they expect to succeed — there is no panic on mismatch, only a typed error signal.
type Kind uint8

const (
	// KindInvalid is the zero value; signals "no value". Use only for sentinel
	// returns and zero-Value construction. Equal / String / AsXxx are all defined
	// for KindInvalid (Equal always returns false against any non-invalid Value;
	// String returns "<invalid>"; AsXxx always returns (zero, false)).
	KindInvalid Kind = 0

	// KindString — Go string. Stored verbatim (strings are already immutable in Go).
	KindString Kind = 1

	// KindInt — Go int64. Range covers any signed 64-bit integer; literal/field
	// parsing converts via strconv.ParseInt.
	KindInt Kind = 2

	// KindFloat — Go float64. NaN/Inf are preserved; Equal compares with operator
	// == (bitwise equality, no epsilon — see Equal's doc comment).
	KindFloat Kind = 3

	// KindBool — Go bool. Distinct from KindInt(0)/KindInt(1) so the type-checker
	// can reject `42 == true` style mistakes.
	KindBool Kind = 4

	// KindIP — Go net.IP (IPv4 or IPv6 in 4- or 16-byte form). CIDR matching is
	// provided by the network-aware operators (compiler/evaluator); the Value
	// itself just holds the address.
	KindIP Kind = 5

	// KindBytes — Go []byte. Bitwise operators and constant-prefix matching live
	// in the evaluator; Value stores the raw bytes (defensive copy).
	KindBytes Kind = 6

	// KindTimestamp — Go time.Time. Comparisons use time.Time's natural ordering;
	// arithmetic with KindDuration yields a new KindTimestamp.
	KindTimestamp Kind = 7

	// KindDuration — Go time.Duration (nanosecond-resolution int64). Comparisons
	// and arithmetic are int64-native.
	KindDuration Kind = 8

	// KindArray — Go []Value. Heterogeneous: elements may be of any Kind. The
	// outer slice is copied defensively; each element Value is already immutable.
	KindArray Kind = 9

	// KindMap — Go map[string]Value. Open-ended dynamic fields (e.g. attrs["x"]).
	// The backing map is copied defensively; keys are sorted on String() output
	// for deterministic logs.
	KindMap Kind = 10
)

// String returns the canonical lowercase name of the Kind. Used in error messages,
// log lines, and in the textual form of the rule language's type names. The returned
// string is stable across versions — it is part of the engine's diagnostic surface.
func (k Kind) String() string {
	switch k {
	case KindInvalid:
		return "invalid"
	case KindString:
		return "string"
	case KindInt:
		return "int"
	case KindFloat:
		return "float"
	case KindBool:
		return "bool"
	case KindIP:
		return "ip"
	case KindBytes:
		return "bytes"
	case KindTimestamp:
		return "timestamp"
	case KindDuration:
		return "duration"
	case KindArray:
		return "array"
	case KindMap:
		return "map"
	default:
		// Defensive: keep the formatter total — a future Kind added without
		// updating this switch must not crash rule-language diagnostics.
		return "unknown(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
}

// ========================== Value — union struct ==========================================

// Value is the universal value carrier for the rule engine. It is a tagged union: the
// Kind discriminator selects which private storage slot is meaningful; all other slots
// hold their zero value.
//
// Constructors copy their inputs (defensive copy for IP / Bytes / Array / Map); once
// built, a Value is immutable-by-convention. This lets compiled plans and event-time
// resolvers share Values across goroutines without synchronization (DECISION D4).
//
// Access pattern:
//
//	v := rule.NewInt(42)
//	if v.Kind() != rule.KindInt {
//	    return errors.New("type error")
//	}
//	if n, ok := v.AsInt(); ok {
//	    // use n
//	}
//
// Field resolvers MUST return KindInvalid (Value{}) when a field is absent — not a
// partially-initialised Value of the expected Kind. The compiler treats KindInvalid
// as "field unresolved" at evaluation time.
type Value struct {
	kind Kind

	// Scalars / value-types — one of these is meaningful per Kind.
	str string  // KindString
	i   int64   // KindInt, KindDuration (Duration == int64 ns under the hood)
	f   float64 // KindFloat
	b   bool    // KindBool
	ip  net.IP  // KindIP — always a freshly-copied []byte, never shared with caller

	// Heap-backed storage — only meaningful for their respective Kinds.
	bytes []byte           // KindBytes
	ts    time.Time        // KindTimestamp
	arr   []Value          // KindArray
	m     map[string]Value // KindMap
}

// Kind returns the discriminator of the Value. Always defined, even for KindInvalid.
// Callers MUST consult Kind before relying on the result of any AsXxx() call.
func (v Value) Kind() Kind { return v.kind }

// IsZero reports whether v is the zero Value (KindInvalid). It does NOT compare the
// underlying scalar — KindInt with i == 0 is a valid Int zero, not a KindInvalid
// Value. IsZero is the right check for "did this field resolve?" / "is this a
// sentinel?".
func (v Value) IsZero() bool { return v.kind == KindInvalid }

// ========================== AsXxx — kind-checked accessors =================================

// AsString returns the underlying string when Kind == KindString, otherwise
// ("", false). bool == false ALWAYS means "kind mismatch" — the returned string is
// the empty string in that case and MUST NOT be used by the caller.
func (v Value) AsString() (string, bool) {
	if v.kind != KindString {
		return "", false
	}
	return v.str, true
}

// AsInt returns the underlying int64 when Kind == KindInt, otherwise (0, false).
// bool == false ALWAYS means "kind mismatch".
func (v Value) AsInt() (int64, bool) {
	if v.kind != KindInt {
		return 0, false
	}
	return v.i, true
}

// AsFloat returns the underlying float64 when Kind == KindFloat, otherwise (0, false).
// bool == false ALWAYS means "kind mismatch".
func (v Value) AsFloat() (float64, bool) {
	if v.kind != KindFloat {
		return 0, false
	}
	return v.f, true
}

// AsBool returns the underlying bool when Kind == KindBool, otherwise (false, false).
// bool == false ALWAYS means "kind mismatch". The (zero-value, false) collision is
// resolved by checking Kind() first when the distinction matters.
func (v Value) AsBool() (bool, bool) {
	if v.kind != KindBool {
		return false, false
	}
	return v.b, true
}

// AsIP returns a COPY of the underlying IP when Kind == KindIP, otherwise (nil, false).
// The copy is intentional: callers may keep the slice without aliasing the engine's
// storage. bool == false ALWAYS means "kind mismatch".
func (v Value) AsIP() (net.IP, bool) {
	if v.kind != KindIP {
		return nil, false
	}
	return append(net.IP(nil), v.ip...), true
}

// AsBytes returns a COPY of the underlying byte slice when Kind == KindBytes,
// otherwise (nil, false). The copy is intentional — callers may retain the slice
// without aliasing the engine's storage. bool == false ALWAYS means "kind mismatch".
func (v Value) AsBytes() ([]byte, bool) {
	if v.kind != KindBytes {
		return nil, false
	}
	return bytes.Clone(v.bytes), true
}

// AsTimestamp returns the underlying time.Time when Kind == KindTimestamp, otherwise
// (time.Time{}, false). bool == false ALWAYS means "kind mismatch".
func (v Value) AsTimestamp() (time.Time, bool) {
	if v.kind != KindTimestamp {
		return time.Time{}, false
	}
	return v.ts, true
}

// AsDuration returns the underlying time.Duration when Kind == KindDuration, otherwise
// (0, false). bool == false ALWAYS means "kind mismatch".
func (v Value) AsDuration() (time.Duration, bool) {
	if v.kind != KindDuration {
		return 0, false
	}
	return time.Duration(v.i), true
}

// AsArray returns a COPY of the underlying Value slice when Kind == KindArray,
// otherwise (nil, false). Element Values are themselves immutable-by-convention, so
// a shallow copy of the slice is the correct level of defensive copying. bool == false
// ALWAYS means "kind mismatch".
func (v Value) AsArray() ([]Value, bool) {
	if v.kind != KindArray {
		return nil, false
	}
	return append([]Value(nil), v.arr...), true
}

// AsMap returns a COPY of the underlying map when Kind == KindMap, otherwise
// (nil, false). The copy is a shallow copy — each value is an immutable Value, so the
// map's keys and value-identity are preserved without aliasing the engine's storage.
// bool == false ALWAYS means "kind mismatch".
func (v Value) AsMap() (map[string]Value, bool) {
	if v.kind != KindMap {
		return nil, false
	}
	return mapsClone(v.m), true
}

// ========================== Constructors ===================================================

// NewString wraps s as a KindString Value. No defensive copy is required: Go strings
// are immutable, so sharing the backing bytes with the caller is safe.
func NewString(s string) Value { return Value{kind: KindString, str: s} }

// NewInt wraps i as a KindInt Value.
func NewInt(i int64) Value { return Value{kind: KindInt, i: i} }

// NewFloat wraps f as a KindFloat Value. NaN and Inf are preserved verbatim.
func NewFloat(f float64) Value { return Value{kind: KindFloat, f: f} }

// NewBool wraps b as a KindBool Value.
func NewBool(b bool) Value { return Value{kind: KindBool, b: b} }

// NewIP wraps ip as a KindIP Value. The constructor performs a defensive copy of ip
// so that subsequent mutation of the caller's slice (ip is a []byte under the hood)
// does NOT affect the resulting Value. Callers may pass nil; the resulting Value is
// a KindIP with an empty IP (len(ip) == 0), which is distinct from KindInvalid.
func NewIP(ip net.IP) Value {
	return Value{kind: KindIP, ip: append(net.IP(nil), ip...)}
}

// NewBytes wraps b as a KindBytes Value. The constructor performs a defensive copy so
// that subsequent mutation of the caller's slice does NOT affect the resulting Value.
// A nil input yields a KindBytes Value with an empty slice — distinct from KindInvalid.
func NewBytes(b []byte) Value {
	return Value{kind: KindBytes, bytes: bytes.Clone(b)}
}

// NewTimestamp wraps t as a KindTimestamp Value. time.Time is a value type with an
// internal pointer; the struct is copied verbatim, which is the conventional Go
// approach (mutating a time.Time's wall clock requires explicit reassignment).
func NewTimestamp(t time.Time) Value { return Value{kind: KindTimestamp, ts: t} }

// NewDuration wraps d as a KindDuration Value. Stored as int64 nanoseconds in the
// shared scalar slot.
func NewDuration(d time.Duration) Value { return Value{kind: KindDuration, i: int64(d)} }

// NewArray wraps a as a KindArray Value. The constructor performs a defensive copy of
// the outer slice; element Values are immutable-by-convention, so a shallow copy is
// the correct level of copying. A nil input yields a KindArray Value with an empty
// slice — distinct from KindInvalid.
func NewArray(a []Value) Value {
	return Value{kind: KindArray, arr: append([]Value(nil), a...)}
}

// NewMap wraps m as a KindMap Value. The constructor performs a defensive copy of the
// map (shallow — values are themselves immutable Values). A nil input yields a
// KindMap Value with an empty map — distinct from KindInvalid.
func NewMap(m map[string]Value) Value {
	return Value{kind: KindMap, m: mapsClone(m)}
}

// mapsClone returns a shallow copy of m; nil yields an empty (non-nil) map so that
// callers may add to it without nil-handling at the use site.
func mapsClone(m map[string]Value) map[string]Value {
	if m == nil {
		return map[string]Value{}
	}
	out := make(map[string]Value, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ========================== Stringer =======================================================

// String returns a stable, human-readable representation of the Value. The format is
// chosen for diagnostic logs and error messages — it is NOT a parser input format.
// Map keys are sorted alphabetically; Array elements appear in source order; nested
// Values use the same rules recursively. KindInvalid renders as "<invalid>".
func (v Value) String() string {
	switch v.kind {
	case KindInvalid:
		return "<invalid>"
	case KindString:
		return v.str
	case KindInt:
		return strconv.FormatInt(v.i, 10)
	case KindFloat:
		// 'g' with -1 precision picks the shortest representation that round-trips.
		return strconv.FormatFloat(v.f, 'g', -1, 64)
	case KindBool:
		return strconv.FormatBool(v.b)
	case KindIP:
		return v.ip.String()
	case KindBytes:
		return hex.EncodeToString(v.bytes)
	case KindTimestamp:
		return v.ts.Format(time.RFC3339Nano)
	case KindDuration:
		return time.Duration(v.i).String()
	case KindArray:
		return arrayString(v.arr)
	case KindMap:
		return mapString(v.m)
	default:
		return "<unknown-kind:" + v.kind.String() + ">"
	}
}

// arrayString renders a KindArray Value as "[v1, v2, ...]" — comma-separated,
// no trailing comma. Empty arrays render as "[]".
func arrayString(arr []Value) string {
	if len(arr) == 0 {
		return "[]"
	}
	// Pre-size the builder to avoid the grow-and-copy dance. Average Value.String()
	// is short (≈8–16 bytes); the +2 per-element covers the ", " separator.
	buf := make([]byte, 0, 2+len(arr)*16)
	buf = append(buf, '[')
	for i, e := range arr {
		if i > 0 {
			buf = append(buf, ',', ' ')
		}
		buf = append(buf, e.String()...)
	}
	buf = append(buf, ']')
	return string(buf)
}

// mapString renders a KindMap Value as "map[k1:v1 k2:v2 ...]" with keys in sorted
// order for deterministic logs. Empty maps render as "map[]".
func mapString(m map[string]Value) string {
	if len(m) == 0 {
		return "map[]"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := make([]byte, 0, 6+len(m)*32)
	buf = append(buf, "map["...)
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, k...)
		buf = append(buf, ':')
		buf = append(buf, m[k].String()...)
	}
	buf = append(buf, ']')
	return string(buf)
}

// ========================== Equality =======================================================

// Equal reports whether two Values are semantically equal. Kind must match first; then
// a Kind-specific comparison is applied.
//
// Float comparison uses Go's == operator (bitwise equality on the IEEE-754
// representation). This is intentional: epsilon-based equality is the evaluator's
// concern (a future `~=` operator), not the Value type's. Two NaN floats are equal
// under this definition because Go's == treats NaN as equal to itself; callers
// needing IEEE-754-distinct NaN behavior must guard at a higher layer.
//
// Bytes are compared via bytes.Equal; IP via net.IP.Equal (which normalises 4-byte
// and 16-byte forms of the same IPv4 address). Timestamp uses time.Time.Equal (which
// compares wall clock and monotonic clock separately). Array compares element-by-
// element; Map compares key sets first, then per-key Values.
//
// nil and empty (length-0) slices/maps compare equal — both sides render as
// "[]" / "map[]" via String() and represent the same logical absence. This matches
// the convention used by the rest of the Go ecosystem (e.g. encoding/json).
//
// KindInvalid is never equal to anything, including another KindInvalid — the zero
// Value is a sentinel, not a value.
func (v Value) Equal(other Value) bool {
	if v.kind != other.kind {
		return false
	}
	switch v.kind {
	case KindInvalid:
		// KindInvalid is a sentinel — two zero Values are NOT equal. This avoids
		// treating "field missing" as "field equal to missing" in rule semantics.
		return false
	case KindString:
		return v.str == other.str
	case KindInt:
		return v.i == other.i
	case KindFloat:
		return v.f == other.f
	case KindBool:
		return v.b == other.b
	case KindIP:
		return v.ip.Equal(other.ip)
	case KindBytes:
		return bytes.Equal(v.bytes, other.bytes)
	case KindTimestamp:
		return v.ts.Equal(other.ts)
	case KindDuration:
		return v.i == other.i
	case KindArray:
		return arrayEqual(v.arr, other.arr)
	case KindMap:
		return mapEqual(v.m, other.m)
	default:
		return false
	}
}

// arrayEqual compares two Value slices element-by-element. nil and empty (len==0)
// slices compare equal — both sides represent the same logical empty array.
func arrayEqual(a, b []Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// mapEqual compares two Value maps by key-set first, then by per-key Equal. nil and
// empty (len==0) maps compare equal. Order of iteration is irrelevant.
func mapEqual(a, b map[string]Value) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !va.Equal(vb) {
			return false
		}
	}
	return true
}

// fmt.Stringer conformance (also picked up by %s / %v formatting in log packages).
var _ fmt.Stringer = Value{}
