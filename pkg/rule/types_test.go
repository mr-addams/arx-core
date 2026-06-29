// ========================== pkg/rule — Value type system tests ============================
//   Sanity-coverage suite for Value/Kind. Comprehensive semantic tests (operator
//   dispatch, edge cases around NaN, big-ints, map ordering under concurrent writes,
//   etc.) live in Group F — Task F1. This file establishes the constructor / accessor /
//   Stringer / Equal contract that A1 must satisfy, plus the defensive-copy guarantee
//   so later tasks can rely on it.

package rule

import (
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------- helpers -----------------------------------------------------

// fixedNow is a stable wall-clock time used in tests so RFC3339Nano output is asserted
// deterministically. Using time.Now() would race the formatter against the test clock.
var fixedNow = time.Date(2026, 6, 25, 12, 34, 56, 789_000_000, time.UTC)

// ---------------------------- constructor + accessor contract -----------------------------

func TestKind_String(t *testing.T) {
	cases := []struct {
		k    Kind
		want string
	}{
		{KindInvalid, "invalid"},
		{KindString, "string"},
		{KindInt, "int"},
		{KindFloat, "float"},
		{KindBool, "bool"},
		{KindIP, "ip"},
		{KindBytes, "bytes"},
		{KindTimestamp, "timestamp"},
		{KindDuration, "duration"},
		{KindArray, "array"},
		{KindMap, "map"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.k.String(); got != tc.want {
				t.Fatalf("Kind(%d).String() = %q, want %q", tc.k, got, tc.want)
			}
		})
	}
	// Unknown kind — defensive branch must not panic and must render meaningfully.
	unknown := Kind(255)
	if got := unknown.String(); !strings.HasPrefix(got, "unknown(") {
		t.Fatalf("unknown Kind.String() = %q, want prefix %q", got, "unknown(")
	}
}

func TestIsZero(t *testing.T) {
	if !(Value{}).IsZero() {
		t.Fatalf("Value{} should be IsZero()==true")
	}
	if (Value{kind: KindInt, i: 0}).IsZero() {
		t.Fatalf("KindInt(0) must NOT be IsZero — it's a valid Int zero, not a sentinel")
	}
	if (NewInt(42)).IsZero() {
		t.Fatalf("NewInt(42) must NOT be IsZero")
	}
}

func TestConstructors_KindAndAccessors(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		v := NewString("hello")
		if v.Kind() != KindString {
			t.Fatalf("Kind = %v, want KindString", v.Kind())
		}
		if got, ok := v.AsString(); !ok || got != "hello" {
			t.Fatalf("AsString() = (%q,%v), want (\"hello\",true)", got, ok)
		}
		// Mismatched accessors return (zero, false).
		if _, ok := v.AsInt(); ok {
			t.Fatalf("AsInt() on String should return ok=false")
		}
		if _, ok := v.AsFloat(); ok {
			t.Fatalf("AsFloat() on String should return ok=false")
		}
		if _, ok := v.AsBool(); ok {
			t.Fatalf("AsBool() on String should return ok=false")
		}
		if _, ok := v.AsIP(); ok {
			t.Fatalf("AsIP() on String should return ok=false")
		}
		if _, ok := v.AsBytes(); ok {
			t.Fatalf("AsBytes() on String should return ok=false")
		}
		if _, ok := v.AsTimestamp(); ok {
			t.Fatalf("AsTimestamp() on String should return ok=false")
		}
		if _, ok := v.AsDuration(); ok {
			t.Fatalf("AsDuration() on String should return ok=false")
		}
		if _, ok := v.AsArray(); ok {
			t.Fatalf("AsArray() on String should return ok=false")
		}
		if _, ok := v.AsMap(); ok {
			t.Fatalf("AsMap() on String should return ok=false")
		}
	})

	t.Run("Int", func(t *testing.T) {
		v := NewInt(42)
		if v.Kind() != KindInt {
			t.Fatalf("Kind = %v, want KindInt", v.Kind())
		}
		if got, ok := v.AsInt(); !ok || got != 42 {
			t.Fatalf("AsInt() = (%d,%v), want (42,true)", got, ok)
		}
		if _, ok := v.AsString(); ok {
			t.Fatalf("AsString() on Int should return ok=false")
		}
	})

	t.Run("Float", func(t *testing.T) {
		v := NewFloat(3.14)
		if v.Kind() != KindFloat {
			t.Fatalf("Kind = %v, want KindFloat", v.Kind())
		}
		if got, ok := v.AsFloat(); !ok || got != 3.14 {
			t.Fatalf("AsFloat() = (%v,%v), want (3.14,true)", got, ok)
		}
	})

	t.Run("Bool", func(t *testing.T) {
		vTrue := NewBool(true)
		if vTrue.Kind() != KindBool {
			t.Fatalf("Kind = %v, want KindBool", vTrue.Kind())
		}
		if got, ok := vTrue.AsBool(); !ok || got != true {
			t.Fatalf("AsBool() = (%v,%v), want (true,true)", got, ok)
		}

		vFalse := NewBool(false)
		// A bool false is a VALID value, not IsZero. The kind discriminator
		// (KindBool) is what distinguishes "value=false" from "no value".
		if vFalse.IsZero() {
			t.Fatalf("NewBool(false) must not be IsZero")
		}
		if got, ok := vFalse.AsBool(); !ok || got != false {
			t.Fatalf("AsBool() on false = (%v,%v), want (false,true)", got, ok)
		}
	})

	t.Run("IP", func(t *testing.T) {
		v := NewIP(net.ParseIP("192.0.2.1"))
		if v.Kind() != KindIP {
			t.Fatalf("Kind = %v, want KindIP", v.Kind())
		}
		got, ok := v.AsIP()
		if !ok {
			t.Fatalf("AsIP() ok=false on KindIP")
		}
		if !got.Equal(net.ParseIP("192.0.2.1")) {
			t.Fatalf("AsIP() = %s, want 192.0.2.1", got)
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		v := NewBytes([]byte{0xde, 0xad, 0xbe, 0xef})
		if v.Kind() != KindBytes {
			t.Fatalf("Kind = %v, want KindBytes", v.Kind())
		}
		got, ok := v.AsBytes()
		if !ok {
			t.Fatalf("AsBytes() ok=false on KindBytes")
		}
		if string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Fatalf("AsBytes() = %x, want deadbeef", got)
		}
	})

	t.Run("Timestamp", func(t *testing.T) {
		v := NewTimestamp(fixedNow)
		if v.Kind() != KindTimestamp {
			t.Fatalf("Kind = %v, want KindTimestamp", v.Kind())
		}
		got, ok := v.AsTimestamp()
		if !ok {
			t.Fatalf("AsTimestamp() ok=false on KindTimestamp")
		}
		if !got.Equal(fixedNow) {
			t.Fatalf("AsTimestamp() = %v, want %v", got, fixedNow)
		}
	})

	t.Run("Duration", func(t *testing.T) {
		v := NewDuration(1500 * time.Millisecond)
		if v.Kind() != KindDuration {
			t.Fatalf("Kind = %v, want KindDuration", v.Kind())
		}
		got, ok := v.AsDuration()
		if !ok || got != 1500*time.Millisecond {
			t.Fatalf("AsDuration() = (%v,%v), want (1.5s,true)", got, ok)
		}
	})

	t.Run("Array", func(t *testing.T) {
		arr := []Value{NewInt(1), NewString("two"), NewBool(true)}
		v := NewArray(arr)
		if v.Kind() != KindArray {
			t.Fatalf("Kind = %v, want KindArray", v.Kind())
		}
		got, ok := v.AsArray()
		if !ok {
			t.Fatalf("AsArray() ok=false on KindArray")
		}
		if len(got) != 3 {
			t.Fatalf("len(AsArray()) = %d, want 3", len(got))
		}
		if !got[0].Equal(NewInt(1)) {
			t.Fatalf("AsArray()[0] = %v, want Int(1)", got[0])
		}
		if !got[1].Equal(NewString("two")) {
			t.Fatalf("AsArray()[1] = %v, want String(\"two\")", got[1])
		}
		if !got[2].Equal(NewBool(true)) {
			t.Fatalf("AsArray()[2] = %v, want Bool(true)", got[2])
		}
	})

	t.Run("Map", func(t *testing.T) {
		m := map[string]Value{
			"a": NewInt(1),
			"b": NewString("two"),
		}
		v := NewMap(m)
		if v.Kind() != KindMap {
			t.Fatalf("Kind = %v, want KindMap", v.Kind())
		}
		got, ok := v.AsMap()
		if !ok {
			t.Fatalf("AsMap() ok=false on KindMap")
		}
		if len(got) != 2 {
			t.Fatalf("len(AsMap()) = %d, want 2", len(got))
		}
		if !got["a"].Equal(NewInt(1)) {
			t.Fatalf("AsMap()[\"a\"] = %v, want Int(1)", got["a"])
		}
		if !got["b"].Equal(NewString("two")) {
			t.Fatalf("AsMap()[\"b\"] = %v, want String(\"two\")", got["b"])
		}
	})
}

// ---------------------------- Stringer contract --------------------------------------------

func TestValue_String(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want string
	}{
		{"invalid", Value{}, "<invalid>"},
		{"string", NewString("hello"), "hello"},
		{"int", NewInt(-42), "-42"},
		{"float", NewFloat(3.14), "3.14"},
		{"bool_true", NewBool(true), "true"},
		{"bool_false", NewBool(false), "false"},
		{"ip", NewIP(net.ParseIP("192.0.2.1")), "192.0.2.1"},
		{"bytes", NewBytes([]byte{0xde, 0xad}), "dead"},
		{"timestamp", NewTimestamp(fixedNow), "2026-06-25T12:34:56.789Z"},
		{"duration", NewDuration(1500 * time.Millisecond), "1.5s"},
		{"empty_array", NewArray(nil), "[]"},
		{"array", NewArray([]Value{NewInt(1), NewInt(2)}), "[1, 2]"},
		{"empty_map", NewMap(nil), "map[]"},
		{"map_sorted", NewMap(map[string]Value{
			"b": NewInt(2),
			"a": NewInt(1),
		}), "map[a:1 b:2]"},
		{"nested", NewArray([]Value{
			NewMap(map[string]Value{"k": NewString("v")}),
			NewInt(7),
		}), "[map[k:v], 7]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------- Equality contract --------------------------------------------

func TestEqual(t *testing.T) {
	t.Run("same_kind_same_value", func(t *testing.T) {
		if !NewInt(42).Equal(NewInt(42)) {
			t.Fatalf("Int(42) must equal Int(42)")
		}
		if !NewString("x").Equal(NewString("x")) {
			t.Fatalf("String(\"x\") must equal String(\"x\")")
		}
		if !NewBool(true).Equal(NewBool(true)) {
			t.Fatalf("Bool(true) must equal Bool(true)")
		}
	})

	t.Run("same_kind_different_value", func(t *testing.T) {
		if NewInt(1).Equal(NewInt(2)) {
			t.Fatalf("Int(1) must not equal Int(2)")
		}
		if NewString("a").Equal(NewString("b")) {
			t.Fatalf("String(\"a\") must not equal String(\"b\")")
		}
	})

	t.Run("different_kind", func(t *testing.T) {
		// Int vs Float — same numeric value, different Kind — must NOT be equal.
		// The compiler is responsible for promotion; Value.Equal is structural.
		if NewInt(42).Equal(NewFloat(42.0)) {
			t.Fatalf("Int(42) must not equal Float(42.0) — different Kind")
		}
		if NewInt(0).Equal(NewBool(false)) {
			t.Fatalf("Int(0) must not equal Bool(false) — different Kind")
		}
	})

	t.Run("float_bitwise", func(t *testing.T) {
		// Float == is bitwise (no epsilon). Equal numbers compare equal; mismatched
		// values do not.
		if !NewFloat(1.5).Equal(NewFloat(1.5)) {
			t.Fatalf("Float(1.5) must equal Float(1.5)")
		}
		if NewFloat(1.5).Equal(NewFloat(1.5000001)) {
			t.Fatalf("Float(1.5) must not equal Float(1.5000001) — bitwise")
		}
	})

	t.Run("ip_4_vs_16_byte", func(t *testing.T) {
		v4 := net.ParseIP("192.0.2.1").To4()           // 4-byte form
		v16 := net.ParseIP("192.0.2.1")                // 16-byte form (::ffff:192.0.2.1)
		if !NewIP(v4).Equal(NewIP(v16)) {
			t.Fatalf("IPv4 4-byte form must equal 16-byte form for same address")
		}
		if NewIP(net.ParseIP("192.0.2.1")).Equal(NewIP(net.ParseIP("192.0.2.2"))) {
			t.Fatalf("Different IPv4 addresses must not be equal")
		}
	})

	t.Run("bytes_equal", func(t *testing.T) {
		if !NewBytes([]byte{1, 2, 3}).Equal(NewBytes([]byte{1, 2, 3})) {
			t.Fatalf("Bytes{1,2,3} must equal Bytes{1,2,3}")
		}
		if NewBytes([]byte{1, 2, 3}).Equal(NewBytes([]byte{1, 2, 4})) {
			t.Fatalf("Bytes{1,2,3} must not equal Bytes{1,2,4}")
		}
	})

	t.Run("timestamp_equal", func(t *testing.T) {
		a := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
		b := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
		if !NewTimestamp(a).Equal(NewTimestamp(b)) {
			t.Fatalf("Two equal timestamps must compare equal")
		}
	})

	t.Run("duration_equal", func(t *testing.T) {
		if !NewDuration(time.Second).Equal(NewDuration(time.Second)) {
			t.Fatalf("Duration(1s) must equal Duration(1s)")
		}
		if NewDuration(time.Second).Equal(NewDuration(time.Minute)) {
			t.Fatalf("Duration(1s) must not equal Duration(1m)")
		}
	})

	t.Run("array_equal", func(t *testing.T) {
		a := NewArray([]Value{NewInt(1), NewInt(2)})
		b := NewArray([]Value{NewInt(1), NewInt(2)})
		c := NewArray([]Value{NewInt(1), NewInt(3)})
		d := NewArray([]Value{NewInt(1)})
		if !a.Equal(b) {
			t.Fatalf("[1,2] must equal [1,2]")
		}
		if a.Equal(c) {
			t.Fatalf("[1,2] must not equal [1,3]")
		}
		if a.Equal(d) {
			t.Fatalf("[1,2] must not equal [1] (different length)")
		}
	})

	t.Run("array_nil_vs_empty", func(t *testing.T) {
		// Both nil and an explicitly empty array must compare equal — they
		// represent the same logical empty sequence.
		if !NewArray(nil).Equal(NewArray([]Value{})) {
			t.Fatalf("nil Array must equal empty Array")
		}
	})

	t.Run("map_equal", func(t *testing.T) {
		a := NewMap(map[string]Value{"x": NewInt(1), "y": NewInt(2)})
		b := NewMap(map[string]Value{"y": NewInt(2), "x": NewInt(1)})
		c := NewMap(map[string]Value{"x": NewInt(1), "y": NewInt(3)})
		if !a.Equal(b) {
			t.Fatalf("Maps with same {key,value} sets must be equal regardless of insertion order")
		}
		if a.Equal(c) {
			t.Fatalf("Maps with different values must not be equal")
		}
	})

	t.Run("map_nil_vs_empty", func(t *testing.T) {
		if !NewMap(nil).Equal(NewMap(map[string]Value{})) {
			t.Fatalf("nil Map must equal empty Map")
		}
	})

	t.Run("invalid_never_equal", func(t *testing.T) {
		// KindInvalid is a sentinel — two zero Values are NOT equal. This protects
		// rule semantics: "field missing" must not collapse to "field equal to
		// another missing field" in downstream comparisons.
		if (Value{}).Equal(Value{}) {
			t.Fatalf("Value{} must not equal Value{} — sentinel semantics")
		}
		if (Value{}).Equal(NewInt(0)) {
			t.Fatalf("Value{} must not equal NewInt(0) — different Kind")
		}
	})
}

// ---------------------------- Defensive-copy contract -------------------------------------

// TestDefensiveCopy_Bytes verifies that mutating the source slice AFTER construction
// does NOT affect the stored Value. The Value is immutable-by-convention; the
// constructor must enforce that.
func TestDefensiveCopy_Bytes(t *testing.T) {
	src := []byte{1, 2, 3}
	v := NewBytes(src)
	src[0] = 99 // mutate source after construction
	got, ok := v.AsBytes()
	if !ok {
		t.Fatalf("AsBytes() ok=false")
	}
	if got[0] != 1 {
		t.Fatalf("Defensive copy failed: got[0]=%d after src[0]=99; want 1", got[0])
	}

	// Mutating the slice returned from AsBytes must NOT affect future reads —
	// AsBytes returns a fresh copy each time.
	got[1] = 77
	again, _ := v.AsBytes()
	if again[1] != 2 {
		t.Fatalf("AsBytes() leaked aliasing: got[1]=%d after got[1]=77; want 2", again[1])
	}
}

func TestDefensiveCopy_IP(t *testing.T) {
	src := net.ParseIP("192.0.2.1").To4()
	v := NewIP(src)
	src[0] = 10 // mutate source — should not affect v
	got, ok := v.AsIP()
	if !ok {
		t.Fatalf("AsIP() ok=false")
	}
	if got.String() != "192.0.2.1" {
		t.Fatalf("Defensive copy failed: got %s after src mutation; want 192.0.2.1", got)
	}

	// Mutating the slice returned from AsIP must not affect future reads.
	got[1] = 9
	again, _ := v.AsIP()
	if again.String() != "192.0.2.1" {
		t.Fatalf("AsIP() leaked aliasing: got %s after mutation; want 192.0.2.1", again)
	}
}

func TestDefensiveCopy_Array(t *testing.T) {
	src := []Value{NewInt(1), NewInt(2)}
	v := NewArray(src)
	src[0] = NewInt(999) // mutate source after construction
	got, _ := v.AsArray()
	if got[0].i != 1 {
		t.Fatalf("Defensive copy failed: arr[0]=%d after src[0]=999; want 1", got[0].i)
	}
}

func TestDefensiveCopy_Map(t *testing.T) {
	src := map[string]Value{"a": NewInt(1)}
	v := NewMap(src)
	src["a"] = NewInt(999) // mutate source after construction
	src["b"] = NewInt(2)   // add a new key to source after construction
	got, _ := v.AsMap()
	if got["a"].i != 1 {
		t.Fatalf("Defensive copy failed: map[\"a\"]=%d after src[\"a\"]=999; want 1", got["a"].i)
	}
	if _, exists := got["b"]; exists {
		t.Fatalf("Defensive copy failed: map[\"b\"] leaked into Value after src[\"b\"]=2")
	}
}

// TestNilAndEmptyConstructorsAreValidKinds — passing nil to NewArray/NewMap/NewBytes
// must yield a Value of the requested Kind with an empty (but non-nil) backing
// store. This is distinct from KindInvalid (zero Value).
func TestNilAndEmptyConstructorsAreValidKinds(t *testing.T) {
	t.Run("array_nil", func(t *testing.T) {
		v := NewArray(nil)
		if v.Kind() != KindArray {
			t.Fatalf("NewArray(nil).Kind() = %v, want KindArray", v.Kind())
		}
		if v.IsZero() {
			t.Fatalf("NewArray(nil) must not be IsZero")
		}
		got, ok := v.AsArray()
		if !ok || len(got) != 0 {
			t.Fatalf("NewArray(nil).AsArray() = (%v,%v), want (empty slice,true)", got, ok)
		}
	})

	t.Run("map_nil", func(t *testing.T) {
		v := NewMap(nil)
		if v.Kind() != KindMap {
			t.Fatalf("NewMap(nil).Kind() = %v, want KindMap", v.Kind())
		}
		if v.IsZero() {
			t.Fatalf("NewMap(nil) must not be IsZero")
		}
		got, ok := v.AsMap()
		if !ok || len(got) != 0 {
			t.Fatalf("NewMap(nil).AsMap() = (%v,%v), want (empty map,true)", got, ok)
		}
	})

	t.Run("bytes_nil", func(t *testing.T) {
		v := NewBytes(nil)
		if v.Kind() != KindBytes {
			t.Fatalf("NewBytes(nil).Kind() = %v, want KindBytes", v.Kind())
		}
		if v.IsZero() {
			t.Fatalf("NewBytes(nil) must not be IsZero")
		}
		got, ok := v.AsBytes()
		if !ok || len(got) != 0 {
			t.Fatalf("NewBytes(nil).AsBytes() = (%v,%v), want (empty slice,true)", got, ok)
		}
	})

	t.Run("ip_nil", func(t *testing.T) {
		v := NewIP(nil)
		if v.Kind() != KindIP {
			t.Fatalf("NewIP(nil).Kind() = %v, want KindIP", v.Kind())
		}
		if v.IsZero() {
			t.Fatalf("NewIP(nil) must not be IsZero")
		}
		got, ok := v.AsIP()
		if !ok {
			t.Fatalf("NewIP(nil).AsIP() ok=false")
		}
		if len(got) != 0 {
			t.Fatalf("NewIP(nil).AsIP() len=%d, want 0", len(got))
		}
	})
}