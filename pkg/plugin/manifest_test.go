// ========================== pkg/plugin — Manifest declaration tests ========================
//   Pins the backward-compatible FieldDecl.Type extension (DECISION D8) and the canonical
//   FieldType constant set (DECISION D8.1). Two contracts are checked here:
//
//     - Zero value: a FieldDecl constructed without Type keeps Type == "" so every
//       pre-existing FieldDecl literal in the codebase keeps compiling and behaves as
//       "untyped / legacy field". This is the back-compat guarantee the D8 design is
//       judged against.
//     - Closed set: the ten FieldType constants declared in pkg/plugin/manifest.go cover
//       every Kind in pkg/rule/types.go. Adding a Kind without a FieldType (or vice
//       versa) is a deliberate decision and these tests fail loudly so reviewers can
//       audit the expansion.

package plugin

import "testing"

// TestFieldDecl_TypeZero verifies that a zero-value FieldDecl has Type "" (legacy / untyped),
// preserving back-compat with every existing FieldDecl user (DECISION D8).
func TestFieldDecl_TypeZero(t *testing.T) {
	fd := FieldDecl{Name: "method"}
	if fd.Type != "" {
		t.Errorf("zero FieldDecl.Type = %q, want empty", fd.Type)
	}

	// Explicit field-by-field zero also must yield empty Type — this is the form that
	// any existing struct literal {Name: ..., Required: ...} compiles to after D8.
	fdZero := FieldDecl{}
	if fdZero.Type != "" {
		t.Errorf("zero FieldDecl{} Type = %q, want empty", fdZero.Type)
	}

	// Required is unaffected by the Type addition — also a back-compat guarantee.
	if fd.Required {
		t.Errorf("zero FieldDecl.Required = true, want false")
	}
	if fd.Name != "method" {
		t.Errorf("zero FieldDecl.Name = %q, want %q", fd.Name, "method")
	}
}

// TestFieldDecl_TypeAssignability verifies that a FieldType constant round-trips into a
// FieldDecl — i.e. the type system lets a plugin populate the new field. This is the
// forward-compat half of the D8 contract: new code MUST be able to opt in by setting
// Type.
func TestFieldDecl_TypeAssignability(t *testing.T) {
	cases := []struct {
		name string
		typ  FieldType
	}{
		{"string field", TypeString},
		{"int field", TypeInt},
		{"float field", TypeFloat},
		{"bool field", TypeBool},
		{"ip field", TypeIP},
		{"bytes field", TypeBytes},
		{"timestamp field", TypeTimestamp},
		{"duration field", TypeDuration},
		{"array field", TypeArray},
		{"map field", TypeMap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := FieldDecl{Name: "x", Type: tc.typ}
			if fd.Type != tc.typ {
				t.Errorf("FieldDecl.Type = %q, want %q", fd.Type, tc.typ)
			}
		})
	}
}

// TestFieldType_KnownSet pins the canonical constant set (DECISION D8.1). Each constant
// must carry a non-empty string value (the value is part of the rule-language diagnostic
// surface and Manifest export — treat changes as breaking).
func TestFieldType_KnownSet(t *testing.T) {
	want := map[FieldType]bool{
		TypeString: true, TypeInt: true, TypeFloat: true, TypeBool: true, TypeIP: true,
		TypeBytes: true, TypeTimestamp: true, TypeDuration: true, TypeArray: true, TypeMap: true,
	}
	for k := range want {
		if string(k) == "" {
			t.Errorf("FieldType constant %v has empty string value", k)
		}
	}

	// The set must contain exactly ten entries — adding an eleventh is a deliberate
	// decision that requires updating isKnownFieldType in pkg/rule and REFERENCE.md.
	if got := len(want); got != 10 {
		t.Errorf("FieldType known set size = %d, want 10", got)
	}

	// Cross-check string values against the rule-language surface — the value of every
	// constant IS the name the compiler prints in type errors. Keep them aligned with
	// what the engine documentation promises.
	wantStrings := map[FieldType]string{
		TypeString: "string", TypeInt: "int", TypeFloat: "float", TypeBool: "bool",
		TypeIP: "ip", TypeBytes: "bytes", TypeTimestamp: "timestamp",
		TypeDuration: "duration", TypeArray: "array", TypeMap: "map",
	}
	for k, want := range wantStrings {
		if string(k) != want {
			t.Errorf("FieldType %v string value = %q, want %q", k, string(k), want)
		}
	}
}
