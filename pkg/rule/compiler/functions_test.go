// ========================== pkg/rule/compiler — function registry tests ====================
//   Coverage goals (Flow 002 Group A/B/C/D — Task D1):
//     1. Registry accessors: Lookup returns a copy of the spec; Names lists every
//        registered function.
//     2. Compile-time signature checks: unknown name (CodeUnknownFunction), wrong
//        arity (CodeBadFuncArity), wrong per-argument Kind (CodeBadFuncArgType).
//     3. Positive compile for each D1 function: lower / upper / len / to_string.
//     4. Positive eval for each D1 function — predicate-position (Bool return) and
//        value-position (used inside a Cmp).
//     5. Edge cases for each D1 function (empty string, multi-byte UTF-8, etc.).
//
//   starts_with / ends_with:
//     These were listed in the D1 brief but are keyword string operators in
//     this language (lexer / parser, DECISION D14 — Flow 001). They are not
//     in the function registry; the operator form (`field starts_with "x"`)
//     compiles and evaluates today via the existing compileStartsWith /
//     evalStartsWith paths. The function form is blocked by a tokenisation
//     conflict and was escalated to /architect for a separate decision.
//
//   Style note: white-box tests in `package compiler` so we can compare against the
//   concrete op types and reuse the helpers from compiler_test.go / eval_test.go.

package compiler

import (
	"sort"
	"strings"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== 1. Registry accessors ============================================

// TestRegistry_LookupKnown exercises Lookup for each D1 function that is
// registered as a function (NOT a keyword operator — starts_with / ends_with
// are keyword string operators in this language and are not in the function
// registry; see strings.go header note for the architectural reason).
func TestRegistry_LookupKnown(t *testing.T) {
	cases := []struct {
		name      string
		wantKind  rule.Kind
		wantArity int
		wantAlloc bool
	}{
		{"lower", rule.KindString, 1, false},
		{"upper", rule.KindString, 1, false},
		{"len", rule.KindInt, 1, false},
		{"to_string", rule.KindString, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, ok := Lookup(c.name)
			if !ok {
				t.Fatalf("Lookup(%q): not found", c.name)
			}
			if spec.Name != c.name {
				t.Errorf("Name = %q, want %q", spec.Name, c.name)
			}
			if spec.ReturnKind != c.wantKind {
				t.Errorf("ReturnKind = %s, want %s", spec.ReturnKind, c.wantKind)
			}
			if len(spec.ParamKinds) != c.wantArity {
				t.Errorf("arity = %d, want %d", len(spec.ParamKinds), c.wantArity)
			}
			if spec.Allocating != c.wantAlloc {
				t.Errorf("Allocating = %v, want %v", spec.Allocating, c.wantAlloc)
			}
			if spec.Eval == nil {
				t.Errorf("Eval is nil; registry entry is invalid")
			}
			// Mutate the returned copy — must not affect the registry.
			spec.Name = "mutated"
			again, _ := Lookup(c.name)
			if again.Name != c.name {
				t.Errorf("Lookup returned shared spec; mutation leaked into the registry")
			}
		})
	}
}

// TestRegistry_LookupUnknown exercises the not-found path of Lookup.
func TestRegistry_LookupUnknown(t *testing.T) {
	if _, ok := Lookup("definitely_not_a_function"); ok {
		t.Errorf("Lookup returned ok=true for an unregistered name")
	}
}

// TestRegistry_NamesSorted returns the registered names sorted, and asserts the
// D1 set is present. starts_with / ends_with are keyword string operators
// (see strings.go header) and intentionally absent from the registry. The
// check is name-based so a future flow that adds more functions does not
// break this test (it asserts presence, not exact equality).
func TestRegistry_NamesSorted(t *testing.T) {
	all := Names()
	if len(all) == 0 {
		t.Fatalf("Names() returned empty; registry was not populated")
	}
	sort.Strings(all)
	want := []string{"len", "lower", "to_string", "upper"}
	got := []string{}
	for _, n := range all {
		for _, w := range want {
			if n == w {
				got = append(got, n)
				break
			}
		}
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("registered names missing from D1 set; got %v, want at least %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("D1 function %q not in registry (got sorted %v)", want[i], got)
		}
	}
}

// ========================== 2. Compile-time negatives =======================================

// TestCompiler_FuncCall_BadArity covers DECISION D16 §2: wrong number of args
// against a registered function returns CodeBadFuncArity. Tested against `lower`
// (arity 1) — calling it with zero or two args must produce the error.
func TestCompiler_FuncCall_BadArity(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"too_few_args", `lower()`},
		{"too_many_args", `lower(http.method, http.uri)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArity {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArity)
			}
			if !strings.Contains(ce.Message, "lower") {
				t.Errorf("Message %q should mention the function name", ce.Message)
			}
		})
	}
}

// TestCompiler_FuncCall_BadArgType covers DECISION D16 §2: per-argument Kind
// mismatch against the declared ParamKinds returns CodeBadFuncArgType. Tested
// against `lower` (expects KindString) — calling it with an Int field must
// produce the error.
func TestCompiler_FuncCall_BadArgType(t *testing.T) {
	// http.status is registered as TypeInt in wafScheme. `lower(http.status)`
	// must fail with CodeBadFuncArgType because lower expects KindString.
	ce := compileErr(t, `lower(http.status)`, wafScheme(t))
	if ce.Code != CodeBadFuncArgType {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArgType)
	}
	if !strings.Contains(ce.Message, "lower") {
		t.Errorf("Message %q should mention the function name", ce.Message)
	}
}

// ========================== 3. Positive compile for D1 =======================================

// TestCompiler_D1Functions_Compile is a smoke test: every D1 function that is
// registered as a function compiles against the WAF scheme. starts_with /
// ends_with are keyword operators (not functions); their compile / eval paths
// are exercised by the existing TestCompiler_StartsWith / TestEval starts_with
// coverage. The structural / type-correctness checks live in the per-function
// eval tests below.
func TestCompiler_D1Functions_Compile(t *testing.T) {
	cases := []string{
		`lower(http.method) eq "get"`,
		`upper(http.method) eq "GET"`,
		`len(http.uri) eq 4`,
		`to_string(http.status) eq "200"`,
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			p, err := Compile(mustParse(t, src), wafScheme(t))
			if err != nil {
				t.Fatalf("Compile(%q): %v", src, err)
			}
			// Root is the Cmp (for value-position forms) or the predicate (for
			// starts_with / ends_with at the root). We just assert the Plan is
			// non-nil and walk to the opFunc to confirm it carries the spec.
			if p == nil || p.Root() == nil {
				t.Fatalf("Compile(%q) returned nil plan", src)
			}
			if !walkPlanHasOpFunc(p.Root()) {
				t.Fatalf("Compile(%q): Plan contains no opFunc", src)
			}
		})
	}
}

// walkPlanHasOpFunc walks the Plan tree looking for any opFunc. The tree is
// small enough that a recursive scan is acceptable in a test; the check exists
// to catch a regression where compileFuncCall short-circuits before emitting
// the op node.
func walkPlanHasOpFunc(o op) bool {
	switch n := o.(type) {
	case *opFunc:
		_ = n
		return true
	case *opAnd:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opOr:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opNot:
		return walkPlanHasOpFunc(n.operand)
	case *opCmp:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opContains:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opStartsWith:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opEndsWith:
		return walkPlanHasOpFunc(n.left) || walkPlanHasOpFunc(n.right)
	case *opIn:
		return walkPlanHasOpFunc(n.element)
	case *opStrict:
		return walkPlanHasOpFunc(n.inner)
	}
	return false
}

// ========================== 4. Positive eval for D1 ==========================================

// TestEval_D1Functions is the eval-side coverage for the D1 set. Each row
// exercises a function in either predicate position (Bool return) or value
// position (returned Value compared with eq). The resolver and event are
// standard; the input Value lives in scalars. starts_with / ends_with are
// keyword string operators — covered by the existing TestEval_TableDriven
// cases ("starts_with_true", "starts_with_false", "ends_with_true", ...).
func TestEval_D1Functions(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	type tc struct {
		name    string
		src     string
		scalars map[string]rule.Value
		want    bool
	}
	cases := []tc{
		// ── lower: ASCII / already-lowered / mixed ────────────────────────────
		{"lower_mixed", `lower(http.method) eq "get"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, true},
		{"lower_already_lower", `lower(http.method) eq "get"`,
			map[string]rule.Value{"http.method": rule.NewString("get")}, true},
		{"lower_no_match", `lower(http.method) eq "post"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, false},
		{"lower_empty", `lower(http.method) eq ""`,
			map[string]rule.Value{"http.method": rule.NewString("")}, true},

		// ── upper: same shape as lower ───────────────────────────────────────
		{"upper_mixed", `upper(http.method) eq "GET"`,
			map[string]rule.Value{"http.method": rule.NewString("get")}, true},
		{"upper_already_upper", `upper(http.method) eq "GET"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, true},
		{"upper_no_match", `upper(http.method) eq "POST"`,
			map[string]rule.Value{"http.method": rule.NewString("get")}, false},

		// ── len: byte length of the field ────────────────────────────────────
		{"len_ascii", `len(http.uri) eq 4`,
			map[string]rule.Value{"http.uri": rule.NewString("/api")}, true},
		{"len_empty", `len(http.uri) eq 0`,
			map[string]rule.Value{"http.uri": rule.NewString("")}, true},
		{"len_seven_bytes", `len(http.uri) eq 7`,
			// "/api/v1" is 7 bytes — pins the byte-count contract (ASCII).
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1")}, true},

		// ── to_string: each scalar Kind ──────────────────────────────────────
		{"to_string_int", `to_string(http.status) eq "200"`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, true},
		{"to_string_int_no_match", `to_string(http.status) eq "404"`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, false},
		{"to_string_string", `to_string(http.method) eq "GET"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, true},
		{"to_string_bool_true", `to_string(custom.flag) eq "true"`,
			map[string]rule.Value{"custom.flag": rule.NewBool(true)}, true},
		{"to_string_bool_false", `to_string(custom.flag) eq "false"`,
			map[string]rule.Value{"custom.flag": rule.NewBool(false)}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := evalCompileOK(t, c.src, scheme)
			r := &mapResolver{scalars: c.scalars}
			got := p.Eval(r, ev)
			if got != c.want {
				t.Errorf("Eval(%q) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}

// ========================== 5. Edge cases ===================================================

// TestEval_LenMultibyteBytes pins the byte-length semantics of `len`. UTF-8
// encoded characters can occupy 2, 3, or 4 bytes — `len` counts bytes, not
// runes. A reviewer reading this in the future may mistake it for a rune
// count; the assertion below is the explicit "we count bytes" contract.
func TestEval_LenMultibyteBytes(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	// "π" is the Greek letter pi; in UTF-8 it is encoded as 2 bytes (0xCF 0x80).
	// "/π/" is therefore 4 bytes.
	src := `len(http.uri) eq 4`
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{scalars: map[string]rule.Value{
		"http.uri": rule.NewString("/π/"),
	}}
	if !p.Eval(r, ev) {
		t.Errorf("len(\"/π/\") should be 4 bytes, but Eval returned false")
	}
}

// TestEval_LenOnLargeString covers a path-length scenario where the byte length
// of a string is well above what an int8 / int16 could hold. The function
// returns int64 — verified by the type, the value bound is implicit.
func TestEval_LenOnLargeString(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	large := strings.Repeat("x", 1024)
	src := `len(http.uri) eq 1024`
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{scalars: map[string]rule.Value{
		"http.uri": rule.NewString(large),
	}}
	if !p.Eval(r, ev) {
		t.Errorf("len(<1024 'x'>) should equal 1024, Eval returned false")
	}
}

// TestEval_StartsWithNotEqual covers the Cmp-over-function-result path: the
// function sits inside a Cmp as the left operand, and the result is compared
// to a literal. This exercises the evalValue path through opFunc (Group C2)
// rather than the predicate-position eval.
func TestEval_FuncInCmp(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	src := `lower(http.method) eq "get"`
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{scalars: map[string]rule.Value{
		"http.method": rule.NewString("GET"),
	}}
	if !p.Eval(r, ev) {
		t.Errorf("lower(\"GET\") == \"get\" should be true, Eval returned false")
	}
}

// TestEval_FuncFailsGracefullyOnUnresolvedArg covers the defensive contract:
// when a function's argument cannot be resolved (field missing), Eval returns
// false rather than panicking. The pattern here exercises
// evalFuncCallValue's ok-false propagation.
func TestEval_FuncFailsGracefullyOnUnresolvedArg(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	src := `lower(http.method) eq "x"`
	p := evalCompileOK(t, src, scheme)
	// mapResolver with no scalars for http.method → Resolve returns ok=false.
	r := &mapResolver{}
	if p.Eval(r, ev) {
		t.Errorf("Eval with unresolved argument should return false, got true")
	}
}

// ========================== Helpers ==========================================================

// (parser is imported for direct Parse calls in the per-function tests if a
// future addition needs them; the no-op anchor keeps the import honest.)
var _ = parser.Parse

// (plugin is imported for the *plugin.Event type used by fixedEvent in the
// eval tests above; the no-op anchor keeps the import honest.)
var _ = (*plugin.Event)(nil)