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

// ========================== D2 — allocating string functions =================================
//
// Coverage for the D2 set (substring / concat / url_decode / url_encode /
// html_entity_decode / remove_bytes). All D2 functions are Allocating=true; the
// tests verify the contract from the registry metadata, the compile-time
// signature checks, and the eval-time behaviour including the explicit bounds
// and error-fallback policies.

// ========================== 6. Registry metadata for D2 =====================================

// TestRegistry_LookupD2 verifies the registry metadata for each D2 entry — the
// expected ParamKinds, ReturnKind, Allocating=true, and (for concat) IsVariadic.
func TestRegistry_LookupD2(t *testing.T) {
	cases := []struct {
		name     string
		arity    int
		variadic bool
		returnK  rule.Kind
		alloc    bool
	}{
		{"substring", 3, false, rule.KindString, true},
		{"concat", 1, true, rule.KindString, true},
		{"url_decode", 1, false, rule.KindString, true},
		{"url_encode", 1, false, rule.KindString, true},
		{"html_entity_decode", 1, false, rule.KindString, true},
		{"remove_bytes", 2, false, rule.KindString, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, ok := Lookup(c.name)
			if !ok {
				t.Fatalf("Lookup(%q): not found", c.name)
			}
			if len(spec.ParamKinds) != c.arity {
				t.Errorf("arity = %d, want %d", len(spec.ParamKinds), c.arity)
			}
			if spec.IsVariadic != c.variadic {
				t.Errorf("IsVariadic = %v, want %v", spec.IsVariadic, c.variadic)
			}
			if spec.ReturnKind != c.returnK {
				t.Errorf("ReturnKind = %s, want %s", spec.ReturnKind, c.returnK)
			}
			if spec.Allocating != c.alloc {
				t.Errorf("Allocating = %v, want %v", spec.Allocating, c.alloc)
			}
			if spec.Eval == nil {
				t.Errorf("Eval is nil; registry entry is invalid")
			}
		})
	}
}

// ========================== 7. Compile-time negatives for D2 ================================

// TestCompiler_D2_BadArity pins CodeBadFuncArity for each D2 entry. concat is
// excluded here — its variadic arity check has a separate test (TestCompiler_Concat_*).
func TestCompiler_D2_BadArity(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"substring_too_few", `substring(http.uri)`},
		{"substring_too_many", `substring(http.uri, 0, 1, 2)`},
		{"url_decode_too_many", `url_decode(http.uri, http.method)`},
		{"url_encode_too_few", `url_encode()`},
		{"html_entity_decode_too_many", `html_entity_decode(http.uri, http.uri)`},
		{"remove_bytes_too_few", `remove_bytes(http.uri)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArity {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArity)
			}
		})
	}
}

// TestCompiler_D2_BadArgType pins CodeBadFuncArgType for representative D2
// entries. The first positional Int arg of substring is exercised against a
// String-typed field; remove_bytes expects both args String and gets a wrong
// type on the second slot.
func TestCompiler_D2_BadArgType(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		// substring(int_field, int_field, int_field) — start expects int → OK;
		// but http.uri is String and the second int slot is http.uri (String).
		// We exercise the FIRST slot: substring(http.method, 0, 1) — but the
		// first slot is String, and http.method IS String, so that's fine.
		// The simplest mismatch is the SECOND slot (Int) being a String field.
		{"substring_string_for_int", `substring(http.uri, http.uri, 1)`},
		{"remove_bytes_string_for_int", `remove_bytes(http.uri, http.status)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArgType {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArgType)
			}
		})
	}
}

// TestCompiler_Concat_Variadic pins the variadic arity check. concat accepts
// zero or more args (IsVariadic with a single ParamKinds entry); an entry must
// compile, and any positive count must compile.
func TestCompiler_Concat_Variadic(t *testing.T) {
	cases := []string{
		`concat()`,
		`concat(http.uri)`,
		`concat(http.uri, http.method)`,
		`concat(http.uri, http.method, http.uri)`,
	}
	for _, src := range cases {
		t.Run(src, func(t *testing.T) {
			if _, err := Compile(mustParse(t, src), wafScheme(t)); err != nil {
				t.Fatalf("Compile(%q): %v", src, err)
			}
		})
	}
}

// TestCompiler_Concat_Variadic_BadArgType pins that concat's variadic slot
// rejects non-String args. http.status is Int; concat(http.uri, http.status)
// must fail with CodeBadFuncArgType.
func TestCompiler_Concat_Variadic_BadArgType(t *testing.T) {
	ce := compileErr(t, `concat(http.uri, http.status)`, wafScheme(t))
	if ce.Code != CodeBadFuncArgType {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArgType)
	}
}

// ========================== 8. Eval coverage for D2 =========================================

// evalFuncString compiles a function-call expression whose return value is
// KindString and compares it against an expected string via `eq`. This is the
// standard "value-position" pattern: the function result is the left operand
// of a Cmp, which exercises both the function's Eval and the evaluator's
// value-position path through opFunc (Group C).
func evalFuncString(t *testing.T, src, want string, scalars map[string]rule.Value) {
	t.Helper()
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{scalars: scalars}
	if !p.Eval(r, ev) {
		t.Errorf("Eval(%q) returned false; want match against %q", src, want)
	}
}

// TestEval_D2_Substring covers the bounds-clamp policy of substring:
//   - normal range
//   - empty range (start == end)
//   - inverted range (start > end after clamp) → ""
//   - end > len → clamped to len
//   - both clamped → covers all
//   - empty input → ""
//   - multi-byte UTF-8 (byte-indexed, matching len())
//
// Note: the language grammar has no unary minus, so a negative literal start is
// a parse error — the runtime clamp on `start < 0` is defensive for runtime-
// supplied Values (a field of Int Kind) and is not reachable from a literal.
// start >= 0 is therefore the only case the test exercises.
func TestEval_D2_Substring(t *testing.T) {
	type tc struct {
		name string
		src  string
		want string
		in   string // field value to bind to http.uri
	}
	cases := []tc{
		{"mid_range", `substring(http.uri, 1, 4) eq "bcd"`, "bcd", "abcdef"},
		{"start_at_zero", `substring(http.uri, 0, 3) eq "abc"`, "abc", "abcdef"},
		{"end_at_len", `substring(http.uri, 3, 6) eq "def"`, "def", "abcdef"},
		{"empty_range", `substring(http.uri, 2, 2) eq ""`, "", "abcdef"},
		{"inverted_range", `substring(http.uri, 4, 1) eq ""`, "", "abcdef"},
		{"end_overflow_clamped", `substring(http.uri, 2, 999) eq "cdef"`, "cdef", "abcdef"},
		{"both_clamped_covers_all", `substring(http.uri, 0, 999) eq "abcdef"`, "abcdef", "abcdef"},
		// Multi-byte UTF-8: substring is byte-indexed (matches len()).
		// "/π/" is 4 bytes; bytes [1:3] are the bytes of π (= "\xcf\x80").
		{"utf8_mid_rune", `substring(http.uri, 1, 3) eq "` + "\xcf\x80" + `"`, "\xcf\x80", "/π/"},
		// Single-byte ASCII in UTF-8 string: bytes [1:4] of "xπy" are the
		// bytes of π.
		{"utf8_rune_at_end", `substring(http.uri, 1, 3) eq "` + "\xcf\x80" + `"`, "\xcf\x80", "xπy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}

	// Empty input — separate case because the input itself differs.
	emptyCases := []struct {
		name string
		src  string
		want string
	}{
		{"empty_input_full_range", `substring(http.uri, 0, 5) eq ""`, ""},
		{"empty_input_zero_zero", `substring(http.uri, 0, 0) eq ""`, ""},
		{"empty_input_inverted", `substring(http.uri, 1, 0) eq ""`, ""},
	}
	for _, c := range emptyCases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(""),
			})
		})
	}
}

// TestEval_D2_Concat covers concat in predicate-position (value compared with
// eq). Variadic arities 0..4 are exercised.
func TestEval_D2_Concat(t *testing.T) {
	type tc struct {
		name string
		src  string
		want string
	}
	cases := []tc{
		{"zero_args", `concat() eq ""`, ""},
		{"one_arg", `concat(http.uri) eq "/api"`, "/api"},
		{"two_args", `concat(http.uri, http.method) eq "/apiGET"`, "/apiGET"},
		{"three_args_mixed", `concat(http.uri, "/", http.method) eq "/api/GET"`, "/api/GET"},
		{"empty_arg_skipped", `concat(http.uri, "", http.method) eq "/apiGET"`, "/apiGET"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri":    rule.NewString("/api"),
				"http.method": rule.NewString("GET"),
			})
		})
	}
}

// TestEval_D2_URLDecode covers url_decode. Each row carries (in, want) separately
// because the input is the percent-encoded form and the expected output is the
// decoded form — they are different strings. The invalid-percent row pins the
// best-effort fallback: malformed input is surfaced as the empty string.
func TestEval_D2_URLDecode(t *testing.T) {
	cases := []struct {
		name, in, want string
		src            string
	}{
		{"plain", "hello%20world", "hello world", `url_decode(http.uri) eq "hello world"`},
		{"percent_plus", "a%2Bb", "a+b", `url_decode(http.uri) eq "a+b"`},
		{"round_trip", "%2Fapi%3Fx%3D1%26y%3D2", "/api?x=1&y=2", `url_decode(http.uri) eq "/api?x=1&y=2"`},
		{"unicode_pct", "%CF%80", "π", `url_decode(http.uri) eq "π"`},
		{"invalid_percent", "%zz", "", `url_decode(http.uri) eq ""`},
		{"empty", "", "", `url_decode(http.uri) eq ""`},
		{"already_plain", "abc", "abc", `url_decode(http.uri) eq "abc"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// TestEval_D2_URLEncode covers url_encode. The encoding is the form used in
// query strings — space → "+", "/" → "%2F", "?" → "%3F", etc. (RFC 3986).
func TestEval_D2_URLEncode(t *testing.T) {
	type tc struct {
		name, in, want string
		src            string
	}
	cases := []tc{
		{"plain", "abc", "abc", `url_encode(http.uri) eq "abc"`},
		{"space_to_plus", "a b", "a+b", `url_encode(http.uri) eq "a+b"`},
		{"slash_encoded", "/api", "%2Fapi", `url_encode(http.uri) eq "%2Fapi"`},
		{"query_string", "x=1&y=2", "x%3D1%26y%3D2", `url_encode(http.uri) eq "x%3D1%26y%3D2"`},
		{"unicode", "π", "%CF%80", `url_encode(http.uri) eq "%CF%80"`},
		{"empty", "", "", `url_encode(http.uri) eq ""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// TestEval_D2_HTMLEntityDecode covers html_entity_decode. Named entities, numeric
// entities, mixed text, and unknown entities are exercised.
func TestEval_D2_HTMLEntityDecode(t *testing.T) {
	type tc struct {
		name, in, want string
		src            string
	}
	cases := []tc{
		{"amp", "a&amp;b", "a&b", `html_entity_decode(http.uri) eq "a&b"`},
		{"lt_gt", "&lt;tag&gt;", "<tag>", `html_entity_decode(http.uri) eq "<tag>"`},
		{"quot", "&quot;x&quot;", `"x"`, `html_entity_decode(http.uri) eq "\"x\""`},
		{"numeric_decimal", "&#65;", "A", `html_entity_decode(http.uri) eq "A"`},
		{"numeric_hex", "&#x41;", "A", `html_entity_decode(http.uri) eq "A"`},
		{"mixed", "Tom &amp; Jerry &lt;3", "Tom & Jerry <3", `html_entity_decode(http.uri) eq "Tom & Jerry <3"`},
		{"unknown_passthrough", "&unknown;", "&unknown;", `html_entity_decode(http.uri) eq "&unknown;"`},
		{"empty", "", "", `html_entity_decode(http.uri) eq ""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// TestEval_D2_RemoveBytes covers remove_bytes. set is a SET OF BYTES; the empty
// set is the identity; mixed-byte and pure-ASCII cases are exercised.
func TestEval_D2_RemoveBytes(t *testing.T) {
	type tc struct {
		name, in, set, want string
		src                 string
	}
	cases := []tc{
		{"empty_set_is_identity", "hello", "", "hello", `remove_bytes(http.uri, "") eq "hello"`},
		{"remove_spaces", "hello world foo", " ", "helloworldfoo", `remove_bytes(http.uri, " ") eq "helloworldfoo"`},
		{"remove_control_chars", "ab\tcd\nef", "\t\n", "abcdef", `remove_bytes(http.uri, "\t\n") eq "abcdef"`},
		{"remove_digits", "v1.2.3-rc4", "0123456789", "v..-rc", `remove_bytes(http.uri, "0123456789") eq "v..-rc"`},
		{"set_larger_than_kept", "abc", "abcdef", "", `remove_bytes(http.uri, "abcdef") eq ""`},
		{"no_overlap", "hello", "xyz", "hello", `remove_bytes(http.uri, "xyz") eq "hello"`},
		{"empty_input", "", "abc", "", `remove_bytes(http.uri, "abc") eq ""`},
		// Byte-set (not rune-set): "café" — 'c' (0x63), 'a' (0x61), 'f' (0x66),
		// 'é' = 0xC3 0xA9. Removing byte 'a' (0x61) drops only the 'a' byte; 'é'
		// stays intact because neither 0xC3 nor 0xA9 equals 0x61. The result
		// "cfé" is therefore valid UTF-8 (c, f, é).
		{"byte_set_keeps_multibyte", "café", "a", "cfé", `remove_bytes(http.uri, "a") eq "cfé"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// ========================== D3 — regex_replace / lookup_json_string ===========================
//
// Coverage for the D3 set. regex_replace has a compile-time precompile fast path
// for literal patterns (DECISION D4) and a per-eval fallback for non-literal
// patterns. lookup_json_string parses the json arg as a top-level JSON object
// and returns the string at the given key — misses return "".

// TestRegistry_LookupD3 verifies the registry metadata for the D3 entries.
func TestRegistry_LookupD3(t *testing.T) {
	cases := []struct {
		name    string
		arity   int
		returnK rule.Kind
		alloc   bool
	}{
		{"regex_replace", 3, rule.KindString, true},
		{"lookup_json_string", 2, rule.KindString, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, ok := Lookup(c.name)
			if !ok {
				t.Fatalf("Lookup(%q): not found", c.name)
			}
			if len(spec.ParamKinds) != c.arity {
				t.Errorf("arity = %d, want %d", len(spec.ParamKinds), c.arity)
			}
			if spec.ReturnKind != c.returnK {
				t.Errorf("ReturnKind = %s, want %s", spec.ReturnKind, c.returnK)
			}
			if spec.Allocating != c.alloc {
				t.Errorf("Allocating = %v, want %v", spec.Allocating, c.alloc)
			}
			if spec.Eval == nil {
				t.Errorf("Eval is nil; registry entry is invalid")
			}
			if spec.IsVariadic {
				t.Errorf("IsVariadic = true; D3 functions are fixed-arity")
			}
		})
	}
}

// TestCompiler_RegexReplace_BadArity pins CodeBadFuncArity.
func TestCompiler_RegexReplace_BadArity(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"too_few", `regex_replace(http.uri)`},
		{"too_few_two", `regex_replace(http.uri, "[0-9]")`},
		{"too_many", `regex_replace(http.uri, "[0-9]", "x", "extra")`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArity {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArity)
			}
		})
	}
}

// TestCompiler_RegexReplace_BadArgType pins CodeBadFuncArgType for each arg.
func TestCompiler_RegexReplace_BadArgType(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		// arg 2 is the pattern; http.status is Int — bad.
		{"pattern_not_string", `regex_replace(http.uri, http.status, "x")`},
		// arg 3 is the replacement; http.status is Int — bad.
		{"repl_not_string", `regex_replace(http.uri, "[0-9]", http.status)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArgType {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArgType)
			}
		})
	}
}

// TestCompiler_RegexReplace_BadPattern pins CodeBadRegex for an invalid literal
// pattern. This is the COMPILE-time check — the regex never makes it to eval.
func TestCompiler_RegexReplace_BadPattern(t *testing.T) {
	ce := compileErr(t, `regex_replace(http.uri, "[invalid", "x")`, wafScheme(t))
	if ce.Code != CodeBadRegex {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadRegex)
	}
	if !strings.Contains(ce.Message, "[invalid") {
		t.Errorf("Message %q should mention the bad pattern", ce.Message)
	}
}

// TestEval_D3_RegexReplace covers the literal-pattern fast path:
//   - simple substitution
//   - no match (returns subject unchanged)
//   - all-match (subject is entirely the pattern)
//   - empty subject
//   - replacement with backreferences ($1)
//   - character classes ([0-9], [a-z])
//   - anchors (^, $)
//   - multi-word subjects
//   - empty replacement (delete the matches)
func TestEval_D3_RegexReplace(t *testing.T) {
	type tc struct {
		name, src, in, want string
	}
	cases := []tc{
		{"digits_to_x", `regex_replace(http.uri, "[0-9]", "x") eq "vx.x.x-rcx"`, "v1.2.3-rc4", "vx.x.x-rcx"},
		{"no_match", `regex_replace(http.uri, "[0-9]", "x") eq "abc"`, "abc", "abc"},
		{"all_match", `regex_replace(http.uri, "[0-9]", "x") eq "xxxx"`, "1234", "xxxx"},
		{"empty_subject", `regex_replace(http.uri, "[0-9]", "x") eq ""`, "", ""},
		// Backreferences in the replacement — RE2 syntax ($1).
		{"backref", `regex_replace(http.uri, "(world)", "hello $1!") eq "hello world!"`, "world", "hello world!"},
		// Anchors.
		{"anchor_start", `regex_replace(http.uri, "^foo", "X") eq "Xbar"`, "foobar", "Xbar"},
		// Delete the match.
		{"empty_replacement", `regex_replace(http.uri, "[0-9]+", "") eq "abcdef"`, "abc123def", "abcdef"},
		// Multi-word subject — each [a-z]+ run is replaced (RE2 non-overlapping
		// match-and-replace, separated by spaces).
		{"multi_word", `regex_replace(http.uri, "[a-z]+", "Z") eq "Z Z Z"`, "abc def ghi", "Z Z Z"},
		// Subject unchanged when pattern is a literal that does not occur.
		{"unicode_kept", `regex_replace(http.uri, "X", "Y") eq "/π/"`, "/π/", "/π/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// TestEval_D3_RegexReplace_NonLiteralPattern covers the per-eval compile path:
// the pattern argument is a field reference (http.pattern) rather than a literal,
// so the compiler does NOT precompile the regex; the evaluator compiles it per
// call (DECISION D4 non-literal fallback). This exercises the real production
// path through evalRegexReplaceValue — not the registry's evalRegexReplaceFallback,
// which is the same algorithm but reachable only via hand-built ops.
func TestEval_D3_RegexReplace_NonLiteralPattern(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	src := `regex_replace(http.uri, http.pattern, "X") eq "vX.X.X-rcX"`
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{scalars: map[string]rule.Value{
		"http.uri":     rule.NewString("v1.2.3-rc4"),
		"http.pattern": rule.NewString("[0-9]"),
	}}
	if !p.Eval(r, ev) {
		t.Errorf("non-literal pattern eval returned false; expected replacement")
	}
}

// TestCompiler_LookupJSONString_BadArity pins CodeBadFuncArity.
func TestCompiler_LookupJSONString_BadArity(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"too_few", `lookup_json_string(http.uri)`},
		{"too_many", `lookup_json_string(http.uri, "k", "extra")`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeBadFuncArity {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArity)
			}
		})
	}
}

// TestCompiler_LookupJSONString_BadArgType pins CodeBadFuncArgType. Both
// arguments are declared as KindString; an Int field is rejected.
func TestCompiler_LookupJSONString_BadArgType(t *testing.T) {
	ce := compileErr(t, `lookup_json_string(http.uri, http.status)`, wafScheme(t))
	if ce.Code != CodeBadFuncArgType {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArgType)
	}
}

// TestEval_D3_LookupJSONString covers the hit/miss paths:
//   - hit with string value
//   - miss (key absent) → ""
//   - invalid JSON → ""
//   - empty JSON → ""
//   - empty key → ""
//   - non-string value (number, bool, null) — converted via fmt.Sprint
//   - whitespace-padded JSON
//   - multiple keys — only the requested one is returned
//
// The key argument is a literal string (not a field reference) so the test
// does not depend on a second scheme field.
func TestEval_D3_LookupJSONString(t *testing.T) {
	type tc struct {
		name, src, in, want string
	}
	cases := []tc{
		{"hit_string", `lookup_json_string(http.uri, "method") eq "GET"`, `{"method":"GET"}`, "GET"},
		{"miss_key", `lookup_json_string(http.uri, "uri") eq ""`, `{"method":"GET"}`, ""},
		{"invalid_json", `lookup_json_string(http.uri, "method") eq ""`, `not json`, ""},
		{"empty_json", `lookup_json_string(http.uri, "method") eq ""`, ``, ""},
		{"empty_key", `lookup_json_string(http.uri, "") eq ""`, `{"method":"GET"}`, ""},
		// Non-string values are converted via fmt.Sprint: the function contract
		// is "always return a string", so 42 → "42", true → "true", null → "<nil>".
		{"number_value", `lookup_json_string(http.uri, "count") eq "42"`, `{"count":42}`, "42"},
		{"bool_value_true", `lookup_json_string(http.uri, "flag") eq "true"`, `{"flag":true}`, "true"},
		{"bool_value_false", `lookup_json_string(http.uri, "flag") eq "false"`, `{"flag":false}`, "false"},
		// JSON whitespace handling: leading/trailing whitespace is permitted.
		{"padded_json", `lookup_json_string(http.uri, "method") eq "GET"`, `  {"method":"GET"}  `, "GET"},
		// Multiple keys — only the requested one is returned.
		{"multi_key", `lookup_json_string(http.uri, "status") eq "200"`, `{"method":"GET","status":200}`, "200"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evalFuncString(t, c.src, c.want, map[string]rule.Value{
				"http.uri": rule.NewString(c.in),
			})
		})
	}
}

// TestEval_D3_LookupJSONString_LiteralArg covers the case where the json arg
// itself is a literal rather than a field reference — exercises the value-
// position path through opLitString on the json slot.
func TestEval_D3_LookupJSONString_LiteralArg(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	src := `lookup_json_string("{\"k\":\"v\"}", "k") eq "v"`
	p := evalCompileOK(t, src, scheme)
	r := &mapResolver{}
	if !p.Eval(r, ev) {
		t.Errorf("literal-json arg eval returned false")
	}
}

// ========================== Helpers ==========================================================

// (parser is imported for direct Parse calls in the per-function tests if a
// future addition needs them; the no-op anchor keeps the import honest.)
var _ = parser.Parse

// (plugin is imported for the *plugin.Event type used by fixedEvent in the
// eval tests above; the no-op anchor keeps the import honest.)
var _ = (*plugin.Event)(nil)
