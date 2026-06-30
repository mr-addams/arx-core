// ========================== pkg/rule/compiler — coercion function tests =======================
//   Coverage goals (Flow 002 Group E — Task E3):
//     1. Registry accessors: Lookup returns the expected FuncSpec for to_int and
//        to_float, with KindInvalid wildcard arguments and Allocating=false.
//     2. Names() includes both E3 names.
//     3. Positive compile for to_int / to_float over different field Kinds, proving
//        the wildcard argument is honored.
//     4. Eval coverage for to_int per supported Kind: identity, truncation, parsing,
//        bool mapping, IP low-64, timestamp Unix, duration nanoseconds, and unsupported
//        Kinds falling back to 0.
//     5. Eval coverage for to_float per supported Kind, mirroring the to_int shape.
//
//   Style note: white-box tests in `package compiler`; the helpers from
//   compiler_test.go and eval_test.go are reused.

package compiler

import (
	"math"
	"net"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
)

// ========================== E3 — Registry ===================================================

// TestRegistry_E3_Lookup verifies the metadata for the E3 coercion functions.
func TestRegistry_E3_Lookup(t *testing.T) {
	cases := []struct {
		name       string
		wantReturn rule.Kind
		wantAlloc  bool
	}{
		{"to_int", rule.KindInt, false},
		{"to_float", rule.KindFloat, false},
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
			if len(spec.ParamKinds) != 1 || spec.ParamKinds[0] != rule.KindInvalid {
				t.Errorf("ParamKinds = %v, want [KindInvalid wildcard]", spec.ParamKinds)
			}
			if spec.ReturnKind != c.wantReturn {
				t.Errorf("ReturnKind = %s, want %s", spec.ReturnKind, c.wantReturn)
			}
			if spec.Allocating != c.wantAlloc {
				t.Errorf("Allocating = %v, want %v", spec.Allocating, c.wantAlloc)
			}
			if spec.Eval == nil {
				t.Errorf("Eval is nil; registry entry is invalid")
			}
		})
	}
}

// TestRegistry_E3_NamesPresent checks that Names() contains both E3 names.
func TestRegistry_E3_NamesPresent(t *testing.T) {
	all := Names()
	sort.Strings(all)
	want := []string{"to_float", "to_int"}
	for _, w := range want {
		found := false
		for _, n := range all {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Names() missing %q; got %v", w, all)
		}
	}
}

// ========================== E3 — Compile ====================================================

// TestCompiler_E3_Compile exercises positive compile over multiple argument Kinds
// (proving the KindInvalid wildcard) and the standard arity negatives. The wildcard
// means per-argument Kind errors are impossible for to_int / to_float, so only arity
// is tested here.
func TestCompiler_E3_Compile(t *testing.T) {
	scheme := wafScheme(t)

	positive := []string{
		`to_int(http.status) eq 200`,
		`to_int(http.uri) eq 0`,
		`to_float(http.ratio) eq 1.5`,
	}
	for _, src := range positive {
		t.Run("positive_"+src, func(t *testing.T) {
			compileOK(t, src, scheme)
		})
	}

	negative := []struct {
		name string
		src  string
	}{
		{"to_int_too_few", `to_int()`},
		{"to_int_too_many", `to_int(http.status, http.uri)`},
		{"to_float_too_few", `to_float()`},
		{"to_float_too_many", `to_float(http.ratio, http.status)`},
	}
	for _, c := range negative {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, scheme)
			if ce.Code != CodeBadFuncArity {
				t.Errorf("got Code %q, want %q", ce.Code, CodeBadFuncArity)
			}
		})
	}
}

// ========================== E3 — Eval to_int ================================================

// TestEval_E3_ToInt pins the complete to_int coercion table. Each row compiles a
// rule comparing to_int(field) against an expected int64 literal and binds the
// input field to a Value of the appropriate Kind.
func TestEval_E3_ToInt(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	cases := []struct {
		name  string
		field string
		v     rule.Value
		want  string
	}{
		{"int_identity_200", "http.status", rule.NewInt(200), "200"},
		{"int_identity_0", "http.status", rule.NewInt(0), "0"},
		{"int_negative", "http.status", rule.NewInt(-42), "-42"},

		{"float_truncate_pos", "http.ratio", rule.NewFloat(3.7), "3"},
		{"float_truncate_neg", "http.ratio", rule.NewFloat(-3.7), "-3"},
		{"float_zero", "http.ratio", rule.NewFloat(0), "0"},

		{"string_number", "http.uri", rule.NewString("42"), "42"},
		{"string_negative", "http.uri", rule.NewString("-100"), "-100"},
		{"string_bad", "http.uri", rule.NewString("abc"), "0"},
		{"string_empty", "http.uri", rule.NewString(""), "0"},

		{"bool_true", "custom.flag", rule.NewBool(true), "1"},
		{"bool_false", "custom.flag", rule.NewBool(false), "0"},

		{"ipv4", "http.client_ip", rule.NewIP(net.ParseIP("10.0.0.1")), strconv.FormatInt(0x0A000001, 10)},
		{"ipv6", "http.client_ip", rule.NewIP(net.ParseIP("::1")), "1"},

		{"timestamp", "http.ts", rule.NewTimestamp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), "1767225600"},
		{"duration", "http.duration", rule.NewDuration(5 * time.Second), "5000000000"},

		{"bytes", "http.body", rule.NewBytes([]byte{0x00, 0xFF}), "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `to_string(to_int(` + c.field + `)) eq ` + strconv.Quote(c.want)
			p := evalCompileOK(t, src, scheme)
			r := buildResolver(map[string]rule.Value{c.field: c.v}, nil)
			if !p.Eval(r, ev) {
				t.Errorf("Eval(%q) for kind %s want %q failed", src, c.v.Kind(), c.want)
			}
		})
	}

	// Float non-finite values map to math.MinInt64 / math.MaxInt64. We exercise
	// them directly through the registry Eval because the rule-language literal
	// form cannot express NaN or Inf.
	t.Run("float_nan", func(t *testing.T) {
		spec, _ := Lookup("to_int")
		got, _ := spec.Eval([]rule.Value{rule.NewFloat(math.NaN())}).AsInt()
		if got != math.MinInt64 {
			t.Errorf("to_int(NaN) = %v, want %v", got, math.MinInt64)
		}
	})
	t.Run("float_pos_inf", func(t *testing.T) {
		spec, _ := Lookup("to_int")
		got, _ := spec.Eval([]rule.Value{rule.NewFloat(math.Inf(1))}).AsInt()
		if got != math.MaxInt64 {
			t.Errorf("to_int(+Inf) = %v, want %v", got, math.MaxInt64)
		}
	})
	t.Run("float_neg_inf", func(t *testing.T) {
		spec, _ := Lookup("to_int")
		got, _ := spec.Eval([]rule.Value{rule.NewFloat(math.Inf(-1))}).AsInt()
		if got != math.MinInt64 {
			t.Errorf("to_int(-Inf) = %v, want %v", got, math.MinInt64)
		}
	})
}

// ========================== E3 — Eval to_float ==============================================

// TestEval_E3_ToFloat pins the complete to_float coercion table, mirroring the to_int
// shape. Float comparison is exact (NewFloat identity), so the expected values are
// written as literals that ParseFloat produces identically.
func TestEval_E3_ToFloat(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	cases := []struct {
		name  string
		field string
		v     rule.Value
		want  string
	}{
		{"int_200", "http.status", rule.NewInt(200), "200"},
		{"int_negative", "http.status", rule.NewInt(-3), "-3"},

		{"float_identity", "http.ratio", rule.NewFloat(3.14), "3.14"},
		{"float_zero", "http.ratio", rule.NewFloat(0), "0"},

		{"string_number", "http.uri", rule.NewString("3.14"), "3.14"},
		{"string_bad", "http.uri", rule.NewString("abc"), "0"},
		{"string_empty", "http.uri", rule.NewString(""), "0"},

		{"bool_true", "custom.flag", rule.NewBool(true), "1"},
		{"bool_false", "custom.flag", rule.NewBool(false), "0"},

		{"ipv4", "http.client_ip", rule.NewIP(net.ParseIP("10.0.0.1")), "1.67772161e+08"},
		{"timestamp_unsupported", "http.ts", rule.NewTimestamp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), "0"},
		{"duration_unsupported", "http.duration", rule.NewDuration(5 * time.Second), "0"},

		{"bytes", "http.body", rule.NewBytes([]byte{0x00, 0xFF}), "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `to_string(to_float(` + c.field + `)) eq ` + strconv.Quote(c.want)
			p := evalCompileOK(t, src, scheme)
			r := buildResolver(map[string]rule.Value{c.field: c.v}, nil)
			if !p.Eval(r, ev) {
				t.Errorf("Eval(%q) for kind %s want %q failed", src, c.v.Kind(), c.want)
			}
		})
	}
}

// ========================== E3 — imports anchors ==============================================

// time is used for timestamp and duration test inputs.
var _ = time.Now

// math is used for NaN/Inf direct-contract tests.
var _ = math.MaxInt64

// net is used for IP test inputs.
var _ = net.ParseIP

// plugin is used for fixedEvent.
var _ = (*plugin.Event)(nil)
