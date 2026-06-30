// ========================== pkg/rule/compiler — timestamp function tests ======================
//   Coverage goals (Flow 002 Group E — Task E2):
//     1. Registry accessors: Lookup returns the expected FuncSpec for now, unix_time,
//        and format_time, including arities, return Kinds, and Allocating flags.
//     2. Names() includes the E2 names.
//     3. Positive compile for all three functions.
//     4. Compile-time negatives: arity mismatch and per-argument Kind mismatch.
//     5. Eval coverage for unix_time over fixed timestamps.
//     6. Eval coverage for format_time with common reference layouts, plus the
//        defensive "does not panic" contract for empty layouts and nil events.
//     7. Eval coverage for now() bounded by time.Now() readings before and after.
//
//   Style note: white-box tests in `package compiler`; the helpers from
//   compiler_test.go and eval_test.go are reused.

package compiler

import (
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
)

// ========================== E2 — Registry ===================================================

// TestRegistry_E2_Lookup verifies the metadata for the E2 functions.
func TestRegistry_E2_Lookup(t *testing.T) {
	cases := []struct {
		name       string
		wantArity  int
		wantReturn rule.Kind
		wantAlloc  bool
	}{
		{"now", 0, rule.KindTimestamp, true},
		{"unix_time", 1, rule.KindInt, false},
		{"format_time", 2, rule.KindString, true},
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
			if len(spec.ParamKinds) != c.wantArity {
				t.Errorf("arity = %d, want %d", len(spec.ParamKinds), c.wantArity)
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

// TestRegistry_E2_NamesPresent checks that Names() contains the E2 names.
func TestRegistry_E2_NamesPresent(t *testing.T) {
	all := Names()
	sort.Strings(all)
	want := []string{"format_time", "now", "unix_time"}
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

// ========================== E2 — Compile ====================================================

// TestCompiler_E2_Compile exercises positive compile and the standard negatives.
func TestCompiler_E2_Compile(t *testing.T) {
	scheme := wafScheme(t)

	positive := []string{
		`now() eq ts"2026-01-01T00:00:00Z"`,
		`unix_time(ts"2026-01-01T00:00:00Z") eq 1767225600`,
		`format_time(ts"2026-06-25T12:34:56Z", ` + strconv.Quote(time.RFC3339) + `) eq "2026-06-25T12:34:56Z"`,
	}
	for _, src := range positive {
		t.Run("positive_"+src, func(t *testing.T) {
			compileOK(t, src, scheme)
		})
	}

	negative := []struct {
		name     string
		src      string
		wantCode string
	}{
		{"now_too_many", `now(1)`, string(CodeBadFuncArity)},
		{"unix_time_too_few", `unix_time()`, string(CodeBadFuncArity)},
		{"unix_time_too_many", `unix_time(ts"2026-01-01T00:00:00Z", 1)`, string(CodeBadFuncArity)},
		{"unix_time_wrong_kind", `unix_time(http.uri)`, string(CodeBadFuncArgType)},
		{"format_time_too_few", `format_time(ts"2026-01-01T00:00:00Z")`, string(CodeBadFuncArity)},
		{"format_time_bad_ts", `format_time(http.uri, "x")`, string(CodeBadFuncArgType)},
		{"format_time_bad_layout", `format_time(ts"2026-01-01T00:00:00Z", http.status)`, string(CodeBadFuncArgType)},
	}
	for _, c := range negative {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, scheme)
			if string(ce.Code) != c.wantCode {
				t.Errorf("got Code %q, want %q", ce.Code, c.wantCode)
			}
		})
	}
}

// ========================== E2 — Eval =======================================================

// TestEval_E2_UnixTime pins the unix_time conversion for representative timestamps.
func TestEval_E2_UnixTime(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	cases := []struct {
		name string
		ts   time.Time
		want string
	}{
		{"epoch", time.Unix(0, 0).UTC(), "0"},
		{"2026-01-01", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "1767225600"},
		{"one_day_later", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), strconv.FormatInt(1767225600+86400, 10)},
		{"pre_1970", time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), "-86400"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `to_string(unix_time(http.ts)) eq ` + strconv.Quote(c.want)
			p := evalCompileOK(t, src, scheme)
			r := buildResolver(map[string]rule.Value{
				"http.ts": rule.NewTimestamp(c.ts),
			}, nil)
			if !p.Eval(r, ev) {
				t.Errorf("Eval(%q) for ts=%v want %q failed", src, c.ts, c.want)
			}
		})
	}
}

// TestEval_E2_FormatTime pins time.Format-based output for valid layouts and confirms
// the no-panic / non-empty-output contract for a zero reference layout and for a nil event.
func TestEval_E2_FormatTime(t *testing.T) {
	scheme := evalWafScheme(t)

	cases := []struct {
		name   string
		ts     time.Time
		layout string
		want   string
	}{
		{
			name:   "rfc3339",
			ts:     time.Date(2026, 6, 25, 12, 34, 56, 0, time.UTC),
			layout: time.RFC3339,
			want:   "2026-06-25T12:34:56Z",
		},
		{
			name:   "rfc3339nano",
			ts:     time.Date(2026, 6, 25, 12, 34, 56, 123_000_000, time.UTC),
			layout: time.RFC3339Nano,
			want:   "2026-06-25T12:34:56.123Z",
		},
		{
			name:   "date_only",
			ts:     time.Date(2026, 6, 25, 12, 34, 56, 0, time.UTC),
			layout: "2006/01/02",
			want:   "2026/06/25",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `format_time(http.ts, ` + strconv.Quote(c.layout) + `) eq ` + strconv.Quote(c.want)
			p := evalCompileOK(t, src, scheme)
			r := buildResolver(map[string]rule.Value{
				"http.ts": rule.NewTimestamp(c.ts),
			}, nil)
			if !p.Eval(r, fixedEvent()) {
				t.Errorf("Eval(%q) failed", src)
			}
		})
	}

	// Empty layout must not panic and must return some string. Go's behaviour
	// for a non-reference layout is unspecified and intentionally not part of
	// the engine's contract — we assert "non-panic, returned a string Value"
	// but do NOT pin the exact string content.
	t.Run("empty_layout_no_panic", func(t *testing.T) {
		src := `format_time(http.ts, "")`
		ast := mustParse(t, src)
		plan, cerr := Compile(ast, scheme)
		if plan == nil {
			t.Fatalf("Compile(%q): %v", src, cerr)
		}
		r := buildResolver(map[string]rule.Value{
			"http.ts": rule.NewTimestamp(time.Date(2026, 6, 25, 12, 34, 56, 0, time.UTC)),
		}, nil)
		v, ok := evalValue(plan.Root(), r, fixedEvent())
		if !ok {
			t.Fatalf("evalValue(format_time(...)) returned ok=false")
		}
		if v.Kind() != rule.KindString {
			t.Errorf("format_time(empty) returned Kind %s, want %s", v.Kind(), rule.KindString)
		}
		s, _ := v.AsString()
		if len(s) == 0 {
			t.Errorf("format_time(empty) returned an empty string")
		}
	})

	// Nil event must not panic. We use evalValue so the test observes a real
	// property of the function, not just the absence of a panic.
	t.Run("nil_event_no_panic", func(t *testing.T) {
		src := `format_time(ts"2026-06-25T12:34:56Z", "2006")`
		ast := mustParse(t, src)
		plan, cerr := Compile(ast, scheme)
		if plan == nil {
			t.Fatalf("Compile(%q): %v", src, cerr)
		}
		v, ok := evalValue(plan.Root(), nil, nil)
		if !ok {
			t.Fatalf("evalValue(format_time(...)) returned ok=false on nil event")
		}
		s, _ := v.AsString()
		if s != "2026" {
			t.Errorf("format_time year-only = %q, want %q", s, "2026")
		}
	})
}

// TestEval_E2_Now asserts that now() returns a KindTimestamp Value whose
// wall-clock instant lies between two time.Now() readings bracketing the eval
// call. The function is non-deterministic, so the test bounds it rather than
// pinning a specific value. The test inspects the Value the function produced
// directly via evalValue (the previous variant only called p.Eval and
// discarded both inputs and outputs — a no-op; this variant observes a real
// property of the function, not merely that Eval returns without panicking).
func TestEval_E2_Now(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()
	src := `now()`
	ast := mustParse(t, src)
	plan, cerr := Compile(ast, scheme)
	if plan == nil {
		t.Fatalf("Compile(%q): %v", src, cerr)
	}

	before := time.Now()
	v, ok := evalValue(plan.Root(), buildResolver(nil, nil), ev)
	after := time.Now()
	if !ok {
		t.Fatalf("evalValue(now()) returned ok=false")
	}
	if v.Kind() != rule.KindTimestamp {
		t.Fatalf("now() returned Kind %s, want %s", v.Kind(), rule.KindTimestamp)
	}
	ts, _ := v.AsTimestamp()
	if ts.Before(before) || ts.After(after) {
		t.Errorf("now() = %v, want between %v and %v", ts, before, after)
	}
}

// ========================== E2 — imports anchors ==============================================

// plugin is used for fixedEvent and nil-event defensive tests.
var _ = (*plugin.Event)(nil)
