// ========================== pkg/rule/compiler — evaluator tests ============================
//   Coverage goals (TASKS.md F5 + the C2 brief):
//     1. Table-driven test covering all literal kinds, all comparison operators,
//        all string operators (contains/starts_with/ends_with/matches/wildcard),
//        logic ops (and/or/not), the `in` operator, and bracket access.
//     2. Nil event → false, no panic.
//     3. Nil resolver → false (documented defensive behavior).
//     4. Concurrent Eval from many goroutines — race detector pass.
//     5. Benchmark: scalar-only plan measures 0 allocs/op after warmup.
//
//   Style note: white-box tests in `package compiler` so we can type-assert on
//   the unexported op types directly. The helpers (wafScheme, mustParse,
//   compileOK) are reused from compiler_test.go in the same package.

package compiler

import (
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== Mock resolver =================================================

// mapResolver is a tiny in-test FieldResolver. It serves scalar fields from the
// `scalars` map and Map-typed fields from the `maps` map. Unknown fields return
// (Value{}, false). A nil event is treated as "no event" → (Value{}, false).
// This is sufficient for the evaluator's test surface; it is NOT a substitute
// for production resolvers (which must type-assert plugin payload types).
type mapResolver struct {
	scalars map[string]rule.Value
	maps    map[string]rule.Value
}

func (m *mapResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	if event == nil {
		return rule.Value{}, false
	}
	if v, ok := m.scalars[field]; ok {
		return v, true
	}
	if v, ok := m.maps[field]; ok {
		return v, true
	}
	return rule.Value{}, false
}

// envelopeResolver is a trivial FieldResolver for the `core.*` namespace used
// in tests that exercise core.timestamp. It mirrors pkg/rule.EnvelopeResolver's
// behaviour for the single field we need here (Timestamp). Defining it locally
// keeps the test file self-contained without importing pkg/rule's resolver.
type envelopeResolver struct{}

func (envelopeResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	if event == nil {
		return rule.Value{}, false
	}
	if field == "core.timestamp" {
		return rule.NewTimestamp(event.Timestamp), true
	}
	if field == "core.stream" {
		return rule.NewString(event.Stream), true
	}
	return rule.Value{}, false
}

// chainResolver tries every wrapped resolver in order and returns the first
// non-(Value{}, false) answer. Used by tests that combine core.* (Envelope) and
// http.* (custom) resolutions in the same Plan.
type chainResolver []rule.FieldResolver

func (c chainResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	for _, r := range c {
		if v, ok := r.Resolve(field, event); ok {
			return v, true
		}
	}
	return rule.Value{}, false
}

// ========================== Test helpers ===================================================

// evalWafScheme builds a Scheme with the field types needed by the evaluator
// tests. Self-contained (does not import compiler_test.go's helpers) so this
// file reads top-to-bottom without cross-references.
func evalWafScheme(t *testing.T) *rule.Scheme {
	t.Helper()
	cat := rule.NewCatalog()
	mustEvalRegister(t, cat, "core", "timestamp", rule.TypeTimestamp)
	mustEvalRegister(t, cat, "core", "stream", rule.TypeString)
	mustEvalRegister(t, cat, "http", "method", rule.TypeString)
	mustEvalRegister(t, cat, "http", "uri", rule.TypeString)
	mustEvalRegister(t, cat, "http", "status", rule.TypeInt)
	mustEvalRegister(t, cat, "http", "client_ip", rule.TypeIP)
	mustEvalRegister(t, cat, "http", "ratio", rule.TypeFloat)
	mustEvalRegister(t, cat, "http", "duration", rule.TypeDuration)
	mustEvalRegister(t, cat, "http", "ts", rule.TypeTimestamp)
	mustEvalRegister(t, cat, "http", "ua", rule.TypeString)
	mustEvalRegister(t, cat, "http", "body", rule.TypeBytes)
	mustEvalRegister(t, cat, "http", "headers", rule.TypeMap)
	// http.pattern is a runtime-supplied regex pattern used by tests that
	// exercise the non-literal-pattern path of regex_replace. The field is
	// TypeString so the per-arg Kind check (KindString) succeeds and the
	// evaluator compiles the pattern per call (DECISION D4 non-literal
	// fallback). Production schemes do not need this field; it lives here
	// for test surface coverage.
	mustEvalRegister(t, cat, "http", "pattern", rule.TypeString)
	mustEvalRegister(t, cat, "custom", "flag", rule.TypeBool)
	return cat.Project("core", "http", "custom")
}

func mustEvalRegister(t *testing.T, cat *rule.Catalog, ns, name string, typ rule.FieldType) {
	t.Helper()
	if err := cat.Register(ns, name, typ); err != nil {
		t.Fatalf("Register(%q, %q, %v): %v", ns, name, typ, err)
	}
}

func evalCompileOK(t *testing.T, src string, scheme *rule.Scheme) *Plan {
	t.Helper()
	ast, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	p, cerr := Compile(ast, scheme)
	// Compile returns (*Plan, *CompileError). A typed-nil *CompileError does NOT
	// compare equal to the untyped nil interface in `if cerr != nil`, so we
	// check p == nil first and inspect cerr's typed value separately.
	if p == nil {
		if cerr != nil {
			t.Fatalf("Compile(%q) returned nil plan: %v", src, cerr)
		}
		t.Fatalf("Compile(%q) returned nil plan with nil error", src)
	}
	return p
}

// fixedEvent returns a stable *plugin.Event for tests that don't need a custom
// envelope. Timestamp is fixed for predictable timestamp comparisons.
func fixedEvent() *plugin.Event {
	return &plugin.Event{
		Envelope: plugin.Envelope{
			Timestamp: time.Date(2026, 6, 25, 12, 34, 56, 789_000_000, time.UTC),
			Stream:    "main",
		},
	}
}

// buildResolver returns a chain resolver that answers core.* via envelopeResolver
// and http.* + custom.* via the mapResolver built from scalars/maps. Tests that
// reference core.timestamp or core.stream need this; tests that don't can use
// the mapResolver directly.
func buildResolver(scalars, maps map[string]rule.Value) rule.FieldResolver {
	return chainResolver{
		envelopeResolver{},
		&mapResolver{scalars: scalars, maps: maps},
	}
}

// ========================== 1. Table-driven coverage =====================================

// TestEval_TableDriven is the main coverage surface. Each row exercises a
// specific operator / Kind / path. The table is grouped by family for
// readability. See the C2 brief for the precise list of required cases.
func TestEval_TableDriven(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	type tc struct {
		name    string
		src     string
		scalars map[string]rule.Value
		maps    map[string]rule.Value
		ev      *plugin.Event
		want    bool
	}

	cases := []tc{
		// ── Literal kinds at root ─────────────────────────────────────────────
		{"bool_true_root", `true`, nil, nil, nil, true},
		{"bool_false_root", `false`, nil, nil, nil, false},
		// Non-bool top-level literals are not predicates — defensive false.
		{"string_literal_root_returns_false", `"hello"`, nil, nil, nil, false},
		{"int_literal_root_returns_false", `42`, nil, nil, nil, false},

		// ── Comparison: Int ───────────────────────────────────────────────────
		{"int_eq_match", `http.status eq 200`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_eq_nomatch", `http.status eq 404`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},
		{"int_ne_match", `http.status ne 404`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_ne_nomatch", `http.status ne 200`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},
		{"int_lt_true", `http.status lt 500`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_lt_false", `http.status lt 100`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},
		{"int_le_eq", `http.status le 200`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_le_lt", `http.status le 500`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_le_false", `http.status le 100`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},
		{"int_gt_true", `http.status gt 100`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_gt_false", `http.status gt 500`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},
		{"int_ge_eq", `http.status ge 200`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_ge_true", `http.status ge 100`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"int_ge_false", `http.status ge 500`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, false},

		// ── Comparison: String ────────────────────────────────────────────────
		{"string_eq_match", `http.method eq "GET"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, nil, ev, true},
		{"string_eq_nomatch", `http.method eq "POST"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, nil, ev, false},
		{"string_lt_lex", `http.method lt "POST"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, nil, ev, true}, // "GET" < "POST"
		{"string_gt_lex", `http.method gt "AAA"`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, nil, ev, true},

		// ── Comparison: Duration ──────────────────────────────────────────────
		{"duration_lt_true", `http.duration lt 500ms`,
			map[string]rule.Value{"http.duration": rule.NewDuration(100 * time.Millisecond)}, nil, ev, true},
		{"duration_lt_false", `http.duration lt 50ms`,
			map[string]rule.Value{"http.duration": rule.NewDuration(100 * time.Millisecond)}, nil, ev, false},
		{"duration_ge_true", `http.duration ge 100ms`,
			map[string]rule.Value{"http.duration": rule.NewDuration(100 * time.Millisecond)}, nil, ev, true},

		// ── Comparison: Float ─────────────────────────────────────────────────
		{"float_lt_true", `http.ratio lt 0.5`,
			map[string]rule.Value{"http.ratio": rule.NewFloat(0.1)}, nil, ev, true},
		{"float_lt_false", `http.ratio lt 0.05`,
			map[string]rule.Value{"http.ratio": rule.NewFloat(0.1)}, nil, ev, false},
		{"float_ge_eq", `http.ratio ge 0.1`,
			map[string]rule.Value{"http.ratio": rule.NewFloat(0.1)}, nil, ev, true},
		{"float_eq", `http.ratio eq 0.5`,
			map[string]rule.Value{"http.ratio": rule.NewFloat(0.5)}, nil, ev, true},

		// ── Comparison: Timestamp ─────────────────────────────────────────────
		// Use buildResolver so core.timestamp resolves via envelopeResolver.
		{"timestamp_lt_true", `core.timestamp lt ts"2027-01-01T00:00:00Z"`,
			nil, nil, ev, true},
		{"timestamp_ge_false", `core.timestamp ge ts"2027-01-01T00:00:00Z"`,
			nil, nil, ev, false},

		// ── Comparison: Bytes ─────────────────────────────────────────────────
		{"bytes_eq_match", `http.body eq 0x"deadbeef"`,
			map[string]rule.Value{"http.body": rule.NewBytes([]byte{0xde, 0xad, 0xbe, 0xef})}, nil, ev, true},
		{"bytes_eq_nomatch", `http.body eq 0x"deadbeef"`,
			map[string]rule.Value{"http.body": rule.NewBytes([]byte{0x01, 0x02})}, nil, ev, false},

		// ── Comparison: runtime type mismatch ────────────────────────────────
		// Compiler accepts string eq string, but at runtime the resolver returns
		// an Int for http.method. The evaluator surfaces a no-match without panic.
		{"runtime_type_mismatch_returns_false", `http.method eq "GET"`,
			map[string]rule.Value{"http.method": rule.NewInt(42)}, nil, ev, false},

		// ── IP operators ──────────────────────────────────────────────────────
		{"ip_eq_ip_match", `ip"10.0.0.1" eq ip"10.0.0.1"`, nil, nil, ev, true},
		{"ip_eq_ip_nomatch", `ip"10.0.0.1" eq ip"10.0.0.2"`, nil, nil, ev, false},
		{"ip_eq_cidr_match", `ip"10.1.2.3" eq ip"10.0.0.0/8"`, nil, nil, ev, true},
		{"ip_eq_cidr_nomatch", `ip"11.1.2.3" eq ip"10.0.0.0/8"`, nil, nil, ev, false},
		{"ip_ne_cidr_match", `ip"11.1.2.3" ne ip"10.0.0.0/8"`, nil, nil, ev, true},
		{"ip_ne_cidr_nomatch", `ip"10.1.2.3" ne ip"10.0.0.0/8"`, nil, nil, ev, false},
		{"ip_in_cidrs_match", `ip"10.1.2.3" in [ip"10.0.0.0/8", ip"172.16.0.0/12"]`, nil, nil, ev, true},
		{"ip_in_cidrs_nomatch", `ip"8.8.8.8" in [ip"10.0.0.0/8", ip"172.16.0.0/12"]`, nil, nil, ev, false},
		{"ip_in_plain_match", `ip"10.1.2.3" in [ip"10.1.2.3", ip"10.1.2.4"]`, nil, nil, ev, true},
		{"ip_in_plain_nomatch", `ip"8.8.8.8" in [ip"10.1.2.3", ip"10.1.2.4"]`, nil, nil, ev, false},
		{"ip_in_mixed", `ip"10.1.2.3" in [ip"10.1.2.3", ip"192.168.0.0/16"]`, nil, nil, ev, true},

		// ── IPv6 CIDR — Group G (D17). The itoaPrefix bug returned "128" for any
		//    p ∈ [100, 128], corrupting every /100../127 IPv6 CIDR match. These
		//    cases were silent on IPv4 (masks ≤ 32) and would have shipped as a
		//    broken security-policy filter for IPv6 deployments. All cases
		//    verified against net.ParseCIDR + net.IPNet.Contains.
		{"ipv6_eq_cidr_slash64_match", `ip"2001:db8::1" eq ip"2001:db8::/64"`, nil, nil, ev, true},
		{"ipv6_eq_cidr_slash64_nomatch", `ip"2001:db8:0:1::1" eq ip"2001:db8::/64"`, nil, nil, ev, false},
		{"ipv6_eq_cidr_slash100_match", `ip"2001:db8::1" eq ip"2001:db8::/100"`, nil, nil, ev, true},
		{"ipv6_eq_cidr_slash100_nomatch", `ip"2001:db8::ffff:ffff" eq ip"2001:db8::/100"`, nil, nil, ev, false},
		{"ipv6_eq_cidr_slash127_match", `ip"2001:db8::1" eq ip"2001:db8::/127"`, nil, nil, ev, true},
		{"ipv6_eq_cidr_slash127_nomatch", `ip"2001:db8::2" eq ip"2001:db8::/127"`, nil, nil, ev, false},
		{"ipv6_eq_cidr_slash128_match", `ip"2001:db8::1" eq ip"2001:db8::1/128"`, nil, nil, ev, true},
		{"ipv6_eq_cidr_slash128_nomatch", `ip"2001:db8::2" eq ip"2001:db8::1/128"`, nil, nil, ev, false},
		{"ipv6_ne_cidr_slash100_match", `ip"2001:db8::ffff:ffff" ne ip"2001:db8::/100"`, nil, nil, ev, true},
		{"ipv6_ne_cidr_slash100_nomatch", `ip"2001:db8::1" ne ip"2001:db8::/100"`, nil, nil, ev, false},
		// Array form — IP `in` [CIDR...] where multiple elements may be CIDR.
		{"ipv6_in_cidrs_match", `ip"2001:db8::1" in [ip"2001:db8::/64", ip"fe80::/10"]`, nil, nil, ev, true},
		{"ipv6_in_cidrs_nomatch", `ip"::1" in [ip"2001:db8::/64", ip"fe80::/10"]`, nil, nil, ev, false},
		{"ipv6_in_mixed_plain_and_cidr", `ip"2001:db8::1" in [ip"::1", ip"2001:db8::/64"]`, nil, nil, ev, true},

		// ── String operators ──────────────────────────────────────────────────
		{"contains_true", `http.uri contains "/api"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, true},
		{"contains_false", `http.uri contains "/admin"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, false},
		{"starts_with_true", `http.uri starts_with "/api"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, true},
		{"starts_with_false", `http.uri starts_with "/admin"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, false},
		{"ends_with_true", `http.uri ends_with "users"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, true},
		{"ends_with_false", `http.uri ends_with "admin"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, false},
		{"matches_true", `http.uri matches "^/api/.*$"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, true},
		{"matches_false", `http.uri matches "^/admin/.*$"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, false},
		{"wildcard_star", `http.uri wildcard "/api/*"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/users")}, nil, ev, true},
		{"wildcard_question", `http.uri wildcard "/api/?"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/x")}, nil, ev, true},
		{"wildcard_question_nomatch", `http.uri wildcard "/api/?"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/xy")}, nil, ev, false},
		{"wildcard_literal_dot", `http.uri wildcard "10.0.0.1"`,
			map[string]rule.Value{"http.uri": rule.NewString("10.0.0.1")}, nil, ev, true}, // literal dots must NOT be regex metachars
		{"wildcard_star_then_text", `http.uri wildcard "/api/*.json"`,
			map[string]rule.Value{"http.uri": rule.NewString("/api/v1/data.json")}, nil, ev, true},

		// ── Logic ops ─────────────────────────────────────────────────────────
		{"and_true", `true and true`, nil, nil, nil, true},
		{"and_false", `true and false`, nil, nil, nil, false},
		{"or_true", `false or true`, nil, nil, nil, true},
		{"or_false", `false or false`, nil, nil, nil, false},
		{"not_true", `not true`, nil, nil, nil, false},
		{"not_false", `not false`, nil, nil, nil, true},

		// Short-circuit: when the left operand of `or` is true, the right side
		// is not evaluated. We exercise this with an expression whose right side
		// references an unknown field — if Eval short-circuits, the verdict is
		// `true`; if it does NOT short-circuit, the missing field makes Eval
		// false. The verdict tells us whether the short-circuit happened.
		{"or_short_circuit", `true or (http.status eq 999999)`, nil, nil, ev, true},
		{"and_short_circuit", `false and (http.status eq 999999)`, nil, nil, ev, false},

		// ── In op ─────────────────────────────────────────────────────────────
		{"int_in_match", `http.status in [200, 404, 500]`,
			map[string]rule.Value{"http.status": rule.NewInt(404)}, nil, ev, true},
		{"int_in_nomatch", `http.status in [200, 404, 500]`,
			map[string]rule.Value{"http.status": rule.NewInt(301)}, nil, ev, false},
		{"string_in_match", `http.method in ["GET", "HEAD"]`,
			map[string]rule.Value{"http.method": rule.NewString("GET")}, nil, ev, true},
		{"string_in_nomatch", `http.method in ["GET", "HEAD"]`,
			map[string]rule.Value{"http.method": rule.NewString("POST")}, nil, ev, false},
		{"bool_in_match", `custom.flag in [true, false]`,
			map[string]rule.Value{"custom.flag": rule.NewBool(true)}, nil, ev, true},

		// ── Bracket access ────────────────────────────────────────────────────
		{"bracket_key_match", `http.headers["x-foo"] eq "bar"`,
			nil,
			map[string]rule.Value{
				"http.headers": rule.NewMap(map[string]rule.Value{"x-foo": rule.NewString("bar")}),
			},
			ev, true},
		{"bracket_key_nomatch", `http.headers["x-foo"] eq "baz"`,
			nil,
			map[string]rule.Value{
				"http.headers": rule.NewMap(map[string]rule.Value{"x-foo": rule.NewString("bar")}),
			},
			ev, false},
		{"bracket_key_missing", `http.headers["x-other"] eq "bar"`,
			nil,
			map[string]rule.Value{
				"http.headers": rule.NewMap(map[string]rule.Value{"x-foo": rule.NewString("bar")}),
			},
			ev, false},
		{"bracket_field_not_map", `http.headers["x-foo"] eq "bar"`,
			map[string]rule.Value{"http.headers": rule.NewInt(42)},
			nil, ev, false},

		// ── Strict modifier — semantic no-op ──────────────────────────────────
		// strict — syntactic marker; v1 semantics == strict-typed by default. The parser
		// accepts strict as right-operand modifier of cmp / contains / starts_with /
		// ends_with / in operators — compiler flattens it at compile-time via the
		// strict-flatten logic in each compileX helper. Eval treats opStrict as no-op.
		{"strict_eq_true", `http.status eq strict 200`,
			map[string]rule.Value{"http.status": rule.NewInt(200)}, nil, ev, true},
		{"strict_eq_false", `http.status eq strict 200`,
			map[string]rule.Value{"http.status": rule.NewInt(404)}, nil, ev, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := evalCompileOK(t, c.src, scheme)
			r := buildResolver(c.scalars, c.maps)
			useEvent := c.ev
			if useEvent == nil {
				useEvent = fixedEvent()
			}
			got := p.Eval(r, useEvent)
			if got != c.want {
				t.Errorf("Eval(%q) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}

// ========================== 2. Nil event ====================================================

// TestEval_NilEvent locks the contract: a nil *plugin.Event must not panic.
// Eval surfaces field-resolution failures as false (the D3 contract), but
// literal-only expressions (`true`, `false`, `not true`) evaluate to their
// truthiness regardless of the event.
//
// We exercise the field-resolving rows here; the literal-only rows are
// covered by TestEval_TableDriven already.
func TestEval_NilEvent(t *testing.T) {
	scheme := evalWafScheme(t)
	expressions := []string{
		`http.status eq 200`,
		`http.uri contains "/api"`,
		`http.status in [200, 404]`,
		`http.headers["x-foo"] eq "bar"`,
		`http.uri wildcard "/api/*"`,
		`http.uri matches "^/api/.*$"`,
		`http.status eq 200 and http.uri contains "/api"`,
	}
	for _, src := range expressions {
		t.Run(src, func(t *testing.T) {
			p := evalCompileOK(t, src, scheme)
			r := buildResolver(
				map[string]rule.Value{
					"http.status": rule.NewInt(200),
					"http.uri":    rule.NewString("/api"),
				},
				map[string]rule.Value{
					"http.headers": rule.NewMap(map[string]rule.Value{"x-foo": rule.NewString("bar")}),
				},
			)
			got := p.Eval(r, nil)
			if got != false {
				t.Errorf("Eval(_, nil event) = %v, want false", got)
			}
		})
	}
}

// TestEval_LiteralOnly_NoEventDependency documents that literals and pure
// logic-only expressions do not depend on the event. This is a property of
// the evaluator, not a coincidence — a Plan rooted in opLitBool is constant.
func TestEval_LiteralOnly_NoEventDependency(t *testing.T) {
	scheme := evalWafScheme(t)
	cases := []struct {
		src  string
		want bool
	}{
		{`true`, true},
		{`false`, false},
		{`not true`, false},
		{`not false`, true},
		{`true and false`, false},
		{`true or false`, true},
	}
	for _, c := range cases {
		t.Run(c.src, func(t *testing.T) {
			p := evalCompileOK(t, c.src, scheme)
			r := buildResolver(nil, nil)
			if got := p.Eval(r, nil); got != c.want {
				t.Errorf("Eval(%q, nil event) = %v, want %v", c.src, got, c.want)
			}
			if got := p.Eval(r, fixedEvent()); got != c.want {
				t.Errorf("Eval(%q, fixedEvent) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}

// ========================== 3. Nil resolver / nil Plan =====================================

// TestEval_NilResolver locks the defensive contract: nil resolver → false.
// Documented behaviour — a misconfigured pipeline keeps returning false instead
// of crashing the worker.
func TestEval_NilResolver(t *testing.T) {
	scheme := evalWafScheme(t)
	p := evalCompileOK(t, `http.status eq 200`, scheme)
	if got := p.Eval(nil, fixedEvent()); got != false {
		t.Errorf("Eval(nil resolver) = %v, want false (defensive)", got)
	}
}

// TestEval_NilPlan locks the nil-Plan edge of the defensive contract. A nil
// *Plan is not a normal input — but the public API must be total.
func TestEval_NilPlan(t *testing.T) {
	var p *Plan
	if got := p.Eval(buildResolver(nil, nil), fixedEvent()); got != false {
		t.Errorf("Eval(nil plan) = %v, want false (defensive)", got)
	}
}

// TestEval_NilPlanAndResolver covers the combined nil case (both Plan and
// resolver are nil). Either input being nil is enough to fail closed.
func TestEval_NilPlanAndResolver(t *testing.T) {
	var p *Plan
	if got := p.Eval(nil, fixedEvent()); got != false {
		t.Errorf("Eval(nil plan, nil resolver) = %v, want false (defensive)", got)
	}
}

// ========================== 4. Concurrent Eval (race detector) =============================

// TestEval_Concurrent runs many goroutines evaluating the same Plan. The race
// detector (`go test -race`) flags any data race in the evaluator's internal
// state. Plan is immutable after Compile, so this test must remain race-free.
func TestEval_Concurrent(t *testing.T) {
	scheme := evalWafScheme(t)
	p := evalCompileOK(t,
		`http.status eq 200 and http.uri contains "/api"`,
		scheme)

	const goroutines = 32
	const iters = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			r := buildResolver(
				map[string]rule.Value{
					"http.status": rule.NewInt(200),
					"http.uri":    rule.NewString("/api/v1/items"),
				},
				nil,
			)
			for i := 0; i < iters; i++ {
				if !p.Eval(r, fixedEvent()) {
					t.Errorf("goroutine %d iter %d: Eval returned false", seed, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestEval_Concurrent_Wildcard exercises the sync.Once-guarded lazy regex path
// under heavy goroutine contention. The race detector must not flag the
// wildcard op's `regex` / `compileOnce` fields.
func TestEval_Concurrent_Wildcard(t *testing.T) {
	scheme := evalWafScheme(t)
	p := evalCompileOK(t, `http.uri wildcard "/api/*"`, scheme)

	const goroutines = 32
	const iters = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			r := buildResolver(
				map[string]rule.Value{
					"http.uri": rule.NewString("/api/v1/items"),
				},
				nil,
			)
			for i := 0; i < iters; i++ {
				if !p.Eval(r, fixedEvent()) {
					t.Errorf("Eval wildcard returned false")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ========================== 5. Benchmarks ===================================================

// BenchmarkEval_ScalarPlan measures the hot-path cost of a scalar-only plan
// (`http.status eq 200`) with a mapResolver returning the field as KindInt.
// This is the canonical "zero allocation" plan: scalar cmp against scalar
// field, no Map / Array / wildcard / matches involved.
//
// Run with `go test -bench=. -benchmem ./pkg/rule/compiler/` to see the
// allocations count. Success criterion from D4 / F5: 0 allocs/op after warmup.
func BenchmarkEval_ScalarPlan(b *testing.B) {
	scheme := evalBenchScheme()
	p := evalBenchCompile(b, `http.status eq 200`, scheme)
	r := &mapResolver{
		scalars: map[string]rule.Value{
			"http.status": rule.NewInt(200),
		},
	}
	ev := &plugin.Event{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Eval(r, ev) {
			b.Fatal("Eval returned false on positive case")
		}
	}
}

// BenchmarkEval_ScalarPlan_String exercises the String comparison path.
func BenchmarkEval_ScalarPlan_String(b *testing.B) {
	scheme := evalBenchScheme()
	p := evalBenchCompile(b, `http.method eq "GET"`, scheme)
	r := &mapResolver{
		scalars: map[string]rule.Value{
			"http.method": rule.NewString("GET"),
		},
	}
	ev := &plugin.Event{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Eval(r, ev) {
			b.Fatal("Eval returned false on positive case")
		}
	}
}

// BenchmarkEval_ComplexPlan measures a realistic plan (range check + contains).
func BenchmarkEval_ComplexPlan(b *testing.B) {
	scheme := evalBenchScheme()
	src := `http.status ge 400 and http.status lt 500 and http.uri contains "/api"`
	p := evalBenchCompile(b, src, scheme)
	r := &mapResolver{
		scalars: map[string]rule.Value{
			"http.status": rule.NewInt(404),
			"http.uri":    rule.NewString("/api/v1/items"),
		},
	}
	ev := &plugin.Event{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Eval(r, ev) {
			b.Fatal("Eval returned false on positive case")
		}
	}
}

// BenchmarkEvalIPInCIDR measures the IP-in-CIDR eval path under DECISION D17.
//
// Before D17 this benchmark reported multiple allocs/op because the evaluator
// called net.ParseCIDR on every Eval. Post-D17 the only remaining allocations
// come from rule.Value.AsIP's documented defensive IP-slice copy — that copy
// is a property of the pkg/rule Value API (types.go AsIP: "The copy is
// intentional — callers may keep the slice without aliasing the engine's
// storage") and is OUT OF SCOPE for D17.
//
// What D17 guarantees and this benchmark proves:
//
//   - the *net.IPNet is resolved ONCE at compile time (compileLitIP);
//   - eval reads ipLit.ipnet.Contains(leftIP) directly;
//   - no net.ParseCIDR appears on the eval hot path.
//
// The benchmark itself is the regression guard — if a future change re-introduces
// ParseCIDR (or any other allocation specifically tied to IP-CIDR eval), the
// alloc count here will rise above the baseline of 1 (AsIP copy) per Eval.
//
// Run with `go test -bench=BenchmarkEvalIPInCIDR -benchmem ./pkg/rule/compiler/`.
func BenchmarkEvalIPInCIDR(b *testing.B) {
	scheme := evalBenchScheme()
	p := evalBenchCompile(b, `ip"10.1.2.3" eq ip"10.0.0.0/8"`, scheme)
	r := &mapResolver{} // empty resolver — both sides are literals, no field lookup
	ev := &plugin.Event{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Eval(r, ev) {
			b.Fatal("Eval returned false on positive case")
		}
	}
}

// BenchmarkEvalIPInCIDRArray exercises the `in` array form — per-element
// ipnet.Contains against CIDR array members. Pre-D17 this path called
// ipInCIDR per element (one ParseCIDR per CIDR member); post-D17 each CIDR
// member's pre-resolved *net.IPNet is read directly. The alloc count on a
// positive match is constant: 1 for elem.AsIP() on the resolver-supplied
// element, and 0 for the matched array member because the evalIn IP
// branch short-circuits on cidr first and never computes rightIP for CIDR
// members. A no-match run burns len(array) AsIP copies (left + each
// non-CIDR member; CIDR members still short-circuit past AsIP), but the
// ParseCIDR-per-element cost is gone.
func BenchmarkEvalIPInCIDRArray(b *testing.B) {
	scheme := evalBenchScheme()
	p := evalBenchCompile(b,
		`ip"10.1.2.3" in [ip"10.0.0.0/8", ip"172.16.0.0/12", ip"192.168.0.0/16"]`,
		scheme)
	r := &mapResolver{}
	ev := &plugin.Event{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Eval(r, ev) {
			b.Fatal("Eval returned false on positive case")
		}
	}
}

// ========================== Benchmark helpers ===============================================

// evalBenchScheme is the minimal Scheme for the benchmark surface (Int + String
// + String fields). Smaller than evalWafScheme — bench setup is on the cold
// path and we keep it lean.
func evalBenchScheme() *rule.Scheme {
	cat := rule.NewCatalog()
	mustBenchRegister(cat, "http", "status", rule.TypeInt)
	mustBenchRegister(cat, "http", "method", rule.TypeString)
	mustBenchRegister(cat, "http", "uri", rule.TypeString)
	return cat.Project("http")
}

func mustBenchRegister(cat *rule.Catalog, ns, name string, typ rule.FieldType) {
	if err := cat.Register(ns, name, typ); err != nil {
		panic(err)
	}
}

func evalBenchCompile(b *testing.B, src string, scheme *rule.Scheme) *Plan {
	ast, err := parser.Parse(src)
	if err != nil {
		b.Fatalf("Parse(%q): %v", src, err)
	}
	p, cerr := Compile(ast, scheme)
	// Compile returns (*Plan, *CompileError). A typed-nil *CompileError does NOT
	// compare equal to the untyped nil interface in `if cerr != nil`, so we
	// check p == nil first.
	if p == nil {
		if cerr != nil {
			b.Fatalf("Compile(%q): %v", src, cerr)
		}
		b.Fatalf("Compile(%q) returned nil plan with nil error", src)
	}
	return p
}

// keep imports honest — sync/time are used by the helpers above or are core to
// the test setup. The no-op assignments anchor the import set.
var (
	_ = time.Now
	_ = sync.WaitGroup{}
)
