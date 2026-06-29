// ========================== pkg/rule/builder tests (Task E2) ===================================
//   Coverage goals:
//     1. Happy path: chain Field calls, build a RuleSet, add a rule, Match fires.
//     2. Empty name error: Field with empty name stores an error and Ruleset returns it.
//     3. Duplicate field: registering the same field twice returns a Catalog error.
//     4. CompileRules: map of two rules, both fire on a matching event.

package builder

import (
	"errors"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/ruleset"
)

// ========================== Helpers =========================================================

// scalarResolver serves scalar field values from a map. Unknown fields return
// (Value{}, false), matching the FieldResolver contract used by the evaluator.
type scalarResolver struct {
	values map[string]rule.Value
}

func (s *scalarResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	if s == nil || s.values == nil {
		return rule.Value{}, false
	}
	v, ok := s.values[field]
	return v, ok
}

func eventStub() *plugin.Event {
	return &plugin.Event{
		Envelope: plugin.Envelope{Stream: "main"},
	}
}

// ========================== 1. Happy path ===================================================

func TestBuilder_HappyPath(t *testing.T) {
	rs, err := New("http").
		Field("http", "status", rule.TypeInt).
		Field("http", "method", rule.TypeString).
		Ruleset()
	if err != nil {
		t.Fatalf("Ruleset: %v", err)
	}

	if err := rs.Add("block_post", "http.status eq 405"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	resolver := &scalarResolver{values: map[string]rule.Value{
		"http.status": rule.NewInt(405),
	}}
	name, ok := rs.Match(eventStub(), resolver)
	if !ok {
		t.Fatalf("Match: expected rule to fire")
	}
	if name != "block_post" {
		t.Errorf("Match: want %q, got %q", "block_post", name)
	}
}

// ========================== 2. Empty name error =============================================

func TestBuilder_EmptyNameError(t *testing.T) {
	b := New("http").
		Field("http", "status", rule.TypeInt).
		Field("http", "", rule.TypeInt)

	if err := b.Err(); err == nil {
		t.Fatalf("Err: expected stored error, got nil")
	}

	rs, err := b.Ruleset()
	if err == nil {
		t.Fatalf("Ruleset: expected error, got nil")
	}
	if rs != nil {
		t.Errorf("Ruleset: expected nil RuleSet on error, got %v", rs)
	}

	// Ruleset must return the same error that Err reported.
	if !errors.Is(err, b.Err()) && err.Error() != b.Err().Error() {
		t.Errorf("Ruleset returned %v, want %v", err, b.Err())
	}
}

// ========================== 3. Duplicate field ==============================================

func TestBuilder_DuplicateField(t *testing.T) {
	rs, err := New("http").
		Field("http", "status", rule.TypeInt).
		Field("http", "status", rule.TypeInt).
		Ruleset()
	if err == nil {
		t.Fatalf("Ruleset: expected duplicate-field error, got nil")
	}
	if rs != nil {
		t.Errorf("Ruleset: expected nil RuleSet on error, got %v", rs)
	}
	if err != rule.ErrFieldExists {
		t.Errorf("Ruleset: expected ErrFieldExists, got %v", err)
	}
}

// ========================== 4. CompileRules ===================================================

func TestBuilder_CompileRules(t *testing.T) {
	rules := map[string]string{
		"status_405":  "http.status eq 405",
		"method_post": "http.method eq \"POST\"",
	}

	rs, err := New("http").
		Field("http", "status", rule.TypeInt).
		Field("http", "method", rule.TypeString).
		CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	resolver := &scalarResolver{values: map[string]rule.Value{
		"http.status": rule.NewInt(405),
		"http.method": rule.NewString("POST"),
	}}

	name, ok := rs.Match(eventStub(), resolver)
	if !ok {
		t.Fatalf("Match: expected a rule to fire")
	}
	// first-match-wins: registration order follows map iteration, which is random,
	// so we just assert the returned name is one of the two loaded rules.
	if name != "status_405" && name != "method_post" {
		t.Errorf("Match: unexpected rule name %q", name)
	}

	loaded := rs.Rules()
	if len(loaded) != 2 {
		t.Errorf("Rules: want 2 rules, got %d", len(loaded))
	}

	stats := rs.Stats()
	seen := 0
	for _, n := range []string{"status_405", "method_post"} {
		if _, ok := stats[n]; !ok {
			t.Errorf("Stats: missing rule %q", n)
		} else {
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("Stats: expected 2 rules, saw %d", seen)
	}
}

// ========================== Additional: Profiles + cross-namespace rule ======================

func TestBuilder_Profiles(t *testing.T) {
	rs, err := New("http").
		Profiles("syslog").
		Field("http", "status", rule.TypeInt).
		Field("syslog", "severity", rule.TypeInt).
		Ruleset()
	if err != nil {
		t.Fatalf("Ruleset: %v", err)
	}

	if err := rs.Add("mixed", "http.status eq 200 and syslog.severity eq 5"); err != nil {
		t.Fatalf("Add mixed-namespace rule: %v", err)
	}

	resolver := &scalarResolver{values: map[string]rule.Value{
		"http.status":     rule.NewInt(200),
		"syslog.severity": rule.NewInt(5),
	}}
	name, ok := rs.Match(eventStub(), resolver)
	if !ok {
		t.Fatalf("Match: expected mixed rule to fire")
	}
	if name != "mixed" {
		t.Errorf("Match: want %q, got %q", "mixed", name)
	}

	// Sanity: the core namespace is implicitly present.
	if err := rs.Add("core_stream", "core.stream eq \"main\""); err != nil {
		t.Fatalf("Add core rule: %v", err)
	}
}

// Compile-time assertion: Builder satisfies the intended public surface.
var _ = (*ruleset.RuleSet)(nil)
