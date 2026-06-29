// ========================== pkg/rule — RuleSet tests (Task E1) =============================
//   Coverage goals (TASKS.md E1, F-group):
//     1. Add with compile error → error returned, no rule stored.
//     2. Add duplicate name → ErrRuleExists on second call.
//     3. Add → Remove → rule gone, Match no longer fires.
//     4. Remove on absent name → no-op, no panic, no error.
//     5. Replace existing rule with VALID expression → swap, new rule fires.
//     6. Replace existing rule with INVALID expression → compile error returned,
//        OLD rule STILL fires (D13 atomicity invariant).
//     7. Replace on absent name → ErrRuleNotFound, no rule added.
//     8. Two rules both matching the same event → first-added wins, second never
//        evaluated, second's counter stays at zero.
//     9. Stats — three rules, Match against each, counts add up.
//    10. Rules — snapshot semantics: captured slice unaffected by subsequent Add.
//    11. Concurrent Add/Remove/Replace vs Match — race detector must pass
//        (`go test -race -count=1 ./pkg/rule/...`).
//
//   Style note: white-box tests in `package ruleset` so we can poke at internal state
//   (e.g. rules slice length) without exporting more API. The package name follows the
//   subpackage layout (see ruleset.go's LOCATION block).

package ruleset

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
)

// ========================== Helpers =================================================================

// wafSchema builds a Catalog + Scheme with a representative WAF-like field set:
// core.* (Envelope) + http.* (typical WAF use cases). Rules in the tests below
// reference fields from this set; cross-profile CompileError is exercised by a
// separate scheme in test 1.
func wafSchema(t *testing.T) (*rule.Catalog, *rule.Scheme) {
	t.Helper()
	cat := rule.NewCatalog()
	mustRegister(t, cat, "core", "timestamp", rule.TypeTimestamp)
	mustRegister(t, cat, "core", "stream", rule.TypeString)
	mustRegister(t, cat, "core", "level", rule.TypeString)
	mustRegister(t, cat, "http", "method", rule.TypeString)
	mustRegister(t, cat, "http", "uri", rule.TypeString)
	mustRegister(t, cat, "http", "status", rule.TypeInt)
	mustRegister(t, cat, "http", "ua", rule.TypeString)
	return cat, cat.Project("core", "http")
}

// mustRegister registers a field in cat, failing the test on error. Mirrors the
// helpers in compiler_test.go and scheme_test.go so the test files read the same
// way (and so a fixture bug surfaces loudly instead of being ignored).
func mustRegister(t *testing.T, cat *rule.Catalog, ns, name string, typ rule.FieldType) {
	t.Helper()
	if err := cat.Register(ns, name, typ); err != nil {
		t.Fatalf("Register(%q, %q, %v): %v", ns, name, typ, err)
	}
}

// newWafRuleSet constructs an empty RuleSet against the WAF scheme. Returns the
// RuleSet and its Scheme (the Scheme is useful for tests that want to assert on
// Scheme-level state, e.g. revision).
func newWafRuleSet(t *testing.T) (*RuleSet, *rule.Scheme) {
	t.Helper()
	cat, scheme := wafSchema(t)
	// "http" is the profile name; New projects (profile, "core") so rules in
	// this RuleSet can reference both core.* and http.* fields. The legacy WAF
	// profile-name → namespace mapping (e.g. "waf" → {core, http}) is owned by
	// E2's Builder; E1 accepts the namespace directly to keep the RuleSet core
	// free of profile-name policy.
	rs, err := New(cat, "http")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rs, scheme
}

// scalarResolver is a tiny FieldResolver that serves scalar fields from a map.
// Unknown fields → (Value{}, false). Used by every Match test below.
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

// atResolver returns a resolver that answers exactly one field with a fixed value.
// Compact helper for tests that don't need the full mapResolver pattern.
func atResolver(field string, v rule.Value) *scalarResolver {
	return &scalarResolver{values: map[string]rule.Value{field: v}}
}

// eventWithStatus builds a plugin.Event whose envelope is empty except for Stream
// (used by some rules to anchor on core.stream). Tests that gate on HTTP fields
// only do not need the envelope populated.
func eventWithStatus() *plugin.Event {
	return &plugin.Event{
		Envelope: plugin.Envelope{Stream: "main"},
	}
}

// ========================== 1. Add compile error =================================================

// TestRuleSet_AddCompileError verifies that Add with a malformed expression returns
// an error AND does NOT store the rule. The atomicity invariant is the whole point
// of compileExpr-then-store; this test guards it.
func TestRuleSet_AddCompileError(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	// Malformed: unknown field `http.bogus`. Compiler returns CompileError.
	err := rs.Add("bad", "http.bogus eq 200")
	if err == nil {
		t.Fatalf("expected compile error, got nil")
	}
	if !strings.Contains(err.Error(), "compile error") &&
		!strings.Contains(err.Error(), "unknown_field") {
		t.Errorf("error does not mention compile/unknown_field; got %v", err)
	}

	// No rule stored. Rules() returns empty slice.
	rs.mu.RLock()
	gotRules := len(rs.rules)
	rs.mu.RUnlock()
	if gotRules != 0 {
		t.Errorf("expected 0 rules after failed Add, got %d", gotRules)
	}

	// Sanity: a valid rule on the same RuleSet still adds cleanly after the
	// failed one. Atomicity at the slot level: failure of slot N must not poison
	// slot N+1.
	if err := rs.Add("good", "http.status eq 200"); err != nil {
		t.Fatalf("Add after failed Add: unexpected error %v", err)
	}
	if got := rs.Rules(); len(got) != 1 || got[0].Name != "good" {
		t.Errorf("Rules(): want [{good ...}], got %v", got)
	}
}

// ========================== 2. Add duplicate name ================================================

// TestRuleSet_AddDuplicate verifies that adding the same name twice returns
// ErrRuleExists on the second call and does NOT silently overwrite the first.
// This is the operator-facing guarantee: "if I typo'd my config, the rule engine
// rejects the duplicate, it doesn't silently drop my working rule on the floor".
func TestRuleSet_AddDuplicate(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	if err := rs.Add("first", "http.status eq 200"); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := rs.Add("first", "http.status eq 404")
	if err == nil {
		t.Fatalf("expected ErrRuleExists on duplicate, got nil")
	}
	if err != ErrRuleExists {
		t.Errorf("expected ErrRuleExists, got %v", err)
	}

	// The first rule is still there with its original expression.
	got := rs.Rules()
	if len(got) != 1 {
		t.Fatalf("Rules(): want 1 rule, got %d", len(got))
	}
	if got[0].Name != "first" || got[0].Expression != "http.status eq 200" {
		t.Errorf("Rules(): first rule was clobbered: %+v", got[0])
	}
}

// ========================== 3. Remove happy path =================================================

// TestRuleSet_Remove verifies that Add → Remove → Match does not fire the removed
// rule. This is the lifecycle contract: an operator removing a rule expects
// downstream traffic to stop seeing it in verdicts immediately.
func TestRuleSet_Remove(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	if err := rs.Add("removable", "http.status eq 200"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Sanity: rule fires before removal.
	resolver := atResolver("http.status", rule.NewInt(200))
	if name, ok := rs.Match(eventWithStatus(), resolver); !ok || name != "removable" {
		t.Fatalf("pre-remove Match: want {removable, true}, got {%q, %v}", name, ok)
	}

	rs.Remove("removable")

	// Rule gone: Match returns ("", false).
	if name, ok := rs.Match(eventWithStatus(), resolver); ok || name != "" {
		t.Errorf("post-remove Match: want {\"\", false}, got {%q, %v}", name, ok)
	}

	// Rules() confirms.
	if got := rs.Rules(); len(got) != 0 {
		t.Errorf("Rules() after Remove: want empty, got %v", got)
	}
}

// ========================== 4. Remove on absent name (no-op) =====================================

// TestRuleSet_RemoveNotFound verifies that Remove on a non-existent name is a true
// no-op. No panic, no error, no state mutation. This is the idempotent-admin
// guarantee: a configuration reload that issues Remove twice must not crash.
func TestRuleSet_RemoveNotFound(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	if err := rs.Add("present", "http.status eq 200"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Should not panic, should not error (no return value).
	rs.Remove("never_existed")
	rs.Remove("present") // first removal is the real one
	rs.Remove("present") // second removal is the no-op path we're testing

	// Rule was removed by the first call, second was a no-op, never_existed
	// was always a no-op. Final state: empty.
	if got := rs.Rules(); len(got) != 0 {
		t.Errorf("Rules() after sequence of Removes: want empty, got %v", got)
	}
}

// ========================== 5+6. Replace existing rule (atomicity) ================================

// TestRuleSet_ReplaceAtomicity is the central atomicity test for Replace. Two
// halves, distinct from each other:
//
//   - VALID expression: swap succeeds, NEW rule fires, OLD expression no longer
//     produces a match.
//   - INVALID expression: compile error returned, OLD rule stays in place AND
//     STILL fires (D13: "compile error returned, old rule keeps firing").
func TestRuleSet_ReplaceAtomicity(t *testing.T) {
	t.Run("valid_expression_swaps_and_new_fires", func(t *testing.T) {
		rs, _ := newWafRuleSet(t)
		if err := rs.Add("r", "http.status eq 200"); err != nil {
			t.Fatalf("Add: %v", err)
		}

		resolver200 := atResolver("http.status", rule.NewInt(200))
		resolver404 := atResolver("http.status", rule.NewInt(404))

		// Pre-Replace: rule fires for 200 only.
		if _, ok := rs.Match(eventWithStatus(), resolver200); !ok {
			t.Fatalf("pre-replace: rule should fire for 200")
		}
		if _, ok := rs.Match(eventWithStatus(), resolver404); ok {
			t.Fatalf("pre-replace: rule should NOT fire for 404")
		}

		// Swap to 404-matches.
		if err := rs.Replace("r", "http.status eq 404"); err != nil {
			t.Fatalf("Replace with valid expr: %v", err)
		}

		// Post-Replace: rule fires for 404 only.
		if _, ok := rs.Match(eventWithStatus(), resolver200); ok {
			t.Errorf("post-replace: rule should NOT fire for 200")
		}
		if _, ok := rs.Match(eventWithStatus(), resolver404); !ok {
			t.Errorf("post-replace: rule should fire for 404")
		}

		// Rules() reflects the new expression.
		got := rs.Rules()
		if len(got) != 1 || got[0].Expression != "http.status eq 404" {
			t.Errorf("Rules(): expected {r, http.status eq 404}, got %+v", got)
		}
	})

	t.Run("invalid_expression_keeps_old_rule_firing", func(t *testing.T) {
		rs, _ := newWafRuleSet(t)
		if err := rs.Add("r", "http.status eq 200"); err != nil {
			t.Fatalf("Add: %v", err)
		}

		resolver200 := atResolver("http.status", rule.NewInt(200))

		// Snapshot counter before the failed Replace.
		statsBefore := rs.Stats()
		countBefore := statsBefore["r"]

		// Try to swap to a malformed expression. Unknown field → compile error.
		err := rs.Replace("r", "http.does_not_exist eq 200")
		if err == nil {
			t.Fatalf("expected compile error, got nil")
		}

		// OLD RULE STILL FIRES — atomicity invariant.
		name, ok := rs.Match(eventWithStatus(), resolver200)
		if !ok || name != "r" {
			t.Errorf("post-failed-replace Match: want {r, true}, got {%q, %v}", name, ok)
		}

		// Old expression unchanged in Rules().
		got := rs.Rules()
		if len(got) != 1 || got[0].Expression != "http.status eq 200" {
			t.Errorf("Rules() after failed Replace: expected original expr preserved, got %+v", got[0])
		}

		// Counter incremented by the post-failed-replace Match (we just made it fire once).
		countAfter := rs.Stats()["r"]
		if countAfter != countBefore+1 {
			t.Errorf("counter: expected %d (before+1), got %d", countBefore+1, countAfter)
		}
	})
}

// ========================== 7. Replace on absent name ============================================

// TestRuleSet_ReplaceNotFound verifies that Replace on a missing name returns
// ErrRuleNotFound and does NOT add the rule. Documented semantics: Replace is a
// swap, not an upsert — see ErrRuleNotFound's doc comment.
func TestRuleSet_ReplaceNotFound(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	err := rs.Replace("ghost", "http.status eq 200")
	if err == nil {
		t.Fatalf("expected ErrRuleNotFound, got nil")
	}
	if err != ErrRuleNotFound {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}

	// No rule was added.
	if got := rs.Rules(); len(got) != 0 {
		t.Errorf("Rules() after failed Replace: want empty, got %v", got)
	}
}

// ========================== 8. Match first-wins ===================================================

// TestRuleSet_MatchFirstWins verifies the linear-walk, first-match semantics of
// RuleSet.Match. Two rules both match the same event; the first-added wins, the
// second is short-circuited and its counter stays at zero.
//
// This guards the D12 contract: "first rule to return true" — and the consequence
// of first-wins, namely counter ordering, which Stats() dashboards will rely on.
func TestRuleSet_MatchFirstWins(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	// Both rules fire on status=200; first added wins.
	if err := rs.Add("first", "http.status eq 200"); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	if err := rs.Add("second", "http.status eq 200"); err != nil {
		t.Fatalf("Add second: %v", err)
	}

	resolver := atResolver("http.status", rule.NewInt(200))

	name, ok := rs.Match(eventWithStatus(), resolver)
	if !ok || name != "first" {
		t.Fatalf("Match: want {first, true}, got {%q, %v}", name, ok)
	}

	// Run Match many times to make sure the second rule's counter never moves
	// despite many first-rule wins.
	for i := 0; i < 50; i++ {
		if _, ok := rs.Match(eventWithStatus(), resolver); !ok {
			t.Fatalf("Match iter %d should have fired", i)
		}
	}

	stats := rs.Stats()
	if stats["first"] != 51 {
		t.Errorf("first counter: want 51, got %d", stats["first"])
	}
	if stats["second"] != 0 {
		t.Errorf("second counter: want 0 (first-wins short-circuit), got %d", stats["second"])
	}
}

// ========================== 9. Stats =================================================================

// TestRuleSet_Stats verifies per-rule match counts add up. Three rules, three
// distinct match conditions, verify each counter individually and the combined map.
func TestRuleSet_Stats(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	if err := rs.Add("by_status", "http.status eq 200"); err != nil {
		t.Fatalf("Add by_status: %v", err)
	}
	if err := rs.Add("by_method", `http.method eq "GET"`); err != nil {
		t.Fatalf("Add by_method: %v", err)
	}
	if err := rs.Add("by_uri", `http.uri contains "admin"`); err != nil {
		t.Fatalf("Add by_uri: %v", err)
	}

	// First rule fires 3 times.
	resStatus := atResolver("http.status", rule.NewInt(200))
	for i := 0; i < 3; i++ {
		if _, ok := rs.Match(eventWithStatus(), resStatus); !ok {
			t.Fatalf("by_status iter %d should fire", i)
		}
	}

	// Second rule (registered second) never matches because the first always
	// wins for our event. So we exercise it via a separate event where by_status
	// does NOT match.
	resMethod := &scalarResolver{values: map[string]rule.Value{
		"http.status": rule.NewInt(404),
		"http.method": rule.NewString("GET"),
	}}
	if _, ok := rs.Match(eventWithStatus(), resMethod); !ok {
		t.Fatalf("by_method should fire on 404+GET")
	}

	// Third rule needs uri containing "admin".
	resURI := &scalarResolver{values: map[string]rule.Value{
		"http.status": rule.NewInt(404),
		"http.method": rule.NewString("POST"),
		"http.uri":    rule.NewString("/admin/login"),
	}}
	for i := 0; i < 2; i++ {
		if _, ok := rs.Match(eventWithStatus(), resURI); !ok {
			t.Fatalf("by_uri iter %d should fire", i)
		}
	}

	stats := rs.Stats()
	if stats["by_status"] != 3 {
		t.Errorf("by_status: want 3, got %d", stats["by_status"])
	}
	if stats["by_method"] != 1 {
		t.Errorf("by_method: want 1, got %d", stats["by_method"])
	}
	if stats["by_uri"] != 2 {
		t.Errorf("by_uri: want 2, got %d", stats["by_uri"])
	}
	if len(stats) != 3 {
		t.Errorf("Stats() map size: want 3, got %d (%v)", len(stats), stats)
	}
}

// ========================== 10. Rules snapshot ====================================================

// TestRuleSet_Rules verifies the snapshot semantics: Rules() returns a freshly
// allocated slice; mutating the RuleSet after a Rules() call does not retroactively
// change the captured result. This is the explicit "snapshot, not live ref"
// contract from D13.
func TestRuleSet_Rules(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	if err := rs.Add("one", "http.status eq 200"); err != nil {
		t.Fatalf("Add one: %v", err)
	}
	if err := rs.Add("two", "http.status eq 404"); err != nil {
		t.Fatalf("Add two: %v", err)
	}

	snap := rs.Rules()
	if len(snap) != 2 {
		t.Fatalf("snapshot size: want 2, got %d", len(snap))
	}
	if snap[0].Name != "one" || snap[1].Name != "two" {
		t.Errorf("snapshot ordering: want [one, two], got %v", snap)
	}

	// Mutate RuleSet after snapshot.
	if err := rs.Add("three", "http.status eq 500"); err != nil {
		t.Fatalf("Add three: %v", err)
	}
	rs.Remove("one")

	// Snapshot is unaffected.
	if len(snap) != 2 {
		t.Errorf("snapshot mutated: size want 2, got %d", len(snap))
	}
	if snap[0].Name != "one" || snap[1].Name != "two" {
		t.Errorf("snapshot mutated: order/contents want [one, two], got %v", snap)
	}

	// Live Rules() reflects the mutation.
	live := rs.Rules()
	if len(live) != 2 || live[0].Name != "two" || live[1].Name != "three" {
		t.Errorf("live Rules(): want [two, three], got %v", live)
	}

	// Defensive: caller can mutate their snapshot freely without affecting RuleSet.
	snap[0].Name = "MUTATED"
	if rs.Rules()[0].Name == "MUTATED" {
		t.Errorf("Rules() aliased into snapshot — caller mutation leaked into RuleSet")
	}
}

// ========================== 11. Concurrent — race detector =========================================

// TestRuleSet_Concurrent exercises the entire concurrency surface: many goroutines
// doing Add / Remove / Replace on a writer side, many goroutines doing Match on a
// reader side. The race detector must report zero races; the test must not panic.
//
// The TestRuleSet_* tests above cover the per-call semantics. This test is the
// canonical race-detector exercise — without RWMutex + atomic counters in the
// right places, running this under `go test -race` reports a violation.
func TestRuleSet_Concurrent(t *testing.T) {
	rs, _ := newWafRuleSet(t)

	// Pre-seed a few rules so the matching goroutines have something to evaluate.
	// (Even when the writer goroutine later removes them, the test covers both
	// the "rules present" and "rules absent" Match paths.)
	if err := rs.Add("seed_a", "http.status eq 200"); err != nil {
		t.Fatalf("Add seed_a: %v", err)
	}
	if err := rs.Add("seed_b", "http.status eq 404"); err != nil {
		t.Fatalf("Add seed_b: %v", err)
	}

	// Stable resolver for the reader side. The reader goroutines fire Match with
	// this resolver against a stream of status values; some match, some do not.
	// The point is to exercise the read-side RLock + counter path heavily without
	// coupling to a particular writer state.
	type pair struct {
		status   int
		resolver *scalarResolver
	}
	pairs := []pair{
		{200, atResolver("http.status", rule.NewInt(200))},
		{404, atResolver("http.status", rule.NewInt(404))},
		{500, atResolver("http.status", rule.NewInt(500))},
	}

	const (
		writers         = 4
		writesPerWriter = 200
		readers         = 4
		readsPerReader  = 5000
	)

	var wg sync.WaitGroup
	var stop atomic.Bool

	// Writer side: cycle through Add (different name each time) and occasional
	// Remove / Replace. Use distinct names so Add succeeds; cycle through a
	// rotating set of names so Remove has targets sometimes present.
	writerNames := make([]string, writesPerWriter)
	for i := range writerNames {
		writerNames[i] = "rule_" + strconv.Itoa(i)
	}

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			for i := 0; i < writesPerWriter && !stop.Load(); i++ {
				name := writerNames[(wID*writesPerWriter+i)%len(writerNames)]
				expr := "http.status eq 200" // all expressions are equivalent here
				switch i % 5 {
				case 0:
					_ = rs.Add(name, expr) // may collide; that's fine
				case 1:
					rs.Remove(name)
				case 2:
					_ = rs.Replace(name, expr) // may collide; that's fine
				case 3:
					_ = rs.Add(name+strconv.Itoa(wID), expr)
				case 4:
					_ = rs.Replace(name, "http.status eq 404") // different valid expression
				}
			}
		}(w)
	}

	// Reader side: spin Match against rotating resolvers, also call Rules() and
	// Stats() intermittently so the read paths are exercised too.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < readsPerReader && !stop.Load(); i++ {
				p := pairs[i%len(pairs)]
				_, _ = rs.Match(eventWithStatus(), p.resolver)
				// Occasional snapshot reads. Make sure these don't race with
				// the writers.
				if i%17 == 0 {
					_ = rs.Rules()
				}
				if i%23 == 0 {
					_ = rs.Stats()
				}
			}
		}()
	}

	wg.Wait()

	// Post-condition: zero panics, zero races. The actual *numbers* in Stats()
	// are not deterministic (depends on writer race outcomes), but the call
	// itself must not deadlock or panic.
	finalStats := rs.Stats()
	if len(finalStats) > writesPerWriter*writers {
		t.Errorf("Stats() map larger than possible: got %d", len(finalStats))
	}
}
