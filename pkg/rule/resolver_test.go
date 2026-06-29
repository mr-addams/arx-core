// ========================== pkg/rule — FieldResolver tests ================================
//   Sanity-coverage suite for FieldResolver and EnvelopeResolver. Verifies the D3 contract
//   end-to-end: nil-event safety, namespace gating, unknown-field signalling, and correct
//   typing for every Envelope field. Comprehensive coverage (concurrent resolvers, deep
//   plugin-side scenarios) lives in Group F — Task F1.

package rule

import (
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// fixedNow matches the fixedNow anchor in types_test.go so a future merge of the
// test files keeps RFC3339Nano output deterministic.
var resolverFixedNow = time.Date(2026, 6, 25, 12, 34, 56, 789_000_000, time.UTC)

// ========================== FieldResolver interface compliance ===========================

// TestEnvelopeResolver_ImplementsFieldResolver is a compile-time check (the value
// assigned to a FieldResolver variable must be assignable). If the signatures ever
// drift, this fails at compile time, not at the first runtime call site.
func TestEnvelopeResolver_ImplementsFieldResolver(t *testing.T) {
	var _ FieldResolver = EnvelopeResolver{}
}

// ========================== Envelope field coverage (table-driven) ========================

// TestEnvelopeResolver_Resolve_CoreFields covers every core.* field end-to-end:
// correct Kind, correct payload, and correct bool return. The table doubles as
// documentation of the canonical mapping (DECISION D5) — Envelope Timestamp maps
// to KindTimestamp, Envelope string fields map to KindString.
func TestEnvelopeResolver_Resolve_CoreFields(t *testing.T) {
	env := plugin.Envelope{
		Timestamp:  resolverFixedNow,
		Stream:     "main",
		Source:     "file:/var/log/app.log",
		SourceType: "file",
		Level:      "INFO",
	}
	event := &plugin.Event{Envelope: env}

	resolver := EnvelopeResolver{}

	cases := []struct {
		name string
		want Value
	}{
		{
			name: "core.timestamp",
			want: NewTimestamp(resolverFixedNow),
		},
		{
			name: "core.stream",
			want: NewString("main"),
		},
		{
			name: "core.source",
			want: NewString("file:/var/log/app.log"),
		},
		{
			name: "core.source_type",
			want: NewString("file"),
		},
		{
			name: "core.level",
			want: NewString("INFO"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolver.Resolve(tc.name, event)
			if !ok {
				t.Fatalf("Resolve(%q) returned ok=false, want true", tc.name)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("Resolve(%q) = %s (kind=%s), want %s (kind=%s)",
					tc.name, got.String(), got.Kind(), tc.want.String(), tc.want.Kind())
			}
			// Kind-level guard: a wrong-typed Value that happens to stringify the
			// same way would still slip past Equal for some Kinds; the Kind check
			// is the stricter contract.
			if got.Kind() != tc.want.Kind() {
				t.Fatalf("Resolve(%q).Kind() = %s, want %s",
					tc.name, got.Kind(), tc.want.Kind())
			}
		})
	}
}

// TestEnvelopeResolver_Resolve_KindMapping pins each core.* field to its
// dedicated Kind per DECISION D5. The cases above already check Kind via Equal;
// this test makes the Kind table readable as documentation in isolation.
func TestEnvelopeResolver_Resolve_KindMapping(t *testing.T) {
	event := &plugin.Event{
		Envelope: plugin.Envelope{
			Timestamp:  resolverFixedNow,
			Stream:     "s",
			Source:     "src",
			SourceType: "file",
			Level:      "INFO",
		},
	}
	resolver := EnvelopeResolver{}

	cases := []struct {
		field string
		want  Kind
	}{
		{"core.timestamp", KindTimestamp},
		{"core.stream", KindString},
		{"core.source", KindString},
		{"core.source_type", KindString},
		{"core.level", KindString},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			got, ok := resolver.Resolve(tc.field, event)
			if !ok {
				t.Fatalf("Resolve(%q) returned ok=false", tc.field)
			}
			if got.Kind() != tc.want {
				t.Fatalf("Resolve(%q).Kind() = %s, want %s", tc.field, got.Kind(), tc.want)
			}
		})
	}
}

// ========================== Negative cases — D3 contract enforcement ====================

// TestEnvelopeResolver_Resolve_NilEvent verifies the nil-event contract: must NOT
// panic, must return (Value{}, false). Without this, every call site has to nil-guard.
func TestEnvelopeResolver_Resolve_NilEvent(t *testing.T) {
	resolver := EnvelopeResolver{}

	// Use defer/recover to convert a hypothetical panic into a clean test failure.
	// If Resolve panics, the test reports it explicitly rather than crashing the suite.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Resolve panicked on nil event: %v", r)
		}
	}()

	cases := []string{
		"core.timestamp",
		"core.stream",
		"core.source",
		"core.source_type",
		"core.level",
		"core.unknown",
		"http.method", // also nil-event-safe
		"",
	}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			got, ok := resolver.Resolve(field, nil)
			if ok {
				t.Fatalf("Resolve(%q, nil) returned ok=true", field)
			}
			if !got.IsZero() {
				t.Fatalf("Resolve(%q, nil) returned non-zero Value: kind=%s, str=%q",
					field, got.Kind(), got.String())
			}
		})
	}
}

// TestEnvelopeResolver_Resolve_NonCoreNamespace verifies that a field outside the
// core.* namespace falls through with (Value{}, false) — a plugin-owned resolver
// owns its own namespace and must not be confused with EnvelopeResolver.
func TestEnvelopeResolver_Resolve_NonCoreNamespace(t *testing.T) {
	event := &plugin.Event{
		Envelope: plugin.Envelope{Timestamp: resolverFixedNow, Stream: "s"},
	}
	resolver := EnvelopeResolver{}

	cases := []string{
		"http.method",        // arxsentinel-owned namespace (H2)
		"http.status",        // arxsentinel-owned namespace (H2)
		"syslog.facility",    // syslog source-owned namespace
		"custom.field",       // arbitrary plugin-owned namespace
		"core",               // namespace without trailing dot — malformed
		"corex.timestamp",    // prefix collision — must NOT match core.*
		".timestamp",         // leading dot — malformed
		"",                   // empty string
	}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			got, ok := resolver.Resolve(field, event)
			if ok {
				t.Fatalf("Resolve(%q) returned ok=true on non-core field; got kind=%s",
					field, got.Kind())
			}
			if !got.IsZero() {
				t.Fatalf("Resolve(%q) returned non-zero Value on non-core field: %s",
					field, got.String())
			}
		})
	}
}

// TestEnvelopeResolver_Resolve_UnknownCoreField verifies that a core.* field not
// in the Envelope returns (Value{}, false). The Scheme's compile-time check (D6)
// should normally prevent this case; Resolve handles it gracefully anyway.
func TestEnvelopeResolver_Resolve_UnknownCoreField(t *testing.T) {
	event := &plugin.Event{
		Envelope: plugin.Envelope{
			Timestamp:  resolverFixedNow,
			Stream:     "s",
			Source:     "src",
			SourceType: "file",
			Level:      "INFO",
		},
	}
	resolver := EnvelopeResolver{}

	cases := []string{
		"core.unknown_field",
		"core.method",     // looks plausible, not in Envelope
		"core.ip",         // would belong to a plugin, not Envelope
		"core.payload",    // explicitly out of scope (D3 payload opacity)
		"core.size",       // looks like an envelope stat, not declared
	}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			got, ok := resolver.Resolve(field, event)
			if ok {
				t.Fatalf("Resolve(%q) returned ok=true on unknown field; got kind=%s, val=%s",
					field, got.Kind(), got.String())
			}
			if !got.IsZero() {
				t.Fatalf("Resolve(%q) returned non-zero Value on unknown field: %s",
					field, got.String())
			}
		})
	}
}

// TestEnvelopeResolver_Resolve_ZeroEnvelope verifies that all core.* fields
// return the typed zero of their Kind when the Envelope is the zero value (no
// fields populated). This catches accidental nil-handling regressions where a
// resolver might return KindInvalid for a real-but-empty Envelope field.
func TestEnvelopeResolver_Resolve_ZeroEnvelope(t *testing.T) {
	event := &plugin.Event{Envelope: plugin.Envelope{}}
	resolver := EnvelopeResolver{}

	cases := []struct {
		field string
		want  Kind
	}{
		{"core.timestamp", KindTimestamp},
		{"core.stream", KindString},
		{"core.source", KindString},
		{"core.source_type", KindString},
		{"core.level", KindString},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			got, ok := resolver.Resolve(tc.field, event)
			if !ok {
				t.Fatalf("Resolve(%q) returned ok=false on zero envelope", tc.field)
			}
			if got.Kind() != tc.want {
				t.Fatalf("Resolve(%q).Kind() = %s, want %s", tc.field, got.Kind(), tc.want)
			}
			// String fields on a zero Envelope must be "" — empty but typed.
			if tc.want == KindString {
				s, _ := got.AsString()
				if s != "" {
					t.Fatalf("Resolve(%q) on zero envelope = %q, want empty string",
						tc.field, s)
				}
			}
		})
	}
}

// ========================== Payload opacity invariant (D3) ==============================

// TestEnvelopeResolver_Resolve_PayloadNeverRead pins the D3 contract: even when the
// Payload is populated with a non-nil, typed value, EnvelopeResolver must answer
// from the Envelope alone. A field that resolves from Payload would leak plugin
// schema into Core and break the opacity invariant.
func TestEnvelopeResolver_Resolve_PayloadNeverRead(t *testing.T) {
	// Payload carries a typed string that happens to share a name with an
	// Envelope field. If EnvelopeResolver ever reached into Payload, it could
	// pick up "core.level" from there instead of from Envelope.Level.
	event := &plugin.Event{
		Envelope: plugin.Envelope{Level: "INFO"},
		Payload:  "WRONG_PAYLOAD_VALUE",
	}
	resolver := EnvelopeResolver{}

	got, ok := resolver.Resolve("core.level", event)
	if !ok {
		t.Fatalf("Resolve(\"core.level\") returned ok=false")
	}
	if got.Kind() != KindString {
		t.Fatalf("Resolve(\"core.level\").Kind() = %s, want kind string", got.Kind())
	}
	s, _ := got.AsString()
	if s != "INFO" {
		t.Fatalf("Resolve(\"core.level\") = %q, want %q (resolver must read Envelope, not Payload)",
			s, "INFO")
	}
}

// TestEnvelopeResolver_Resolve_PayloadDoesNotCreateFields verifies that core.* fields
// NOT in Envelope remain unresolved even when the Payload carries them. This is
// the contrapositive of TestEnvelopeResolver_Resolve_PayloadNeverRead — a leaked
// resolver could surface payload-named fields as if they were core.* fields.
//
// We deliberately exclude the real Envelope field names (timestamp/stream/source/
// source_type/level) from the probe set: those resolve from Envelope by design.
// What we want to catch is "core.<payload-only-key>" resolving from Payload.
func TestEnvelopeResolver_Resolve_PayloadDoesNotCreateFields(t *testing.T) {
	// Payload keys that do NOT correspond to any Envelope field. If any of
	// these resolve, the resolver has reached into Payload.
	payloadOnlyKeys := []string{
		"method",
		"path",
		"query",
		"client_ip",
		"user_agent",
	}
	payload := make(map[string]any, len(payloadOnlyKeys))
	for _, k := range payloadOnlyKeys {
		payload[k] = "should-never-be-read"
	}
	event := &plugin.Event{
		Envelope: plugin.Envelope{},
		Payload:  payload,
	}
	resolver := EnvelopeResolver{}

	for _, key := range payloadOnlyKeys {
		resolvedName := "core." + key
		t.Run(resolvedName, func(t *testing.T) {
			got, ok := resolver.Resolve(resolvedName, event)
			if ok {
				t.Fatalf("Resolve(%q) returned ok=true; EnvelopeResolver leaked Payload data: %s",
					resolvedName, got.String())
			}
			if !got.IsZero() {
				t.Fatalf("Resolve(%q) returned non-zero Value; possible Payload leak: %s",
					resolvedName, got.String())
			}
		})
	}
}

// ========================== Interface contract surface ===================================

// TestFieldResolver_Resolve_NeverPanics fuzzes the contract boundary: arbitrary
// inputs must not panic. This is a property-level guard — specific scenarios are
// covered by the named tests above, this catches regressions in the nil/empty
// branches under surprising inputs.
func TestFieldResolver_Resolve_NeverPanics(t *testing.T) {
	resolver := EnvelopeResolver{}
	event := &plugin.Event{Envelope: plugin.Envelope{}}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Resolve panicked on edge-case input: %v", r)
		}
	}()

	inputs := []string{
		"",
		".",
		"..",
		"core",
		"core.",
		".core",
		"core..timestamp",
		"core.timestamp.extra", // extra dot segments are not in our schema
		string([]byte{0x00}),
		"CORE.TIMESTAMP", // case-sensitive: must NOT match
	}
	for _, f := range inputs {
		_, _ = resolver.Resolve(f, event)
		_, _ = resolver.Resolve(f, nil)
	}
}

// ========================== Sanity — resolver is stateless and reusable ==================

// TestEnvelopeResolver_Stateless verifies that the same resolver instance can be
// reused across many calls without state corruption. Two back-to-back Resolve
// calls with different inputs must yield independent, correct results.
func TestEnvelopeResolver_Stateless(t *testing.T) {
	resolver := EnvelopeResolver{}

	eventA := &plugin.Event{Envelope: plugin.Envelope{Level: "INFO", Stream: "a"}}
	eventB := &plugin.Event{Envelope: plugin.Envelope{Level: "WARN", Stream: "b"}}

	gotA1, _ := resolver.Resolve("core.level", eventA)
	gotA2, _ := resolver.Resolve("core.level", eventA)
	gotB, _ := resolver.Resolve("core.level", eventB)

	if !gotA1.Equal(gotA2) {
		t.Fatalf("two resolves of the same event differ: %s vs %s", gotA1.String(), gotA2.String())
	}
	if gotA1.Equal(gotB) {
		t.Fatalf("resolves of different events returned equal values: %s", gotA1.String())
	}
}

// TestEnvelopeResolver_InternalHelpers verifies the package-private helpers
// remain consistent with the documented prefix. A future D7 revision would
// update both in lockstep; this test catches a half-edit.
func TestEnvelopeResolver_InternalHelpers(t *testing.T) {
	if corePrefix != "core." {
		t.Fatalf("corePrefix = %q, want %q", corePrefix, "core.")
	}
	if !isCoreField("core.timestamp") {
		t.Fatalf("isCoreField(\"core.timestamp\") = false, want true")
	}
	if isCoreField("http.method") {
		t.Fatalf("isCoreField(\"http.method\") = true, want false")
	}
	// Prefix-collision guard: "corex" is NOT "core".
	if isCoreField("corex.timestamp") {
		t.Fatalf("isCoreField(\"corex.timestamp\") = true, want false (prefix collision)")
	}
}