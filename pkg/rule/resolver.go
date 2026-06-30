// ========================== pkg/rule — FieldResolver + EnvelopeResolver ===================
//   FieldResolver is the payload-boundary bridge between the rule engine and the plugin
//   world (DECISION D3). The engine never reads plugin.Event.Payload directly; it asks a
//   resolver to look up a field by name. EnvelopeResolver is the Core-owned resolver for
//   the `core.*` namespace — it reads ONLY the Envelope half of an Event and never the
//   Payload (D3 payload opacity invariant).
//
//   WHAT IS HERE:
//     - FieldResolver interface (D3 contract)
//     - EnvelopeResolver — Core-owned implementation for `core.*`
//     - resolveCore — internal dispatch table over Envelope fields
//
//   WHAT IS NOT HERE:
//     - HTTP/syslog/<custom> resolvers — owned by plugins (Group H in arxsentinel)
//     - Compiled-plan dispatch over the resolver — evaluator concern (Group C)
//     - Any non-stdlib dependency (D2)
//
//   DEPENDENCY RULE:
//     pkg/rule → stdlib only, plus sibling arx-core/pkg/plugin for the Event/Envelope
//     boundary. The resolver itself reads only Envelope (a stdlib-friendly value struct)
//     so it does not drag any plugin-side type into the engine.
//
//   CONCURRENCY:
//     EnvelopeResolver is stateless and immutable-by-convention: zero fields, zero
//     synchronization needed. The same instance may be shared across goroutines without
//     coordination. This matches DECISION D4 (zero-alloc, safe-for-concurrent Eval).

package rule

import (
	"strings"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// corePrefix is the namespace prefix owned by Core (DECISION D7). Every field name
// EnvelopeResolver accepts MUST be prefixed with this namespace; any other namespace
// returns (Value{}, false) so the dispatch chain can fall through to a plugin-owned
// resolver without ambiguity.
//
// Single source of truth for the namespace spelling: if D7 is ever revised, this
// is the one edit. strings.CutPrefix uses it as a string literal below; both stay
// in sync by convention (the test TestEnvelopeResolver_InternalHelpers guards against
// a half-edit).
const corePrefix = "core."

// ========================== FieldResolver interface ======================================

// FieldResolver is the payload-boundary bridge between the rule engine and the plugin
// world. The engine calls Resolve(field, event) at evaluation time to fetch a Value
// for a field referenced by a compiled expression. The implementation is owned by
// the namespace owner (Core for `core.*`, each plugin for its own namespace).
//
// Contract (DECISION D3):
//
//   - field is the fully-qualified dotted name as it appeared in the expression,
//     e.g. "core.timestamp" or "http.method". Implementations MUST parse the namespace
//     themselves; the engine does not pre-split.
//   - Resolve MUST return (Value{}, false) for: unknown namespace, unknown field in
//     the namespace, or any kind mismatch the implementation chooses to surface.
//   - Resolve MUST NOT panic on a nil event — return (Value{}, false) instead. This
//     matches the broader pkg/plugin convention that nil events are sentinel values
//     rather than crash triggers.
//   - Resolve MUST NOT inspect event.Payload — only fields owned by the namespace
//     may be read. The Payload opacity invariant (D3) is enforced by convention
//     because the Go type system cannot prevent it.
//   - Resolve should be allocation-conscious on the hot path. A poorly-allocating
//     resolver undoes the zero-alloc guarantees of the compiled evaluator.
type FieldResolver interface {
	Resolve(field string, event *plugin.Event) (Value, bool)
}

// ========================== EnvelopeResolver ==============================================

// EnvelopeResolver is Core's FieldResolver for the `core.*` namespace. It reads the
// Envelope half of an Event (Timestamp, Stream, Source, SourceType, Level) and never
// touches the Payload. The struct carries no state — a single zero-value instance
// may be shared across goroutines and across many RuleSet evaluations.
//
// Usage:
//
//	var resolver rule.FieldResolver = rule.EnvelopeResolver{}
//	v, ok := resolver.Resolve("core.timestamp", event)
//
// EnvelopeResolver is intentionally minimal: it does not cache, does not validate,
// and does not own any lifecycle. If a future requirement adds resolver-level
// configuration, promote it to a struct field rather than a global.
type EnvelopeResolver struct{}

// Compile-time assertion: EnvelopeResolver satisfies the FieldResolver interface.
// If the signature drifts, the build fails here — earlier and louder than at the
// first call site.
var _ FieldResolver = EnvelopeResolver{}

// Resolve implements FieldResolver for the `core.*` namespace.
//
// Behaviour matrix:
//
//   - event == nil                 → (Value{}, false) — no panic, by contract
//   - namespace != "core"          → (Value{}, false) — different resolver's job
//   - field with no namespace dot  → (Value{}, false) — malformed field name
//   - unknown core.<field>         → (Value{}, false) — not a registered Envelope field
//   - known core.<field>           → (typed Value, true) — see resolveCore
//
// The function is intentionally a thin shim around resolveCore so the public
// signature stays trivially testable and the dispatch table stays local.
func (EnvelopeResolver) Resolve(field string, event *plugin.Event) (Value, bool) {
	if event == nil {
		// Contract: nil event is a sentinel, not a crash trigger. Returning the
		// zero Value mirrors the "field unresolved" semantics so callers can treat
		// it uniformly with the unknown-field case.
		return Value{}, false
	}

	// Fast reject for fields outside the core namespace before any string work.
	// Splitting once up-front keeps the hot path branch-light.
	rest, ok := strings.CutPrefix(field, corePrefix)
	if !ok {
		return Value{}, false
	}
	return resolveCore(rest, event)
}

// resolveCore dispatches a namespace-stripped field name to the matching Envelope
// accessor. Each branch wraps the Envelope's typed field in the corresponding
// Value constructor — no payload inspection, no reflection, no allocation beyond
// the Value itself.
//
// Adding a new Envelope field requires:
//  1. Adding the case here.
//  2. Adding a table-driven test case in resolver_test.go.
//  3. (Eventually) Registering the field in the Catalog/Scheme (Group A — Task A3).
//
// The exhaustive switch (rather than a map) keeps resolveCore alloc-free on the
// hot path: a map lookup would require hashing the field name on every Resolve
// call, which a switch on short strings beats easily.
func resolveCore(name string, event *plugin.Event) (Value, bool) {
	switch name {
	case "timestamp":
		return NewTimestamp(event.Timestamp), true
	case "stream":
		return NewString(event.Stream), true
	case "source":
		return NewString(event.Source), true
	case "source_type":
		return NewString(event.SourceType), true
	case "level":
		return NewString(event.Level), true
	default:
		// Unknown core.* field — the Scheme's compile-time check (D6) should have
		// caught this before traffic flows, so reaching here means either a
		// resolver registered for a field the Scheme doesn't know about (a
		// misconfiguration) or a stale expression after a resolver change.
		return Value{}, false
	}
}

// ========================== Internal helpers ==============================================

// isCoreField reports whether a fully-qualified field name belongs to the core.*
// namespace. Package-private helper for future tasks in this package (Scheme
// registration in A3, compile-time validation in C1) to reuse the same prefix
// definition without duplicating the literal.
//
// Not part of the public FieldResolver contract: plugin-owned resolvers answer
// for their own namespace, not this one.
func isCoreField(field string) bool {
	return strings.HasPrefix(field, corePrefix)
}
