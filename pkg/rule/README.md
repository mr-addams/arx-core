# pkg/rule

A universal, payload-agnostic rule expression engine embedded by arx-core
plugins as a library. Inspired by Cloudflare Wirefilter, with own naming and a
richer type system. Stdlib-only.

The engine compiles rule expressions at load time and evaluates them against an
opaque `*plugin.Event` at hot-path time. It returns a boolean verdict only — it
never executes an action on the event, never reads `Event.Payload`, and never
holds state about the traffic it sees. The embedding plugin owns the action and
the payload.

## Status

Phase 1 of Flow 001 is complete: Groups A–F (value system, FieldResolver
boundary, lexer, parser, type-checker / compiler, evaluator, RuleSet, Builder)
are merged into `main` and covered by a comprehensive test suite. Group G ships
last, after the code is green; this README is part of Group G.

The `v0.2.0` tag is the planned Phase 1 release tag. It will be cut after
Group G closes (this README plus `pkg/rule/REFERENCE.md` and the
`cookbook/rule-engine/` entries).

## Why pkg/rule exists

arx-core is product-agnostic. It does not know whether a plugin is a WAF, a
syslog anomaly detector, a rate-limiter, or a domain-specific correlator. Yet
nearly every one of them needs to express conditional logic in configuration:
block if `http.status eq 403 and http.uri.path contains "/admin"`, alert
if `core.level eq "critical"`.

Wirefilter proved the shape: a small predicate language compiled to a typed
plan, evaluated against fields. The arx-core author chose to build an
in-house engine rather than wrap Wirefilter for five concrete reasons:

- Product-agnostic by construction. The Engine sees values, not payload
  types. `FieldResolver` is the only boundary the plugin crosses. Plugins
  control every byte of their payload and decide themselves which fields
  to expose.
- A richer Value type system: bytes (bitwise patterns), timestamps, durations,
  IP + CIDR membership, arrays, and a Map kind for dynamic open-ended payload
  fields (`attrs["tenant_id"] eq "acme"`).
- A two-layer field surface: a process-wide `Catalog` plus per-profile
  `Scheme` projections so a `waf` profile can never reference a `syslog.*`
  field by mistake, and a `syslog` profile cannot accidentally compile an
  `http.*` rule.
- Zero non-stdlib dependencies. The only stdlib pull-in is `regexp` for the
  `matches` operator and `net` for IP / CIDR parsing. Everything else — the
  lexer, the parser, the compiler, the evaluator — is plain Go.
- Clean hand-off of action decisions. The Engine returns a verdict; the
  plugin decides pass, drop, enrich, alert, or route. Plugins that want
  a different action model wire it themselves.

Wirefilter remains the inspiration; arx-core does not pretend otherwise.
Where the surface differs (more Kinds, two-layer field surface, strict no-
coercion typing) the divergence is deliberate and is justified in the
design notes linked below.

## Architecture

### Layer overview

The engine is five layers plus two user-facing helpers. Edges flow top to
bottom at compile time and bottom to top at evaluation time.

```
                +-----------------------+
                |       Catalog         |  process-wide field registry
                | (D6 — global, RWMutex)|
                +----------+------------+
                           |  Project(namespaces...)
                           v
                +-----------------------+
                |        Scheme         |  immutable per-profile projection
                |     (D6, D9 — frozen)  |
                +----------+------------+
                           |  FieldInfo[]
                           v
       +-----------+   NewCompiler    +----------------+
       |  Builder  | ---------------> |    Compiler    |
       |  (E2)     |                  |  (C1, type checker)
       +-----------+                  +-------+--------+
                                                | Plan (typed, immutable)
                                                v
                                       +----------------+
                                       |      Plan      |   Eval / Match
                                       | (C1, C2 — D4)  | ---------
                                       +--------+-------+         |
                                                ^                 v
+-------------+        +-----------+    +--------+-------------+   +-----------+
|   Source    |        |  Parser   |    |   Evaluator (C2)     |   | Verdict   |
|   string    | -----> | Parse(src)|    | Eval(resolver,event) |->| bool only |
+-------------+        +-----------+    +----------------------+   +-----------+
                              ^
                              |
                       +------+------+
                       |    Lexer    |  tokenizer (Token stream)
                       | (B1, D14)   |
                       +-------------+
```

The two user-facing helpers wrap the layers:

- `RuleSet` (subpackage `pkg/rule/ruleset`) is the mutable, thread-safe
  collection of compiled rules bound to a Scheme. It is what an embedding
  plugin embeds. Its public API is `New` / `Add` / `Remove` / `Replace` /
  `Match` / `Rules` / `Stats`.
- `Builder` (subpackage `pkg/rule/builder`) is the fluent helper for
  assembling a `RuleSet` from a field schema. It hides the
  Catalog / Scheme / Compiler construction so a plugin's bootstrap code
  reads as a one-liner per field.

### Catalog ≠ Scheme (D6)

The engine keeps two different field surfaces on purpose.

A `Catalog` is the process-wide registry of every field known to the
engine. It is append-only after startup — there is no `Unregister`. Every
successful `Register` bumps a monotonic `Revision()` counter so that a
compiled plan can detect when the field surface it was compiled against
has changed.

A `Scheme` is an immutable projection of a Catalog, built via
`(*Catalog).Project(namespaces...)`. Once constructed, the Scheme is frozen;
subsequent `Register` calls into the source `Catalog` have no effect on it.

The two-layer model exists because plugins come from different vendors,
declare different namespaces, and a single registry has to keep them all in
one place. The Scheme exists because the engine needs a stable view of
"this profile's allowed fields" — without the projection layer, every
compile would see every field that any loaded plugin ever registered, and a
configuration typo in a `syslog` profile could silently pull in an `http.*`
field that the syslog pipeline does not actually emit.

### Compile-once / eval-many (D4)

A compiled `Plan` is immutable. Once `(*Compiler).Compile` returns, the
plan is self-contained and may be shared across goroutines without
synchronization. This is the "compile once, evaluate many times" invariant.

The hot path — `(*Plan).Eval(resolver, event)` — is allocation-free after
warmup for scalar-only plans. Concretely: a plan containing only literals,
field references, comparison operators, and IP / String equality walks
without a single byte allocated per call. The only allocations the engine
exposes on the hot path are:

- A custom `FieldResolver` that allocates per call. `EnvelopeResolver` for
  `core.*` is alloc-free for non-IP scalars; alloc behaviour is a property
  of the resolver, not the evaluator.
- Plan that contains a `wildcard` op: the pattern compiles lazily via
  `sync.Once` on the first Eval, amortised across subsequent calls.
- Plan that contains `in` over `Array` or `Map` values: those Kinds are
  heap-backed by design.

The contract is verified by benchmarks; see `Performance contract` below.

### FieldResolver as the payload boundary (D3)

The engine never reads `Event.Payload`. It calls `FieldResolver.Resolve`
to ask for a field's value, and the implementation is owned by the
namespace owner (Core for `core.*`, each plugin for its own namespace).

The contract is documented on the interface itself in
`pkg/rule/resolver.go` (see `FieldResolver`). Implementations MUST:
return `(Value{}, false)` for unknown / mismatched / absent fields; not
panic on a `nil` event (sentinels, not crash triggers); and not inspect
`event.Payload` — payload-opacity (D3) is a Go type-system gap, so the
invariant is by convention, not by compiler.

The Core-provided implementation is `EnvelopeResolver`. It is a zero-sized
struct (carries no state) and answers for the five `core.*` fields:
`core.timestamp`, `core.stream`, `core.source`, `core.source_type`,
`core.level`. Plugins that want their own namespaces ship their own
resolver — see `Embedding pkg/rule in a plugin` below.

### Profiles gate field access (D9)

Each plugin declares a profile name (e.g. `waf`, `syslog-anomaly`,
`rate-anomaly`, `generic`). A profile declares which namespaces its rules
are allowed to reference.

The gating happens at `RuleSet` construction: `ruleset.New(catalog, profile)`
internally calls `catalog.Project(profile, "core")`. The resulting
`Scheme` carries only the Envelope fields (always implicit) plus the
fields of the profile's namespace.

Cross-profile references are therefore caught at compile time as
`unknown_field`. A rule that tries to reference `http.uri.path` from a
profile whose Scheme does not include `http` produces
`compile error at line N, col M: field "http.uri.path" is not in the active
scheme [unknown_field]`.

### Action boundary (D12)

The engine is a predicate, not an actor. `(*RuleSet).Match(event, resolver)`
returns `(ruleName string, matched bool)` — the name of the first rule
whose plan returned `true`, or `("", false)` if no rule matched. The
embedding plugin decides what to do with that verdict: pass the event
through, drop it, add a tag, increment a counter, route it down a parallel
sink, or any combination of these.

A plugin that wants richer semantics can call `(*Plan).Eval` directly and
treat the boolean as it pleases. The engine never sees the action.

## Value type system

The engine's universal value carrier is `Value` (defined in
`pkg/rule/types.go`). It is a tagged union selected by the `Kind` enum.
Constructors are defensive-copy by convention; once built, a `Value` is
immutable and may be shared across goroutines without synchronization.

| Kind            | Go backing    | Notes                                                  |
|-----------------|---------------|--------------------------------------------------------|
| `KindString`    | `string`      | Lexer-resolved escape sequences; immutable in Go.      |
| `KindInt`       | `int64`       | Unsigned lexer token; signed conversion by parser.     |
| `KindFloat`     | `float64`     | NaN / Inf preserved; Equal uses bitwise equality.      |
| `KindBool`      | `bool`        | Distinct from `KindInt(0/1)` so `42 == true` is a type |
|                 |               | error.                                                  |
| `KindIP`        | `net.IP`      | CIDR handled at compile time; evaluator supports       |
|                 |               | `IP in IP-CIDR`.                                        |
| `KindBytes`     | `[]byte`      | Hex-decoded from `0x"..."` literals.                   |
| `KindTimestamp` | `time.Time`   | RFC 3339 from `ts"..."` prefix literals.               |
| `KindDuration`  | `time.Duration` | Go-style `1h30m` strings parsed via                |
|                 |               | `time.ParseDuration`.                                   |
| `KindArray`     | `[]Value`     | Heterogeneous element Kinds; used by `in [...]`.       |
| `KindMap`       | `map[string]Value` | Open-ended dynamic payload fields;               |
|                 |               | `attrs["tenant_id"] eq "acme"`.                         |
| `KindInvalid`   | (zero `Value`)| Sentinel for "field unresolved" / Kind zero. NOT equal |
|                 |               | to itself; `Equal(zero, zero) == false`.                |

The canonical `Kind` enum lives in `pkg/rule/types.go` (D5). `FieldType`
(the textual mirror surfaced in `Manifest.FieldDecl.Type`) is a string-
typed alias defined in `pkg/plugin/manifest.go` and re-exported as
`rule.FieldType` from `pkg/rule/scheme.go` — same identity, not just
convertible (D8.1).

## Field namespaces

Field references in the rule language are fully-qualified dotted names
(`http.uri.path`, `syslog.severity`, `core.level`). The namespace before
the first dot is the owner.

- `core.*` — Core-owned. Five fixed fields: `timestamp` (Timestamp),
  `stream` (String), `source` (String), `source_type` (String),
  `level` (String). Always present in every RuleSet's Scheme.
- `http.*` — plugin-owned. Declared by an HTTP-aware plugin (the
  arxsentinel WAF) in its `Manifest.Produces`. http-typed fields are
  registered by the plugin into the engine's shared `Catalog` at
  bootstrap time.
- `syslog.*` — plugin-owned. Same story, declared by a syslog source.
- `<custom>.*` — any plugin can own a namespace; the engine imposes
  no namespace vocabulary beyond "lowercase, non-empty, no dots".

The convention (D7) is enforced at registration: `(*Catalog).Register`
rejects fields without a namespace prefix (`ErrEmptyNamespace`), with
malformed namespaces (`ErrInvalidNamespace`), or with malformed names
(`ErrInvalidName`). Duplicate registrations with the same type return
`ErrFieldExists`; with a different type return `ErrFieldTypeMismatch`.

## Expression language — quick tour

The closed operator set is fixed by the lexer (D14) and the compiler (C1).
Programs are a constant token set plus a free-form identifier grammar
(`http.uri.path`) and three prefix-string literal forms (`ts"..."`,
`ip"..."`, `0x"..."`).

| Operator keyword | Meaning                                             |
|------------------|-----------------------------------------------------|
| `eq`, `ne`       | Equality / inequality.                              |
| `lt`, `le`,      | Ordering. Both operands must be Orderable.          |
| `gt`, `ge`       |                                                     |
| `and`, `or`,     | Logical composition and negation.                   |
| `not`            |                                                     |
| `in`             | Set membership. Right side is an array literal.     |
| `contains`       | Substring test. Both operands must be String.       |
| `starts_with`    | Prefix test. Both operands must be String.          |
| `ends_with`      | Suffix test. Both operands must be String.          |
| `matches`        | Regex match. Right operand must be a string literal |
|                  | containing the regex pattern; pattern is compiled   |
|                  | at compile time.                                    |
| `wildcard`       | Shell-glob-style match: `?` (any single char), `*`  |
|                  | (any sequence). Pattern is a string literal.        |
| `strict`         | Modifier keyword. v1 is strict-typed by default;    |
|                  | the marker is preserved in the Plan for future      |
|                  | semantics.                                          |

Booleans `true` and `false` are reserved as bare tokens (TBool, not
TKeyword), so a name like `http.eq` is an identifier, not a comparison
keyword collision.

Literal forms:

```text
"plain string"                  → KindString, with backslash escapes
42                               → KindInt (unsigned; sign is parser-side)
3.14                             → KindFloat
true / false                     → KindBool
1h30m                            → KindDuration (Go duration grammar)
ts"2026-06-29T10:00:00Z"         → KindTimestamp (RFC 3339)
ip"10.0.0.0/8"                   → KindIP (CIDR — evaluator does IP-in-CIDR match)
0x"deadbeef"                     → KindBytes (hex-decoded)
```

The list above is the v1 set. The full operator / function / type reference
table — including type-rule edge cases (IP `eq` CIDR, `strict` placement,
`in` over arrays of mixed Kinds) — lives in `pkg/rule/REFERENCE.md`. The
runnable recipes (WAF-style rules, syslog anomaly rules, custom-plugin
resolver wiring) live under `cookbook/rule-engine/`.

Realistic rule examples:

```text
# WAF: block obvious probes
http.uri.path contains "/.env" or http.uri.path contains "/wp-admin"

# WAF: deny access from internal ranges to admin endpoints
http.uri.path starts_with "/admin" and ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"]

# WAF: match specific HTTP status signatures
http.status eq 403 and not http.user_agent contains "Mozilla"

# Severity-gated syslog triage
syslog.severity le 3 and core.source_type eq "syslog"

# Time-windowed rule (timestamp >= a fixed wall clock)
core.timestamp ge ts"2026-06-01T00:00:00Z"
```

## Quick start

This is a copy-pasteable snippet. It uses only the public API of
`pkg/rule/builder`, `pkg/rule/ruleset`, and `pkg/rule/`. Save as
`quickstart_test.go` next to a Go module that imports
`github.com/mr-addams/arx-core`, and `go test` should compile and pass.

```go
package quickstart_test

import (
    "testing"
    "time"

    "github.com/mr-addams/arx-core/pkg/plugin"
    "github.com/mr-addams/arx-core/pkg/rule"
    "github.com/mr-addams/arx-core/pkg/rule/builder"
)

// quickStart exercises the minimum surface of pkg/rule:
// build a RuleSet via Builder, add two rules, evaluate an event.
func quickStart(t *testing.T) {
    // Builder.New("example") implicitly registers core.{timestamp,stream,
    // source,source_type,level} and accepts declarations for one profile
    // namespace ("example"). Profiles() adds additional namespaces.
    rs, err := builder.New("example").
        Field("example", "tenant", rule.TypeString).
        Field("example", "attempts", rule.TypeInt).
        Profiles("audit").
        CompileRules(map[string]string{
            "stream_filter": `core.stream eq "main"`,
            "tenant_alert":  `example.tenant eq "acme" or example.attempts gt 5`,
        })
    if err != nil {
        t.Fatalf("builder: %v", err)
    }

    // Real resolvers live in plugins; the test composes a tiny two-namespace
    // resolver covering both the core.* (via EnvelopeResolver) and example.*
    // fields. EnvelopeResolver{} is stateless and goroutine-safe.
    var resolver rule.FieldResolver = exampleResolver{
        core:    rule.EnvelopeResolver{},
        tenant:  "acme",
        attempts: 7,
    }

    ev := &plugin.Event{
        Envelope: plugin.NewEnvelope("main", "stdin", "test", "info",
            time.Now()),
        Payload: nil, // engine never reads this — opaque to the embedding plugin
    }

    name, matched := rs.Match(ev, resolver)
    t.Logf("matched=%v name=%q", matched, name) // matches "tenant_alert"
}

type exampleResolver struct {
    core      rule.EnvelopeResolver
    tenant    string
    attempts  int64
}

func (r exampleResolver) Resolve(field string, _ *plugin.Event) (rule.Value, bool) {
    // core.* is delegated to the embedded EnvelopeResolver, which holds the
    // canonical mapping for the five transport-metadata fields.
    if len(field) >= 5 && field[:5] == "core." {
        return r.core.Resolve(field, nil)
    }
    switch field {
    case "example.tenant":
        return rule.NewString(r.tenant), true
    case "example.attempts":
        return rule.NewInt(r.attempts), true
    }
    return rule.Value{}, false
}
```

The example registers two rules and constructs an event whose
`core.stream == "main"` and whose `example.attempts == 7`. Because
`Match` walks the rule slice in registration order and stops at the first
predicate that returns true (D12), the `"stream_filter"` rule wins: its
expression is `core.stream eq "main"`, which is true for the event, so
`Match` returns `("stream_filter", true)` without evaluating
`"tenant_alert"`. The embedded snippet is intentionally minimal — its
purpose is to anchor the API surface, not to be a load-bearing fixture.

For plugin-shaped event sources (a WAF processor, a syslog source), the
plugin ships its own `FieldResolver` for its namespace; the embedding
test then composes that resolver with `EnvelopeResolver` to cover both
sides.

## Embedding pkg/rule in a plugin

A plugin that wants its rules to be evaluated by the engine does three
things at bootstrap time:

1. **Declare fields in the Manifest.** Each field is a `FieldDecl` on
   `Manifest.Produces` (for fields the plugin emits) or
   `Manifest.Consumes` (for fields it needs from upstream). Set
   `FieldDecl.Type` to the matching `FieldType` constant (`TypeString`,
   `TypeInt`, `TypeIP`, etc.). The zero value (`""`) means "untyped
   legacy field" — the engine ignores it; opt in explicitly to make the
   field visible to a Scheme.

2. **Register fields into the shared `Catalog`.** Iterate over the
   Manifest's `Produces` and call `(*Catalog).Register("http", decl.Name,
   decl.Type)`. The Catalog enforces namespace convention (D7): lowercase
   names, dots only as the namespace / name separator, and no duplicate
   registrations.

3. **Ship a `FieldResolver`.** The plugin owns a struct that implements
   `rule.FieldResolver`. `Resolve` looks up the field in the plugin's
   payload, wraps the answer in the appropriate `rule.NewXxx`
   constructor, and returns `(value, true)`. Unknown fields and `nil`
   events return `(rule.Value{}, false)`.

The engine never imports the plugin, and the plugin never imports the
internals of the engine — the contract on both sides is a few signatures
and a handful of constants. See `pkg/plugin/manifest.go` for the
`FieldDecl.Type` extension point (D8), `pkg/rule/resolver.go` for the
`FieldResolver` contract (D3), and the cookbook entries under
`cookbook/rule-engine/` for annotated examples of declaring Manifest
fields, registering a FieldResolver, and compiling rules.

## Performance contract

The hot path is `(*Plan).Eval(resolver, event)` (C2). Contract (D4):

- After warmup (a few initial calls), scalar-only plans achieve
  `0 allocs/op`.
- A plan containing a `wildcard` op amortises the lazy regex compile
  across all subsequent calls (via `sync.Once`).
- The cost of a custom `FieldResolver` is the resolver's responsibility,
  not the engine's. `EnvelopeResolver` for `core.*` fields is
  allocation-free for non-IP scalars.

Benchmarks live in `pkg/rule/compiler/eval_test.go`:

- `BenchmarkEval_ScalarPlan` — kind-int comparison (e.g. `http.status eq 200`).
- `BenchmarkEval_ScalarPlan_String` — kind-string comparison.
- `BenchmarkEval_ComplexPlan` — range check + contains substring check.

All three bench plans sit at `0 B/op` on `go 1.26 / linux-amd64`. Re-run
the benchmarks after touching the evaluator; a regression here is a D4
contract violation.

## Out of scope (v1)

These are deliberate non-features for Phase 1 (per the decisions
listed in [References](#references) below). Adding them requires an
architectural review, not a code change.

- **Rate-limiting, windowed aggregation, stateful detectors (D10).**
  The engine evaluates a single event against a snapshot of rules; it
  does not track traffic across events and does not produce "matches
  per second" semantics. A future flow will introduce a separate
  aggregation / state layer; do not couple it to `pkg/rule`.
- **Action execution (D12).** The engine returns a predicate verdict;
  the plugin decides what to do with it. There is no `pass` / `drop` /
  `tag` keyword in the rule language and there will not be one in v1.
- **Negative numeric literals (D15).** Bare `-42` / `-3.14` are not
  tokenised; the lexer emits only unsigned `TInt` / `TFloat`, and there
  is no `TMinus` token in v1. Unary negation on field references or
  literals is deferred to a future extension (lexer enum change), not
  supported in v1.
- **HTTP-specific field names in `pkg/rule` (D7).** `http.*` fields are
  owned by the arxsentinel WAF plugin, not by Core. The engine imposes
  no vocabulary beyond the namespace convention; HTTP shapes live in
  the plugin that produces them.
- **External (non-stdlib) dependencies (D2).** The only stdlib
  dependencies the engine pulls in are `net` (for IP / CIDR parsing) and
  `regexp` (for `matches`). No third-party parser, no third-party regex
  engine.

## References

- [`pkg/rule/REFERENCE.md`](./REFERENCE.md) — full operator / function /
  type reference table (Group G, Task G2).
- `cookbook/rule-engine/` — runnable cookbook recipes for WAF, syslog,
  rate-profile, and a custom-plugin wiring example (Group G, Task G3).
- [`.opencode/flows/001_2026-06-25_universal-rule-engine/DECISIONS.md`](../../.opencode/flows/001_2026-06-25_universal-rule-engine/DECISIONS.md) —
  the architectural decision records that govern the engine.
- [`pkg/plugin/manifest.go`](../plugin/manifest.go) — `FieldDecl.Type`,
  the integration point between a plugin's Manifest and the rule engine.
- [`pkg/plugin/event.go`](../plugin/event.go), [`pkg/plugin/envelope.go`](../plugin/envelope.go) —
  the Event / Envelope contract that `FieldResolver.Resolve` operates on.

## Changelog

| Version     | Status   | Notes                                                           |
|-------------|----------|-----------------------------------------------------------------|
| `v0.2.0`    | Planned  | Phase 1 complete: Groups A–F (value system, FieldResolver,      |
|             |          | lexer, parser, compiler, evaluator, RuleSet, Builder) all       |
|             |          | merged and tested. Group G (this README + REFERENCE.md +         |
|             |          | cookbook) ship in the same release. First public release of     |
|             |          | `pkg/rule`.                                                     |
