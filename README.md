# arx-core

A universal, domain-agnostic core for telemetry processing — the building
block for distributed telemetry collection and processing networks.

## Status

Published library. arx-core is a standalone public Go module
(`github.com/mr-addams/arx-core`) — a universal core for telemetry
processing. It implements a composable streaming pipeline — sources,
processors, detectors, sinks, executors — with no built-in assumptions about
the data domain, the wire protocol, or the payload schema.

The design goal is broad protocol coverage: arx-core is being equipped with
the widest practical set of source/sink/processor plugins so that a single
node can speak the major standard telemetry protocols. Each node is a
self-contained building block — composing many of them is what makes it
possible to build distributed telemetry collection and processing networks.

arx-core originated as the pipeline core of ArxSentinel and was extracted into
a standalone module. ArxSentinel is now simply its first consumer: product-
specific logic — security scoring, threat intelligence, vendor integrations —
lives in that product layer and reaches arx-core only through the public
runtime contract. Nothing in the core is tied to that origin.

## Installation

arx-core is a standard Go module. Add it to your project:

```bash
go get github.com/mr-addams/arx-core@v0.1.0
```

## Packages

A one-line summary of every package under `arx-core/pkg/`. Signatures,
responsibilities, and invariants for the public runtime contract live in
[`docs/contract.md`](docs/contract.md).

Top-level packages:

- **dedup** — TTL-window key store with `Contains` (read-only) and `Mark` (side-effect) for duplicate-suppression of repeated events.
- **detector** — registry of detector plugin factories plus shared config helpers; detectors self-register via `init()` and are looked up by name.
- **execplugin** — out-of-process plugin adapters: source/detector/sink/executor implementations that communicate with a child process over NDJSON.
- **executor** — registry of executor plugin factories (self-registration via `init()`); the `queue/` subpackage supplies the in-memory queue primitive.
- **input** — package-level constants and a `LineReader` helper for line-buffered input sources.
- **logger** — structured logging interfaces and a no-op default; stdlib-only, no product-layer dependencies.
- **ncs** — Named Channel Switch: an in-process singleton that maps named channels to in-memory, bbolt, or redis-backed queues with fan-in semantics.
- **parser** — line-format parsers (nginx combined plus `real_ip` by default) implementing a common `Parse(line)` interface.
- **pipeline** — configuration validator that checks `DataType` compatibility between adjacent plugins in a chain (fail-fast on mismatch).
- **plugin** — shared types used across the registries: `DataType`, `Manifest`, and the interfaces that source/processor/detector/sink/executor plugins implement.
- **pluginregistry** — generic `Registry[F, M]` core: a type-parameterised, mutex-guarded name → factory/manifest store shared by every concrete registry.
- **processor** — registry of processor plugin factories; processors transform events between source and detector stages.
- **runtime** — generic line-streaming engine: `Run`, `LineProcessor` dispatch, SIGHUP reload; orchestrates per-pipeline goroutines (Merge → Process → Sinks).
- **sink** — registry of sink plugin factories. Subpackages:
  - `exec` — fan events out to a child process via stdin.
  - `file` — append lines to a file (with rotation hooks).
  - `format` — render events through a pluggable text/JSON encoder before downstream dispatch.
  - `sentinel` — emit to an internal sentinel channel for in-process fan-out.
  - `stdout` — write to standard output.
- **source** — registry of source plugin factories. Subpackages:
  - `exec` — collect lines from a child process's stdout.
  - `file` — tail a file with logrotate awareness (fsnotify-based).
  - `http` — accept line payloads over HTTP.
  - `sentinel` — receive lines from an in-process sentinel channel.
  - `stdin` — read lines from standard input.
  - `syslog` — receive RFC 5424 syslog messages over UDP/TCP.
- **tail** — `tail -f`-style file reader with logrotate support (rename and copytruncate); consumed by `source/file`.

## Documentation

The full entry point for learning arx-core lives under `docs/`:

- [`docs/architecture.md`](docs/architecture.md) — engine lifecycle, NCS wiring, fan-in contracts, the generic `runtime.Run` execution model.
- [`docs/contract.md`](docs/contract.md) — reference of the public runtime contract: `Run`, `LineProcessor`, `LineProcessorFactory`, `Action`, `EventContext`, `ProcessorState`, `RunOptions`.
- [`docs/plugin-development.md`](docs/plugin-development.md) — how to author source/detector/sink/executor plugins: interfaces, registries, blank-imports, manifests, and lifecycle hooks.
- [`docs/build-profiles.md`](docs/build-profiles.md) — `arx_tag` build-tag profiles and their composition rules.

These documents are being populated in subsequent phases of Flow 082.
For a worked usage example that consumes only public arx-core APIs,
see [`examples/logaggregator/`](examples/logaggregator/) (added in a
later flow phase).

## Boundary rules

The dependency direction is strictly one-way: consumers depend on arx-core,
never the reverse. Files inside `arx-core/` must not import anything from a
consuming product layer — for the reference consumer, ArxSentinel, that means
its `pkg/` and `internal/` are off-limits. This boundary is enforced by ADR-002
and is what keeps arx-core publishable as a standalone, reusable core.
Product-specific packages — vendor integrations, scoring, deploy tooling —
live in the consumer and reach arx-core only through its public runtime
contract.

## License

Elastic License 2.0 — see [LICENSE](LICENSE).
