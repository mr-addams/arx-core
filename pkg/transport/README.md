# pkg/transport — Sentinel Mesh Transport

`pkg/transport` is a node-to-node network link for arx-core instances. It gives
sentinel nodes a QUIC-based transport layer for exchanging telemetry (heartbeats,
metrics, alerts) and control messages (pings, rule updates) over UDP. The
transport is **disabled by default** (DECISION D21): a node that does not
configure `transport.enabled: true` opens no ports, spawns no goroutines, and
has zero network surface.

When enabled, an arx-core node becomes a peer in a sentinel mesh. Peers are
identified by self-signed Ed25519 keys, authenticated via TOFU (Trust On First
Use) with hard-reject on fingerprint mismatch, and connected over QUIC + TLS 1.3
on UDP port 4097. The protocol surface is closed for v0.1.0 (DECISION D29).

---

## Quick Start

### Step 1 — Generate the node identity

The transport generates a fresh Ed25519 private key on first start. Write a small
Go program (or use the arxsentinel bootstrap) that constructs a `transport.Config`
and calls `transport.New`:

```go
package main

import (
    "fmt"
    "log"

    "github.com/mr-addams/arx-core/pkg/transport"
)

func main() {
    cfg := transport.Config{
        Enabled:        true,
        IdentityPath:   "/etc/arx-core/node.key",
        KnownNodesPath: "/etc/arx-core/known-nodes",
        Listen:         "0.0.0.0:4097",
    }

    tr, err := transport.New(cfg)
    if err != nil {
        log.Fatalf("transport.New: %v", err)
    }

    // Print the node's fingerprint — share this with your peers.
    fmt.Println("Node fingerprint:", tr.Identity().Fingerprint())
}
```

On first run, `transport.New` generates a new Ed25519 key, saves it to
`IdentityPath` with `0600` permissions, and returns a `*Transport` whose
`Identity().Fingerprint()` is the canonical `sha256:<hex>` string. The
fingerprint is the node's public identity — share it with every peer that
should talk to this node.

### Step 2 — Exchange fingerprints with a peer

Each operator runs Step 1 on their node and copies the resulting
`sha256:...` fingerprint. The two operators exchange fingerprints over a
secure side-channel (PGP, encrypted messaging, in-person). Each operator
then pastes the **other** node's fingerprint into their own node's
`transport.peers[]` configuration:

```go
cfg := transport.Config{
    Enabled:        true,
    IdentityPath:   "/etc/arx-core/node.key",
    KnownNodesPath: "/etc/arx-core/known-nodes",
    Listen:         "0.0.0.0:4097",
    Peers: []transport.PeerConfig{
        {
            Host:        "peer-1.example.net:4097",
            Fingerprint: "sha256:4f8a2b3c1d9e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
        },
    },
}
```

**Alternative — TOFU on first contact:** set `Fingerprint: ""` (empty string)
in the peer config. The transport will pin the fingerprint presented on the
first successful connection. Use this only when the first connection happens
over a trusted network (DECISION D24 §5).

### Step 3 — Enable and start

Set `Enabled: true` in the config and call `tr.Run(ctx)`. Run blocks until
the context is cancelled:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

tr, err := transport.New(cfg)
if err != nil {
    log.Fatalf("transport.New: %v", err)
}

// Run blocks until ctx is cancelled.
if err := tr.Run(ctx); err != nil {
    log.Fatalf("transport.Run: %v", err)
}
```

When `Enabled` is `false`, `Run` returns immediately — no goroutine, no
listener, no dial (proven by regression test per DECISION D21).

---

## Topology Examples

The transport does not enforce a topology shape. The operator expresses the
desired topology by listing peers in `Config.Peers`. Three common patterns:

### Hub-Spoke

The hub lists every spoke; each spoke lists only the hub.

```go
// Hub config
cfg := transport.Config{
    Enabled:        true,
    IdentityPath:   "/etc/arx-core/hub.key",
    KnownNodesPath: "/etc/arx-core/known-nodes",
    Listen:         "0.0.0.0:4097",
    Peers: []transport.PeerConfig{
        {Host: "spoke-1.example.net:4097", Fingerprint: "sha256:aaaa..."},
        {Host: "spoke-2.example.net:4097", Fingerprint: "sha256:bbbb..."},
        {Host: "spoke-3.example.net:4097", Fingerprint: "sha256:cccc..."},
    },
}

// Spoke-1 config
cfg := transport.Config{
    Enabled:        true,
    IdentityPath:   "/etc/arx-core/spoke1.key",
    KnownNodesPath: "/etc/arx-core/known-nodes",
    Listen:         "0.0.0.0:4097",
    Peers: []transport.PeerConfig{
        {Host: "hub.example.net:4097", Fingerprint: "sha256:zzzz..."},
    },
}
```

The arxsentinel product translates a YAML block like this into the Go `Config`
shown above:

```yaml
# arxsentinel product config (not arx-core)
transport:
  enabled: true
  identity: /etc/arx-core/hub.key
  known-nodes: /etc/arx-core/known-nodes
  listen: 0.0.0.0:4097
  peers:
    - host: spoke-1.example.net:4097
      fingerprint: sha256:aaaa...
```

### Mesh

Every node lists every other node. For a 3-node mesh:

```go
// Node A
cfg := transport.Config{
    Peers: []transport.PeerConfig{
        {Host: "node-b.example.net:4097", Fingerprint: "sha256:bbbb..."},
        {Host: "node-c.example.net:4097", Fingerprint: "sha256:cccc..."},
    },
}

// Node B
cfg := transport.Config{
    Peers: []transport.PeerConfig{
        {Host: "node-a.example.net:4097", Fingerprint: "sha256:aaaa..."},
        {Host: "node-c.example.net:4097", Fingerprint: "sha256:cccc..."},
    },
}

// Node C
cfg := transport.Config{
    Peers: []transport.PeerConfig{
        {Host: "node-a.example.net:4097", Fingerprint: "sha256:aaaa..."},
        {Host: "node-b.example.net:4097", Fingerprint: "sha256:bbbb..."},
    },
}
```

### Hierarchical

Parent lists children; each child lists its parent.

```go
// Parent (coordinator)
cfg := transport.Config{
    Peers: []transport.PeerConfig{
        {Host: "child-1.example.net:4097", Fingerprint: "sha256:aaaa..."},
        {Host: "child-2.example.net:4097", Fingerprint: "sha256:bbbb..."},
    },
}

// Child-1
cfg := transport.Config{
    Peers: []transport.PeerConfig{
        {Host: "parent.example.net:4097", Fingerprint: "sha256:zzzz..."},
    },
}
```

---

## Configuration Reference

The `Config` struct is the contract between the arxsentinel product config
chain and the transport package. Key fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `Enabled` | `bool` | — | `false` | Master gate (DECISION D21). When false, `Run` is a no-op. |
| `IdentityPath` | `string` | when enabled | — | Path to the Ed25519 private key file. Generated on first start (DECISION D23). |
| `Listen` | `string` | when enabled | `127.0.0.1:4097` | QUIC bind address. Overridden by env `ARXSENTINEL_TRANSPORT_LISTEN`. |
| `KnownNodesPath` | `string` | when enabled | — | Path to the TOFU known-nodes file. See [OPERATIONS.md](OPERATIONS.md) for the format. |
| `Peers` | `[]PeerConfig` | — | `[]` | Config-level peer roster. Each entry has `Host` (required) and `Fingerprint` (empty = TOFU on first contact). |

**Precedence chain for `Listen`:** explicit `cfg.Listen` > env var
`ARXSENTINEL_TRANSPORT_LISTEN` > built-in default `127.0.0.1:4097`.

---

## Threat Model Summary

The transport protects against:
- **Passive DPI** — traffic looks like HTTP/3 (QUIC + TLS 1.3 over UDP, ALPN
  `arx-core/1`). A passive observer cannot distinguish sentinel frames from
  HTTP/3 without deeper inspection.
- **In-flight tampering** — QUIC + TLS 1.3 AEAD provides integrity and
  confidentiality for every packet.
- **MITM with un-pinned key** — TOFU hard-reject drops any connection whose
  fingerprint differs from the pinned value (DECISION D24).

The transport does **NOT** protect against:
- **Traffic analysis** — packet size, timing, and flow patterns are observable.
  Operators who need traffic-analysis resistance should overlay with WireGuard
  or a similar VPN.
- **Peer compromise after pinning** — an attacker who steals a peer's private
  key after the fingerprint was pinned will pass the TOFU check. Key rotation
  (see [OPERATIONS.md](OPERATIONS.md)) is the mitigation.
- **UDP-layer DoS** — no rate-limiting or IP allowlist at the transport layer.
  Operators should rate-limit UDP at the firewall.

See [PROTOCOL.md](PROTOCOL.md) for the full security model.

---

## Further Reading

- **[PROTOCOL.md](PROTOCOL.md)** — full protocol specification: wire format,
  handshake sequence, TOFU mechanism, stream types, error codes, security model.
- **[OPERATIONS.md](OPERATIONS.md)** — operations manual: first start, adding a
  node, key rotation without downtime, diagnostics, known-nodes file format.
