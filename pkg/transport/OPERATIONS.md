# Sentinel Transport — Operations Manual

**Audience:** operator who runs arx-core nodes with `transport.enabled: true`.

This document covers the day-2 operations: first start, adding a node to an
existing mesh, key rotation without downtime, diagnostics, and the known-nodes
file format.

---

## 1. First Start

### Identity Generation

When `transport.New` is called with `Enabled: true` and `IdentityPath` pointing
at a non-existent file, the transport generates a fresh Ed25519 private key and
writes it to the specified path with `0600` permissions (owner read/write only).
The key file is 64 bytes (raw Ed25519 private key, RFC 8032 format).

To bootstrap a node and print its fingerprint:

```go
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

fmt.Println(tr.Identity().Fingerprint())
// Output: sha256:4f8a2b3c1d9e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a
```

The fingerprint is the node's public identity. It is a `sha256:` prefix followed
by 64 lowercase hex characters (SHA-256 of the Ed25519 public key).

**Important:** the key file is a sensitive operational artefact. Protect it:
- File permissions are `0600` automatically.
- Back up the key file. Losing it forces a key rotation across all peers.
- On-disk encryption is the operator's responsibility.

### Fingerprint Exchange Procedure

1. **Node A** operator runs the bootstrap, copies the fingerprint.
2. **Node B** operator runs the bootstrap, copies the fingerprint.
3. Both operators exchange fingerprints over a **secure side-channel**:
   PGP-encrypted email, encrypted messaging (Signal, Matrix), or in-person.
   Do NOT exchange fingerprints over the same network the transport will use
   (that would allow a MITM to substitute their own key).
4. **Node A** operator pastes Node B's fingerprint into Node A's
   `transport.peers[]` config:
   ```go
   Peers: []transport.PeerConfig{
       {Host: "node-b.example.net:4097", Fingerprint: "sha256:bbbb..."},
   }
   ```
5. **Node B** operator pastes Node A's fingerprint into Node B's config:
   ```go
   Peers: []transport.PeerConfig{
       {Host: "node-a.example.net:4097", Fingerprint: "sha256:aaaa..."},
   }
   ```
6. Both nodes restart with `Enabled: true`.

**Fallback — TOFU on first contact:** if the network is trusted (e.g. a
dedicated VLAN or WireGuard overlay), set `Fingerprint: ""` in the peer config.
The transport will pin the fingerprint presented on the first successful
connection. Do NOT use this fallback over an untrusted network — an attacker
who lands the first connection will be pinned as the legitimate peer.

---

## 2. Adding a Node to an Existing Mesh

### Procedure

1. **Generate the new node's identity.** Start the new node with
   `Enabled: true` and a fresh `IdentityPath`. The transport generates the
   key on first start. Print the fingerprint.

2. **Share the fingerprint.** The new node's operator shares the fingerprint
   with every existing peer that should see the new node (secure side-channel).

3. **Update every existing peer's config.** Each existing peer's operator adds
   a `transport.peers[]` entry with the new node's host and fingerprint:
   ```go
   Peers: append(existingPeers, transport.PeerConfig{
       Host:        "new-node.example.net:4097",
       Fingerprint: "sha256:new_node_fingerprint...",
   })
   ```

4. **Restart every existing peer.** v0.1.0 requires a process restart for
   config changes (DECISION D25: edit + restart, no live peer-add).

5. **Configure the new node.** The new node's operator adds the existing peers
   to the new node's `transport.peers[]`.

6. **Restart the new node** with `Enabled: true`.

### Topology-Specific Notes

| Topology | Who Restarts |
|----------|-------------|
| **Hub-spoke** | Hub + the new spoke. Other spokes are unaffected (they only talk to the hub). |
| **Mesh** | Every node restarts (every node must know about the new node). |
| **Hierarchical** | Parent + new child. Siblings of the new child are unaffected. |

---

## 3. Key Rotation Without Downtime

Key rotation is the most safety-critical operation. The transport uses TOFU
with hard-reject on mismatch (DECISION D24), so a key change on one node
requires updating the pinned fingerprint on every peer BEFORE the rotating
node starts using the new key.

### Recommended Sequence (Pre-Share Variant — Zero Downtime)

This sequence minimises the window where connections are rejected. The key
insight: **update the peers' known-nodes files BEFORE the rotating node
switches to the new key.**

**Step 1 — Generate a new identity on the rotating node.**

On the node whose key is being rotated, generate a new identity at a
**different path** (do not overwrite the current key yet):

```go
// Generate a new identity (in-memory only)
newID, err := transport.Generate()
if err != nil {
    log.Fatalf("Generate: %v", err)
}

// Save to a temporary path
if err := newID.Save("/etc/arx-core/node.key.new"); err != nil {
    log.Fatalf("Save: %v", err)
}

fmt.Println("New fingerprint:", newID.Fingerprint())
```

**Step 2 — Read the new fingerprint.**

The output is a `sha256:<hex>` string. This is the fingerprint every peer
must pin.

**Step 3 — Share the new fingerprint with every peer operator.**

Use the same secure side-channel as the initial fingerprint exchange.

**Step 4 — Each peer operator updates the known-nodes file.**

On each peer, edit the known-nodes file (see §6 for the format). Find the
line matching the rotating node's host and replace the old fingerprint with
the new one:

```
# Before
rotating-node.example.net:4097|sha256:old_fingerprint...

# After
rotating-node.example.net:4097|sha256:new_fingerprint...
```

Save the file. Do NOT restart the peer yet.

**Step 5 — Each peer operator restarts their node.**

The restarted peers will have the new fingerprint pinned. When they connect
to the rotating node, the rotating node is still presenting the OLD cert
(its key file has not been swapped yet). The result: **TOFU hard-reject** —
the connection is dropped, and an ERROR is logged with both the expected
(new) and presented (old) fingerprints.

This is expected. The window between Step 5 and Step 7 is the only period
where connections fail. To minimise it, sequence the rolling restart so
peers come up just before the rotating node does, or arrange a maintenance
window.

**Step 6 — Stop the rotating node. Swap the key file.**

```bash
mv /etc/arx-core/node.key.new /etc/arx-core/node.key
```

Or update the config's `IdentityPath` to point at the new file.

**Step 7 — Restart the rotating node.**

The rotating node now presents the new cert. Peers that were restarted in
Step 5 have the new fingerprint pinned and will accept the connection.

### Trade-offs

- **Window of rejection:** between Step 5 and Step 7, peers that have the new
  pin will reject the rotating node's old cert. This is logged as a TOFU
  hard-reject (ERROR level). The window is bounded by the time it takes to
  restart the rotating node.
- **No data loss:** frames queued during the window are lost (UDP). The
  telemetry and control protocols above the transport are responsible for
  retry/recovery.
- **Rollback:** if the rotation fails (e.g. the new key is corrupted), restore
  the old key on the rotating node and re-pin the old fingerprint on all peers.
  The old key file is still intact until Step 6.

### What NOT to Do

- **Do NOT** update the rotating node's key file before updating the peers'
  known-nodes. The rotating node would restart with the new key, every peer
  would hard-reject (they still have the old pin), and the node would be
  isolated until every peer is updated.
- **Do NOT** delete the old key file until the rotation is confirmed working.
  Keep it as a rollback point.

---

## 4. Diagnostics

### Reading a TOFU Hard-Reject Alert

When a peer presents a fingerprint that differs from the pinned value, the
transport logs an ERROR with both fingerprints:

```
transport: TOFU fingerprint MISMATCH (D24 hard-reject): host="10.0.0.2:4097" expected=sha256:old_fingerprint... presented=sha256:new_fingerprint...
```

- **expected (pinned):** the fingerprint stored in the known-nodes file.
- **presented:** the fingerprint from the peer's current certificate.

**If both fingerprints are legitimate** (e.g. a key rotation in progress):
follow the key rotation procedure in §3.

**If the presented fingerprint is unexpected:** investigate the peer. The peer
may have been compromised (key stolen and replaced), or an attacker may be
spoofing the peer's identity.

### Reading a Forged-Key Challenge Rejection

When TLS passes (the cert is correct or first-contact) but the peer cannot
sign the nonce with the private key matching the cert:

```
transport: server: challenge outbound: signature verification FAILED (peer does not hold the private key for the presented cert)
```

This means the peer presented a valid cert during TLS but could not prove
ownership of the corresponding private key. Possible causes:
- The peer's identity file is corrupted (key bytes do not match the cert).
- An attacker is replaying a captured cert without the private key.

**Operator action:** investigate the peer's identity file. If the file is
corrupted, restore from backup or generate a new key and re-pin on all peers.

### Log Lines to Grep

| What to look for | Log pattern | Severity |
|-----------------|-------------|----------|
| TOFU hard-reject | `transport: TOFU fingerprint MISMATCH` | ERROR |
| Signed challenge failure | `transport: signed challenge FAILED` | ERROR |
| Challenge outbound failure | `signature verification FAILED` | ERROR |
| Version mismatch (rolling upgrade) | `dropping frame: unsupported protocol_version` | WARN |
| TLS verification event | `transport: TLS verify` | ERROR (mismatch) / DEBUG (success) |

### Known-Nodes Manual Editing

To manually edit the known-nodes file:

1. Stop the node (or accept that changes take effect on restart — v0.1.0 has
   no live reload).
2. Edit the file with a text editor. Preserve the `|` separator and the
   `sha256:` prefix. Do not strip blank lines or comment lines.
3. Save the file. The transport uses atomic save (temp+rename), so a crash
   during the transport's own write will not corrupt the file. Manual edits
   are not atomic — the operator is responsible for a clean write.
4. Restart the node.

---

## 5. Known-Nodes File Format

### Path

Configurable via `Config.KnownNodesPath`. Required when `Enabled` is `true`.
No default and no env var in v0.1.0 (the path must be explicitly supplied).

### Format

One entry per line:

```
<host>|<fingerprint>
```

- **host:** the peer's dial address (host:port). Must match the `Host` field
  in the corresponding `PeerConfig`.
- **fingerprint:** the canonical `sha256:<hex>` fingerprint.
- **Separator:** `|` (pipe). Neither host strings nor `sha256:<hex>`
  fingerprints can contain `|`.
- **Comments:** lines starting with `#` are ignored.
- **Blank lines:** ignored.
- **Permissions:** `0600` (owner read/write only).
- **Atomic save:** the transport writes via temp-file-then-rename. A crash
  during save leaves the old file intact.

### Example

```
# hub
hub.example.net:4097|sha256:4f8a2b3c1d9e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a
# spoke-1
spoke-1.example.net:4097|sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
# spoke-2
spoke-2.example.net:4097|sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Manual Editing Procedure

1. Open the file in a text editor.
2. Add, remove, or modify lines. Preserve the `|` separator.
3. Save the file.
4. Restart the node for changes to take effect (v0.1.0: no live reload).

The transport's `KnownNodes.Load()` method can re-read the file at runtime,
but SIGHUP wiring is a future-flow task (DECISION D25 forbids live
reconfiguration in v0.1.0).

---

## 6. References

- **[README.md](README.md)** — quick start, configuration, topology examples.
- **[PROTOCOL.md](PROTOCOL.md)** — full protocol specification: wire format,
  handshake sequence, TOFU mechanism, stream types, error codes, security model.
