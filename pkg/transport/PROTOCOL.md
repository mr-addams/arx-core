# Sentinel Transport Protocol — v0.1.0

**Protocol surface:** closed per DECISION D29. All additions require a new flow
and a `protocol_version` bump.

---

## 1. Frame Structure (DECISION D27)

Every on-wire message is a **length-prefixed Protobuf frame**:

```
+----------------+-----------------------------------+
| 4 bytes, BE    |  N bytes                          |
| length prefix  |  marshalled Frame (protobuf)      |
+----------------+-----------------------------------+
```

- **Length prefix:** 4 bytes, big-endian (network byte order). Encodes the byte
  count of the marshalled `Frame` body only — the prefix itself is not counted.
- **Frame body:** a single Protobuf message of type `arx.transport.v1.Frame`,
  marshalled via standard protobuf encoding (`google.golang.org/protobuf/proto`).
- **Maximum frame body size:** 1 MiB (`MaxFrameSize = 1 << 20`). A length prefix
  declaring a larger body is rejected before allocation (DECISION D27 §3).

The schema lives in `pkg/transport/proto/transport.proto`; the generated
`.pb.go` is committed to the repo so a clean checkout builds without `protoc`.

---

## 2. Message-Type Table (resolves OPEN QUESTION 1)

Seven message types in v0.1.0, grouped by their natural stream type:

| Message | Direction | Stream | Purpose | Key Fields |
|---------|-----------|--------|---------|------------|
| `Heartbeat` | telemetry (uni) | Telemetry | Periodic liveness beacon | `sender_node_id`, `monotonic_clock_ms` |
| `TelemetryBatch` | telemetry (uni) | Telemetry | Batch of N metric samples | `sender_node_id`, `samples[]` (name, type, value) |
| `Alert` | telemetry (uni) | Telemetry | Security event forwarding | `sender_node_id`, `rule_id`, `severity`, `payload` |
| `Ping` | control (bi) | Control | Liveness probe with RTT measurement | `nonce`, `monotonic_clock_ms` |
| `Pong` | control (bi) | Control | Ping response | `nonce`, `receiver_monotonic_clock_ms` |
| `RuleUpdate` | control (bi) | Control | Publish a new/modified rule | `sender_node_id`, `rule_id`, `payload` |
| `RuleUpdateAck` | control (bi) | Control | Rule application confirmation | `rule_id`, `status` (APPLIED/REJECTED), `reason` |

**Source of truth:** `pkg/transport/proto/transport.proto`. The table above is
a summary; the `.proto` file defines field numbers, types, and semantics.

**Telemetry messages** (Heartbeat, TelemetryBatch, Alert) are fire-and-forget,
sent on unidirectional streams. The sender does not expect a response at the
transport level.

**Control messages** (Ping, Pong, RuleUpdate, RuleUpdateAck) are
request/response, sent on bidirectional streams. A Ping expects a Pong; a
RuleUpdate expects a RuleUpdateAck.

---

## 3. Handshake Sequence

The full handshake from UDP packet to established connection:

```
Client                                Server
  |                                     |
  | 1. QUIC connect (UDP, port 4097)    |
  |------------------------------------>|
  | 2. TLS 1.3 handshake               |
  |    both present self-signed Ed25519 |
  |    certs (no PKI, no expiry)        |
  |<----------------------------------->|
  | 3. TOFU fingerprint check           |
  |    (both sides, in TLS callback)    |
  |    - first contact → pin           |
  |    - match → allow                  |
  |    - mismatch → HARD REJECT + alert |
  |<----------------------------------->|
  | 4. Mutual signed challenge          |
  |    each side opens a bi stream      |
  |    and accepts one; 32-byte nonce   |
  |    → 64-byte Ed25519 signature      |
  |<----------------------------------->|
  | 5. Established — frames flow on     |
  |    uni/bi streams per stream type   |
  |<----------------------------------->|
```

### Step-by-step

**Step 1 — QUIC connect.** The client initiates a QUIC connection to the
server's UDP address (default port 4097). QUIC provides multiplexed streams,
TLS 1.3 encryption, and connection migration.

**Step 2 — TLS 1.3 handshake.** Both sides present a self-signed Ed25519
certificate (DECISION D22). The cert has:
- No chain (self-signed, no parent CA).
- No expiry enforcement (`NotAfter = 9999-12-31` — a sentinel value, not a
  real expiry).
- Subject: `CN=arx-core transport` (the identity is the Ed25519 public key,
  not the CN).
- ALPN: `arx-core/1` (the version suffix allows future protocol negotiation).

The TLS config uses `InsecureSkipVerify: true` to bypass stdlib chain
verification (which would reject a self-signed cert). The actual security gate
is the custom `VerifyPeerCertificate` callback (Step 3).

**Step 3 — TOFU fingerprint check.** Both sides run the same callback inside
the TLS handshake:
1. Extract the peer's Ed25519 public key from the presented certificate.
2. Compute `sha256:` + hex(SHA256(pub_key)).
3. Look up the peer's host in the known-nodes store:
   - **First contact** (host not in store) → pin the fingerprint, allow.
   - **Match** (host in store, fingerprint matches) → allow.
   - **Mismatch** (host in store, fingerprint differs) → **HARD REJECT**:
     connection dropped, ERROR log emitted with both the expected (pinned)
     and presented (actual) fingerprints. No soft-warn, no accept-once, no
     override (DECISION D24).

**Step 4 — Mutual signed challenge.** After TLS completes, both sides prove
possession of the private key matching the presented cert. Each side opens a
bidirectional QUIC stream and accepts one from the peer:
1. Challenger writes a 32-byte random nonce.
2. Responder reads the nonce, signs it with its Ed25519 private key, writes
   the 64-byte signature back.
3. Challenger verifies the signature against the peer's public key (extracted
   from the TLS cert).

Both directions run in parallel (two goroutines). A signature verification
failure drops the connection with error code `0x01` and logs an ERROR.

**Step 5 — Established.** Frames flow on unidirectional (telemetry) and
bidirectional (control) streams per the stream-type convention (§6).

---

## 4. TOFU Mechanism (DECISION D24)

### Fingerprint Algorithm

```
fingerprint = "sha256:" + hex(SHA256(ed25519_public_key))
```

- SHA-256 of the raw 32-byte Ed25519 public key.
- Hex-encoded lowercase.
- Prefix `sha256:` makes the fingerprint self-describing in logs and config.
- Example: `sha256:4f8a2b3c1d9e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a`

### Known-Nodes File Format

Line-oriented, human-editable:

```
# comments start with '#' and are ignored
# blank lines are ignored
host|fingerprint
host|fingerprint
```

- Separator: `|` (pipe). Neither host strings nor `sha256:<hex>` fingerprints
  can contain `|`.
- File permissions: `0600` (owner read/write only).
- Atomic save: temp-file-then-rename pattern prevents half-written files.
- Manual editing: edit the file, save, restart the node (no live reload in
  v0.1.0). See [OPERATIONS.md](OPERATIONS.md) for the procedure.

### Mismatch Behaviour

**HARD REJECT.** On fingerprint mismatch:
1. Connection is dropped immediately.
2. ERROR log emitted with both the expected (pinned) and presented (actual)
   fingerprints.
3. Peer is NOT added to any active roster.
4. No soft-warn, no accept-once, no override flag.
5. The pinned value is ground truth — the attacker's fingerprint is never stored.

### Empty Fingerprint in Peer Config

A `Fingerprint: ""` in `PeerConfig` means "TOFU on first contact" (DECISION
D24 §5). The first fingerprint presented by that peer is pinned into known-nodes
and becomes the authoritative value for all subsequent connections.

---

## 5. Stream-Type Convention (resolves OPEN QUESTION 5)

Stream types are distinguished by QUIC stream ID (RFC 9000 §2.1). Bit 1 of the
stream ID determines the type:

| Bit 1 (0x02 mask) | Stream Type | Message Types |
|--------------------|-------------|---------------|
| Set (1) | **Unidirectional** — telemetry | Heartbeat, TelemetryBatch, Alert |
| Clear (0) | **Bidirectional** — control | Ping, Pong, RuleUpdate, RuleUpdateAck |

**Canonical implementation** in `pkg/transport/protocol.go`:

```go
const streamIDUniBit uint64 = 0x02

func IsTelemetryStream(id uint64) bool { return id&streamIDUniBit != 0 }
func IsControlStream(id uint64) bool   { return id&streamIDUniBit == 0 }
```

The two predicates are complementary and cover the entire QUIC stream-ID space
without overlap. Bit 0 (client- vs server-initiated) is not used for dispatch.

---

## 6. Versioning (DECISION D27 §3, D29)

- **Current protocol version:** `1` (v0.1.0).
- Every `Frame` carries `protocol_version = 1`.
- A frame with an unsupported version is **dropped** and logged at **WARN**
  (not ERROR — protocol evolution is expected).
- No version negotiation in v0.1.0. A node that receives an unknown version
  simply drops the frame and continues.
- The `protocol_version` field is field number 1 in the `Frame` protobuf
  message and is reserved in every future version.

---

## 7. Error Code Table

| Code | Name | Cause | Operator Action |
|------|------|-------|-----------------|
| `0x01` | Signed challenge failed | Peer presented a valid cert (TLS passed) but could not sign the nonce with the matching private key. The peer may have a corrupted identity file, or an attacker is spoofing the cert without the private key. | Investigate the peer's identity file and key rotation history. Check logs for `signature verification FAILED`. |
| — (TLS-level) | TOFU fingerprint mismatch | TLS handshake failed because the peer's fingerprint differs from the pinned value. The ERROR log contains both the expected (pinned) and presented (actual) fingerprints. | If the mismatch is a legitimate key rotation, follow the key rotation procedure in [OPERATIONS.md](OPERATIONS.md). If unexpected, investigate the peer. |
| — (frame-level) | Version mismatch | A frame with `protocol_version != 1` was received and dropped. Logged at WARN. | Confirm both peers run the same arx-core version. Expected during a rolling upgrade. |

---

## 8. Security Model

### Protects Against

| Threat | Mitigation |
|--------|------------|
| **Passive DPI** | Traffic uses QUIC + TLS 1.3 over UDP with ALPN `arx-core/1`. To a passive observer the traffic is indistinguishable from HTTP/3. Note: ALPN `arx-core/1` is distinguishable from real HTTP/3 ALPNs (`h3`, `h3-XX`) to a determined observer who inspects the TLS handshake. |
| **In-flight tampering** | QUIC + TLS 1.3 provides AEAD encryption and integrity for every packet. Tampered packets are rejected at the QUIC layer. |
| **MITM with un-pinned key** | TOFU hard-reject (DECISION D24) drops any connection whose fingerprint differs from the pinned value. An attacker who does not hold the pinned private key cannot complete the handshake. |
| **Forged-key attack** | The mutual signed challenge (DECISION D23 §4) is defence-in-depth: even if a future quic-go bug bypasses the TLS cert check, an attacker who has the cert but not the private key cannot sign the nonce. |

### Does NOT Protect Against

| Threat | Rationale | Mitigation (operator) |
|--------|-----------|----------------------|
| **Traffic analysis** | Packet size, timing, and flow patterns are observable at the UDP layer. The transport does not pad packets or add cover traffic. | Overlay with WireGuard or a similar VPN for traffic-analysis resistance. |
| **Peer compromise after pinning** | An attacker who steals a peer's private key after the fingerprint was pinned will pass the TOFU check. The pinned fingerprint is the ground truth; the attacker's key matches it. | Follow the key rotation procedure in [OPERATIONS.md](OPERATIONS.md) to re-pin all peers after a compromise. |
| **UDP-layer DoS** | No rate-limiting, no IP allowlist, no connection-tracking at the transport layer. An attacker can flood the UDP port. | Rate-limit UDP at the firewall. Use `iptables` or `nftables` to restrict source IPs. |

---

## 9. References

- **Protobuf schema:** `pkg/transport/proto/transport.proto`
- **Go implementation:** `pkg/transport/protocol.go` (encode/decode, stream
  dispatch, version check)
- **QUIC:** [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- **TLS 1.3:** [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- **Ed25519:** [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
- **DECISIONS:** D22 (QUIC + TLS 1.3), D23 (Ed25519 identity), D24 (TOFU),
  D27 (wire format), D29 (closed v0.1.0 surface)
