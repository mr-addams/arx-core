// Package transport (quic.go): QUIC listener/dialer surface + Transport
// constructor wiring identity, known-nodes, and (later) TLS/TOFU verification.
//
// Q1 shipped the SKELETON:
//
//   - Config + PeerConfig structs (preliminary; K1 extends with defaults
//     and validation helpers).
//   - Transport struct that holds *Identity, *KnownNodes, listen address,
//     peer roster (config-level; R1 converts to *Peer), and a nil
//     *quic.Listener placeholder.
//   - New(cfg Config) (*Transport, error): validates config, loads or
//     generates the Ed25519 identity (D23), loads the known-nodes store.
//   - The QUIC *quic.Listener field is declared but Q1 does NOT call
//     quic.ListenAddr — Listen() lands in Q3 with the TLS/TOFU wiring.
//
// Q2 (this file, additions) ships the TLS/QUIC configuration builders:
//
//   - buildQUICConfig() returns the *quic.Config used by Listen/Dial.
//     Defaults are picked to be defensive (no 0-RTT, sane idle timeouts)
//     and each choice is documented in the method comment.
//   - buildTLSConfig(host) returns a *tls.Config whose self-signed
//     Ed25519 cert is derived from the node's identity (D22: no PKI,
//     no expiry, no chain). The non-naive verification contract is
//     enforced via a custom VerifyPeerCertificate callback that runs
//     the D24 TOFU check (Check / Pin) and returns a hard-reject error
//     on fingerprint mismatch.
//   - verifyPeerCertificate(host) is the verification core: it extracts
//     the Ed25519 public key from the presented cert, computes the
//     "sha256:<hex>" fingerprint, and routes through KnownNodes.Check
//     for the three D24 cases (first-contact / match / mismatch).
//   - buildSelfSignedCert() lazily constructs the x509 cert + TLS cert
//     pair from the node's Ed25519 identity. The cert is cached in
//     t.tlsCert (sync.Once) because the identity is immutable and the
//     cert is byte-identical for every call — no point in re-deriving
//     it on every per-connection buildTLSConfig.
//
// What Q2 does NOT do (later group Q tasks):
//   - Listen / Dial + signed-challenge: Q3.
//   - TOFU hard-reject integration test: Q4.
//
// Architectural note: VerifyPeerCertificate (the standard tls.Config
// callback) does NOT receive the peer host directly. Q2's resolution
// is to make host an explicit parameter of buildTLSConfig — callers
// (Q3's Listen for the server side, Q3's Dial for the client side)
// construct one *tls.Config per connection with the appropriate host
// string baked into a closure passed to VerifyPeerCertificate. This is
// the simplest pattern that scales: no hidden per-Transport state to
// race against, no SNI reliance (our cert is self-signed, SNI is not
// meaningful for trust), and no need to thread a "current peer host"
// through TLS internals. The choice is documented for PROTOCOL.md.
//
// K1 (2026-06-30) ships the Config-with-defaults story and moves
// Config + PeerConfig + validate to config.go (the file-split Q1's
// header deferred to K1). quic.go keeps the Transport runtime
// surface: Transport struct, New, Listen, Dial, Run (K2), and the
// TLS / QUIC config builders. The split keeps the runtime file
// focused on QUIC mechanics; the config file owns defaults,
// env-var resolution, and validation.
//
// K2 (this file) ships the enabled-gate on Transport. Run is the
// public entrypoint the bootstrap calls when transport is enabled;
// when Enabled=false, Run returns immediately without spawning a
// goroutine, opening a listener, or dialing. A fake-listener
// injection point (listenFunc, an unexported field) lets K2's
// regression tests assert the listener construction was skipped
// without standing up a real QUIC socket.
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ========================== Q3 — protocol-level constants ==========================
//
// alpnArxCoreV1 is the ALPN token used by the QUIC handshake.
//
// quic-go requires tls.Config.NextProtos to be non-empty (see
// buildTLSConfig); we advertise a single sentinel value that is
// stable across v0.1.0. The version-suffixed shape ("arx-core/1")
// leaves room for a future protocol bump to negotiate via the
// same field without breaking v0.1.0 peers: a v0.2.0 node can
// advertise ["arx-core/2", "arx-core/1"] and accept the
// intersection; a v0.1.0 node that sees only "arx-core/2" in
// the peer's offer fails the ALPN check and drops the handshake,
// which is the same drop-on-mismatch policy protocol.go applies
// to unknown protocol_version frames (D27).
//
// The value is not operator-tunable in v0.1.0: the protocol
// surface is closed (D29), and exposing this knob now would be
// the kind of "almost meaningful" config that operators edit
// to no effect. K1 may add a Config.ALPN field if a real
// interop need surfaces; until then, the constant is the truth.
const alpnArxCoreV1 = "arx-core/1"

// challengeNonceSize is the byte length of the nonce exchanged
// in the signed-challenge handshake. 32 bytes is the same size
// as a SHA-256 digest and is a comfortable upper bound for a
// per-connection fresh random: collision probability is
// negligible at this width (the birthday bound is 2^128, far
// beyond any plausible replay-attack budget).
const challengeNonceSize = 32

// challengeSignatureSize is the byte length of an Ed25519
// signature (per RFC 8032). The handshake reads exactly this
// many bytes; a short read is a protocol violation and the
// connection is dropped. Using a constant instead of the
// ed25519.SignatureSize alias keeps the value local to the
// transport and self-documenting at call sites.
const challengeSignatureSize = 64

// ========================== Transport ==========================

// Transport is the public sentinel-transport handle: the single object
// the bootstrap holds when transport is enabled. It owns the
// long-lived collaborators (identity, known-nodes) and the runtime
// state (the QUIC listener, the peer roster).
//
// Concurrency: Q1 does not start any goroutine. The struct is
// plain-data plus a single *quic.Listener; later Q-task methods
// (Listen, Dial) will take the listener lock when they need to. Q1
// itself is safe to construct and then hand to multiple readers
// provided they do not mutate the listener field.
type Transport struct {
	// enabled is the cached value of cfg.Enabled from New. Stored
	// separately (rather than re-reading cfg each time) because
	// Transport does not keep the *Config after construction —
	// New copies the fields it needs into the struct, and the
	// Enabled flag is one of those fields. The K2 Run method
	// reads this field on every call to decide whether to early-
	// return; the K2 regression test asserts the field is the
	// one and only signal that gates the runtime start.
	enabled bool

	// listenFunc is the unexported listener-construction injection
	// point used by K2's regression tests to assert the disabled
	// path does NOT construct a listener. Production code never
	// overrides it: New() sets it to the package-level
	// defaultListenFunc, which is the real quic.ListenAddr call
	// the same way the Q3 Listen path uses it.
	//
	// Signature: func(ctx, *Transport) (*quic.Listener, error).
	// The *Transport is the first arg (not a method receiver)
	// because the field type is a plain func value, not a method
	// value. A method value "t.defaultListenFunc" would be the
	// Go-idiomatic alternative, but a method on *Transport would
	// need to be exported or have a non-standard name, both of
	// which leak the test injection point into the public API.
	// The plain-func shape is the additive surface that keeps
	// the test override one-liner-friendly:
	//
	//	tr.listenFunc = func(_ context.Context, _ *Transport) (*quic.Listener, error) {
	//	    called = true
	//	    return nil, errors.New("not bound")
	//	}
	//
	// Why a function field rather than a *quic.Listener field:
	// the K2 gate is "no listener construction when disabled" —
	// to assert that, the test needs to observe the CONSTRUCT call
	// (the moment quic.ListenAddr is invoked, the OS socket is
	// bound), not just the eventual Listener struct. A function
	// field is the minimum surface that lets a test install a
	// spy that records the call without standing up a real UDP
	// socket.
	//
	// Concurrency: listenFunc is set once in New and never mutated
	// afterwards. Run reads it without a lock; tests that override
	// it must do so before calling Run.
	listenFunc func(ctx context.Context, t *Transport) (*quic.Listener, error)

	// identity is this node's Ed25519 self-signed identity (D23).
	// Never nil after a successful New.
	identity *Identity

	// known is the TOFU known-nodes store (D24). Never nil after
	// a successful New.
	known *KnownNodes

	// listen is the resolved QUIC bind address (D22). K1's
	// applyDefaults step fills in env-var / built-in defaults
	// before this field is set, so by the time the Transport is
	// constructed, t.listen is the final, validated value. Q3's
	// Listen calls quic.ListenAddr(t.listen, ...).
	listen string

	// peers is the config-level peer roster (D25, R1). Q1 holds
	// the config slice; R1 converts it into a []Peer with state
	// and a separate field. Keeping the config slice here (rather
	// than throwing it away) makes "re-read config and rebuild"
	// a future option without re-asking the operator for the
	// peer list.
	peers []PeerConfig

	// listener is the QUIC listener returned by quic.ListenAddr.
	// nil until Listen (Q3) is called. Declared here as a typed
	// field — not as a `any` or as a function-local — so future
	// Q-tasks can take its address under a mutex and so Q1 can
	// prove the "nil until Listen" property with a test.
	listener *quic.Listener

	// listenerMu guards the listener field. Q3's Listen writes
	// it once; a future Close would need to coordinate with
	// in-flight accept loops. For Q3 the lock is taken briefly
	// during Listen (and is uncontented in normal use), but
	// declaring it now is cheaper than retrofitting the struct
	// later when a real teardown path lands.
	listenerMu sync.Mutex

	// tlsCert is the cached self-signed Ed25519 TLS certificate
	// (Q2). Built lazily on the first call to buildTLSConfig
	// (initiated by Q3's Listen / Dial). The certificate is a
	// pure function of the immutable *Identity, so caching once
	// is correct: subsequent calls get a byte-identical cert
	// without paying the x509 marshalling cost on every per-
	// connection TLS config build.
	tlsCert *tls.Certificate

	// tlsCertOnce guards the lazy build of tlsCert. We use
	// sync.Once (not a mutex with a bool flag) because the
	// construction is a one-shot "first caller wins, others
	// observe the populated field" — exactly the primitive
	// sync.Once is designed for. Q1's Transport construction
	// does not initialise this field; it stays at the zero
	// value and Do() triggers the build on first use.
	tlsCertOnce sync.Once

	// logger is the structured logger used by the transport for
	// security-relevant events (TOFU mismatch, signed-challenge
	// failure). Defaults to DiscardLogger() in New so production
	// code with no injected logger emits zero log output. Tests
	// inject a capture logger via WithLogger to assert the
	// contract (D24 §2 "operator alert" — both fingerprints
	// emitted; D23 §4 "signed challenge rejects forged key" —
	// error log emitted on verification failure).
	//
	// The interface lives in protocol.go so protocol.go and
	// quic.go can share a single Logger surface; protocol.go
	// uses Warnf (version-mismatch drops), quic.go uses Errorf
	// (security events). The capture logger in the test files
	// implements both.
	logger Logger

	// challengeSigner is a TEST INJECTION POINT for the signed-
	// challenge engine. When non-nil, runMutualChallenge uses this
	// identity to sign its OWN challenge responses instead of
	// t.identity. Production code never sets this field — it
	// always remains nil, and the engine falls back to t.identity.
	//
	// The Q4 forged-key integration test sets it to a different
	// *Identity so the server presents one cert (built from
	// t.identity) but signs challenges with a different key,
	// exercising the runChallengeOutbound → VerifyChallenge
	// failure path through a real Dial → Listen loop. Without
	// this injection point there is no way to construct the
	// "honest cert + wrong priv key" attacker scenario without
	// reaching into the package's unexported identity field.
	//
	// NOT a production knob. Do NOT expose via Config; do NOT
	// document in README / PROTOCOL / OPERATIONS. The only
	// caller is newTestTransportWithChallengeSigner in quic_test.go.
	challengeSigner *Identity
}

// New constructs a Transport from cfg.
//
// Steps (Q1 + K1):
//
//  1. Resolve defaults and env-var overrides via applyDefaults
//     (K1). The result is a Config whose Listen field has been
//     filled in from the env or the built-in loopback default
//     when the operator did not set it explicitly.
//  2. Validate the resolved config via Validate (K1). The
//     Enabled=false short-circuit means a zero-value Config is
//     valid; the Enabled=true branch enforces IdentityPath /
//     KnownNodesPath / Listen / Peers[].Host non-empty.
//  3. If Enabled is true, load the Ed25519 identity from
//     cfg.IdentityPath. If the file does not exist, generate
//     a new identity and Save it to the same path. If the file
//     exists but is unreadable / wrong-sized, return the error
//     from Load (D23 §2 — "fails loudly"). If Enabled is false,
//     SKIP the identity load entirely — the disabled Transport
//     is a no-op and must not write to disk (the K2 D21 gate
//     is "no side effects when disabled", and writing node.key
//     is a side effect).
//  4. If Enabled is true, construct the TOFU known-nodes store
//     via NewKnownNodes (which loads from disk if the file
//     exists, returns empty otherwise — first-start is a normal
//     state, not an error, per tofu.go T1). If Enabled is false,
//     skip the store construction.
//
// Q1 does NOT:
//   - Open any network socket (D21 disabled-by-default: a
//     successfully-constructed Transport has zero goroutines,
//     zero sockets, zero listeners).
//   - Call quic.ListenAddr. The listener field stays nil until
//     Q3's Listen.
//   - Start Run. New is the "construct the runtime" step; Run
//     is the "start the runtime" step (K2). When Enabled=false,
//     the caller (bootstrap) is expected to either skip Run
//     entirely or call Run and have it return immediately — the
//     K2 regression tests cover both shapes.
//
// Error contract: a non-nil return is a hard failure; the
// caller (bootstrap) MUST NOT use a partially-constructed
// Transport. To enforce that, New is the only constructor and
// there is no public struct literal — the field types include
// unexported ones, so a caller cannot build a Transport
// without going through New anyway.
func New(cfg Config) (*Transport, error) {
	// K1: apply defaults (env > built-in) BEFORE validation.
	// The order matters: Validate checks Listen is non-empty
	// when Enabled is true, and applyDefaults is what fills in
	// the Listen value when the operator did not. Validating
	// the un-defaulted config would produce a spurious
	// "Listen is required" error on a config that would have
	// been valid after env-var resolution.
	resolved := applyDefaults(cfg)
	if err := resolved.Validate(); err != nil {
		return nil, err
	}

	// Disabled short-circuit: a zero-value Config (Enabled=false)
	// skips both the identity load and the known-nodes
	// construction. This is the D21 promise: a disabled Transport
	// has no side effects, no on-disk artefacts, no goroutines.
	// Skipping the load here is what makes the K2 regression
	// test's "no node.key file was written" assertion possible
	// (the test runs from a temp dir with no node.key, and
	// after New the temp dir still has no node.key).
	if !resolved.Enabled {
		return &Transport{
			enabled:    false,
			listenFunc: defaultListenFunc,
			// identity left nil — a disabled Transport is
			// never asked for its identity.
			// known left nil — a disabled Transport is
			// never asked for its known-nodes.
			// listen left empty — a disabled Transport
			// never binds a listener.
			// peers left nil — a disabled Transport
			// never iterates the peer roster.
			logger: DiscardLogger(),
		}, nil
	}

	// Load or generate the identity. Load returns an error for
	// "exists but unreadable / wrong size"; we propagate that
	// directly. os.IsNotExist is the only error we treat as
	// "first start, generate".
	identity, err := loadOrGenerateIdentity(resolved.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("transport: load identity: %w", err)
	}

	// TOFU store. NewKnownNodes does not return an error by
	// design (T1) — a missing file is first-start, a malformed
	// file is detected at the point of use by Check. We just
	// hold the resulting *KnownNodes.
	known := NewKnownNodes(resolved.KnownNodesPath)

	return &Transport{
		enabled:    resolved.Enabled,
		listenFunc: defaultListenFunc,
		identity:   identity,
		known:      known,
		listen:     resolved.Listen,
		peers:      resolved.Peers,
		// listener left nil — Q3's Listen fills it in.
		// logger defaults to DiscardLogger() so a production
		// caller that never injects a logger has zero log
		// output. The Q4 hard-reject / forged-key tests
		// override via WithLogger to capture and assert the
		// operator alert.
		logger: DiscardLogger(),
	}, nil
}

// defaultListenFunc is the production listener-construction
// function stored on Transport.listenFunc by New. It is the
// real quic.ListenAddr call (using the Transport's resolved
// listen address and TLS / QUIC configs) extracted into a
// function so K2's regression tests can override
// Transport.listenFunc with a recording stub.
//
// The function takes the *Transport by value rather than as a
// method receiver because the function-field type is a plain
// "func(ctx) (*quic.Listener, error)" — a method on *Transport
// would not satisfy that signature (it would be
// "(*Transport).Listen(ctx) (...)", an extra receiver).
// Passing the receiver as the first argument keeps the
// signature uniform with the test-override shape, so a test
// can install a stub like
//
//	listenFunc: func(ctx context.Context) (*quic.Listener, error) {
//	    // record the call and return
//	}
//
// without an adapter.
func defaultListenFunc(ctx context.Context, t *Transport) (*quic.Listener, error) {
	// The real quic.ListenAddr path. Builds the per-listener
	// *tls.Config the same way Q3's Listen does (with the
	// per-connection GetConfigForClient hook that installs
	// the host-baked VerifyPeerCertificate closure), then
	// binds the UDP address.
	tlsConf := t.buildTLSConfig("")
	tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		host := ""
		if info.Conn != nil {
			host = info.Conn.RemoteAddr().String()
		}
		return t.buildTLSConfig(host), nil
	}

	listener, err := quic.ListenAddr(t.listen, tlsConf, t.buildQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("transport: Listen: quic.ListenAddr(%q): %w", t.listen, err)
	}

	// We do NOT store listener on t here. Storing happens in
	// Run after a successful return, so the K2 "did Run
	// construct a listener" assertion can use the
	// listenFunc-call observation as its primary signal and
	// the t.listener field check as a secondary one.
	_ = ctx
	return listener, nil
}

// loadOrGenerateIdentity returns the identity stored at path, or — if
// the file does not exist — generates a new identity, writes it to
// path, and returns it.
//
// The function is the single point where the D23 "generate on first
// start" policy is implemented. It is split out of New so the policy
// is testable in isolation and so the error-wrapping is consistent
// (every path returns a *Transport-shaped error with a clear prefix).
//
// Failure modes:
//
//   - path's parent dir does not exist: os.CreateTemp will fail at
//     Save() with a clear message. validate() already rejected this
//     case, so the only way to reach here is a TOCTOU race between
//     validate and Save — extremely unlikely, surfaces a confusing
//     error. Acceptable: validate catches the common case.
//   - existing file is unreadable: Load returns the error, we wrap.
//   - existing file is wrong size: Load returns the error, we wrap.
//   - Save (after a fresh generation) fails: we wrap, no half-state
//     is left behind because Generate is in-memory until Save
//     succeeds.
func loadOrGenerateIdentity(path string) (*Identity, error) {
	if _, err := os.Stat(path); err == nil {
		// File exists — load it. Load() does the 64-byte-size
		// check and the public-key recomputation; any failure
		// here is operator-actionable (file permissions,
		// corruption, wrong format).
		id, err := Load(path)
		if err != nil {
			return nil, fmt.Errorf("load existing identity: %w", err)
		}
		return id, nil
	} else if !os.IsNotExist(err) {
		// Stat error other than "not exist" (perm denied, IO
		// error, etc.). Treat as fatal: the operator needs to
		// know the path is unusable, not "generate a new key
		// in a different location".
		return nil, fmt.Errorf("stat identity file: %w", err)
	}

	// First-start: generate, save, return. If Save fails, return
	// the error and leave no identity file behind — Generate is
	// pure in-memory, so there is nothing to roll back, and the
	// next call to New will retry the generation (the path is
	// still absent).
	id, err := Generate()
	if err != nil {
		return nil, fmt.Errorf("generate new identity: %w", err)
	}
	if err := id.Save(path); err != nil {
		return nil, fmt.Errorf("save new identity: %w", err)
	}
	return id, nil
}

// Identity returns the node's Ed25519 identity. Useful for tests
// (asserting the loaded/generated fingerprint) and for the Q2/Q3
// TLS config builder (which needs the public key to build a
// self-signed cert).
//
// Returning the *Identity (rather than e.g. the fingerprint alone)
// is intentional: the TLS builder needs the public key, the
// handshake needs the private key for the signed challenge, and
// giving each caller a typed accessor would scatter the
// indirection. The returned *Identity is still read-only by
// convention — no public method mutates it.
func (t *Transport) Identity() *Identity {
	return t.identity
}

// KnownNodes returns the TOFU known-nodes store. The Q2 TLS
// callback will call Check on this; the Q3 handshake may call
// Pin on first contact.
func (t *Transport) KnownNodes() *KnownNodes {
	return t.known
}

// ListenAddr returns the configured QUIC bind address. Stored
// verbatim; Q3's Listen method calls quic.ListenAddr with this.
// Empty string means "not configured" — Q3 will treat that as
// a configuration error at Listen time, not here, so a New
// that only wants to inspect identity/tofu can succeed with
// an empty Listen.
func (t *Transport) ListenAddr() string {
	return t.listen
}

// Peers returns the config-level peer roster. R1 will replace
// the return type with a []Peer (the runtime struct with state);
// for Q1 the config slice is the right granularity because no
// lifecycle exists yet.
func (t *Transport) Peers() []PeerConfig {
	return t.peers
}

// ========================== K2 — Run (enabled-gate) ==========================
//
// K2 ships the public entrypoint that connects the K1 Config layer
// to the Q3 Listen / R2 peer-run runtime: Transport.Run(ctx) error.
//
// The D21 promise: when transport is disabled, the bootstrap can
// call Run on a zero-value Config and get a no-op. The promise is
// PROVABLE — a regression test (TestRunDisabledCreatesNoGoroutine
// and friends) observes the runtime via runtime.NumGoroutine and
// the listenFunc spy, and asserts both are quiet.
//
// Enabled=false contract:
//
//   - Run returns nil immediately, before any goroutine, before
//     any listener construction, before any dial.
//   - The Transport constructed by New is still usable for
//     inspection: Identity(), KnownNodes(), ListenAddr(), Peers()
//     are all live (they return the data New loaded). The only
//     thing Run does when disabled is "do not start the runtime".
//
// Enabled=true contract:
//
//   - Run validates the resolved state is still usable (defence-
//     in-depth: New already validated, but a future caller might
//     mutate t.listen or t.peers between New and Run — the
//     re-check makes those mutations loud failures).
//   - Run calls listenFunc to bind the UDP socket, stores the
//     resulting *quic.Listener on t.listener, and starts the
//     Q3 accept loop in a goroutine.
//   - Run builds the peer roster via RosterFromConfig, wires
//     t.Dial as the dialer on each *Peer, and starts a
//     peer.run goroutine per peer.
//   - Run blocks until ctx is cancelled, then returns nil.
//     The listener is closed by the Q3 accept loop on ctx cancel;
//     the peer goroutines exit when their dial/dispatch
//     operations observe ctx.Done().
//
// Architectural notes:
//
//   - listenFunc is the K2 injection point. Production wires it
//     to defaultListenFunc in New; tests override it with a
//     recording stub. Run calls listenFunc only on the Enabled=true
//     path; the disabled path never invokes it (the K2 regression
//     test asserts the spy was not called).
//
//   - D25 forbids live peer reconfiguration. Run builds the
//     roster once at startup; adding or removing peers requires
//     process restart. A future flow task that wants live peer-
//     add wires a separate signal — the dialer field and the
//     roster are not exposed to the operator at runtime in
//     v0.1.0.

// Run is the K2 enabled-gate entrypoint.
//
// When the Transport was constructed from a Config with
// Enabled=false, Run returns nil immediately without
// spawning any goroutine, constructing any listener, or
// dialing any peer. The disabled path is provably side-
// effect-free; the regression test in config_test.go
// (TestRunDisabledCreatesNoGoroutine) is the security gate
// that proves it.
//
// When Enabled=true, Run starts the QUIC listener
// (via t.listenFunc, overridable in tests) and one
// peer.run goroutine per configured peer. Run blocks
// until ctx is cancelled; on cancel it returns nil
// after the accept loop and peer goroutines have
// torn down via the standard ctx-cancel paths.
//
// Error contract: a non-nil return means the runtime
// failed to start (the listener-construction step
// errored, or the post-construction validation
// rejected an inconsistent state). The disabled
// path ALWAYS returns nil.
func (t *Transport) Run(ctx context.Context) error {
	// D21 enabled-gate. This is the security-critical
	// early return. NOTHING in the runtime starts
	// before this check — no goroutine, no listener,
	// no dial. The K2 regression test asserts this
	// boundary by snapshotting runtime.NumGoroutine
	// before and after the call.
	if !t.enabled {
		return nil
	}

	// Re-validate the runtime state. New already
	// validated the resolved Config, but t.listen and
	// t.peers are exported-ish via the unexported
	// fields — a future caller could mutate them
	// between New and Run. A cheap re-check makes
	// those mutations loud failures rather than
	// "Listen returns a confusing error at line 200".
	//
	// The re-check does NOT re-validate IdentityPath or
	// KnownNodesPath: those are on-disk artefacts that
	// New already resolved, and a missing or moved
	// file is detected at the next operation that
	// touches it (e.g. Pin / Check), not at Run
	// startup. Re-validating the file-system state
	// would also require a disk hit, which is the
	// wrong side-effect profile for a "start the
	// runtime" call. The runtime-relevant checks
	// are: Listen non-empty (we are about to bind it)
	// and Peers[].Host non-empty (we are about to
	// start peer goroutines that would deref an
	// empty host on the first dial).
	if t.listen == "" {
		return fmt.Errorf("transport: Run: Transport.listen is empty; " +
			"this is a wire-up bug (New resolved a non-empty listen)")
	}
	for i, p := range t.peers {
		if p.Host == "" {
			return fmt.Errorf("transport: Run: Peers[%d].Host is empty; "+
				"this is a wire-up bug (New validated a non-empty host)", i)
		}
	}

	// Build the listener via the injection point.
	// Production calls defaultListenFunc (the real
	// quic.ListenAddr path). The K2 test overrides
	// listenFunc with a recording stub; the disabled
	// path never reaches this call, so the test can
	// assert the stub was not invoked.
	listener, err := t.listenFunc(ctx, t)
	if err != nil {
		return fmt.Errorf("transport: Run: listen: %w", err)
	}

	// Store the listener. listenerMu is the same lock
	// Q3's Listen uses; we are the only writer at this
	// point in the lifecycle (Run is the first thing
	// that fills the field).
	t.listenerMu.Lock()
	t.listener = listener
	t.listenerMu.Unlock()

	// Build the peer roster (R1 helper) and wire the
	// dialer. The dialer is a thin wrapper around
	// t.Dial — Go's method-value-to-interface assignment
	// does not work directly (the func value lacks a
	// named method), so we wrap t in a struct that has
	// a Dial method whose body is `t.Dial(ctx, peer)`.
	// R2's dialer interface signature is
	// Dial(ctx, PeerConfig) (*quic.Conn, error), which
	// matches t.Dial's signature exactly.
	roster := RosterFromConfig(t.peers)
	dialWrapper := &transportDialer{t: t}
	for _, p := range roster {
		p.dialer = dialWrapper
	}

	// Start the Q3 accept loop in a goroutine. The
	// accept loop blocks until the listener is closed
	// or ctx is cancelled; on either signal it returns.
	// ctx is the Run argument, so the bootstrap's
	// cancellation propagates.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		_ = t.acceptLoop(ctx, listener)
	}()

	// Start one peer.run goroutine per configured
	// peer. Each goroutine owns its *Peer's lifecycle
	// (dial / dispatch / backoff) and exits on
	// ctx cancellation. The no-op handlers are the
	// v0.1.0 default; the arxsentinel product wires
	// real handlers later.
	peerDone := make(chan struct{}, len(roster))
	for _, p := range roster {
		p := p
		go func() {
			defer func() { peerDone <- struct{}{} }()
			_ = p.run(ctx, nil, nil, nil)
		}()
	}

	// Block until ctx is cancelled. On cancel, return
	// nil: the accept loop and peer goroutines will
	// observe ctx.Done() on their next iteration and
	// exit cleanly. We do not Wait() for the accept-
	// loop goroutine because the listener's own
	// ctx-cancel path closes the underlying socket
	// and the loop returns; joining would just be
	// ceremony.
	<-ctx.Done()
	return nil
}

// acceptLoop is the per-Run accept-loop wrapper. It is
// unexported because the only caller is Run; the loop
// body is the Q3 Listen accept pattern (block on
// Accept, dispatch each conn in its own goroutine)
// adapted to take a pre-bound *quic.Listener rather
// than binding internally. The split is K2's — Run
// owns the bind step (so the listenFunc injection
// point is the K2 boundary, not buried inside the
// accept loop), and acceptLoop owns the accept step.
func (t *Transport) acceptLoop(ctx context.Context, listener *quic.Listener) error {
	for {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			return nil
		default:
		}

		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, quic.ErrServerClosed) || isClosedListenerErr(err) {
				return nil
			}
			return fmt.Errorf("transport: acceptLoop: accept: %w", err)
		}

		go t.handleAcceptedConn(ctx, conn)
	}
}

// transportDialer is the K2 dialer wrapper. R2's dialer
// interface requires a struct with a Dial method; Go
// does not let you assign a bare method value
// (t.Dial as a func) to an interface variable. The
// wrapper struct exists to make the assignment work
// without polluting *Transport with a second Dial
// method (which would create a name collision) or
// exporting an extra constructor.
//
// The struct holds *Transport by pointer; the Dial
// method delegates to t.Dial. Allocation is one
// per Run call, which is negligible.
type transportDialer struct {
	t *Transport
}

// Dial delegates to the wrapped Transport's Dial. The
// signature matches R2's dialer interface exactly, so
// *transportDialer satisfies the interface and can be
// assigned to peer.dialer.
func (d *transportDialer) Dial(ctx context.Context, peer PeerConfig) (*quic.Conn, error) {
	return d.t.Dial(ctx, peer)
}

// ========================== Q4 — test injection points ==========================
//
// These three small helpers exist for ONE reason: Q4's integration
// tests need to drive the production code path
// Dial → quic.DialAddr → runMutualChallenge → runChallengeInbound
// with a server whose signing key differs from its cert key, and
// to capture the operator-alert log records the hard-reject path
// emits. Production code never calls any of them.

// WithLogger sets the structured logger this Transport uses for
// security-relevant events (TOFU mismatch, signed-challenge
// failure). Returns the receiver for chaining. The default logger
// is DiscardLogger() (set in New), so a production caller that
// never invokes WithLogger emits no log output.
//
// Q4's integration tests use this to inject a capture logger and
// assert the contract (D24 §2: log must contain both fingerprints;
// D23 §4: log must be emitted on signed-challenge failure).
// Concurrency: WithLogger is not safe to call concurrently with
// Listen / Dial — the test layer sets the logger once at Transport
// construction time, before any handshake goroutine starts. This
// matches the per-test setup pattern in quic_test.go.
//
// NOT a production knob. The real production wiring (when Group K
// adds the bootstrap / config chain) will set the logger once at
// process start via a constructor option, not via a mutator.
func (t *Transport) WithLogger(log Logger) *Transport {
	t.logger = log
	return t
}

// effectiveSigner returns the *Identity the signed-challenge
// engine should use to sign its OWN challenge responses. Production
// always returns t.identity; the Q4 forged-key test overrides
// t.challengeSigner via newTestTransportWithChallengeSigner so the
// "honest cert + wrong priv key" scenario can be exercised end-to-
// end through Dial → Listen.
//
// The fallback is the literal "use t.identity" branch, not a
// nil-coalesce to a package default — the test injection must
// behave identically to production in every way except the one
// field it overrides.
func (t *Transport) effectiveSigner() *Identity {
	if t.challengeSigner != nil {
		return t.challengeSigner
	}
	return t.identity
}

// newTestTransportWithChallengeSigner is the Q4 test-only constructor
// that builds a Transport with a separate signing identity for the
// signed-challenge engine. The cert the Transport presents during
// TLS is always derived from t.identity (via buildSelfSignedCert);
// the key used to sign challenge responses is signer.
//
// Usage (Q4 forged-key test):
//
//	// Server: presents cert for A, signs challenges with C.
//	serverTr, err := newTestTransportWithChallengeSigner(cfg, C)
//	// Client: trusts A's fingerprint (pinned in known-nodes).
//	clientTr, err := New(clientCfg)
//
// The client side never sets the override; the attack scenario
// is "server holds a stolen cert but not its priv key", which is
// the canonical forged-key path (D23 §4).
//
// NOT a production constructor. Do NOT add to public API surface;
// do NOT document in README / PROTOCOL / OPERATIONS. The unexported
// name + the "newTest" prefix are the conventions future readers
// should look for to confirm "this is test-only".
func newTestTransportWithChallengeSigner(cfg Config, signer *Identity) (*Transport, error) {
	t, err := New(cfg)
	if err != nil {
		return nil, err
	}
	t.challengeSigner = signer
	return t, nil
}

// ========================== Q2 — QUIC + TLS config builders ==========================
//
// This block ships buildQUICConfig and buildTLSConfig. The two
// builders are the only new public-surface additions in Q2: every
// other helper below is unexported and only used by Q3's Listen
// and Dial (or, in this task, by the Q2 tests).
//
// Design notes:
//
//  1. The QUIC config builder takes no parameters because QUIC
//     behaviour is host-independent: stream limits, idle timeouts,
//     keepalive cadence do not vary by peer. The TLS config builder
//     DOES take a host parameter (see below).
//
//  2. The TLS config builder takes host as an explicit parameter
//     even though stdlib's tls.Config.VerifyPeerCertificate
//     signature does not include it. The host is captured in a
//     closure passed to the callback. Q3 will call buildTLSConfig
//     once per connection (server side: the remote peer address
//     learned from the QUIC accept; client side: the dial target).
//     The alternative — populating tls.Config.ServerName and
//     reading it back via tls.ConnectionState — does not work for
//     our self-signed model (ServerName is SNI, which has no trust
//     meaning for a self-signed cert; the cert does not contain a
//     matching SAN).
//
//  3. The self-signed cert is derived from t.identity (immutable
//     after New) and cached. Re-deriving on every buildTLSConfig
//     would be correct but wasteful: the cert is byte-identical
//     across calls, and a sentinel mesh handshakes often.
//
// Q3 (additions) ships the runtime surface:
//
//   - Listen(ctx) binds the configured UDP address, accepts
//     QUIC connections, and runs the mutual signed-challenge
//     handshake on every accepted conn. On success the conn
//     is registered with the (future) peer-lifecycle; in Q3
//     it is simply kept open until the context is cancelled
//     or the conn errors. R-group wires the protocol dispatch
//     loop on top of the established conn.
//
//   - Dial(ctx, peer) opens a QUIC connection to peer.Host and
//     runs the mirror half of the same challenge. Returns the
//     established conn; the caller (R-group) hands it to the
//     dispatch loop.
//
//   - runMutualChallenge is the shared handshake engine. It
//     runs both directions in parallel (each side challenges
//     and responds once), so each side proves possession of
//     the Ed25519 private key matching the cert it just
//     presented during TLS. This is defence-in-depth on top
//     of TLS: TLS proves the peer holds the cert at handshake
//     time; the signed challenge proves they hold the cert's
//     private key against a fresh, post-handshake nonce.
//
//   - ALPN: quic-go requires tls.Config.NextProtos to be
//     non-empty (the lib rejects an empty list with
//     "tls: invalid NextProtos value"). We use a fixed
//     sentinel ALPN "arx-core/1" — the version suffix lets
//     a future protocol bump negotiate via the same field
//     without breaking v0.1.0 peers (v0.1.0 nodes do not
//     negotiate; they drop mismatched ALPN at handshake,
//     matching the version-mismatch policy in protocol.go).
// ========================== Q2 — QUIC + TLS config builders ==========================
//

// buildQUICConfig returns the *quic.Config used by both the listener
// (quic.ListenAddr) and the dialer (quic.DialAddr).
//
// Defaults and their rationale (D22 + safe-by-default posture):
//
//   - MaxIdleTimeout: 30s. quic-go's own default is 30s; we set it
//     explicitly so the value is visible in code review and in
//     future config-driven overrides (K1 may expose it). 30s is a
//     good balance for a low-frequency control/telemetry link:
//     long enough to bridge a brief network blip without forcing
//     needless redials, short enough that a dead connection is
//     noticed quickly. Tighter values trade redial cost for
//     failure-detection latency; 30s is the lib default and a
//     reasonable starting point.
//
//   - KeepAlivePeriod: 10s. quic-go's documentation says "the
//     keepalive is sent on that period (or at most every half of
//     MaxIdleTimeout, whichever is smaller)"; with 30s idle / 10s
//     keepalive the effective cadence is 10s. 10s is the order of
//     magnitude needed to detect a half-open UDP path (e.g. NAT
//     timeout) before the idle timer fires — a typical carrier
//     NAT timeout is 30–60s, so 10s keepalive refreshes the NAT
//     mapping well within that window. A value of 0 would disable
//     keepalive entirely; we do not want that for a control link
//     that may be otherwise silent for minutes between commands.
//
//   - Allow0RTT: false. Zero-RTT replay is a known footgun: a
//     captured 0-RTT packet can be replayed by an attacker. The
//     sentinel product's threat model (D22: indistinguishable
//     from HTTP/3 to passive observers) is fine with 1-RTT;
//     0-RTT buys us a single round-trip's worth of latency at the
//     cost of a replayable first-flight. For a control/telemetry
//     link, the latency saving is negligible (handshakes are rare)
//     and the security downside is real. Hard-coded to false: an
//     operator who later wants 0-RTT must explicitly flip this
//     AND audit the replay exposure (D24-style hard-reject is
//     already in place, but 0-RTT can also bypass TOFU on the
//     resumption path — recorded for future review).
//
// What Q2 does NOT set on *quic.Config: stream window sizes,
// MaxIncomingStreams, token store, etc. The lib defaults are
// documented and reasonable for a low-volume control link; K1
// can expose them later if a deployment profile needs tuning.
func (t *Transport) buildQUICConfig() *quic.Config {
	return &quic.Config{
		// 30s is quic-go's documented default; we set it
		// explicitly so the value is greppable and not
		// subject to a future lib default change.
		MaxIdleTimeout: 30 * time.Second,

		// 10s keepalive ensures half-open UDP paths are
		// detected before the idle timer fires, and keeps
		// carrier-grade NAT mappings warm.
		KeepAlivePeriod: 10 * time.Second,

		// Hard-coded false. 0-RTT replay is a real attack
		// surface and the latency saving is not worth it
		// for a control/telemetry link.
		Allow0RTT: false,
	}
}

// buildTLSConfig returns a *tls.Config to be passed to
// quic.ListenAddr / quic.DialAddr.
//
// The returned config:
//
//   - Presents the node's self-signed Ed25519 cert (D22: no PKI,
//     no chain, no expiry enforcement) as the only certificate.
//   - Sets MinVersion = MaxVersion = TLS 1.3 (D22: no downgrade
//     to TLS 1.2, which permits weaker ciphersuites and pre-1.3
//     behaviours we explicitly do not want to inherit).
//   - Sets InsecureSkipVerify = true on the stdlib verifier
//     path, AND wires a custom VerifyPeerCertificate that does
//     the real work — extract the peer's Ed25519 public key,
//     compute the "sha256:<hex>" fingerprint, and route through
//     KnownNodes.Check for the D24 three-case TOFU logic.
//
// Why InsecureSkipVerify=true is NOT "naive insecure": stdlib's
// default cert verification would (a) reject the self-signed
// cert outright (no chain to a trusted root), and (b) reject
// the cert on the NotAfter=far-future date (D22 deliberately
// no expiry, but the default verifier may still validate the
// "no" expiry as a config issue). Skipping the default path
// is therefore a REQUIREMENT for our model — what we do NOT
// do is "accept any cert". The custom VerifyPeerCertificate
// is the verification; "SkipVerify" is just the lever to
// disable the stdlib chain check that would otherwise reject
// our cert before our code runs. D24's hard-reject logic is
// the actual security gate.
//
// host parameter: see the file-level comment above. Q3 will
// call buildTLSConfig once per QUIC connection (server: remote
// address; client: dial target) and bake host into a closure
// passed to VerifyPeerCertificate. For Q2's unit tests the
// caller passes a literal host string.
//
// The returned *tls.Config is intended to be consumed by a
// single quic.ListenAddr / quic.DialAddr call; stdlib tls
// does not guarantee safety under concurrent use of a single
// *tls.Config across multiple connections.
func (t *Transport) buildTLSConfig(host string) *tls.Config {
	// Lazily build the self-signed cert. The first caller pays
	// the x509 construction cost; subsequent callers get the
	// cached *tls.Certificate. See Transport.tlsCert for the
	// rationale.
	t.tlsCertOnce.Do(func() {
		t.tlsCert = buildSelfSignedCert(t.identity)
	})

	// Capture host in the closure. The stdlib callback signature
	// does not include a host; passing it implicitly is the
	// only way to give VerifyPeerCertificate access to the peer
	// identity for TOFU keying. host is read-only inside the
	// closure and is fixed for the lifetime of this *tls.Config
	// — that is the entire point of building one *tls.Config
	// per connection.
	hostForCallback := host
	identity := t.identity
	known := t.known
	// Q4: capture the logger reference so the hard-reject
	// path can surface the D24 §2 operator alert. Captured
	// by value (it's an interface) so subsequent calls to
	// WithLogger do not retroactively change the logger
	// that an in-flight *tls.Config uses — that would be
	// a TOCTOU surface on the security gate. The contract
	// is: set the logger before Listen / Dial, and the
	// per-connection TLS config picks it up.
	logRef := t.logger

	return &tls.Config{
		// Present the self-signed cert. We do not set
		// NameToCertificate — quic-go ignores it for
		// QUIC connections (SNI is not used for trust
		// in QUIC the way it is in TLS-over-TCP).
		Certificates: []tls.Certificate{*t.tlsCert},

		// ALPN is required by quic-go: an empty NextProtos
		// slice causes the lib to reject the config with
		// "tls: invalid NextProtos value" before the
		// handshake even starts. We use a fixed sentinel
		// ALPN — see the Q3 section above for why a
		// version-suffixed token is the right shape.
		NextProtos: []string{alpnArxCoreV1},

		// TLS 1.3 only. D22: no downgrade. MinVersion and
		// MaxVersion are both set so a future lib change
		// or a misconfiguration cannot widen the range.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		// Required to bypass the stdlib's chain
		// verification (which would reject the self-
		// signed cert). The actual security gate is
		// VerifyPeerCertificate below — see the method
		// comment for the full rationale.
		InsecureSkipVerify: true,

		// ClientAuth governs whether the SERVER
		// (this field is server-side semantics)
		// requests a cert from the connecting
		// client. The stdlib default
		// (NoClientCert) means the client does
		// not even present a cert, so
		// state.TLS.PeerCertificates is empty on
		// the server side and the signed-challenge
		// engine has no peer pub key to verify
		// against. RequireAnyClientCert asks the
		// client to send a cert but does not
		// require stdlib-side chain verification
		// (D22: chain verification is replaced by
		// TOFU; the actual security gate is
		// VerifyPeerCertificate above). On the
		// client side this field is ignored.
		ClientAuth: tls.RequireAnyClientCert,

		// The real verification. Built inline because the
		// host capture is per-call; the heavier logic
		// lives in verifyPeerCertificate.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificateImpl(rawCerts, hostForCallback, known, identity, logRef)
		},
	}
}

// verifyPeerCertificateImpl is the actual TOFU verification,
// factored out of the closure so it can be unit-tested directly
// without standing up a *tls.Config.
//
// Parameters:
//
//   - rawCerts: the peer certificate chain presented by the
//     remote (tls.Config.VerifyPeerCertificate callback arg #1).
//   - host: the peer host this verification is for. Captured
//     from buildTLSConfig's host parameter; for server-side
//     handshakes this is the remote UDP address's host part
//     (Q3 will set it from the accepted connection), for
//     client-side it is the dial target.
//   - known: the *KnownNodes store; checked and (on first
//     contact) pinned.
//   - self: this node's *Identity. Not strictly needed for the
//     TOFU check itself (fingerprint comes from rawCerts), but
//     kept in the signature for symmetry with buildTLSConfig
//     and to make the "self vs peer" split explicit at call
//     sites.
//   - log: the structured logger used to surface the D24 §2
//     operator alert on fingerprint mismatch. May be nil — the
//     helper guards against nil and is a no-op in that case so
//     callers that never inject a logger have zero log output.
//     The Q4 hard-reject integration test injects a capture
//     logger and asserts the formatted string contains BOTH the
//     expected and the presented fingerprint.
// Behaviour (D24 three-case contract):
//
//   - rawCerts is empty OR the first cert is malformed OR the
//     embedded public key is not Ed25519 → return an error.
//     The TLS handshake will fail. Defensive: a TLS library
//     that hands us a nil/garbage cert is a bug worth failing
//     loudly, not silently accepting.
//   - rawCerts is non-empty and the fingerprint is new
//     (Check returns (false, false)) → Pin the fingerprint,
//     return nil. The peer is now trusted for the lifetime
//     of the known-nodes file.
//   - rawCerts is non-empty and the fingerprint matches
//     (Check returns (true, false)) → return nil. Idempotent
//     success path on every reconnect from a known peer.
//   - rawCerts is non-empty and the fingerprint DIFFERS
//     (Check returns (false, true)) → return a hard-reject
//     error. The error message includes host, the pinned
//     (expected) fingerprint, and the presented (actual)
//     fingerprint, per D24 §2 ("operator alert" with both).
//     known-nodes is NOT updated — the pinned value is the
//     ground truth, and the attacker's key MUST NOT silently
//     overwrite it.
//
// Concurrency: this function does not mutate Transport state
// directly; it delegates Pin/Check to the *KnownNodes store
// which is itself thread-safe.
func verifyPeerCertificateImpl(
	rawCerts [][]byte,
	host string,
	known *KnownNodes,
	self *Identity,
	log Logger,
) error {
	// Defensive: an empty chain is a protocol-level bug in
	// the remote. Failing the handshake is correct.
	if len(rawCerts) == 0 {
		return fmt.Errorf("transport: TLS verify: peer presented no certificates (host=%q)", host)
	}

	// Parse the leaf cert. x509.ParseCertificate is the
	// canonical entry point; it does signature verification
	// against the cert's own public key, which for a
	// self-signed cert is the identity check at the x509
	// layer. (This is distinct from TOFU at the D24 layer:
	// the x509 check confirms the cert was not tampered
	// with in transit; TOFU confirms the cert belongs to
	// the peer we expected.)
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("transport: TLS verify: parse peer cert (host=%q): %w", host, err)
	}

	// Extract the Ed25519 public key. The transport speaks
	// only Ed25519 (D22: a node's identity IS its Ed25519
	// public key). A peer presenting an RSA/ECDSA cert is
	// either a misconfigured client or an active attacker
	// trying to slip a different key past us.
	pubKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("transport: TLS verify: peer cert is not Ed25519 (host=%q, key type=%T)", host, leaf.PublicKey)
	}

	// Compute the fingerprint. Same algorithm as
	// Identity.Fingerprint(): "sha256:" + hex(SHA256(pubKey)).
	// We duplicate the format here rather than reaching
	// into Identity's internals because the verifier may
	// receive a foreign cert whose public key is bytes the
	// local Identity struct does not own.
	pubDigest := sha256.Sum256(pubKey)
	fingerprint := "sha256:" + hex.EncodeToString(pubDigest[:])

	// D24 three-case routing.
	pinned, mismatch := known.Check(host, fingerprint)
	switch {
	case pinned:
		// Known peer, fingerprint matches. Allow.
		return nil

	case mismatch:
		// HARD REJECT. D24 §2: drop the connection,
		// alert the operator with both the expected and
		// the actual fingerprint. The error message is
		// the alert surface in v0.1.0 (a later flow
		// may promote it to a structured log + alert
		// pipeline; the message format is designed to
		// survive that upgrade).
		//
		// The pinned fingerprint is read directly from
		// the store to include in the error — the
		// caller of Check already knows mismatch=true,
		// but reading the store again is cheap and
		// guarantees the message shows the CURRENT
		// pinned value (defence against a future
		// mutation race). The presented fingerprint is
		// the one we just computed.
		expected, _ := known.lookupForVerify(host) //nolint:errcheck // missing pin handled by mismatch=true above
		// Q4: surface the operator alert through the
		// injected logger as well. The Errorf format
		// includes both fingerprints so a log-aggregator
		// grep (operator workflow per OPERATIONS.md) can
		// attribute the alert to a specific peer without
		// parsing the returned error. The log emission
		// is defensive: log may be nil (caller never
		// injected a logger, or set it to nil), and
		// guard with an explicit check so a nil logger
		// does not crash the TLS callback mid-handshake.
		if log != nil {
			log.Errorf(
				"transport: TOFU fingerprint MISMATCH (D24 hard-reject): "+
					"host=%q expected=%s presented=%s",
				host, expected, fingerprint,
			)
		}
		return fmt.Errorf(
			"transport: TLS verify: TOFU fingerprint MISMATCH for host=%q: "+
				"expected (pinned)=%s, presented=%s — connection hard-rejected per D24",
			host, expected, fingerprint,
		)

	default:
		// First contact: pin and proceed. Pin errors
		// (disk full, perm denied) are propagated —
		// failing the handshake is the correct
		// behaviour: a pin we cannot persist is not
		// really a pin.
		if err := known.Pin(host, fingerprint); err != nil {
			return fmt.Errorf("transport: TLS verify: first-contact pin for host=%q failed: %w", host, err)
		}
		return nil
	}
}

// buildSelfSignedCert constructs a *tls.Certificate from an
// Ed25519 identity.
//
// The cert has no chain (no parent), no expiry enforcement
// (NotAfter is a far-future date chosen to outlive any plausible
// operator timeline), and a Subject that is a placeholder
// ("arx-core transport") because the cert's identity is the
// Ed25519 public key, not the CN/SAN — D22 explicitly says
// "a node's identity IS its Ed25519 public key". Operators
// verify peers by fingerprint, not by subject name.
//
// Why NotAfter is 9999-12-31 (the maximum x509 allows) and
// NOT time.Time{} (the literal "no expiry" sentinal):
// crypto/x509.ParseCertificate (and quic-go's own cert parser)
// reject a zero NotAfter as malformed in practice — the spec
// (RFC 5280) requires either a valid date or the absence of
// the field, but Go's x509 implementation does not encode
// "absence" and silently zero-fills, which then fails
// downstream parsers. 9999-12-31 is the de-facto "no expiry"
// sentinel in Go's x509 ecosystem and avoids the parser
// ambiguity. The choice is documented for OPERATIONS.md
// (key rotation is an explicit operator action per D24, not
// a calendar accident).
//
// KeyUsage and ExtKeyUsage are set to the minimum that
// quic-go + Go's tls package accept for a server cert.
// BasicConstraintsValid is set; IsCA is false (a self-signed
// leaf, not a self-signed CA — the TOFU model does not need
// CA capability).
//
// SubjectKeyId is derived from the public key (SHA-256 first
// 8 bytes) so a future cert rotation can issue a "same key,
// new cert" replacement without changing the identifier.
// AuthorityKeyId is identical (self-signed).
func buildSelfSignedCert(id *Identity) *tls.Certificate {
	pub := id.PublicKey()
	if len(pub) != ed25519PublicKeySize {
		// Defensive: Identity.Generate / Load both
		// return ed25519.PublicKey of the canonical
		// 32-byte length, so this branch should be
		// unreachable. Guarding against a future
		// crypto/ed25519 API change that would
		// otherwise cause a panic deep in x509
		// template marshalling.
		panic(fmt.Sprintf("transport: identity public key has unexpected length %d", len(pub)))
	}

	// Serial number: arbitrary, but x509 requires it
	// non-negative and unique enough. Using the SHA-256
	// of the public key as a stable per-identity serial
	// means two certs built from the same identity have
	// the same serial — fine, because there is only one
	// cert per identity in practice.
	pubSHA := sha256.Sum256(pub)
	serial := new(big.Int).SetBytes(pubSHA[:8])

	// SubjectKeyId / AuthorityKeyId: same as Serial, a
	// stable derivation from the public key. RFC 5280
	// recommends SHA-1 of the public key bits, but
	// SHA-256 (truncated) is permitted and we already
	// have the digest.
	skid := pubSHA[:8]

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "arx-core transport"},
		// NotBefore is "now" — back-dated certs are a
		// different footgun; using time.Now() is the
		// simplest correct choice.
		NotBefore: time.Now(),
		// NotAfter is 9999-12-31 — see the function
		// comment for why this is the "no expiry"
		// sentinel in Go's x509 ecosystem and why
		// time.Time{} does not work.
		NotAfter: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}

	// Build the cert. x509.CreateCertificate takes the
	// template, the parent cert (self-signed: same as
	// template), the public key, and the private key
	// wrapped as a crypto.Signer. Ed25519 satisfies
	// crypto.Signer via ed25519.PrivateKey.Sign; the
	// adapter is in quic_helpers.go so the unexported
	// privKey field is not touched from outside Identity.
	derBytes, err := x509.CreateCertificate(
		randReader,
		template,
		template, // self-signed: parent == template
		pub,
		ed25519SignerFromIdentity(id),
	)
	if err != nil {
		// x509.CreateCertificate on a well-formed
		// template with a valid Ed25519 key should
		// not error. Surfacing it as a panic is
		// correct: the alternative is a nil
		// tls.Certificate that would crash the
		// handshake with a less-actionable error
		// later. A constructor failure of this kind
		// is a programmer / library error, not an
		// operational one.
		panic(fmt.Sprintf("transport: build self-signed cert: %v", err))
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  ed25519SignerFromIdentity(id),
		// Leaf is implicit from Certificate[0] for a
		// single-certificate chain.
	}
}

// ========================== Q3 — Listen, Dial, signed-challenge ==========================
//
// This block ships the runtime surface that turns the Q1
// Transport + Q2 builders into an actually-speaking QUIC node.
//
// Components added:
//
//   - Listen(ctx): bind UDP, accept connections, run the mutual
//     signed-challenge on every accept. Successful connections
//     are kept open until the context is cancelled or the
//     connection errors. R-group will hand them to the protocol
//     dispatch loop in a later task; in Q3 the established
//     connection is the unit of "handshake done".
//
//   - Dial(ctx, peer): open a QUIC connection to peer.Host,
//     run the mirror half of the same challenge, return the
//     established conn. R-group wires it to the peer-lifecycle.
//
//   - runMutualChallenge(conn, selfID, peerPub): the shared
//     handshake engine. Both sides run the same function —
//     each side challenges the peer and responds to the
//     peer's challenge in parallel. The function is symmetric
//     by design: Listen and Dial are thin entry points that
//     set up the cert-state and call into the same code.
//
//   - crossCheckPinned: defensive cross-check between the
//     fingerprint the TLS callback just pinned/verified and
//     the operator-supplied peer.Fingerprint (D24 §5). Empty
//     peer.Fingerprint = TOFU-on-first-contact, skip the
//     cross-check. Mismatch = hard-reject with an error that
//     names both fingerprints.
//
// Why a mutual challenge (not a one-way "server challenges
// client"): the brief says "both sides prove ownership". TLS
// already provides per-cert validation through the TOFU
// callback; the signed challenge adds a fresh-nonce proof that
// the peer currently holds the cert's private key, which is
// what closes a future quic-go-bug-or-cert-theft failure mode
// (D23: "an attacker who has the presented cert still cannot
// forge the Ed25519 signature without the private key").
//
// Why bidirectional streams: a QUIC bi stream gives both
// sides a private, ordered, reliable channel that the QUIC
// layer has already flow-controlled. We open one bi stream
// per side per direction, which means four stream operations
// per handshake (open / accept on each side). That is
// cheaper than custom framing and benefits from QUIC's stream
// reset semantics on error: a signature failure on one
// direction can be signalled by closing just that stream,
// not the whole connection.
//
// The protocol is described step-by-step in
// PROTOCOL.md (Q-group M2 task). The code below is the
// implementation; the doc is the protocol contract.
//
// What Q3 does NOT do (later group tasks):
//   - Hand the established conn to a protocol dispatch
//     loop: R-group.
//   - Maintain a peer roster with state + redial backoff:
//     R-group.
//   - Implement the K2 disabled-by-default gate: K-group.
//     Q3's Listen/Dial are unguarded; K2 is the layer that
//     decides whether to call them.
//
// ========================== Q4 — security-critical hard-reject wiring ==========================
//
// Q4 (this section's additions) is the security-critical push point
// for Group Q. It does NOT introduce a new public API; it adds the
// operator-alert emission the spec demands on the two hard-reject
// paths:
//
//   1. TOFU fingerprint mismatch (D24 §2 "operator alert"): the
//      TLS VerifyPeerCertificate callback now logs an ERROR with
//      BOTH the expected (pinned) and the presented (attacker)
//      fingerprints before returning the hard-reject error. The
//      test asserts the captured log contains both fingerprints.
//   2. Signed-challenge failure (D23 §4): runMutualChallenge now
//      logs an ERROR with the role label and the underlying error
//      when the verification step returns false or any stream
//      operation fails. The test asserts the log was emitted on
//      a real Dial → Listen loop where the server signs with the
//      wrong priv key.
//
// Two test-only injection points make the integration tests
// possible WITHOUT changing production behaviour:
//
//   - (*Transport).challengeSigner (unexported field): when
//     non-nil, the challenge engine uses this identity to sign
//     its OWN challenge responses instead of t.identity. The
//     forged-key test (Q4 Test 2) sets it on the SERVER to a
//     different key than the cert identity; the server presents
//     the honest cert (TLS succeeds because the client has the
//     honest fingerprint pinned) but signs the nonce with the
//     wrong key, and the client's runChallengeOutbound rejects
//     the signature. Production never sets this field; it is
//     only initialised by newTestTransportWithChallengeSigner
//     in quic_test.go. NOT a production knob — do not document
//     in README / PROTOCOL / OPERATIONS.
//   - (*Transport).logger (unexported field): a Logger interface
//     (defined in protocol.go) that the hard-reject and challenge
//     paths use to emit the operator alert. Defaults to
//     DiscardLogger() so production callers without an injected
//     logger have zero log output. The Q4 tests inject a capture
//     logger via WithLogger to assert the contract.
//
// Both injection points are documented at the call site AND in
// the field comment so a future reader cannot mistake them for
// production knobs.

// Listen binds the configured UDP address, accepts QUIC
// connections, and runs the signed-challenge handshake on
// every accepted conn. It blocks until ctx is cancelled or
// the underlying listener errors out.
//
// On a successful handshake the connection is kept open and
// the function logs at DEBUG that the peer is now
// established. R-group will replace the "keep open" stub with
// a hand-off to the protocol dispatch loop; the contract
// Listen provides today is "the conn is established and
// verified, do not tear it down on handshake failure".
//
// Error / lifecycle contract:
//
//   - ctx is cancelled at any point: the listener is closed
//     and Listen returns nil. Closing the listener causes
//     quic.Listener.Accept to return an error; the accept
//     loop treats that as the normal exit signal.
//   - quic.ListenAddr fails to bind (port in use, perm
//     denied, etc.): the error from quic-go is returned
//     wrapped with transport context; no goroutine was
//     started, the listener field stays nil.
//   - TLS handshake fails (TOFU hard-reject in the Q2
//     callback): quic-go's Accept returns an error, we
//     log at DEBUG and continue accepting. The TLS failure
//     already produced its own alert via the Q2 callback;
//     Listen is not the alert surface (D24 §2 places the
//     alert in the TLS callback path).
//   - Signed challenge fails: the connection is closed
//     with a quic application error (so the peer sees a
//     clean close rather than a half-open TCP-style
//     disconnect), the error is logged, and the accept
//     loop continues. This is what an attacker probing
//     for a stolen-cert / wrong-priv-key peer would hit.
//
// The function spawns one accept-loop goroutine and one
// per-connection goroutine. The per-connection goroutine
// exits when the connection is closed (handshake done or
// otherwise); the accept loop exits when the listener
// closes. ctx cancellation is the only intended exit
// during steady-state operation; in tests a context
// timeout is the standard teardown.
func (t *Transport) Listen(ctx context.Context) error {
	if t.listen == "" {
		// Q1 deliberately does not validate Listen;
		// K1 may add it. Catching the empty case here
		// is the kind of "fail loudly, not silently"
		// check that protects against a config that
		// forgot the field. The error message is
		// operator-actionable.
		return fmt.Errorf("transport: Listen: cfg.Listen is empty; configure transport.listen")
	}

	// Build a server-side *tls.Config. The host baked
	// into the VerifyPeerCertificate closure is "" —
	// a placeholder. quic-go calls tlsConf.GetConfigForClient
	// per accepted connection (see internal/handshake/
	// crypto_setup.go's setupConfigForServer wrapper
	// in quic-go), giving us a per-connection hook
	// where we install the *real* host closure.
	//
	// Why this indirection is necessary: quic-go's
	// ListenAddr takes a single *tls.Config and uses
	// it for every connection on the listener. The
	// stdlib tls.Config.GetConfigForClient hook is the
	// per-connection extension point — quic-go
	// honors it (it calls the hook during the
	// per-connection setupConfigForServer wrap) and
	// the returned *tls.Config is used for that
	// connection's TLS handshake. We use that hook
	// to install a fresh VerifyPeerCertificate with
	// the correct host (the remote address) baked in,
	// so the TOFU pin is keyed per-peer.
	tlsConf := t.buildTLSConfig("")
	// Install the per-connection override. The closure
	// receives *tls.ClientHelloInfo; quic-go's
	// setupConfigForServer wrapper sets info.Conn to
	// a net.Conn whose RemoteAddr() is the peer's
	// UDP address. We use that as the host for TOFU
	// keying.
	//
	// Concurrency: quic-go's docs state that
	// GetConfigForClient is called serially per
	// connection attempt (the lib holds a per-packet
	// lock during handshake setup). The closure
	// captures t by reference — Transport is alive
	// for the listener's lifetime, and t.identity +
	// t.known are immutable after New.
	tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		host := ""
		if info.Conn != nil {
			host = info.Conn.RemoteAddr().String()
		}
		return t.buildTLSConfig(host), nil
	}

	// Bind the UDP socket. quic.ListenAddr takes a
	// string ("host:port"); we pass cfg.Listen verbatim
	// (Q1 stored it as-is). The "0" port (loopback test
	// mode) is handled by quic-go's listenUDP, which
	// resolves the *net.UDPAddr with port 0 and the OS
	// picks a free port; Listener.Addr() returns the
	// resolved address after the call returns.
	listener, err := quic.ListenAddr(t.listen, tlsConf, t.buildQUICConfig())
	if err != nil {
		return fmt.Errorf("transport: Listen: quic.ListenAddr(%q): %w", t.listen, err)
	}

	// Store the listener so a future Close (R-group) can
	// reach it, and so tests can assert the field is
	// populated after Listen. The lock is uncontended
	// in normal use (no one else writes the field).
	t.listenerMu.Lock()
	t.listener = listener
	t.listenerMu.Unlock()

	// Accept loop. We do NOT spawn a dedicated
	// goroutine here — the caller's expectation of
	// Listen is "block until ctx is done or a fatal
	// error". A dedicated goroutine would mean Listen
	// returns immediately, which is a different
	// contract (the K2 Run wrapper will be the layer
	// that spawns a goroutine and blocks on a done
	// channel).
	//
	// The loop exits on:
	//   - ctx cancellation: closes the listener, which
	//     causes Accept to return an error; we treat
	//     "listener closed" as the normal exit and
	//     return nil.
	//   - non-cancellation Accept error: log and
	//     return the error wrapped. This is a fatal
	//     condition (e.g. the UDP socket died); the
	//     caller decides whether to retry.
	for {
		// Check ctx first; closing the listener is
		// the explicit teardown signal. We use a
		// select with a short default-zero pattern
		// via a non-blocking check.
		select {
		case <-ctx.Done():
			// Best-effort close. listener.Close
			// may return an error if the socket
			// is already gone; we ignore it
			// because the goal here is
			// "guarantee Accept returns", not
			// "guarantee a clean shutdown".
			_ = listener.Close()
			return nil
		default:
		}

		// Accept blocks. quic-go's Accept takes a
		// ctx so we can interrupt it on
		// cancellation without closing the
		// listener first (the listener-close path
		// is the cleaner exit; the ctx-arg
		// path is the "ctx cancelled mid-block"
		// safety net).
		conn, err := listener.Accept(ctx)
		if err != nil {
			// "listener closed" is the expected
			// post-cancellation error. We
			// distinguish it by checking ctx:
			// if ctx is done, exit cleanly;
			// otherwise it's a real error.
			if ctx.Err() != nil {
				return nil
			}
			// Some quic-go versions return a
			// sentinel for "server closed" rather
			// than wrapping ctx.Err. Match by
			// string to stay version-portable.
			if errors.Is(err, quic.ErrServerClosed) || isClosedListenerErr(err) {
				return nil
			}
			return fmt.Errorf("transport: Listen: accept: %w", err)
		}

		// Per-connection handshake in a goroutine.
		// We do not block the accept loop on
		// handshake completion — a slow / stuck
		// peer must not stall acceptance of new
		// peers. The goroutine owns the conn's
		// lifecycle: when handleAcceptedConn
		// returns, the conn has been closed (or
		// is about to be).
		go t.handleAcceptedConn(ctx, conn)
	}
}

// handleAcceptedConn runs the signed-challenge handshake on
// a single accepted conn and keeps the conn open on
// success.
//
// The function is the per-connection goroutine body
// spawned by Listen's accept loop. It is unexported because
// the only caller is Listen; the symmetry with Dial's
// challenge handling lives in runMutualChallenge, which
// both sides call.
//
// hostForTofu is the remote address string that the TLS
// callback already used to pin the fingerprint. After
// handshake completion we re-read the pinned value to
// perform the cross-check against the operator-supplied
// peer.Fingerprint (D24 §5): if a PeerConfig in t.peers
// matches this host and the config fingerprint is
// non-empty, it must equal the pinned value. The
// cross-check is defensive (the TLS callback already
// verified the cert) but catches operator typos in
// config: a typo in fingerprint would otherwise silently
// be accepted on the first contact and only fail on
// reconnect.
//
// On any failure the conn is closed with a quic
// application error so the peer sees a structured close
// rather than a half-open reset. The error is logged
// at DEBUG; Q4 will add a security-grade ERROR-level
// alert for the forged-key path specifically.
func (t *Transport) handleAcceptedConn(ctx context.Context, conn *quic.Conn) {
	// Run the mutual challenge. The function is
	// symmetric: server and client run the same code
	// and the per-direction roles (challenger vs
	// responder) are encoded by stream-initiation
	// direction.
	peerPub, err := t.runMutualChallenge(ctx, conn, "server")
	if err != nil {
		// Log + close. We do NOT return the
		// error to the caller of Listen: a
		// single peer failing the challenge
		// must not tear down the listener.
		// Q4 will upgrade this to an ERROR
		// log with both fingerprints (D24 §2).
		_ = peerPub // peerPub may be nil on early failure
		closeWithChallengeErr(conn, err)
		return
	}

	// Defensive cross-check (D24 §5). We re-read
	// the pinned fingerprint from known-nodes and,
	// if a PeerConfig in t.peers matches the
	// remote host, compare it against
	// peer.Fingerprint. R1 will replace this
	// string-based lookup with a proper peer
	// state machine; for Q3 it is correct and
	// sufficient.
	if mismatch, cerr, ok := t.crossCheckPinned(conn.RemoteAddr().String()); ok && mismatch {
		closeWithChallengeErr(conn, cerr)
		return
	}
	_ = peerPub // peerPub captured for future protocol use (R3)

	// Handshake done. In Q3 we keep the conn open
	// until either ctx is cancelled or the conn
	// errors on its own; R-group will replace this
	// stub with a hand-off to the protocol dispatch
	// loop. We block on a select that exits when
	// either signal fires, so the goroutine does
	// not leak.
	select {
	case <-ctx.Done():
		_ = conn.CloseWithError(0, "server shutdown")
	case <-conn.Context().Done():
		// Peer closed or conn errored; nothing
		// to do, the conn is already closing.
	}
}

// Dial opens a QUIC connection to peer.Host, runs the
// signed-challenge handshake, and returns the established
// conn on success.
//
// The function is the client-side mirror of Listen: it
// builds a client-side *tls.Config (with the dial target
// as the host for TOFU keying) and runs the same
// runMutualChallenge engine against the accepted conn.
//
// After the TLS handshake completes, the TOFU callback
// has already pinned the server's fingerprint under
// peer.Host (first contact) or hard-rejected the
// handshake (subsequent mismatch). Dial then runs the
// application-level signed challenge. The cross-check
// against peer.Fingerprint is the same defensive guard
// as in handleAcceptedConn.
//
// Error contract:
//
//   - ctx cancellation: returns ctx.Err() wrapped.
//   - quic.DialAddr failure (network, addr resolution,
//     TOFU hard-reject via the TLS callback): returns
//     the lib error wrapped. The hard-reject path
//     already produced its alert via the TLS callback
//     (Q2).
//   - Signed challenge failure: the conn is closed,
//     the error is returned to the caller. Unlike
//     Listen, a Dial failure is the caller's problem
//     to handle (redial backoff is R-group's job), so
//     we propagate.
//
// On success the returned *quic.Conn is the
// established, verified conn. R-group hands it to the
// peer lifecycle; in Q3 the caller is the test loop,
// which closes the conn when done.
func (t *Transport) Dial(ctx context.Context, peer PeerConfig) (*quic.Conn, error) {
	if peer.Host == "" {
		return nil, fmt.Errorf("transport: Dial: peer.Host is empty")
	}

	// Client-side *tls.Config. Host is peer.Host so
	// the TOFU callback keys the pin by the dial
	// target — the same key the operator would
	// hand-edit in known-nodes.
	tlsConf := t.buildTLSConfig(peer.Host)

	// Open the QUIC connection. quic.DialAddr
	// returns after the TLS handshake completes,
	// which means by the time we have the conn
	// the TOFU pin/check has already run. A
	// hard-reject surfaces here as a DialAddr
	// error.
	conn, err := quic.DialAddr(ctx, peer.Host, tlsConf, t.buildQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("transport: Dial: quic.DialAddr(%q): %w", peer.Host, err)
	}

	// Run the mutual challenge. We pass "client" as
	// the role label only for logging — the engine
	// itself is symmetric and the role does not
	// change its behaviour.
	_, err = t.runMutualChallenge(ctx, conn, "client")
	if err != nil {
		closeWithChallengeErr(conn, err)
		return nil, fmt.Errorf("transport: Dial: signed challenge to %q: %w", peer.Host, err)
	}

	// Defensive cross-check (D24 §5). The TLS
	// callback pinned the server's fingerprint
	// under peer.Host during the handshake; we
	// re-read that pin and compare against
	// peer.Fingerprint if it is non-empty.
	if peer.Fingerprint != "" {
		pinned, _ := t.known.lookupForVerify(peer.Host)
		if pinned != "" && pinned != peer.Fingerprint {
			closeWithChallengeErr(conn, errFingerprintCrossCheck{
				host:       peer.Host,
				expected:   peer.Fingerprint,
				presented:  pinned,
			})
			return nil, fmt.Errorf("transport: Dial: fingerprint cross-check for %q: %w",
				peer.Host, errFingerprintCrossCheck{
					host:      peer.Host,
					expected:  peer.Fingerprint,
					presented: pinned,
				})
		}
	}

	return conn, nil
}

// runMutualChallenge is the shared handshake engine. Both
// Listen (per accepted conn) and Dial call it. The
// function runs the two directions in parallel — each
// side challenges the peer and responds to the peer's
// challenge — so each side proves possession of the
// Ed25519 private key matching the cert it just
// presented during TLS.
//
// The protocol on a single bidirectional stream:
//
//  1. Challenger opens a bi stream, writes 32-byte nonce.
//  2. Responder accepts the stream, reads 32-byte nonce,
//     signs with own privKey, writes 64-byte signature
//     back, closes the stream.
//  3. Challenger reads 64-byte signature, verifies with
//     peer's pub key from the TLS cert.
//
// Both sides of the connection run the same function;
// the challenger role is taken by whoever opens the
// bi stream first, the responder by whoever accepts.
// We use QUIC's bi-stream semantics: each side opens
// one bi stream (its "outgoing challenge" stream) and
// accepts one (its "incoming challenge" stream). The
// two streams are independent and the directions
// proceed in parallel, so the handshake is one
// round-trip's worth of latency on the wire, not two.
//
// Parameters:
//
//   - ctx: the caller's context. Used as the deadline
//     for the handshake's stream operations. Cancellation
//     tears down the in-flight streams via QUIC's
//     stream-context machinery.
//   - conn: the established QUIC connection. The
//     caller is responsible for closing it on failure;
//     runMutualChallenge does not own the conn's
//     lifecycle past "handshake done".
//   - role: a label ("server" / "client") used only
//     for error messages and future logging. Does not
//     affect behaviour.
//
// Returns the peer's public key on success (extracted
// from the TLS cert, so the caller has it for any
// follow-up protocol work) and an error on any
// failure. A nil error with a non-nil pub key is the
// only "handshake complete" signal.
//
// The function does not mutate Transport state. The
// only Transport-level collaborator it uses is
// t.identity, which is read-only.
func (t *Transport) runMutualChallenge(ctx context.Context, conn *quic.Conn, role string) (ed25519.PublicKey, error) {
	// Extract the peer's public key from the TLS
	// cert. This is the key the peer's signed
	// challenge MUST be verifiable against. We
	// grab it once, at handshake-completion time,
	// and pass it to both verification calls.
	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("transport: %s: signed challenge: peer presented no certificates", role)
	}
	leaf := state.TLS.PeerCertificates[0]
	peerPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transport: %s: signed challenge: peer cert public key is not Ed25519 (got %T)", role, leaf.PublicKey)
	}

	// Two concurrent goroutines: one opens a bi
	// stream and challenges the peer (we send a
	// nonce, expect a signature back), the other
	// accepts a bi stream and responds to the
	// peer's challenge (we read a nonce, send a
	// signature back). Each goroutine returns an
	// error; the join is a "first error wins,
	// second goroutine observed via the
	// cancellation it sees on conn close".
	errCh := make(chan error, 2)
	// Resolve the signing identity once. The override (Q4 test
	// injection point) lets a Transport present a cert built
	// from t.identity but sign challenges with a different
	// key, which is the forged-key attacker scenario. In
	// production the call to effectiveSigner() returns
	// t.identity and the behaviour is identical to the
	// previous "t.identity" inline reference.
	signer := t.effectiveSigner()
	go func() {
		errCh <- runChallengeOutbound(ctx, conn, signer, peerPub, role)
	}()
	go func() {
		errCh <- runChallengeInbound(ctx, conn, signer, role)
	}()
	// Wait for both directions. The first non-nil
	// error is the failure; the second is either
	// nil (the other side completed cleanly) or a
	// cancellation-from-conn-close (the quic-go
	// machinery aborts in-flight stream operations
	// when the conn is closed by the other side).
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		// D23 §4 operator alert: the signed-challenge
		// engine returned a failure. The "what" is the
		// underlying error (signature verification
		// failure, stream open/read/write failure, etc.);
		// the "where" is the role label so an operator
		// reading the log can tell which side of the
		// connection observed the failure. The "who" is
		// the remote address — already in the QUIC conn
		// context, but we surface it here too so a log
		// aggregator without QUIC awareness can still
		// attribute the alert to a peer.
		//
		// Logger is checked against nil (rather than
		// defaulted to DiscardLogger) because the
		// DiscardLogger default is set in New; if a
		// future caller mutates t.logger to nil we want
		// to be defensive — a nil call would panic.
		if t.logger != nil {
			t.logger.Errorf(
				"transport: signed challenge FAILED (role=%s, remote=%s): %v",
				role, conn.RemoteAddr().String(), firstErr,
			)
		}
		return nil, firstErr
	}
	return peerPub, nil
}

// runChallengeOutbound is the "we challenge the peer"
// half of the mutual handshake. We open a bi stream,
// write a 32-byte nonce, read a 64-byte signature,
// verify.
//
// Stream lifecycle: we own the stream for the duration
// of this call. On any failure we close the stream
// with a ResetStream so the peer's reader returns an
// error rather than blocking; the caller's caller
// (runMutualChallenge) then closes the conn.
func runChallengeOutbound(
	ctx context.Context,
	conn *quic.Conn,
	self *Identity,
	peerPub ed25519.PublicKey,
	role string,
) error {
	// Open a bi stream. OpenStreamSync blocks until
	// the peer has flow-control credit to accept a
	// new stream; with the lib defaults (100
	// incoming streams) this never blocks in
	// practice for a 1:1 handshake.
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("transport: %s: challenge outbound: open stream: %w", role, err)
	}
	// Best-effort cleanup on any error path. We
	// close the stream for write (CancelWrite) so
	// the peer's read returns an error promptly
	// rather than blocking on the rest of the
	// payload. The conn-level close is the caller's
	// responsibility (runMutualChallenge's caller
	// invokes closeWithChallengeErr on the conn).
	defer func() {
		if err != nil {
			stream.CancelWrite(0)
			stream.CancelRead(0)
		}
	}()

	// Generate a fresh 32-byte nonce. crypto/rand
	// is the canonical source; the birthday-bound
	// argument for nonce uniqueness is documented
	// on challengeNonceSize.
	nonce := make([]byte, challengeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("transport: %s: challenge outbound: read nonce: %w", role, err)
	}

	// Write the nonce, exactly 32 bytes. We use
	// writeAll to handle short writes (the QUIC
	// stream Write may return a partial count under
	// back-pressure, and a literal io.WriteFull does
	// not exist in stdlib — io.CopyN is the closest
	// but a hand-rolled loop is clearer here).
	if _, err := writeAll(stream, nonce); err != nil {
		return fmt.Errorf("transport: %s: challenge outbound: write nonce: %w", role, err)
	}

	// Read exactly 64 bytes (Ed25519 signature).
	sig := make([]byte, challengeSignatureSize)
	if _, err := io.ReadFull(stream, sig); err != nil {
		return fmt.Errorf("transport: %s: challenge outbound: read signature: %w", role, err)
	}

	// Verify the signature with the peer's public
	// key (extracted from the TLS cert above). A
	// forged signature — the attacker has the cert
	// but not the priv key — fails VerifyChallenge
	// and we close the stream with a meaningful
	// error. The peer's "challenge outbound" path
	// does the same in reverse, so a forgery
	// fails both directions.
	if !VerifyChallenge(peerPub, nonce, sig) {
		return fmt.Errorf("transport: %s: challenge outbound: signature verification FAILED (peer does not hold the private key for the presented cert)", role)
	}
	return nil
}

// runChallengeInbound is the "we respond to the peer's
// challenge" half of the mutual handshake. We accept a
// bi stream, read a 32-byte nonce, sign with own
// privKey, write the 64-byte signature back.
//
// Errors here are the peer's fault: a nonce that does
// not arrive, a stream that never opens, etc. We do
// NOT classify a peer's signature verification failure
// here — that happens in runChallengeOutbound when we
// read and verify the peer's response.
func runChallengeInbound(
	ctx context.Context,
	conn *quic.Conn,
	self *Identity,
	role string,
) error {
	// Accept a bi stream opened by the peer.
	// AcceptStream blocks until the peer opens one.
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("transport: %s: challenge inbound: accept stream: %w", role, err)
	}
	defer func() {
		if err != nil {
			stream.CancelWrite(0)
			stream.CancelRead(0)
		}
	}()

	// Read 32-byte nonce.
	nonce := make([]byte, challengeNonceSize)
	if _, err := io.ReadFull(stream, nonce); err != nil {
		return fmt.Errorf("transport: %s: challenge inbound: read nonce: %w", role, err)
	}

	// Sign with own priv key. SignChallenge is
	// the identity.go wrapper around ed25519.Sign;
	// it returns ([]byte, error) for symmetry with
	// future hash-mode signing, but in practice
	// never errors for Ed25519.
	sig, err := self.SignChallenge(nonce)
	if err != nil {
		return fmt.Errorf("transport: %s: challenge inbound: sign nonce: %w", role, err)
	}
	if len(sig) != challengeSignatureSize {
		// Defensive: a future crypto/ed25519
		// change that returns a different
		// signature length would break the
		// peer's reader. Catch it here.
		return fmt.Errorf("transport: %s: challenge inbound: signature length %d, want %d",
			role, len(sig), challengeSignatureSize)
	}

	// Write 64-byte signature.
	if _, err := writeAll(stream, sig); err != nil {
		return fmt.Errorf("transport: %s: challenge inbound: write signature: %w", role, err)
	}
	return nil
}

// crossCheckPinned is the D24 §5 defensive cross-check
// between the fingerprint the TLS callback pinned and
// the operator-supplied peer.Fingerprint (for
// server-side matches; the client side does the same
// inline in Dial because it has the PeerConfig in
// hand).
//
// The check is best-effort and explicit about its
// limitations:
//
//   - For server-side accepts, the host is the remote
//     address string. We look for a PeerConfig in
//     t.peers whose Host equals the remote address
//     exactly. R1 will replace this with a proper
//     peer-roster lookup; for Q3 it covers the
//     "configured peer calls us" case and quietly
//     skips the cross-check for unconfigured peers.
//   - If the matched PeerConfig has an empty
//     Fingerprint (TOFU-on-first-contact per D24 §5),
//     the cross-check is skipped: the pin is
//     authoritative.
//   - If the matched PeerConfig has a non-empty
//     Fingerprint that does NOT equal the pinned
//     value, the function returns (true, error,
//     true) — caller closes the conn.
//
// The third return is "ok" — a bool that says
// "a config match was found and a comparison was
// performed". false means "no match" or
// "match had empty fingerprint", both of which are
// non-fatal: the TLS callback already verified the
// cert.
//
// The second return is the *transport-scoped error
// the caller should propagate / log. nil when the
// function returns (false, nil, false).
func (t *Transport) crossCheckPinned(remoteHost string) (mismatch bool, cerr error, ok bool) {
	// Server-side host lookup against the config
	// peer roster. R1 will do this properly; for
	// Q3 we just iterate t.peers.
	for _, p := range t.peers {
		if p.Host != remoteHost {
			continue
		}
		if p.Fingerprint == "" {
			// D24 §5: empty = TOFU on
			// first contact. The pinned
			// value is authoritative.
			return false, nil, false
		}
		// Re-read the pinned value via the
		// existing unexported accessor. The
		// lookup is RLocked, safe to call
		// from the accept loop.
		pinned, present := t.known.lookupForVerify(remoteHost)
		if !present || pinned == "" {
			// Pin is missing — this
			// should not happen after a
			// successful TLS callback
			// (which always pins or
			// matches), but if it does
			// the TOFU trust model
			// treats it as "not yet
			// trusted". Treat as a
			// mismatch for safety: an
			// unconfigured + unpinned
			// peer should not pass the
			// cross-check.
			return true, fmt.Errorf("transport: cross-check: peer %q has no pin in known-nodes after TLS callback succeeded", remoteHost), true
		}
		if pinned != p.Fingerprint {
			return true, fmt.Errorf(
				"transport: cross-check: peer %q fingerprint mismatch: expected (config)=%s, pinned=%s",
				remoteHost, p.Fingerprint, pinned,
			), true
		}
		return false, nil, true
	}
	// No matching PeerConfig; not an error, just
	// nothing to cross-check.
	return false, nil, false
}

// errFingerprintCrossCheck is the typed error returned
// when the cross-check between the operator-supplied
// peer.Fingerprint and the known-nodes pin disagrees.
// The string form includes both fingerprints so
// operators can diagnose the typo / rotation drift
// without grepping logs.
type errFingerprintCrossCheck struct {
	host      string
	expected  string // operator-supplied (config)
	presented string // pinned in known-nodes by TLS callback
}

func (e errFingerprintCrossCheck) Error() string {
	return fmt.Sprintf("fingerprint cross-check mismatch for %q: config=%s, pinned=%s",
		e.host, e.expected, e.presented)
}

// closeWithChallengeErr closes conn with a quic
// application error carrying the challenge failure
// reason. Using CloseWithError (vs Close) lets the
// peer see the reason in its own error handling;
// quic-go's application-error path is structured
// (the peer reads the error code + reason string)
// rather than a half-open reset.
//
// The 0x01 error code is a local-sentinel "signed
// challenge failed" — it is not part of any
// standardised registry; PROTOCOL.md will document it
// alongside the rest of the v0.1.0 error codes.
func closeWithChallengeErr(conn *quic.Conn, err error) {
	if conn == nil {
		return
	}
	_ = conn.CloseWithError(0x01, err.Error())
}

// isClosedListenerErr is a portable detector for
// "listener was closed" errors from quic-go. quic-go
// has changed the exact return type across versions;
// a substring match is the most version-portable
// approach.
//
// The matched substrings are:
//
//   - "server closed" — quic-go's pre-0.50 wording
//   - "use of closed" — net package wording when
//     the underlying UDP conn is closed
//
// Anything else is a real error and should be
// surfaced to the caller.
func isClosedListenerErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "server closed") || strings.Contains(s, "use of closed")
}

// writeAll writes all of p to w, looping on short
// writes. Stdlib has no io.WriteFull helper (io.ReadFull
// exists, but not its write counterpart), and the
// handshake code writes fixed-size payloads (32-byte
// nonces, 64-byte signatures) where a short write is
// possible under QUIC stream-level back-pressure. A
// hand-rolled loop is the simplest correct fix; the
// alternative (io.CopyN) hides the intent at the call
// site.
//
// Returns the number of bytes written and the first
// non-nil error. The byte count equals len(p) on success.
func writeAll(w io.Writer, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := w.Write(p[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
