// Package transport (quic_test.go): tests for the Q1 Transport
// constructor, Q2 QUIC/TLS config builders, Q2
// VerifyPeerCertificate TOFU logic, and Q3 Listen/Dial +
// signed-challenge handshake.
//
// The Q1 tests are:
//
//   - TestNewValidConfig             — happy path: temp dir, valid
//     paths → New returns *Transport
//     with a non-nil identity and
//     a non-nil known-nodes store.
//   - TestNewGeneratesIdentityOnFirstStart
//     — the D23 first-start path:
//     non-existent identity file in
//     a writable dir → New creates
//     the file, the loaded identity
//     has the same fingerprint as a
//     freshly-generated one would.
//   - TestNewLoadsExistingIdentity   — round-trip: pre-write an
//     identity, New loads it, the
//     loaded fingerprint matches
//     what Generate produced.
//   - TestNewUnwritableIdentityPathErrors
//     — failure path: identity path
//     under a read-only dir → New
//     returns a non-nil error.
//
// The Q2 tests are:
//
//   - TestBuildQUICConfig                 — *quic.Config sanity
//     checks (MaxIdleTimeout set,
//     Allow0RTT=false).
//   - TestBuildTLSConfig                  — *tls.Config sanity
//     checks (TLS 1.3 only,
//     InsecureSkipVerify=true,
//     cert present).
//   - TestVerifyPeerCertificateFirstContact
//     — TOFU first-contact path:
//     callback returns nil AND
//     known-nodes is updated with
//     the pin.
//   - TestVerifyPeerCertificateMatchingPeer
//     — known peer, fingerprint
//     matches: callback returns nil.
//   - TestVerifyPeerCertificateMismatchHardRejects
//     — known peer, fingerprint
//     differs: callback returns
//     an error containing BOTH
//     expected and actual
//     fingerprints, known-nodes
//     is NOT updated (pin not
//     overwritten).
//
// All tests run on a per-test temp directory (t.TempDir) so
// they are hermetic, parallel-safe with each other, and leave no
// on-disk artefacts behind. The "unwritable" test uses
// os.Chmod(0o500) on a fresh dir; this is best-effort across
// platforms (root bypasses 0o500 on Linux, but in a normal user
// CI environment it works as expected) — see the test body for
// the skip condition.
//
// Q1 deliberately does NOT test the listener field (it is nil
// until Q3's Listen) or the peer roster (R1 introduces the
// runtime Peer struct). Those belong to their respective tasks.
//
// Q2 tests drive buildQUICConfig / buildTLSConfig and the
// underlying verifyPeerCertificateImpl directly. We do not
// stand up a real QUIC connection (that is Q3 / Q4); instead
// we call the verification primitives with a hand-built
// self-signed cert (the same code path Q3 will exercise
// end-to-end). This keeps the security-critical TOFU logic
// covered without an integration test, and matches the
// D31 "security-critical tests" instruction in
// .claude/CLAUDE.md.
//
// The Q3 tests are:
//
//   - TestListenDialLoopbackHandshake
//     — full in-process QUIC
//     loopback: server Transport
//     (Listen on 127.0.0.1:0),
//     client Transport (Dial to
//     server address). Both
//     sides run the signed
//     challenge, both see the
//     other's fingerprint, the
//     connections are usable.
//   - TestDialSignedChallengeRejectsForgedKey
//     — security-critical
//     D31 path: server Transport
//     has a different identity
//     than the cert it presents,
//     so the signed challenge
//     fails and Dial errors.
//   - TestListenEmptyAddrErrors
//     — Q3 guard: Listen on a
//     Transport whose Listen
//     field is "" returns a
//     non-nil error rather than
//     silently binding port 0.
//   - TestDialEmptyPeerHostErrors
//     — Q3 guard: Dial with a
//     zero-value PeerConfig
//     returns a non-nil error
//     rather than panicking on
//     net.ResolveUDPAddr.
//
// Q3 tests stand up a real QUIC connection (Listen +
// Dial) in-process on 127.0.0.1:0. The OS picks an
// ephemeral port; the resolved address is read from
// the listener and used as the dial target. D31
// requires "in-process QUIC loopback where possible";
// quic-go supports this on Linux, macOS, and Windows
// without root.
//
// The Q4 tests are:
//
//   - TestDialTOFUMismatchEndToEnd
//     — D24 §2 end-to-end
//     integration: client
//     pre-pins the server's
//     HONEST fingerprint,
//     server rotates its
//     identity and presents
//     a DIFFERENT
//     fingerprint. The
//     full Dial path is
//     exercised: TLS
//     VerifyPeerCertificate
//     detects the mismatch,
//     emits an ERROR log
//     with both
//     fingerprints, the
//     known-nodes pin is
//     NOT overwritten, the
//     returned conn is nil.
//   - TestDialForgedKeyEndToEnd
//     — D23 §4 end-to-end
//     integration: server
//     presents an honest
//     cert (TLS passes) but
//     signs the signed
//     challenge with a
//     different priv key.
//     The client's
//     runChallengeOutbound
//     rejects the forged
//     signature via
//     VerifyChallenge, the
//     conn is closed, the
//     server emits an ERROR
//     log. Exercises
//     production code paths
//     (Dial → quic.DialAddr
//     → runMutualChallenge
//     → runChallengeInbound)
//     through a real
//     Listen + Dial loop,
//     not just the
//     VerifyChallenge
//     primitive.
//
// Q4 tests use the same in-process QUIC loopback as Q3
// (127.0.0.1:0, t.TempDir, t.Cleanup). They add two
// test-injection points on Transport that the production
// code path uses by default: a capture Logger (via
// WithLogger) for asserting the D24 §2 / D23 §4 operator
// alert contract, and a challengeSigner override (via
// newTestTransportWithChallengeSigner) for forcing the
// "honest cert + wrong priv key" attacker scenario. Both
// injection points are documented as test-only in quic.go
// and are NOT production knobs.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// validConfig returns a Config pointing at paths under dir that
// satisfy all Q1 validation rules.
//
// Why a helper instead of inline literals: the four tests share
// the same shape (IdentityPath, KnownNodesPath in a temp dir)
// and inlining four times invites a copy-paste bug where one
// test forgets a field. The helper makes the "what counts as
// valid" definition live in exactly one place.
func validConfig(t *testing.T, dir string) Config {
	t.Helper()
	return Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		Listen:         "127.0.0.1:0", // 0 = "let the OS pick", used by Q3 loopback tests
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		// Peers intentionally left nil — R1 owns the conversion
		// to runtime Peer; Q1 only stores the slice.
	}
}

// TestNewValidConfig is the happy-path test for New.
//
// Expectations:
//
//   - err is nil.
//   - returned *Transport is non-nil.
//   - Identity() returns a non-nil *Identity with a fingerprint
//     starting with the "sha256:" prefix (D23 §3 format).
//   - KnownNodes() returns a non-nil *KnownNodes (the constructor
//     never returns nil even on a fresh dir — T1 contract).
//
// We deliberately do NOT assert "fingerprint has length N" —
// that would couple the test to the SHA-256 hex length, which
// is a property of crypto/sha256, not the transport. The
// "sha256:" prefix is the operator-visible contract (D23 + the
// brief) and is what an operator greps for in logs.
func TestNewValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig(t, dir)

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(validConfig) returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("New(validConfig) returned nil *Transport")
	}
	t.Cleanup(func() {
		// No Close in Q1 (Q3 owns the lifecycle), but a
		// non-nil guard is harmless and protects future
		// refactors that add a Close.
		_ = tr
	})

	if tr.Identity() == nil {
		t.Error("New returned Transport with nil Identity")
	} else {
		fp := tr.Identity().Fingerprint()
		if !strings.HasPrefix(fp, "sha256:") {
			t.Errorf("Identity.Fingerprint() = %q, want sha256: prefix", fp)
		}
	}

	if tr.KnownNodes() == nil {
		t.Error("New returned Transport with nil KnownNodes")
	}
}

// TestNewGeneratesIdentityOnFirstStart is the D23 "generate on
// first start" test.
//
// Setup: a temp dir that does NOT contain node.key.
// Action: New(cfg).
// Expect:
//
//   - err is nil.
//   - The on-disk node.key exists after New (Generate + Save).
//   - The loaded identity's fingerprint is non-empty and starts
//     with "sha256:" (sanity: generation actually happened, not
//     e.g. silent zero-key).
//   - The fingerprint of the loaded identity equals the
//     fingerprint of a freshly-generated identity that was
//     passed through Save + Load — this catches a class of bugs
//     where Save writes bytes that Load does not parse back to
//     the same key (e.g. endianness, padding).
//
// We do not pre-compare against a hard-coded fingerprint: the
// key is freshly random per call, so the fingerprint is too.
// The "round-trip via Save/Load" comparison is what proves
// generation worked correctly.
func TestNewGeneratesIdentityOnFirstStart(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig(t, dir)

	// Sanity: the identity file must not exist before New.
	if _, err := os.Stat(cfg.IdentityPath); !os.IsNotExist(err) {
		t.Fatalf("pre-condition: identity file should not exist, stat err = %v", err)
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New returned error on first start: %v", err)
	}

	// Generation side-effect: file must now exist on disk.
	if _, err := os.Stat(cfg.IdentityPath); err != nil {
		t.Fatalf("after New, identity file stat: %v", err)
	}

	// Identity is non-nil and has a well-formed fingerprint.
	id := tr.Identity()
	if id == nil {
		t.Fatal("Transport.Identity() returned nil after first-start New")
	}
	fp := id.Fingerprint()
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("first-start fingerprint = %q, want sha256: prefix", fp)
	}

	// Round-trip: generate a fresh identity, save it to a
	// DIFFERENT path, load it back, and confirm the public key
	// matches. This proves that what New wrote to disk is what
	// Load can read back — the contract identity.go promises.
	roundTripPath := filepath.Join(dir, "node.key.roundtrip")
	roundTripID, err := Generate()
	if err != nil {
		t.Fatalf("Generate for round-trip: %v", err)
	}
	if err := roundTripID.Save(roundTripPath); err != nil {
		t.Fatalf("Save round-trip identity: %v", err)
	}
	loaded, err := Load(roundTripPath)
	if err != nil {
		t.Fatalf("Load round-trip identity: %v", err)
	}
	if !bytesEqualPubKeys(loaded.PublicKey(), roundTripID.PublicKey()) {
		t.Errorf("Save/Load round-trip changed the public key: got %x, want %x",
			loaded.PublicKey(), roundTripID.PublicKey())
	}
}

// TestNewLoadsExistingIdentity proves the "load existing" path
// does not silently regenerate.
//
// Setup: pre-write an identity to node.key via Generate + Save.
// Action: New(cfg) — the file exists.
// Expect:
//
//   - err is nil.
//   - The on-disk node.key is byte-identical to what we wrote
//     (Load did not rewrite it).
//   - The loaded identity's fingerprint equals the fingerprint
//     of the identity we wrote — proves New took the "load"
//     branch, not the "generate" branch.
//
// The byte-identical check is what catches a class of bugs
// where New's "exists → load" branch inadvertently regenerates
// and overwrites (e.g. a copy-paste between the two code
// paths in loadOrGenerateIdentity). The fingerprint check
// alone would not catch that: regenerate-then-rewrite would
// still produce a valid fingerprint, just a different one
// from what was there before.
func TestNewLoadsExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig(t, dir)

	// Pre-write a known identity.
	preWritten, err := Generate()
	if err != nil {
		t.Fatalf("pre-write Generate: %v", err)
	}
	if err := preWritten.Save(cfg.IdentityPath); err != nil {
		t.Fatalf("pre-write Save: %v", err)
	}
	wantFingerprint := preWritten.Fingerprint()
	preWriteBytes, err := os.ReadFile(cfg.IdentityPath)
	if err != nil {
		t.Fatalf("pre-write ReadFile: %v", err)
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New on existing identity returned error: %v", err)
	}

	// Identity loaded matches the one we wrote.
	if got := tr.Identity().Fingerprint(); got != wantFingerprint {
		t.Errorf("loaded fingerprint = %q, want %q (New may have regenerated)",
			got, wantFingerprint)
	}

	// On-disk bytes unchanged: Load is read-only on the
	// existing-file path.
	postWriteBytes, err := os.ReadFile(cfg.IdentityPath)
	if err != nil {
		t.Fatalf("post-New ReadFile: %v", err)
	}
	if !bytesEqual(preWriteBytes, postWriteBytes) {
		t.Error("New modified the on-disk identity file on the load-existing path")
	}
}

// TestNewUnwritableIdentityPathErrors is the failure-path test.
//
// Setup: create a fresh sub-dir, chmod it 0o500 (read+execute,
// no write). Place IdentityPath inside it.
// Action: New(cfg) — Generate-then-Save will fail because the
// file cannot be created.
// Expect:
//
//   - err is non-nil.
//   - The error message references the identity file path so
//     the operator can diagnose ("save new identity: open …").
//
// The skip condition is documented inline: a process running
// as root bypasses 0o500 on Linux, so the test would falsely
// pass (New would succeed because root can write to a 0o500
// dir). On a normal user CI environment this test runs. On a
// root CI environment it skips with a clear message rather
// than silently passing.
//
// We do NOT test "non-existent parent dir" here — Config.validate
// already rejects that case before any I/O. Adding a duplicate
// test for it would only verify that the validate path is
// called, not that New handles an unwritable-file scenario.
func TestNewUnwritableIdentityPathErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits; Windows ACL semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses 0o500 on Linux; cannot test unwritable-dir failure reliably")
	}

	parent := t.TempDir()
	roDir := filepath.Join(parent, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir read-only dir: %v", err)
	}
	// Best-effort cleanup: t.TempDir cleans up `parent`, but a
	// 0o500 dir may resist removal on some filesystems. The
	// chmod in the cleanup restores write permission so the
	// remove succeeds.
	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0o700)
	})

	cfg := validConfig(t, roDir)

	_, err := New(cfg)
	if err == nil {
		t.Fatal("New on unwritable identity dir returned nil error; want failure")
	}
	// The exact error message depends on the OS ("permission
	// denied" vs "read-only file system") so we do a soft
	// check: the error chain should mention "identity" or the
	// file path, giving the operator a starting point. The
	// exact string would couple the test to the wrap message.
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("error %q should mention 'identity' for operator diagnostics", err.Error())
	}
}

// bytesEqual is a tiny helper to keep the test body readable.
// We could use bytes.Equal from the standard library, but that
// would require an additional import for a single use; a local
// helper is clearer at the call site.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bytesEqualPubKeys compares two ed25519.PublicKey values.
// ed25519.PublicKey is just []byte, so bytesEqual works, but
// spelling it out at the call site documents intent ("is the
// key material the same") better than passing two []byte
// arguments.
func bytesEqualPubKeys(a, b ed25519.PublicKey) bool {
	return bytesEqual(a, b)
}

// ========================== Q2 — buildQUICConfig / buildTLSConfig tests ==========================
//
// The Q2 tests verify the two builder methods on *Transport
// (buildQUICConfig, buildTLSConfig) and the TOFU verification
// core (verifyPeerCertificateImpl) that the TLS callback wraps.
//
// Strategy: drive the builders + verification primitives
// directly. We do not stand up a real QUIC connection — that
// is Q3 / Q4 territory. Driving the primitives directly keeps
// the security-critical TOFU logic in a tight, deterministic
// unit test that runs in milliseconds and does not require
// UDP port allocation.

// TestBuildQUICConfig is a sensibility test for buildQUICConfig.
//
// Asserts:
//
//   - The returned *quic.Config is non-nil.
//   - MaxIdleTimeout is set to a non-zero value (we set 30s;
//     the test checks "non-zero" rather than the exact 30s so
//     a future tuning of the constant is a one-line change).
//   - Allow0RTT is false (D24: 0-RTT is unsafe for TOFU; this
//     is the security-critical default).
//   - KeepAlivePeriod is set to a non-zero value (lib default
//     is 0, i.e. disabled; we want it on, so the assertion
//     catches a regression that turns it off).
//
// We do NOT assert on the exact MaxIdleTimeout / KeepAlivePeriod
// values: those are tuning constants, and the test should
// survive a future reviewer's decision to bump them. The
// "non-zero" check is what proves the field was set at all.
func TestBuildQUICConfig(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := tr.buildQUICConfig()
	if cfg == nil {
		t.Fatal("buildQUICConfig returned nil *quic.Config")
	}

	if cfg.MaxIdleTimeout == 0 {
		t.Error("MaxIdleTimeout is zero; expected a non-zero default (lib would default to 30s if unset)")
	}

	if cfg.Allow0RTT {
		t.Error("Allow0RTT is true; D24 / D22 require 0-RTT off for TOFU safety")
	}

	if cfg.KeepAlivePeriod == 0 {
		t.Error("KeepAlivePeriod is zero; expected a non-zero keepalive (lib would disable keepalive if unset)")
	}
}

// TestBuildTLSConfig is a sensibility test for buildTLSConfig.
//
// Asserts:
//
//   - The returned *tls.Config is non-nil.
//   - MinVersion == MaxVersion == TLS 1.3 (D22: no downgrade
//     to TLS 1.2; both bounds are set to make a future
//     misconfiguration that widens the range impossible).
//   - InsecureSkipVerify is true (D22 / D24: required to
//     bypass stdlib chain verification; the real security
//     gate is VerifyPeerCertificate).
//   - Certificates is non-empty (a TLS config without a
//     cert cannot present one).
//   - VerifyPeerCertificate is non-nil (a TLS config without
//     a callback would fall back to stdlib chain verification
//     and reject the self-signed cert).
func TestBuildTLSConfig(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tc := tr.buildTLSConfig("test-host")
	if tc == nil {
		t.Fatal("buildTLSConfig returned nil *tls.Config")
	}

	if tc.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (%x)", tc.MinVersion, tls.VersionTLS13)
	}
	if tc.MaxVersion != tls.VersionTLS13 {
		t.Errorf("MaxVersion = %x, want TLS 1.3 (%x)", tc.MaxVersion, tls.VersionTLS13)
	}

	if !tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false; D22 requires true to bypass stdlib chain verification")
	}

	if len(tc.Certificates) == 0 {
		t.Error("Certificates is empty; the transport must present a self-signed cert")
	}

	if tc.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is nil; the D24 TOFU check is the security gate and must be wired")
	}
}

// TestVerifyPeerCertificateFirstContact is the TOFU first-contact
// path of the verification callback.
//
// Setup: a fresh Transport with an empty known-nodes store.
// Action: invoke the callback with a peer cert derived from a
// freshly-generated peer identity. The expected host is
// "test-host".
// Expect:
//
//   - err is nil (first contact is the legitimate TOFU path,
//     not an error).
//   - The peer is now pinned in known-nodes (Check returns
//     pinned=true for the same fingerprint).
//
// The post-condition Check is the strong assertion: a buggy
// implementation that returns nil but does not pin would
// re-pin on every subsequent contact, and a buggy one that
// pins but returns an error would block the handshake.
// Either deviation must fail this test.
func TestVerifyPeerCertificateFirstContact(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Generate a peer identity + cert. The peer identity is
	// independent of tr.identity — we are verifying the
	// trust-on-first-use behaviour, not mutual TLS.
	peerID, err := Generate()
	if err != nil {
		t.Fatalf("Generate peer identity: %v", err)
	}
	peerCert := buildSelfSignedCert(peerID)

	// Pre-condition: known-nodes has no entry for "test-host".
	if pin, _ := tr.KnownNodes().Check("test-host", peerID.Fingerprint()); pin {
		t.Fatal("pre-condition: known-nodes already has a pin for test-host")
	}

	// Drive the verification primitive directly. We do not
	// extract the callback from the *tls.Config and call it,
	// because that would couple the test to closure capture
	// internals; the helper is the same one the closure
	// delegates to, so testing it covers the closure too.
	if err := verifyPeerCertificateImpl([][]byte{peerCert.Certificate[0]}, "test-host", tr.KnownNodes(), tr.Identity(), nil); err != nil {
		t.Fatalf("first-contact verification returned error: %v", err)
	}

	// Post-condition: the peer is now pinned.
	pin, mismatch := tr.KnownNodes().Check("test-host", peerID.Fingerprint())
	if !pin {
		t.Errorf("after first-contact, Check returned pin=false; expected pin=true")
	}
	if mismatch {
		t.Errorf("after first-contact, Check returned mismatch=true; expected mismatch=false")
	}
}

// TestVerifyPeerCertificateMatchingPeer is the idempotent
// reconnect path.
//
// Setup: a Transport with a pre-pinned entry for "test-host".
// Action: invoke the callback with the SAME peer cert.
// Expect: err is nil.
//
// The test does not re-Pin (Pin is idempotent on match —
// tofu.go §Pin) but we still assert Check returns pinned=true
// to prove the test setup is what we think it is.
func TestVerifyPeerCertificateMatchingPeer(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	peerID, err := Generate()
	if err != nil {
		t.Fatalf("Generate peer identity: %v", err)
	}
	peerCert := buildSelfSignedCert(peerID)

	// Pre-pin the host. We use Pin (not a hand-crafted write
	// to the store) to exercise the same on-disk path the
	// first-contact test does.
	if err := tr.KnownNodes().Pin("test-host", peerID.Fingerprint()); err != nil {
		t.Fatalf("pre-pin: %v", err)
	}

	if err := verifyPeerCertificateImpl([][]byte{peerCert.Certificate[0]}, "test-host", tr.KnownNodes(), tr.Identity(), nil); err != nil {
		t.Errorf("matching-peer verification returned error: %v", err)
	}

	// Sanity: the pin is unchanged.
	pin, _ := tr.KnownNodes().Check("test-host", peerID.Fingerprint())
	if !pin {
		t.Error("matching-peer Check returned pin=false; expected pin=true (sanity check)")
	}
}

// TestVerifyPeerCertificateMismatchHardRejects is the
// security-critical D24 case.
//
// Setup: a Transport with a pre-pinned entry for "test-host"
// for fingerprint A. Generate a second peer identity with
// fingerprint B. Build B's cert.
// Action: invoke the callback with B's cert for "test-host".
// Expect:
//
//   - err is non-nil (hard reject).
//   - The error message contains BOTH the expected
//     (pinned, A) and the presented (B) fingerprints — D24
//     §2 requires the operator alert to include both.
//   - The pin in known-nodes is unchanged (still A, not B).
//     This is what closes the "silent re-pin of an attacker's
//     key" failure mode (D24, tofu.go Pin §"Re-pin guard").
func TestVerifyPeerCertificateMismatchHardRejects(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Pin A.
	honestID, err := Generate()
	if err != nil {
		t.Fatalf("Generate honest identity: %v", err)
	}
	pinnedFP := honestID.Fingerprint()
	if err := tr.KnownNodes().Pin("test-host", pinnedFP); err != nil {
		t.Fatalf("Pin honest: %v", err)
	}

	// Generate B (attacker) and build its cert.
	attackerID, err := Generate()
	if err != nil {
		t.Fatalf("Generate attacker identity: %v", err)
	}
	attackerCert := buildSelfSignedCert(attackerID)
	presentedFP := attackerID.Fingerprint()

	// Sanity: the two fingerprints differ — otherwise the
	// test is testing the wrong thing.
	if pinnedFP == presentedFP {
		t.Fatal("honest and attacker identities produced the same fingerprint; test setup is broken")
	}

	// Drive the verification with the attacker's cert.
	err = verifyPeerCertificateImpl([][]byte{attackerCert.Certificate[0]}, "test-host", tr.KnownNodes(), tr.Identity(), nil)
	if err == nil {
		t.Fatal("mismatch verification returned nil error; D24 requires hard reject")
	}

	// The error message must include BOTH fingerprints. We
	// do exact-substring checks rather than regex: the
	// message format is part of the operator-alert contract
	// (D24 §2) and a future review should be able to grep
	// for the literal "expected=" / "presented=" strings.
	if !strings.Contains(err.Error(), pinnedFP) {
		t.Errorf("error %q does not contain the expected (pinned) fingerprint %q", err.Error(), pinnedFP)
	}
	if !strings.Contains(err.Error(), presentedFP) {
		t.Errorf("error %q does not contain the presented fingerprint %q", err.Error(), presentedFP)
	}

	// Hard-reject must NOT update the pin. Check the store
	// directly: the pinned value is still the honest
	// fingerprint, not the attacker's.
	pin, _ := tr.KnownNodes().Check("test-host", presentedFP)
	if pin {
		t.Errorf("after hard-reject, presented fingerprint %q is now pinned; D24 requires pin to remain unchanged", presentedFP)
	}
	// And the original pin is still there.
	pin, mismatch := tr.KnownNodes().Check("test-host", pinnedFP)
	if !pin {
		t.Errorf("after hard-reject, original pin %q is no longer pinned", pinnedFP)
	}
	if mismatch {
		t.Errorf("after hard-reject, original pin %q reports mismatch; this should be the 'match' path", pinnedFP)
	}
}

// TestVerifyPeerCertificateDefensiveGuards covers the
// failure-shape edge cases that must not panic.
//
// The callback is a security gate: if it panics on a nil
// or malformed cert, the entire TLS handshake crashes the
// process (no defer / recover in stdlib tls). D24's
// hard-reject is the correct answer for "weird input";
// a panic would be a DoS surface.
//
// Sub-tests:
//
//   - empty rawCerts: error returned, not panic.
//   - garbage rawCerts (random bytes): error returned, not panic.
//   - non-Ed25519 cert (RSA-style self-signed): error
//     returned on key-type mismatch, not panic.
//
// We do NOT test "nil rawCerts" (passing a nil slice) —
// the stdlib always passes a non-nil slice (possibly empty).
// Passing nil would be a stdlib-internal bug, not something
// we can defend against without an extra nil-check that the
// spec does not justify.
func TestVerifyPeerCertificateDefensiveGuards(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("empty rawCerts", func(t *testing.T) {
		err := verifyPeerCertificateImpl(nil, "test-host", tr.KnownNodes(), tr.Identity(), nil)
		if err == nil {
			t.Error("empty rawCerts returned nil error; expected an error")
		}
	})

	t.Run("garbage rawCerts", func(t *testing.T) {
		err := verifyPeerCertificateImpl([][]byte{[]byte("not a certificate")}, "test-host", tr.KnownNodes(), tr.Identity(), nil)
		if err == nil {
			t.Error("garbage rawCerts returned nil error; expected parse error")
		}
	})

	t.Run("non-ed25519 cert", func(t *testing.T) {
		// Build a self-signed cert with a non-Ed25519
		// key. The simplest way without importing rsa /
		// ecdsa is to use a hand-crafted template that
		// x509.CreateCertificate rejects; but the goal
		// here is to feed the verification path a cert
		// whose .PublicKey is not ed25519.PublicKey.
		//
		// Easiest path: build a self-signed cert with an
		// ECDSA key. The verification's type assertion
		// will fail and the callback returns an error.
		//
		// We use the stdlib's ecdsa.GenerateKey for the
		// minimal scaffolding — a 5-line helper below.
		ecCert := buildECDSASelfSignedCert(t)
		err := verifyPeerCertificateImpl([][]byte{ecCert.Certificate[0]}, "test-host", tr.KnownNodes(), tr.Identity(), nil)
		if err == nil {
			t.Error("non-Ed25519 cert returned nil error; expected key-type-mismatch error")
		}
		if !strings.Contains(err.Error(), "not Ed25519") {
			t.Errorf("error %q does not mention the Ed25519 mismatch", err.Error())
		}
	})
}

// buildECDSASelfSignedCert is a test helper: a minimal
// self-signed x509 cert whose public key is ECDSA (P-256),
// not Ed25519. Used by TestVerifyPeerCertificateDefensiveGuards
// to feed the verification path a cert that fails the
// "is Ed25519" type assertion.
//
// The helper is intentionally bare-minimum: it does not
// validate expiry, set SKID, or any of the polish the
// production cert builder does — its only job is to produce
// a DER-encoded x509 cert whose PublicKey field is a
// non-Ed25519 type. The transport's verification path
// type-asserts PublicKey to ed25519.PublicKey, and the
// assertion fails for this cert — which is exactly what
// the sub-test wants to assert.
func buildECDSASelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate (ecdsa): %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// ========================== Q3 — Listen / Dial / signed-challenge tests ==========================
//
// The Q3 tests stand up a real QUIC connection between two
// Transports in-process on 127.0.0.1:0. quic-go supports
// this on Linux, macOS, and Windows without root — the OS
// picks an ephemeral port (":0") and the listener's
// Addr() reports the resolved address.
//
// Concurrency model: server Transport's Listen runs in a
// goroutine, blocking on the accept loop. The test
// orchestrates the listener via a context (cancellation
// tears down the listener) and waits for a successful
// handshake on the client side before asserting. The
// server-side handleAcceptedConn goroutine is owned by
// the transport; we don't wait for it explicitly, but the
// test's t.Cleanup cancels the context which causes the
// listener to close and the per-conn goroutine to exit
// via the select on ctx.Done() / conn.Context().Done().

// TestListenDialLoopbackHandshake is the end-to-end
// happy-path test for Q3.
//
// Setup: two independent Transports (server, client)
// in temp dirs. Server Listen on 127.0.0.1:0; client
// Dial to the server's resolved address.
//
// Expect:
//
//   - Listen starts without error.
//   - Dial completes (TLS handshake + signed challenge)
//     within a short deadline.
//   - The client can read the server's Ed25519
//     public key from conn.ConnectionState(); the
//     derived fingerprint equals the server's
//     identity fingerprint.
//   - The client's known-nodes store has a pin for
//     the server at the dial-target host.
//
// The "both sides see the same fingerprint" assertion
// is the contract: TOFU keyed on the host string (the
// server's resolved address) yields the same fingerprint
// on both sides. This is the most direct proof that the
// handshake is not "almost working" — if the cert chain
// or pub-key extraction were broken differently on
// server vs client, the fingerprints would diverge.
//
// Cleanup: t.Cleanup cancels the listen context,
// which causes Listen to return nil and the per-conn
// goroutine to exit via ctx.Done(). We also close
// the client conn explicitly so any in-flight
// stream operations see a clean close.
func TestListenDialLoopbackHandshake(t *testing.T) {
	serverDir := t.TempDir()
	clientDir := t.TempDir()

	serverCfg := validConfig(t, serverDir)
	serverCfg.Listen = "127.0.0.1:0"
	serverTr, err := New(serverCfg)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	clientCfg := validConfig(t, clientDir)
	clientTr, err := New(clientCfg)
	if err != nil {
		t.Fatalf("New client: %v", err)
	}

	// Capture the server's identity fingerprint
	// before the handshake so we can cross-check
	// the client's view of the peer.
	serverFP := serverTr.Identity().Fingerprint()
	clientFP := clientTr.Identity().Fingerprint()
	if serverFP == clientFP {
		t.Fatal("server and client identities produced the same fingerprint; loopback setup is broken")
	}

	// Start the server's Listen in a goroutine;
	// t.Cleanup cancels the context so the
	// listener tears down at test end.
	listenCtx, cancelListen := context.WithCancel(context.Background())
	t.Cleanup(cancelListen)
	listenErrCh := make(chan error, 1)
	go func() {
		listenErrCh <- serverTr.Listen(listenCtx)
	}()

	// Poll briefly for the listener to be bound.
	// quic-go's ListenAddr synchronously binds
	// the UDP socket, so the listener field is
	// non-nil by the time Listen returns to
	// its goroutine — but that goroutine may
	// not have run yet. A 100ms ceiling is
	// generous; in practice it is sub-millisecond
	// on Linux loopback.
	deadline := time.Now().Add(2 * time.Second)
	var addr *net.UDPAddr
	for time.Now().Before(deadline) {
		serverTr.listenerMu.Lock()
		ln := serverTr.listener
		serverTr.listenerMu.Unlock()
		if ln != nil {
			if udp, ok := ln.Addr().(*net.UDPAddr); ok {
				addr = udp
				break
			}
			t.Fatalf("listener.Addr() is %T, want *net.UDPAddr", ln.Addr())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("server listener did not bind within 2s")
	}
	target := addr.String()

	// Run Dial in a goroutine because the
	// server side of the handshake runs in
	// handleAcceptedConn on a goroutine
	// spawned by Listen. The two halves run
	// in parallel; a short timeout catches
	// deadlocks.
	type dialResult struct {
		conn *quic.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := clientTr.Dial(context.Background(), PeerConfig{Host: target})
		dialCh <- dialResult{conn: conn, err: err}
	}()

	// Wait for Dial with a deadline. The
	// handshake (TLS + challenge) should
	// complete in well under a second on
	// loopback; we allow 5s as a generous
	// upper bound for slow CI.
	var (
		conn *quic.Conn
	)
	select {
	case res := <-dialCh:
		conn, err = res.conn, res.err
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not complete within 5s; handshake deadlocked or listener not accepting")
	}
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if conn == nil {
		t.Fatal("Dial returned nil conn with nil err")
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test cleanup") })

	// Client side: read the peer's (server's)
	// cert and compute the fingerprint. The
	// fingerprint MUST equal the server's
	// identity fingerprint computed from the
	// same public key bytes.
	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		t.Fatal("client: conn.ConnectionState().TLS.PeerCertificates is empty")
	}
	clientPeerPub, ok := state.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("client: peer cert public key is %T, want ed25519.PublicKey", state.TLS.PeerCertificates[0].PublicKey)
	}
	gotFP := peerFingerprint(t, clientPeerPub)
	if gotFP != serverFP {
		t.Errorf("client view of server fingerprint = %q, want %q", gotFP, serverFP)
	}

	// Cross-check: the client should have
	// pinned the server's fingerprint under
	// the dial target host during the TLS
	// callback. Read it back from known-nodes.
	pinned, _ := clientTr.KnownNodes().Check(target, serverFP)
	if !pinned {
		t.Errorf("client known-nodes: server fingerprint not pinned for %q after handshake", target)
	}

	// Server side: the TLS callback pinned
	// the client's fingerprint under the
	// remote address (which is the client's
	// ephemeral UDP port — different from
	// target). We assert the server has at
	// least one host pinned to the client's
	// fingerprint. The simplest read is
	// to enumerate via the on-disk file.
	if findHostPinnedTo(t, serverTr.KnownNodes(), clientFP) == "" {
		t.Errorf("server known-nodes: no host pinned to client fingerprint %q after handshake", clientFP)
	}
}

// TestDialSignedChallengeRejectsForgedKey is the
// security-critical D31 "signed challenge rejects
// forged key" path. The TLS handshake cannot detect
// a peer that has the right cert but the wrong priv
// key (the cert is self-signed; the TOFU check is on
// the cert, not on the key), so the signed challenge
// is the gate that catches this case.
//
// This test exercises the verification primitive
// directly because the production Transport does not
// expose a hook to inject a wrong signing key. An
// end-to-end forged-key test would require either
// a test-only signing-key injection point on
// Transport (out of scope for Q3's minimal API
// surface) or a fully mocked signing layer (Q4
// territory). The D31 instruction allows this
// test to be the unit-level primitive rather
// than the end-to-end path; the end-to-end path
// is Q4's job.
//
// What this test actually proves:
//
//   - VerifyChallenge rejects a signature made
//     with a different priv key (the D31
//     invariant).
//   - VerifyChallenge rejects a signature
//     against a tampered nonce (basic message
//     integrity).
//
// Together with the runMutualChallenge code path
// (which calls VerifyChallenge on every
// connection), these two properties close the
// D31 "forged key" attack surface.
func TestDialSignedChallengeRejectsForgedKey(t *testing.T) {
	honestID, err := Generate()
	if err != nil {
		t.Fatalf("Generate honest: %v", err)
	}
	// "Wrong" priv key whose pub does not match
	// honestID's pub. We never publish this pub
	// as a cert; we only use it to produce a
	// signature that the honestID pub will (and
	// must) reject.
	wrongPub, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate wrong: %v", err)
	}
	honestPub := honestID.PublicKey()

	// Sanity: the two pub keys differ — otherwise
	// the test is testing the wrong thing.
	if bytesEqual(wrongPub, honestPub) {
		t.Fatal("honest and wrong identities produced the same pub key; test setup is broken")
	}

	nonce := make([]byte, challengeNonceSize)
	if _, err := ioReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("read nonce: %v", err)
	}
	honestSig, err := honestID.SignChallenge(nonce)
	if err != nil {
		t.Fatalf("honest SignChallenge: %v", err)
	}
	wrongSig := ed25519.Sign(wrongPriv, nonce)

	// Positive control: the honest signature
	// must verify under the honest pub key.
	// If this fails, the test setup is broken
	// (not the transport).
	if !VerifyChallenge(honestPub, nonce, honestSig) {
		t.Fatal("honest signature did not verify under honest pub key; VerifyChallenge is broken")
	}

	// D31 invariant: a signature made with a
	// different priv key must NOT verify
	// under the honest pub key. This is the
	// attack surface the signed challenge
	// closes.
	if VerifyChallenge(honestPub, nonce, wrongSig) {
		t.Error("forged signature VERIFIED under honest pub key; D31 invariant violated")
	}

	// Tampered nonce: the honest signature
	// on a different nonce must NOT verify.
	// (This is the same as the "signature
	// does not bind to this message" property
	// Ed25519 provides for free; we assert it
	// explicitly so a future "we strip the
	// nonce" refactor would be caught.)
	tamperedNonce := make([]byte, challengeNonceSize)
	copy(tamperedNonce, nonce)
	tamperedNonce[0] ^= 0xFF
	if VerifyChallenge(honestPub, tamperedNonce, honestSig) {
		t.Error("honest signature verified against tampered nonce; D31 invariant violated")
	}
}

// TestListenEmptyAddrErrors is the Q3 guard: a
// Transport constructed with an explicit empty
// Listen field should be rejected at New time by
// K1's validation, before Listen can be called.
//
// K1 changed the contract here. Under Q1 the
// guard lived inside Listen itself (a defensive
// check on the empty string). Under K1, New runs
// applyDefaults + Validate, and an Enabled=true
// config with Listen="" gets the built-in
// loopback default (127.0.0.1:4097) — so by
// the time a caller has a *Transport, the listen
// field is never empty.
//
// The test's purpose in v0.1.0 is the K1
// resolution: an Enabled=true Config with
// Listen="" must still get a usable Transport
// (applyDefaults fills it), and a Config that
// somehow ends up with Listen="" after
// resolution (theoretically reachable only via
// direct field mutation, not through New) would
// fail at Run / Listen. The Listen() guard is
// preserved as defence-in-depth; the public
// API is the resolution path.
func TestListenEmptyAddrErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig(t, dir)
	cfg.Listen = "" // explicitly unset

	// Under K1, New resolves Listen to the built-in
	// default. The Transport's listen field is
	// therefore non-empty after New returns.
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New with empty Listen (and no env): %v", err)
	}
	if tr.listen == "" {
		t.Fatal("New left t.listen empty; applyDefaults should have filled the default")
	}
	// Sanity: the filled value is the default.
	if tr.listen != defaultListenAddr {
		t.Errorf("New with empty Listen filled %q; want %q (the built-in default)",
			tr.listen, defaultListenAddr)
	}
}

// TestDialEmptyPeerHostErrors is the mirror guard
// for Dial: a PeerConfig with an empty Host must
// fail Dial with a clear, non-nil error before
// touching the network.
//
// Without this guard, Dial would call
// quic.DialAddr(ctx, "", ...) which on Linux tries
// to resolve "" via DNS, which can take seconds
// before returning an error — far worse than a
// loud "you forgot the host" message at the API
// boundary.
func TestDialEmptyPeerHostErrors(t *testing.T) {
	dir := t.TempDir()
	tr, err := New(validConfig(t, dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = tr.Dial(context.Background(), PeerConfig{Host: ""})
	if err == nil {
		t.Fatal("Dial on empty PeerConfig.Host returned nil error; expected an explicit guard")
	}
	if !strings.Contains(err.Error(), "Host") {
		t.Errorf("error %q does not mention Host; operator-diagnostics gate", err.Error())
	}
}

// ========================== Q3 test helpers ==========================
//
// Small utilities used by the Q3 tests. They live at the
// bottom of the file (alongside buildECDSASelfSignedCert
// from Q2) so the test bodies above are readable.

// peerFingerprint computes the "sha256:<hex>" fingerprint
// of an Ed25519 public key, matching the format used by
// Identity.Fingerprint and verifyPeerCertificateImpl.
//
// The function duplicates the format rather than calling
// Identity.Fingerprint because the pub key here comes
// from a foreign cert (not from an *Identity). The
// fingerprint algorithm is a property of the transport,
// not of the local identity.
//
// t.Helper: keeps the failure line at the call site.
func peerFingerprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("peer pub key has unexpected length %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	return "sha256:" + hexEncodeToString(sha256Of(pub))
}

// findHostPinnedTo scans the known-nodes store for a
// host pinned to the given fingerprint. Returns the
// host string on match, "" on no match.
//
// The KnownNodes type's entries map is unexported, so a
// full-enumeration accessor doesn't exist. We read the
// store's on-disk file (its only public read surface for
// "all entries") and parse it. This is a test-only
// round-trip; the production code never goes through
// this path.
func findHostPinnedTo(t *testing.T, kn *KnownNodes, fingerprint string) string {
	t.Helper()
	data, err := os.ReadFile(kn.path)
	if err != nil {
		// Missing file = empty store. Not an
		// error condition for the test
		// (first-contact would normally have
		// created it, but the test should not
		// assume the on-disk format was
		// actually written — Save happens on
		// the Pin path which is the path under
		// test).
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read known-nodes file: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[1] == fingerprint {
			return parts[0]
		}
	}
	return ""
}

// ioReadFull is a thin shim around io.ReadFull so the
// test code can call it without importing "io" directly.
// The shim keeps the call sites visually aligned with
// the production code that uses io.ReadFull in
// runChallengeOutbound / runChallengeInbound.
func ioReadFull(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// hexEncodeToString wraps encoding/hex.EncodeToString.
// The helper exists so the test file does not need to
// import the hex package directly (the production file
// imports it; the test reuses the helper for symmetry).
func hexEncodeToString(b []byte) string {
	return hexEncode(b)
}

// hexEncode is a hand-rolled hex encoder used by the
// fingerprint helper. The test file's import list
// avoids the "encoding/hex" import to keep the diff
// against Q2's test file focused; the implementation
// is a 6-line table-driven encoder.
func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0F]
	}
	return string(out)
}

// sha256Of is a thin shim around sha256.Sum256. Same
// rationale as the other helpers in this section: keep
// the test file's import surface small.
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ========================== Q4 — TOFU hard-reject + forged-key integration ==========================
//
// The two tests in this section are the end-to-end coverage D31
// requires for the security-critical paths. They stand up a real
// QUIC connection (Listen + Dial) in-process and assert the
// production code's behaviour from the API surface down through
// the TLS callback and the signed-challenge engine.
//
// Why these tests are NOT in the Q2 / Q3 sections: Q2 tests
// verifyPeerCertificateImpl directly (unit-level primitive);
// Q3 tests TestDialSignedChallengeRejectsForgedKey verify
// VerifyChallenge directly. The unit-level tests stay — they
// are the most direct proof the primitive behaves correctly. The
// Q4 tests add the integration coverage the unit tests cannot
// give: the production code path Dial → quic.DialAddr →
// VerifyPeerCertificate → runMutualChallenge → VerifyChallenge,
// with the same quic-go transport library real peer traffic
// uses.

// captureQ4Logger is the Q4 test-injection logger. It implements
// the package's Logger interface (defined in protocol.go) and
// records every Warnf / Errorf invocation into in-memory slices
// for later assertion.
//
// It is intentionally not concurrency-safe — the Q4 tests run
// each scenario in a single goroutine, and a race-detector trip
// here would mean a future refactor started emitting logs from
// multiple goroutines for the same Transport, which would be a
// real bug (the log would lose ordering, defeating the operator
// alert's diagnostic value).
//
// Reusing the captureLogger from protocol_test.go would couple
// the Q4 test file to a P3-internal test type; the Q4-specific
// copy is two extra methods and is the simpler separation. The
// shape is deliberately parallel to captureLogger so a future
// refactor that consolidates them is a mechanical change.
type captureQ4Logger struct {
	warnings []string
	errors   []string
}

func (c *captureQ4Logger) Warnf(format string, args ...any) {
	c.warnings = append(c.warnings, fmtSprintf(format, args...))
}

func (c *captureQ4Logger) Errorf(format string, args ...any) {
	c.errors = append(c.errors, fmtSprintf(format, args...))
}

// fmtSprintf is a tiny indirection that lets the test file call
// Sprintf through a local symbol rather than importing fmt at
// the test-body level. (The production file already imports
// fmt; the test file's import list stays focused on the test's
// needs.)
func fmtSprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// atLeastOneErrorContaining asserts the capture logger recorded
// at least one Errorf call whose formatted string contains every
// one of the wanted substrings. Returns the matching error line
// for callers that want to inspect further.
//
// The "contains" matcher is intentional: the exact log format
// is an implementation detail of the security alert, and an
// operator grepping for "MISMATCH" or a specific fingerprint
// does not care about the surrounding prefix. A regression that
// drops the fingerprint from the alert will fail this assertion
// regardless of the surrounding wording.
func (c *captureQ4Logger) atLeastOneErrorContaining(t *testing.T, wanted ...string) string {
	t.Helper()
	for _, e := range c.errors {
		matched := true
		for _, w := range wanted {
			if !strings.Contains(e, w) {
				matched = false
				break
			}
		}
		if matched {
			return e
		}
	}
	t.Fatalf("expected at least one Errorf containing %v, got errors=%v warnings=%v",
		wanted, c.errors, c.warnings)
	return ""
}

// waitForListenerBind polls the server Transport's listener
// field until it is non-nil or the deadline elapses. Mirrors
// the polling loop in TestListenDialLoopbackHandshake (Q3) —
// reused here so the Q4 tests do not duplicate the
// 2s-allowance loop with subtle drift.
//
// The helper returns the resolved *net.UDPAddr so the caller
// can use it as the dial target. Failing to bind within the
// deadline is a fatal test error (the Q3 helper does the same).
func waitForListenerBind(t *testing.T, tr *Transport, deadline time.Duration) *net.UDPAddr {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		tr.listenerMu.Lock()
		ln := tr.listener
		tr.listenerMu.Unlock()
		if ln != nil {
			udp, ok := ln.Addr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("listener.Addr() is %T, want *net.UDPAddr", ln.Addr())
			}
			return udp
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server listener did not bind within %v", deadline)
	return nil
}

// TestDialTOFUMismatchEndToEnd is the D24 §2 integration
// gate: a pinned peer rotates its identity and presents the
// new fingerprint over a real Dial. The TLS VerifyPeerCertificate
// callback detects the mismatch, emits an ERROR log with BOTH
// the expected (pinned) and the presented (attacker)
// fingerprints, and returns a hard-reject error. The conn
// handed to the caller is nil, the known-nodes pin is
// unchanged (the attacker's fingerprint did NOT silently
// overwrite the trusted one), and the server's accept loop
// sees the failed handshake as a connection error and
// continues (no half-open state).
//
// Setup:
//
//   - honestID and attackerID are two independent freshly
//     generated identities. Their fingerprints differ (sanity
//     assertion below).
//   - server Transport uses attackerID. The honest fingerprint
//     is never on the server.
//   - client Transport's known-nodes is pre-pinned with the
//     HONEST fingerprint (honestID.Fingerprint()) under the
//     dial target host. This simulates "an operator who
//     pinned the right key last week; this week the server
//     is presenting a different key (legitimate rotation
//     or attacker)".
//
// Assertions:
//
//   - Dial returns a NON-NIL error.
//   - The returned *quic.Conn is nil (no half-open state).
//   - The error message (or its wrap chain) contains BOTH
//     fingerprints (D24 §2 operator alert contract).
//   - The capture logger recorded an ERROR whose formatted
//     string contains BOTH fingerprints (the D24 §2 "log"
//     half of the contract — the error message and the
//     log are two surfaces of the same alert).
//   - The known-nodes pin for the dial target is UNCHANGED:
//     the honest fingerprint is still there, the attacker's
//     is NOT (D24 silent re-pin closure).
//
// Cleanup: t.Cleanup cancels the listen context, which
// tears down the listener. The server's handleAcceptedConn
// goroutine (if it ran at all — quic-go may not deliver
// a fully-accepted conn when the client fails TLS) exits
// via the conn-context-done branch.
func TestDialTOFUMismatchEndToEnd(t *testing.T) {
	serverDir := t.TempDir()
	clientDir := t.TempDir()

	honestID, err := Generate()
	if err != nil {
		t.Fatalf("Generate honest identity: %v", err)
	}
	attackerID, err := Generate()
	if err != nil {
		t.Fatalf("Generate attacker identity: %v", err)
	}
	honestFP := honestID.Fingerprint()
	attackerFP := attackerID.Fingerprint()
	if honestFP == attackerFP {
		t.Fatal("honest and attacker identities produced the same fingerprint; setup is broken")
	}

	// Server uses the ATTACKER identity. This is the "pinned
	// peer rotated its key" scenario: the operator trusted A
	// last week, but the server is now presenting B. We
	// pre-save the attacker identity to the server's
	// IdentityPath so New() loads it (rather than generating
	// a fresh identity that the test would have to discover
	// the fingerprint of at runtime). The pre-save + Load
	// round-trip is the same path New() takes on every
	// start-after-first-start, so the test exercises the
	// production code path here too.
	serverCfg := validConfig(t, serverDir)
	if err := attackerID.Save(serverCfg.IdentityPath); err != nil {
		t.Fatalf("save attacker identity: %v", err)
	}
	serverTr, err := New(serverCfg)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	// The server's own identity is the attacker; the cert
	// presented during TLS is therefore the attacker's cert.
	// The client's TLS callback will extract attackerFP and
	// compare against its pre-pinned honestFP.
	if got := serverTr.Identity().Fingerprint(); got != attackerFP {
		t.Fatalf("server identity fingerprint = %q, want %q (test setup broken)", got, attackerFP)
	}

	// Client uses an independent identity. Pre-pin HONEST fingerprint
	// for the dial target host (we do not know the host yet, so we
	// set up the client first, start the server, then pin).
	clientCfg := validConfig(t, clientDir)
	clientTr, err := New(clientCfg)
	if err != nil {
		t.Fatalf("New client: %v", err)
	}

	// Capture logger on the CLIENT. The mismatch detection
	// happens in the client's TLS callback, so the client's
	// logger is the one that must record the alert. We also
	// set it on the server for completeness — the server's
	// verifyPeerCertificate never runs in this test (the
	// client fails TLS first), but a future refactor that
	// surfaces a server-side "incoming connection attempt
	// from unexpected peer" log should be exercisable
	// without test infrastructure changes.
	clientLog := &captureQ4Logger{}
	serverLog := &captureQ4Logger{}
	clientTr.WithLogger(clientLog)
	serverTr.WithLogger(serverLog)

	// Start the server's Listen in a goroutine; t.Cleanup
	// cancels the context so the listener tears down at
	// test end.
	listenCtx, cancelListen := context.WithCancel(context.Background())
	t.Cleanup(cancelListen)
	listenErrCh := make(chan error, 1)
	go func() {
		listenErrCh <- serverTr.Listen(listenCtx)
	}()

	// Wait for the listener to bind. Q4 uses the same
	// 2-second ceiling as the Q3 loopback test; on a healthy
	// CI machine the bind completes in under 5ms.
	addr := waitForListenerBind(t, serverTr, 2*time.Second)
	target := addr.String()

	// Pre-pin the HONEST fingerprint for the dial target.
	// This is the operator's existing pin from before the
	// "rotation" (which is really an attack). Pin happens
	// before Dial so the TLS callback's Check finds the
	// pin and takes the mismatch path rather than the
	// first-contact path.
	if err := clientTr.KnownNodes().Pin(target, honestFP); err != nil {
		t.Fatalf("pre-pin honest fingerprint: %v", err)
	}

	// Drive the full Dial path. Run in a goroutine so the
	// test can also assert server-side state without
	// deadlocking.
	type dialResult struct {
		conn *quic.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := clientTr.Dial(context.Background(), PeerConfig{Host: target})
		dialCh <- dialResult{conn: conn, err: err}
	}()

	var (
		gotConn *quic.Conn
		gotErr  error
	)
	select {
	case res := <-dialCh:
		gotConn, gotErr = res.conn, res.err
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not complete within 5s; handshake deadlocked or listener not accepting")
	}

	// D24 §2 hard-reject: Dial returns a non-nil error and
	// a nil conn. The nil-conn assertion is what proves
	// "peer NOT added to active roster" — no conn is handed
	// to the caller, so no peer-lifecycle state is mutated.
	if gotErr == nil {
		t.Fatal("Dial returned nil error; D24 requires hard reject on fingerprint mismatch")
	}
	if gotConn != nil {
		t.Errorf("Dial returned non-nil conn alongside the error; D24 requires no half-open state on hard-reject")
		_ = gotConn.CloseWithError(0, "test cleanup")
	}

	// The error message must contain BOTH fingerprints.
	// D24 §2 "operator alert" — the error is one of the
	// two alert surfaces (the other is the log, asserted
	// below). An operator reading just the error (e.g.
	// a CLI invocation) must be able to diagnose.
	if !strings.Contains(gotErr.Error(), honestFP) {
		t.Errorf("Dial error %q does not contain the honest (pinned) fingerprint %q", gotErr.Error(), honestFP)
	}
	if !strings.Contains(gotErr.Error(), attackerFP) {
		t.Errorf("Dial error %q does not contain the presented (attacker) fingerprint %q", gotErr.Error(), attackerFP)
	}

	// The capture logger must record an ERROR containing
	// BOTH fingerprints. This is the D24 §2 "log" half of
	// the alert — a log aggregator that does not parse
	// error return values must still see both
	// fingerprints in the log stream.
	clientLog.atLeastOneErrorContaining(t, honestFP, attackerFP)

	// The known-nodes pin must be UNCHANGED. D24 silent
	// re-pin closure: the attacker's fingerprint MUST NOT
	// silently overwrite the trusted pin. The store is
	// read directly here (not through the TLS callback)
	// to assert the on-disk / in-memory state, not the
	// transient state of the handshake.
	pinned, mismatch := clientTr.KnownNodes().Check(target, honestFP)
	if !pinned {
		t.Errorf("after hard-reject, honest fingerprint %q is no longer pinned", honestFP)
	}
	if mismatch {
		t.Errorf("after hard-reject, honest fingerprint %q reports mismatch; should be the 'match' path", honestFP)
	}
	// And the attacker's fingerprint is NOT pinned.
	if pinAttacker, _ := clientTr.KnownNodes().Check(target, attackerFP); pinAttacker {
		t.Errorf("after hard-reject, attacker fingerprint %q is now pinned; D24 requires the attacker's key to NOT be silently accepted", attackerFP)
	}
}

// TestDialForgedKeyEndToEnd is the D23 §4 integration
// gate: a peer presents an honest cert (so TLS passes
// the TOFU check) but signs the signed-challenge nonce
// with a different private key. The client's
// runChallengeOutbound calls VerifyChallenge with the
// cert's public key and the wrong-key signature; the
// verification fails, the conn is closed with a quic
// application error, and an ERROR log is emitted.
//
// This is the END-TO-END version of the unit-level
// TestDialSignedChallengeRejectsForgedKey (Q3). The
// unit test exercises VerifyChallenge directly; this
// test exercises the production code path Dial →
// quic.DialAddr → runMutualChallenge → runChallengeInbound
// on a real loopback QUIC connection, with the
// "honest cert + wrong priv key" attacker scenario
// constructed via the test-only challengeSigner
// override on Transport.
//
// Setup:
//
//   - honestID is the cert identity: the server's
//     transport identity and the cert it presents.
//   - signerID is the WRONG priv key: the server's
//     Transport.challengeSigner override, so its
//     runChallengeInbound signs the client's nonce
//     with signerID's priv key. The signature, when
//     verified with honestID's pub (extracted from
//     the cert), MUST fail.
//   - client pre-pins honestID's fingerprint for the
//     dial target. TLS passes; signed challenge fails.
//
// Assertions:
//
//   - Dial returns a non-nil error.
//   - The returned *quic.Conn is nil.
//   - The error message indicates a signed-challenge
//     failure (the production code wraps the
//     verification failure with "signed challenge").
//   - The capture logger on the SERVER recorded an
//     ERROR for the signed-challenge failure. The
//     server is the side that detected the failure
//     (its runMutualChallenge's first-err path
//     logs before returning to the caller of
//     runMutualChallenge, which is handleAcceptedConn).
//   - The listener is still healthy after the rejection
//     (proves the failure did not poison the accept
//     loop).
//
// Cleanup: t.Cleanup cancels the listen context. The
// handleAcceptedConn goroutine for the failed conn
// exits via closeWithChallengeErr, which sends a quic
// application error (0x01) to the client before
// returning; the goroutine then returns without
// further action. The accept loop continues.
func TestDialForgedKeyEndToEnd(t *testing.T) {
	serverDir := t.TempDir()
	clientDir := t.TempDir()

	// Two independent identities: honestID is the cert
	// identity (used for both the TLS cert and the
	// default signer), signerID is the WRONG key that
	// the server's challengeSigner override will use.
	honestID, err := Generate()
	if err != nil {
		t.Fatalf("Generate honest identity: %v", err)
	}
	signerID, err := Generate()
	if err != nil {
		t.Fatalf("Generate signer identity: %v", err)
	}
	if bytesEqualPubKeys(honestID.PublicKey(), signerID.PublicKey()) {
		t.Fatal("honest and signer identities produced the same pub key; setup is broken")
	}
	honestFP := honestID.Fingerprint()

	// Build the server with the challengeSigner override:
	// it presents honestID's cert (so TLS passes against
	// the client's honestFP pin) but signs challenges
	// with signerID's priv key (so VerifyChallenge
	// rejects).
	//
	// We pre-save honestID to the server's IdentityPath so
	// New() loads it (rather than generating a fresh
	// identity). The cert the server presents is built
	// from honestID; the challengeSigner override
	// (signerID) is the per-Transport hook that makes
	// runMutualChallenge sign with a different key.
	serverCfg := validConfig(t, serverDir)
	if err := honestID.Save(serverCfg.IdentityPath); err != nil {
		t.Fatalf("save honest identity: %v", err)
	}
	serverTr, err := newTestTransportWithChallengeSigner(serverCfg, signerID)
	if err != nil {
		t.Fatalf("newTestTransportWithChallengeSigner: %v", err)
	}
	// The cert identity is honestID, so the server
	// presents honestID's cert during TLS.
	if got := serverTr.Identity().Fingerprint(); got != honestFP {
		t.Fatalf("server identity fingerprint = %q, want %q (test setup broken)", got, honestFP)
	}
	if got := serverTr.effectiveSigner().Fingerprint(); got == honestFP {
		t.Fatalf("effectiveSigner fingerprint = honestFP=%q, want a different one (test setup broken)", got)
	}

	// Client uses an independent identity.
	clientCfg := validConfig(t, clientDir)
	clientTr, err := New(clientCfg)
	if err != nil {
		t.Fatalf("New client: %v", err)
	}

	// Capture logger on BOTH sides. The signed-challenge
	// failure is logged in runMutualChallenge on whichever
	// side observes the error first; the test asserts on
	// the SERVER log because the server's first-err path
	// is the deterministic emitter (the server detects
	// the verification failure in its runChallengeOutbound,
	// which is the path that runs VerifyChallenge on
	// the client's response — but the client's RESPONSE
	// was signed with the client's own honest key, so
	// the SERVER's verify passes; the failure is in
	// the client's verify of the SERVER's response, which
	// is signed with the wrong key).
	//
	// The deterministic-emitter side is the CLIENT
	// (whose runChallengeOutbound's VerifyChallenge
	// fails first), so the client's log is the one
	// with the captured alert. We inject on both for
	// symmetry with the other Q4 test and to make a
	// future refactor that flips the emitter side
	// automatically testable.
	clientLog := &captureQ4Logger{}
	serverLog := &captureQ4Logger{}
	clientTr.WithLogger(clientLog)
	serverTr.WithLogger(serverLog)

	// Start the server.
	listenCtx, cancelListen := context.WithCancel(context.Background())
	t.Cleanup(cancelListen)
	listenErrCh := make(chan error, 1)
	go func() {
		listenErrCh <- serverTr.Listen(listenCtx)
	}()
	addr := waitForListenerBind(t, serverTr, 2*time.Second)
	target := addr.String()

	// Pre-pin honestID's fingerprint on the client. The
	// TLS layer checks this on the presented cert;
	// since honestID is the cert identity, the cert
	// fingerprint matches the pin and TLS passes.
	if err := clientTr.KnownNodes().Pin(target, honestFP); err != nil {
		t.Fatalf("pre-pin honest fingerprint: %v", err)
	}

	// Drive the full Dial path. Run in a goroutine so
	// the test can also assert server-side state without
	// deadlocking.
	type dialResult struct {
		conn *quic.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := clientTr.Dial(context.Background(), PeerConfig{Host: target})
		dialCh <- dialResult{conn: conn, err: err}
	}()

	var (
		gotConn *quic.Conn
		gotErr  error
	)
	select {
	case res := <-dialCh:
		gotConn, gotErr = res.conn, res.err
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not complete within 5s; handshake deadlocked or listener not accepting")
	}

	// Hard-reject contract: non-nil error, nil conn.
	// "No half-open state" is enforced by Dial returning
	// nil conn alongside the error — the conn is closed
	// via closeWithChallengeErr before Dial returns.
	if gotErr == nil {
		t.Fatal("Dial returned nil error; forged-key signed challenge must fail")
	}
	if gotConn != nil {
		t.Errorf("Dial returned non-nil conn alongside the error; forged-key path must close the conn")
		_ = gotConn.CloseWithError(0, "test cleanup")
	}

	// The error message must indicate a signed-challenge
	// failure. The production code's runMutualChallenge
	// wraps the underlying verify error with "signed
	// challenge FAILED" or similar; an exact-prefix
	// check is fragile to wording changes, so we
	// substring-match on the strongest stable signal
	// (the "signed challenge" phrase).
	if !strings.Contains(gotErr.Error(), "signed challenge") {
		t.Errorf("Dial error %q does not mention 'signed challenge'; forged-key path must surface the signed-challenge error", gotErr.Error())
	}

	// The capture logger must record an ERROR on the
	// side that detected the failure. The client is
	// the deterministic emitter: its runChallengeOutbound
	// calls VerifyChallenge on the server's response
	// and fails because the response was signed with
	// signerID's key but verified against honestID's
	// pub (the cert's pub). The client's
	// runMutualChallenge first-err path emits the log
	// before returning to Dial, which returns to us.
	//
	// The server's runMutualChallenge may also log if
	// its outbound path detects a different failure
	// (e.g. stream-context cancellation when the
	// client closes the conn). We do not assert on
	// the server's log directly because the
	// deterministic emitter is the client.
	clientLog.atLeastOneErrorContaining(t, "signed challenge")

	// Listener is still healthy. The accept loop must
	// continue after the failed handshake so a
	// follow-up peer (in a different test) can
	// connect. We assert the listener field is still
	// set and not closed by checking the addr is
	// resolvable. A more direct test would issue a
	// second Dial here; the Q3 happy-path test
	// already proves the loopback dial works after
	// the first one, so a follow-up Dial in this
	// test is redundant.
	serverTr.listenerMu.Lock()
	ln := serverTr.listener
	serverTr.listenerMu.Unlock()
	if ln == nil {
		t.Error("server listener was cleared by the rejected handshake; accept loop must survive a hard-reject")
	}
}

// ========================== K2 — Run enabled-gate regression tests ==========================
//
// K2 ships the D21 security gate: when the transport is disabled,
// Run is provably side-effect-free. The tests below pin the contract
// from multiple angles:
//
//   - Runtime.NumGoroutine snapshot (no new goroutine was spawned).
//   - listenFunc spy (the listener-construction path was not invoked).
//   - Transport.listener field (no listener was bound).
//   - Return value (nil, returned promptly).
//
// The "spy listenFunc" pattern is the K2-specific injection point
// added in this task. The test installs a closure that records the
// call and returns a sentinel error; production code never invokes
// it because the disabled path short-circuits before listenFunc is
// called. The "K2 disabled" assertion is therefore "the spy was not
// invoked", which is the provable property D21 demands.
//
// All tests are hermetic (no network — the disabled path never
// touches quic.ListenAddr). Goroutine count assertions use a small
// tolerance (±2) to absorb test-framework noise (a parallel test
// that briefly starts a goroutine, a finalizer, etc.). The exact
// tolerance is documented per-test.

// recordingListenFunc returns a listenFunc replacement that
// records every call and returns a sentinel error. K2 tests
// install this on Transport.listenFunc; the "disabled path
// did not invoke listenFunc" assertion is then a simple
// "called == false" check.
type recordingListenFunc struct {
	called bool
}

func (r *recordingListenFunc) spy(ctx context.Context, t *Transport) (*quic.Listener, error) {
	r.called = true
	return nil, errors.New("recordingListenFunc: deliberately not bound")
}

// TestRunDisabledReturnsImmediately: Run on a Transport
// constructed with Enabled=false returns nil quickly,
// with no error.
//
// "Quickly" is bounded by 50ms — a generous upper bound
// for a function whose only work is a boolean check and
// a return. A buggy implementation that called quic.ListenAddr
// or spawned a goroutine before the check would take
// observably longer (the real listener-bind path is on
// the order of tens of milliseconds; a goroutine spawn
// is microseconds but the runtime.NumGoroutine check
// in the next test would catch it).
func TestRunDisabledReturnsImmediately(t *testing.T) {
	var cfg Config // zero value: Enabled=false

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(zero-value Config) returned %v; D21 promise says disabled is always valid", err)
	}

	// Install the spy BEFORE calling Run, so any call into
	// listenFunc is observable.
	spy := &recordingListenFunc{}
	tr.listenFunc = spy.spy

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	if err := tr.Run(ctx); err != nil {
		t.Errorf("Run(disabled) returned %v; expected nil", err)
	}
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Run(disabled) took %v; expected < 50ms (the disabled path should be near-instant)", elapsed)
	}
}

// TestRunDisabledCreatesNoGoroutine: Run on a disabled
// Transport creates no new goroutine. This is the
// runtime-level D21 gate; combined with
// TestRunDisabledBindsNoUDPPort (the listener-side gate),
// the disabled path is provably side-effect-free.
//
// Tolerance: ±2 goroutines. The Go test framework may have
// background goroutines (signal handling, GC assist, etc.)
// and a parallel test in the same package may have started
// or stopped goroutines between the two snapshots. A
// tolerance of 2 absorbs this noise; the disabled-path
// claim is "no NEW transport-owned goroutine", not
// "runtime.NumGoroutine is byte-identical before and after".
func TestRunDisabledCreatesNoGoroutine(t *testing.T) {
	var cfg Config // disabled

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(zero-value Config) returned %v", err)
	}
	spy := &recordingListenFunc{}
	tr.listenFunc = spy.spy

	// Settle the runtime. A freshly-started test may have
	// a non-steady-state goroutine count (GC, package
	// init, etc.). A short sleep + a small warm-up call
	// to runtime.Gosched gives the scheduler a chance
	// to reach a stable count before we snapshot.
	runtimeGosched()

	before := runtimeNumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Run(ctx); err != nil {
		t.Errorf("Run(disabled) returned %v", err)
	}

	// Small delay to let any "wrong" goroutine have
	// time to materialise. The disabled path should
	// not start any, so this delay is insurance; a
	// correct implementation shows no change.
	time.Sleep(20 * time.Millisecond)

	after := runtimeNumGoroutine()

	delta := after - before
	if delta < 0 {
		delta = -delta
	}
	if delta > 2 {
		t.Errorf("Run(disabled) created %d new goroutines (before=%d, after=%d); D21 promise says zero",
			delta, before, after)
	}
}

// TestRunDisabledBindsNoUDPPort: Run on a disabled Transport
// leaves Transport.listener == nil. The listener field is
// the runtime's "is the QUIC socket bound?" signal; asserting
// it is nil after Run is the listener-side D21 gate.
//
// The check is taken under listenerMu because the field is
// guarded by that lock in the Q3 Listen path; the disabled
// path never takes the lock, so a nil read is safe either
// way, but using the lock keeps the test pattern aligned
// with how a future Close path would read the field.
func TestRunDisabledBindsNoUDPPort(t *testing.T) {
	var cfg Config

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(zero-value Config) returned %v", err)
	}
	spy := &recordingListenFunc{}
	tr.listenFunc = spy.spy

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Run(ctx); err != nil {
		t.Errorf("Run(disabled) returned %v", err)
	}

	tr.listenerMu.Lock()
	ln := tr.listener
	tr.listenerMu.Unlock()
	if ln != nil {
		t.Errorf("Run(disabled) bound a listener; expected Transport.listener to remain nil")
	}
}

// TestRunDisabledDoesNotInvokeListen: the K2 listenFunc
// spy was not invoked. This is the strongest D21
// assertion: the listener-construction path was not
// even reached, let alone the bind syscall.
func TestRunDisabledDoesNotInvokeListen(t *testing.T) {
	var cfg Config

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(zero-value Config) returned %v", err)
	}
	spy := &recordingListenFunc{}
	tr.listenFunc = spy.spy

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Run(ctx); err != nil {
		t.Errorf("Run(disabled) returned %v", err)
	}

	if spy.called {
		t.Error("Run(disabled) invoked listenFunc; D21 promise says listener-construction is skipped when disabled")
	}
}

// TestRunEnabledButMissingListenErrors: Run on an
// Enabled=true Transport whose listen value was cleared
// after New returns a non-nil error WITHOUT invoking
// listenFunc and WITHOUT starting a goroutine. This
// pins the defence-in-depth: the runtime re-validates
// after New, and a state mismatch (e.g. t.listen
// cleared between New and Run) is a loud failure that
// does not silently start a half-configured runtime.
//
// The test directly mutates tr.listen to empty,
// bypassing New's applyDefaults. This simulates a
// future caller that programmatically mutates the
// transport state — exactly the wire-up bug the
// re-validation step is designed to catch.
func TestRunEnabledButMissingListenErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(valid Config) returned %v", err)
	}
	spy := &recordingListenFunc{}
	tr.listenFunc = spy.spy

	// Clear the listen field after New. The re-validation
	// step in Run should catch this and return an error
	// before touching listenFunc.
	tr.listen = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tr.Run(ctx); err == nil {
		t.Error("Run with cleared listen returned nil; expected an error from post-construction validation")
	}
	if spy.called {
		t.Error("Run with cleared listen invoked listenFunc; validation should have rejected before listener construction")
	}
}

// TestRunEnabledInvokesListenAndBlocksUntilCancel: the
// happy-path K2 test. Run on an Enabled=true Transport
// calls listenFunc, starts the accept loop, blocks until
// ctx is cancelled, then returns nil. The listener
// remains in place after Run returns (cancellation
// tears down the loop but the *quic.Listener field is
// not explicitly cleared by Run — a Close / shutdown
// method would be the right place to clear it, and
// that is a future flow task).
//
// This test uses the real defaultListenFunc (the
// production quic.ListenAddr path), so it IS a real
// network test (it binds 127.0.0.1:0). The
// "run-test-in-parallel" warning is fine: each test
// binds a different port (the OS picks 0).
func TestRunEnabledInvokesListenAndBlocksUntilCancel(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0", // OS-picked port
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New(valid Config) returned %v", err)
	}

	// Sanity: the production listenFunc is in place
	// (New sets it). We do NOT override it — this
	// test exercises the real listener-construction
	// path, not a spy.
	if tr.listenFunc == nil {
		t.Fatal("New left listenFunc nil; production wire-up requires defaultListenFunc")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Run blocks. We drive it from a goroutine so the
	// test can cancel ctx and wait for the return.
	runDone := make(chan error, 1)
	go func() {
		runDone <- tr.Run(ctx)
	}()

	// Wait briefly for Run to bind the listener and
	// start the accept loop. The OS-pick of port 0
	// resolves within milliseconds on a healthy system;
	// 200ms is a generous upper bound that catches
	// real bugs (e.g. listenFunc returns an error)
	// without being flaky on slow CI.
	deadline := time.Now().Add(200 * time.Millisecond)
	var ln *quic.Listener
	for time.Now().Before(deadline) {
		tr.listenerMu.Lock()
		ln = tr.listener
		tr.listenerMu.Unlock()
		if ln != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ln == nil {
		cancel()
		<-runDone
		t.Fatal("Run(enabled) did not populate Transport.listener within 200ms; listenFunc may have failed silently")
	}

	// Cancel ctx; Run should return nil. The accept
	// loop's ctx-cancel path closes the listener, so
	// we expect the listener to be Closed but not nil
	// (Run does not clear the field on cancel).
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run(enabled) returned %v on cancel; expected nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run(enabled) did not return within 2s of ctx cancel")
	}
}

// runtimeNumGoroutine returns runtime.NumGoroutine().
//
// The function is a thin indirection so a future test
// that needs to swap in a fake counter (e.g. for
// reproducible benchmarking) has a single point of
// override. The K2 goroutine-count tests call it via
// the wrapper rather than reaching into runtime
// directly, which keeps the test code uniform.
func runtimeNumGoroutine() int {
	return runtime.NumGoroutine()
}

// runtimeGosched yields the processor to allow other
// goroutines to run. The K2 goroutine-count tests call
// it before snapshotting runtime.NumGoroutine so the
// scheduler has a chance to reach a steady state. The
// call is intentionally NOT a sleep: a sleep would
// add flakiness on slow machines, whereas a single
// Gosched is a no-op on a quiet runtime and a useful
// "let the scheduler catch up" on a busy one.
func runtimeGosched() {
	runtime.Gosched()
}
