// ========================== Identity tests =================================================
//
//	Tests verify identity generation is non-deterministic and that the fingerprint
//	follows the documented "sha256:" prefix format.
package transport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateProducesDistinctFingerprints proves that Generate uses fresh randomness.
//
// A deterministic key generator would silently defeat the self-signed identity design,
// so we guard the contract with an explicit inequality check.
func TestGenerateProducesDistinctFingerprints(t *testing.T) {
	id1, err := Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, id1.Fingerprint())

	id2, err := Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, id2.Fingerprint())

	assert.NotEqual(t, id1.Fingerprint(), id2.Fingerprint(),
		"two freshly generated identities must have different fingerprints")
}

// TestFingerprintHasSHA256Prefix verifies the documented fingerprint format.
//
// The prefix matters because downstream transport code may split on it to determine
// the digest algorithm; an unexpected format would break peer identity comparisons.
func TestFingerprintHasSHA256Prefix(t *testing.T) {
	id, err := Generate()
	require.NoError(t, err)

	assert.True(t, hasPrefix(id.Fingerprint(), "sha256:"),
		"fingerprint must start with sha256: prefix")
}

// hasPrefix reports whether s starts with prefix.
//
// Kept in the test file as a tiny helper so the package under test has no
// unnecessary dependencies.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// TestSaveLoadRoundTrip proves that a freshly generated identity survives a
// Save/Load cycle with its fingerprint intact.
//
// The fingerprint is derived from the public key, which in turn is recomputed
// from the private key on Load. If the file format silently dropped or
// reordered bytes, the recovered public key would differ and the fingerprint
// would not match. This is the single most important test in identity.go: it
// covers end-to-end the full generation → serialization → deserialization
// pipeline.
func TestSaveLoadRoundTrip(t *testing.T) {
	id, err := Generate()
	require.NoError(t, err)
	originalFP := id.Fingerprint()
	require.NotEmpty(t, originalFP)

	path := filepath.Join(t.TempDir(), "node.key")
	require.NoError(t, id.Save(path))

	loaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, originalFP, loaded.Fingerprint(),
		"fingerprint must match after save/load round-trip")
}

// TestLoadWrongSize proves that Load refuses to read a key file that is not
// exactly 64 bytes.
//
// A truncated or padded file would produce a syntactically-valid Ed25519
// PrivateKey (it is just a []byte) but with garbage cryptographic content —
// silent acceptance would be a security bug. The error must be loud so an
// operator sees "this file is corrupt" rather than "this node has a new key".
func TestLoadWrongSize(t *testing.T) {
	// 32 bytes is half the expected key — a plausible truncation size from a
	// failed write that made it through the OS buffer.
	path := filepath.Join(t.TempDir(), "short.key")
	require.NoError(t, os.WriteFile(path, make([]byte, 32), 0o600))

	_, err := Load(path)
	require.Error(t, err, "loading a 32-byte file must fail")
	assert.Contains(t, err.Error(), "32",
		"error must mention the actual size to help diagnosis")
}

// TestSavePermissions0600 proves that Save writes a 0600 file (owner read/write
// only), as required by DECISION D23.
//
// This is a regression guard against a future refactor that drops the explicit
// chmod — a default-umask 0644 key file is a security bug for a node that
// hosts an Ed25519 identity used for transport authentication.
func TestSavePermissions0600(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod 0600 is not enforced when running as root; skipping permission check")
	}

	id, err := Generate()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "node.key")
	require.NoError(t, id.Save(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"key file must be owner read/write only")
}

// TestSignVerifyRoundTrip proves that a signature produced by SignChallenge
// verifies cleanly under the matching PublicKey.
//
// This is the happy path of the handshake proof (DECISION D23, task I3): the
// node signs the peer's nonce, the peer verifies with the public key it
// pinned. If this round-trip ever broke, the entire signed-challenge layer
// would be silently useless.
func TestSignVerifyRoundTrip(t *testing.T) {
	id, err := Generate()
	require.NoError(t, err)

	nonce := []byte("handshake-nonce-1f3a")
	sig, err := id.SignChallenge(nonce)
	require.NoError(t, err)
	require.NotEmpty(t, sig, "ed25519 signature must not be empty")

	assert.True(t, VerifyChallenge(id.PublicKey(), nonce, sig),
		"signature produced by SignChallenge must verify under the matching public key")
}

// TestVerifyTamperedNonce proves that flipping a single bit of the signed
// nonce causes verification to fail.
//
// Ed25519 is deterministic over the signed message: any change to the message
// bytes must invalidate the signature. A test that produces a signature over
// nonce A and "verifies" it against nonce B is a security bug — it would let an
// attacker replay signatures in a different context. The tamper is one byte
// xor'd with 0x01 so the test reads cleanly.
func TestVerifyTamperedNonce(t *testing.T) {
	id, err := Generate()
	require.NoError(t, err)

	nonce := []byte("handshake-nonce-2b7e")
	sig, err := id.SignChallenge(nonce)
	require.NoError(t, err)

	tampered := append([]byte(nil), nonce...)
	tampered[0] ^= 0x01

	assert.False(t, VerifyChallenge(id.PublicKey(), tampered, sig),
		"verification must fail when the nonce differs from what was signed")
}

// TestVerifyWrongKey proves that a valid signature under one key does NOT
// verify under a different, unrelated public key.
//
// This guards the TOFU-boundary check (DECISION D24): if verification somehow
// accepted a signature under any pubkey, an attacker who intercepted a
// signature from a real peer could replay it as if it came from themselves.
// A fresh *Identity gives a key that shares no private material with the
// signer, so a "true" return here is a bug in either Ed25519 or this wrapper.
func TestVerifyWrongKey(t *testing.T) {
	signer, err := Generate()
	require.NoError(t, err)

	other, err := Generate()
	require.NoError(t, err)
	require.NotEqual(t, signer.PublicKey(), other.PublicKey(),
		"sanity: two freshly generated identities must have distinct public keys")

	nonce := []byte("handshake-nonce-3c9d")
	sig, err := signer.SignChallenge(nonce)
	require.NoError(t, err)

	assert.False(t, VerifyChallenge(other.PublicKey(), nonce, sig),
		"a signature under one key must not verify under an unrelated key")
}
