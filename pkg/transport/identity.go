// Package transport holds the sentinel transport-layer code, including
// self-signed Ed25519 identities used by transport endpoints (DECISIONS D22, D23).
//
// Identities are isolated in this package so callers outside the transport layer
// cannot accidentally reach into the private key material.
package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// ========================== Identity — Ed25519 self-signed identity ==========================

// Identity represents a self-signed Ed25519 endpoint identity.
//
// Fields are deliberately unexported: exposing a private key would let callers
// leak secret material. The only stable public surface is Fingerprint().
// Public key and fingerprint are cached at construction time because an
// identity should be immutable after generation and fingerprinting is
// deterministic given the public key.
type Identity struct {
	privKey     ed25519.PrivateKey
	pubKey      ed25519.PublicKey
	fingerprint string
}

// Generate creates a brand-new Ed25519 identity.
//
// The returned identity carries a private key, the matching public key, and a
// pre-computed SHA-256 fingerprint. Callers MUST NOT share the private key;
// transport code should treat *Identity as an opaque credential.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 identity: %w", err)
	}

	fp := "sha256:" + hex.EncodeToString(sha256Sum(pub))
	return &Identity{
		privKey:     priv,
		pubKey:      pub,
		fingerprint: fp,
	}, nil
}

// Fingerprint returns the stable identity fingerprint.
//
// The format is "sha256:" + lowercase hex(SHA256(public key)). It is computed
// once at generation and cached to keep the receiver a plain value type.
func (i *Identity) Fingerprint() string {
	return i.fingerprint
}

// Save writes the identity's private key to path with 0600 permissions.
//
// The on-disk format is the raw 64-byte Ed25519 private key (RFC 8032 layout:
// 32-byte seed followed by 32-byte derived public key). This matches what
// crypto/ed25519.PrivateKey contains in memory, so a Load can reconstruct the
// full key with no further encoding.
//
// The write is atomic: bytes first go to a temporary file in the SAME directory
// as the target, then os.Rename swaps it into place. A crash between the temp
// write and the rename either leaves the old key untouched or the new key fully
// in place — never a half-written key file. The temp file is in the same
// directory because os.Rename is only atomic within one filesystem; a temp
// file on /tmp could cross filesystems and break the atomicity guarantee.
//
// 0600 is required by DECISION D23: the key file is a sensitive operational
// artefact and must be owner-readable only. We chmod the temp file BEFORE
// writing any key material so there is no window where the file exists with
// default (typically 0644) permissions.
func (i *Identity) Save(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "node.key.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	// Remove the temp file on any failure path. The success path closes + renames,
	// which deletes the temp entry from the directory.
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup; ignore error — the file may already be renamed away.
		_ = os.Remove(tmpPath)
	}()

	// Lock down permissions before any key bytes hit disk. On POSIX, CreateTemp
	// honours umask; 0600 explicit is the only way to guarantee owner-only.
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp key file: %w", err)
	}

	if _, err := tmp.Write(i.privKey); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write ed25519 key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp key file: %w", err)
	}

	// Atomic swap. From here on, either the old key file is intact, or the new
	// one is — never a half-written file at path.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp key file into place: %w", err)
	}
	return nil
}

// Load reads an Ed25519 identity from a raw 64-byte file produced by Save.
//
// The file must be exactly 64 bytes: any other size (truncated write, garbage,
// wrong-format file) is a hard error. crypto/ed25519.PrivateKey is a []byte of
// that fixed length — there is no way to recover a valid key from anything
// else, so silent zero-padding or zero-truncation would be a security bug.
//
// Public key and fingerprint are recomputed from the loaded private key rather
// than trusted from disk. This is the canonical recovery path: the public key
// is the trailing 32 bytes of the private key (per RFC 8032), and the
// fingerprint is SHA256(public key). Recomputing means a tampered key file
// cannot smuggle in a mismatched (public, private) pair.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity file %q has %d bytes, want %d", path, len(raw), ed25519.PrivateKeySize)
	}

	priv := ed25519.PrivateKey(raw)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		// Defensive: ed25519.PrivateKey.Public() always returns ed25519.PublicKey
		// in practice, but a future crypto/ed25519 change could break that
		// assumption. Treat it as a corrupted key file.
		return nil, fmt.Errorf("identity file %q: ed25519 public key type assertion failed", path)
	}

	fp := "sha256:" + hex.EncodeToString(sha256Sum(pub))
	return &Identity{
		privKey:     priv,
		pubKey:      pub,
		fingerprint: fp,
	}, nil
}

// PublicKey returns the Ed25519 public key half of this identity.
//
// The handshake (Group Q) sends this public key to the peer so the peer can
// verify signed challenges; the fingerprint is derived from the same bytes, so
// returning the raw key is safe — it is the entire identity, by definition
// (DECISION D22: a node's identity IS its Ed25519 public key).
func (i *Identity) PublicKey() ed25519.PublicKey {
	return i.pubKey
}

// SignChallenge produces an Ed25519 signature over nonce using this identity's
// private key.
//
// This is the "signed challenge" half of the handshake (DECISION D23, task I3):
// during the QUIC handshake the peer sends a random nonce, the node returns
// ed25519.Sign(priv, nonce), and the peer verifies with the pinned public key.
// It is defence-in-depth on top of TLS 1.3: even if a future quic-go bug
// mis-routes the self-signed certificate check, an attacker who has the
// presented cert still cannot forge the Ed25519 signature without the private
// key. The signature scheme is identical to ed25519.Sign — the wrapper exists
// only to keep callers from reaching into the unexported privKey field.
func (i *Identity) SignChallenge(nonce []byte) ([]byte, error) {
	return ed25519.Sign(i.privKey, nonce), nil
}

// VerifyChallenge checks that sig is a valid Ed25519 signature of nonce under
// the given public key.
//
// The function is package-level (not a method on *Identity) because the verifier
// is usually verifying a FOREIGN signature with a peer's public key it has
// received out of band — it does not have an *Identity for that peer, only the
// public key bytes. Putting verify on a receiver would force callers to
// construct a half-identity just to call a one-liner. The signature check is
// the standard ed25519.Verify; the wrapper exists to make the call site
// self-documenting ("is this a valid signed challenge?") rather than a bare
// ed25519 call buried in transport logic.
func VerifyChallenge(pub ed25519.PublicKey, nonce, sig []byte) bool {
	return ed25519.Verify(pub, nonce, sig)
}

// sha256Sum returns the SHA-256 digest of b as a byte slice suitable for hex encoding.
//
// It wraps sha256.Sum256 so the caller does not have to convert [32]byte to []byte.
func sha256Sum(b []byte) []byte {
	digest := sha256.Sum256(b)
	return digest[:]
}
