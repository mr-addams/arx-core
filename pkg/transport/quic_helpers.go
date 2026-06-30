// Package transport (quic_helpers.go): internal helpers used by the
// Q2 TLS/cert builders.
//
// These helpers are kept in a separate file (not inlined into
// quic.go) for two reasons:
//
//  1. The Q2 spec puts the user-visible API in quic.go
//     (buildQUICConfig, buildTLSConfig, the file-level package
//     docs). The helpers below are implementation detail — the
//     signer adapter, the cert-builder's "rand reader" choice,
//     and the small lookup method on KnownNodes. Inlining them
//     into quic.go would inflate that file past the
//     ~30-100 LOC sweet spot for "one cohesive concern" that
//     the project task-atomicity rule aims for.
//
//  2. Several helpers here (signer adapter, cert rand) are
//     trivially testable in isolation, so a separate file is
//     the natural home for their (forthcoming) tests. Q2's
//     quic_test.go tests the public surface; future tasks can
//     add quic_helpers_test.go if the helpers grow tests.
//
// What lives here:
//
//   - ed25519SignerFromIdentity: returns a crypto.Signer view of
//     the identity's private key. x509.CreateCertificate requires
//     a crypto.Signer; *Identity.privKey is one (ed25519.PrivateKey
//     implements crypto.Signer) but the field is unexported, so
//     callers in the same package use this adapter rather than
//     reach into the struct.
//   - randReader: the io.Reader passed to x509.CreateCertificate.
//     Ed25519 signing ignores the reader, so this is purely
//     cosmetic for Ed25519 — but x509.CreateCertificate's
//     signature requires a non-nil reader, so we expose a
//     package-level constant for clarity and future-proofing
//     (e.g. a future x509 change that actually consumes the
//     reader).
//   - (*KnownNodes).lookupForVerify: a tiny read used by the
//     hard-reject error path in verifyPeerCertificateImpl to
//     fetch the currently-pinned fingerprint for the error
//     message. Kept as a method (not exported) because the
//     only caller is the verification path.
package transport

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

// ed25519SignerFromIdentity returns a crypto.Signer view of the
// identity's Ed25519 private key.
//
// The identity's privKey field is ed25519.PrivateKey, which
// already implements crypto.Signer (it has a Sign(rand, msg, opts)
// method that delegates to ed25519.Sign). This helper exists to
// keep the type signature explicit at call sites: x509.CreateCertificate
// wants a crypto.Signer, and "pass the identity" is more readable
// than "cast privKey to crypto.Signer inline". It is a one-line
// accessor in code; the verbosity lives in the comment so the
// file's surface is obvious to a future reader.
func ed25519SignerFromIdentity(id *Identity) crypto.Signer {
	return id.privKey
}

// randReader is the io.Reader passed to x509.CreateCertificate.
//
// Ed25519 ignores the reader during signing (per
// crypto/ed25519 docs: "Sign signs the given message with priv.
// rand is ignored and can be nil."), so for Ed25519 this is a
// formality. We use crypto/rand.Reader rather than nil to keep
// the call site defensive against a future Ed25519 change that
// starts consuming the reader for, e.g., salted signing modes
// or hash-to-curve operations.
//
// Defined as a package-level constant (not a per-call local) so
// tests can assert "we use crypto/rand" by symbol identity if
// they need to. It is not exposed publicly.
var randReader io.Reader = rand.Reader

// ed25519PublicKeySize is the byte length of an Ed25519 public key
// (32 bytes per RFC 8032). Re-exported locally as a typed constant
// so buildSelfSignedCert's defensive check reads as
// "an ed25519 public key is 32 bytes" rather than
// "the magic number 32".
const ed25519PublicKeySize = ed25519.PublicKeySize
