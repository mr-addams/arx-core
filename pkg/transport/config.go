// Package transport (config.go): Config struct, defaults, validation,
// and env-var resolution for the sentinel transport.
//
// File split decision (K1, 2026-06-30): the Config type and its
// validation/defaults were originally in quic.go (Q1 put them there
// because Q1 needed a Config to define New's signature and a separate
// file for a single type was over-engineering at Q1 time). K1 is the
// task that grows Config from a "minimum-field" placeholder into the
// user-facing configuration surface with defaults, env-var resolution,
// and explicit validation — exactly the cohesive concern that deserves
// its own file. Moving Config here keeps quic.go focused on the QUIC
// runtime surface (Transport, New, Listen, Dial, Run, signed challenge)
// and makes "where do I add a new config field?" answerable with
// "config.go" without grepping the runtime file.
//
// Q1's comment in quic.go said: "Moving to a dedicated config.go at
// K1 is a 1-line import-shuffle — no API impact." The shuffle turned
// out to be Config + PeerConfig + validate, with quic.go dropping the
// type declarations but otherwise unchanged. The transport package's
// exported surface is identical: same Config struct (same fields,
// same types), same New(cfg Config) signature, same constructors
// for downstream callers.
//
// LoadConfig interop notes (D25 + Group K brief):
//
// The arxsentinel product populates a Config from its config chain
// (YAML + env + flags) and passes the populated Config to
// transport.New. arx-core itself does NOT parse YAML: the transport
// package is a library, not a daemon, and the bootstrap layer is
// the product's job. The Config struct is the contract between the
// product and the transport; defaults and env-var resolution here
// are the convenience layer for products that want the "raw config
// fields" workflow (populate everything explicitly) and the "minimal
// config" workflow (rely on defaults + env) alike.
//
// Defaults and the precedence chain (K1 brief + D22):
//
//	explicit cfg value    (highest precedence — operator wins)
//	> env var             (operator-set env on the host)
//	> built-in default    (lowest precedence — safe loopback)
//
// Concretely, for the Listen field:
//
//	explicit cfg.Listen = "10.0.0.1:4097"  →  Listen = "10.0.0.1:4097"
//	empty cfg.Listen + ARXSENTINEL_TRANSPORT_LISTEN="10.0.0.1:4097"  →  Listen = "10.0.0.1:4097"
//	empty cfg.Listen + no env            →  Listen = "127.0.0.1:4097"  (default)
//
// IdentityPath and KnownNodesPath have NO defaults and NO env vars
// (Open Question 6 in DECISIONS.md is explicitly unresolved: the
// path's default location requires arx-core to know the config dir,
// which crosses the arx-core / config-chain boundary). Empty values
// for those two fields when Enabled=true are explicit misconfiguration
// errors caught by Validate.
//
// Why the precedence chain lives in applyDefaults and NOT in Validate:
// Validate is a pure, side-effect-free check ("are the resolved
// values usable?"). applyDefaults is the side-effecting step that
// reads the environment. Splitting them keeps Validate hermetic
// (testable with no env mutation) and makes "what did defaults do
// to my config?" answerable with "look at the result of
// applyDefaults, not Validate".
package transport

import (
	"fmt"
	"os"
	"path/filepath"
)

// ========================== K1 — Config, defaults, validation ==========================
//
// Env var names live as package-level constants so tests, docs, and
// future code can reference the string by symbol (not by literal)
// and a typo in one place surfaces as a build error rather than a
// silent "env var did nothing" runtime failure.
const (
	// envTransportListen is the env var that overrides the QUIC
	// listen address. D22 §1 names it explicitly: "default port
	// 4097, configurable via transport.listen and env
	// ARXSENTINEL_TRANSPORT_LISTEN". The constant is the single
	// source of truth; the applyDefaults method reads it.
	envTransportListen = "ARXSENTINEL_TRANSPORT_LISTEN"

	// defaultListenAddr is the loopback bind address the transport
	// uses when cfg.Listen is empty AND no env var is set. 127.0.0.1
	// (not 0.0.0.0) is the deliberate choice: a node that boots
	// without explicit configuration is most plausibly a test
	// instance or a developer workstation, neither of which should
	// be advertising a transport on all interfaces by default. The
	// 4097 port is D22 §1.
	//
	// This default is the explicit "operator did not configure"
	// fallback. An operator who wants 0.0.0.0:4097 (the
	// "advertise-on-every-interface" choice) must either set
	// cfg.Listen or export ARXSENTINEL_TRANSPORT_LISTEN.
	defaultListenAddr = "127.0.0.1:4097"
)

// PeerConfig is the config-level representation of a peer entry (D25).
//
// The struct is intentionally minimal: the transport does not parse YAML
// (D25 + the bootstrap integration is a later flow; the arxsentinel
// product config chain populates these values out-of-band). PeerConfig
// holds exactly what the transport needs to attempt a connection — host
// and the operator-pre-shared fingerprint, which may be empty for
// "TOFU on first contact" (D24 §5).
//
// Conversion to the runtime *Peer (with state machine, redial backoff,
// etc.) is Group R's job (R1). PeerConfig is the config entry-point;
// Peer is the lifecycle object. Keeping them separate means a config
// re-read does not reset in-flight connection state.
//
// PeerConfig was moved here from quic.go in the K1 file split. The
// type is small enough to live in either file; putting it next to
// Config (the slice element) makes the config-side surface reviewable
// in one place.
type PeerConfig struct {
	// Host identifies the peer for dialing. Format is whatever
	// net.ResolveUDPAddr accepts (host:port or host alone with default
	// port; PROTOCOL.md documents the expected form). The
	// transport does not parse it here — Dial is the boundary
	// where the string becomes a *net.UDPAddr.
	Host string

	// Fingerprint is the operator-pre-shared fingerprint, in the
	// canonical "sha256:<hex>" form produced by Identity.Fingerprint().
	// Empty means "TOFU on first contact": the first presented
	// fingerprint is pinned into known-nodes (D24 §5). A non-empty
	// value MUST match exactly — a mismatch at handshake time is the
	// Q4 hard-reject case.
	Fingerprint string
}

// Config is the transport configuration (K1 spec).
//
// The struct is the contract between the arxsentinel product config
// chain and the transport package. See the package-level comment at
// the top of this file for the LoadConfig interop story and the
// defaults / env / explicit precedence chain.
//
// Field rules (K1):
//
//   - Enabled is the master gate (D21). Zero value = false =
//     "disabled" — the K2 regression test (TestRunDisabledCreatesNoGoroutine
//     and friends) proves the disabled path is provably side-effect-free.
//   - IdentityPath is required when Enabled is true (D23). No default
//     and no env var (Open Question 6: the default location requires
//     knowing the bootstrap's config dir, which is cross-layer).
//   - Listen has a default (defaultListenAddr) and an env var
//     (envTransportListen). Empty + no env = the loopback default;
//     non-empty = the operator's choice; empty + env = the env value.
//   - KnownNodesPath is required when Enabled is true. No default
//     and no env var (same reasoning as IdentityPath).
//   - Peers is the config-level roster; R1 converts it into *Peer
//     instances with state. Empty is a valid "no peers yet" state.
//
// Zero-value Config: equivalent to {Enabled: false, no paths, no peers}.
// A caller who wants the transport enabled must populate at least
// Enabled=true, IdentityPath, KnownNodesPath, and Listen (or rely on
// the Listen default + env-var resolution in applyDefaults).
type Config struct {
	// Enabled is the master gate (D21). When false, the bootstrap
	// does not invoke the transport at all; the K2 regression test
	// proves this creates no goroutine and no listener.
	Enabled bool

	// IdentityPath is the on-disk location of the node's Ed25519
	// private key. Required when Enabled is true. New creates the
	// file here on first start (D23 §1).
	IdentityPath string

	// Listen is the QUIC bind address (D22 §1). Empty value is
	// resolved by applyDefaults: the env var wins, the built-in
	// loopback default wins if no env is set.
	Listen string

	// KnownNodesPath is the on-disk location of the TOFU
	// known-nodes file. Required when Enabled is true.
	KnownNodesPath string

	// Peers is the config-level peer roster (D25). The transport
	// does not dial from this slice in Q1; R1 turns it into
	// runtime *Peer objects with state.
	Peers []PeerConfig
}

// applyDefaults resolves defaults and env-var overrides onto a copy
// of cfg, returning the resolved Config.
//
// Precedence chain (highest to lowest):
//
//  1. explicit cfg value (operator wins)
//  2. env var (host-level configuration)
//  3. built-in default (safe loopback)
//
// The function does NOT mutate its argument. It returns a new
// Config; callers (New) use the returned value. The non-mutating
// shape makes the function testable (a test passes a Config, gets
// a Config back, asserts the resolution) and matches the
// "explicit value beats env" rule literally: an explicit cfg.Listen
// is never overwritten by the env var, because we only read the env
// when cfg.Listen is the empty string.
//
// The function reads os.Getenv directly. Tests that need to control
// the env-var value use t.Setenv (Go 1.17+; we are on 1.26) which
// restores the prior value at test cleanup.
//
// What applyDefaults does NOT do:
//
//   - Validate the resolved values. Validation is Validate's job
//     (see below) and runs AFTER applyDefaults in New.
//   - Mutate IdentityPath or KnownNodesPath. Both have no env vars
//     and no defaults (Open Question 6 is unresolved); empty values
//     are caught by Validate when Enabled is true.
//   - Touch the Enabled flag. The master gate is the caller's
//     decision; applyDefaults does not flip it.
func applyDefaults(cfg Config) Config {
	out := cfg

	// Listen: explicit > env > default. The "explicit wins" rule is
	// implemented by reading the env ONLY when cfg.Listen is the
	// empty string — non-empty cfg.Listen short-circuits the env
	// lookup entirely, which is the literal "operator value is
	// preserved" behaviour the precedence chain promises.
	if out.Listen == "" {
		if v := os.Getenv(envTransportListen); v != "" {
			out.Listen = v
		} else {
			out.Listen = defaultListenAddr
		}
	}

	return out
}

// Validate is the exported, K1-era validation step. It is the public
// surface for "check this Config before passing it to New", and the
// single place where Enabled semantics are enforced:
//
//   - Enabled=false: every field is allowed to be zero. The
//     transport is disabled; a disabled Transport does not look
//     at IdentityPath, KnownNodesPath, Listen, or Peers. A caller
//     who passes a zero-value Config (the D21 promise) gets back
//     a valid *Transport (no validation error).
//   - Enabled=true: IdentityPath, KnownNodesPath must be non-empty
//     and the parent dir of IdentityPath must exist; Listen must
//     be non-empty (applyDefaults guarantees this when called first
//     — callers that skip applyDefaults get a validation error
//     here, which is the loud failure the spec demands); each
//     PeerConfig in Peers must have a non-empty Host.
//
// Peers[].Fingerprint is NOT validated: empty is the legitimate
// "TOFU on first contact" path (D24 §5), and a non-empty value
// is checked at handshake time (Q4 hard-reject), not at config-load
// time. Validating the fingerprint shape at this layer would
// require a SHA-256-length check that the runtime never cares about.
//
// The function does NOT mutate its argument. The returned error is
// the only output; the caller decides what to do with a bad config.
// Calling Validate repeatedly is safe.
//
// What Q1's old validate() covered is preserved: the IdentityPath
// non-empty / parent-dir-exists / not-a-directory checks are
// unchanged. K1 extends that with the Enabled-aware "skip all the
// required-field checks when false" rule and the Peers[].Host
// non-empty check. K1's contribution is the Enabled branch; the
// Enabled=true branch is the same set of rules the old validate()
// had plus the new Peers check and the Listen check.
func (c *Config) Validate() error {
	// D21: disabled = no validation. A zero-value Config is
	// a valid Config when the transport is off; the K2
	// regression test (TestRunDisabledReturnsImmediately and
	// friends) is the security gate that proves this is
	// not a footgun.
	if !c.Enabled {
		return nil
	}

	// IdentityPath: required, parent dir must exist, must not
	// point at an existing directory. Same rules Q1 shipped.
	if c.IdentityPath == "" {
		return fmt.Errorf("transport: Config.IdentityPath is required when Enabled=true")
	}
	if c.KnownNodesPath == "" {
		return fmt.Errorf("transport: Config.KnownNodesPath is required when Enabled=true")
	}

	// Listen: required when Enabled=true. applyDefaults fills
	// it from env or the built-in default, so a caller that
	// ran applyDefaults before Validate will never hit this
	// branch. Callers that skip applyDefaults get a loud
	// failure here — exactly the "fail loudly, not silently"
	// posture the D21/D24/D23 spec demands.
	if c.Listen == "" {
		return fmt.Errorf("transport: Config.Listen is required when Enabled=true " +
			"(set it explicitly, or set ARXSENTINEL_TRANSPORT_LISTEN, or rely on the default)")
	}

	// Parent dir must exist. The transport does not mkdir — that is
	// the bootstrap's job (it knows the config dir layout, the
	// transport does not). If the parent is missing, fail loudly so
	// the operator notices the misconfiguration rather than seeing
	// a generated key appear in an unexpected place.
	dir := filepath.Dir(c.IdentityPath)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("transport: Config.IdentityPath parent dir %q: %w", dir, err)
	}

	// IdentityPath must not point at an existing directory. The
	// check is "does a non-file exist here?" — if the path is an
	// existing file, the next step (load-or-generate) will handle
	// it; if it is a directory, generation would fail with a
	// confusing os.Create error later. Catch it here with a
	// specific message.
	if info, err := os.Stat(c.IdentityPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("transport: Config.IdentityPath %q is a directory, not a file", c.IdentityPath)
		}
	}
	// err != nil at this point means "does not exist" — fine, that
	// is the first-start case. Any other stat error (perm denied
	// etc.) is also fine: Generate below will surface it as a
	// concrete Save() error rather than us pre-validating and
	// giving a less-actionable message.

	// Peers: each entry's Host must be non-empty. Fingerprint
	// is not validated (empty = TOFU, see function comment).
	for i, p := range c.Peers {
		if p.Host == "" {
			return fmt.Errorf("transport: Config.Peers[%d].Host is required when Enabled=true", i)
		}
	}

	return nil
}
