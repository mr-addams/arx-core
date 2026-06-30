// Package transport (config_test.go): tests for the K1 Config
// layer (defaults, env-var resolution, validation).
//
// What this file covers:
//
//   - TestConfigZeroValueIsDisabled — the D21 promise at the
//     struct level: a zero-value Config has Enabled == false,
//     which is the gate that makes "drop arx-core into a
//     project, it works without networking" possible.
//
//   - TestConfigExplicitEnabledIsPreserved — symmetry of the
//     above: Enabled=true is not silently flipped by applyDefaults
//     or Validate. The D21 promise is two-sided; the disabled
//     case is the common one, the enabled case must not regress
//     it.
//
//   - TestConfigApplyDefaultsListenEnvOverride — env-var beats
//     built-in default. Tests the middle rung of the precedence
//     chain (explicit > env > default).
//
//   - TestConfigApplyDefaultsListenDefault — env unset + empty
//     cfg → the built-in loopback default. Tests the bottom rung.
//
//   - TestConfigApplyDefaultsExplicitWinsOverEnv — top rung:
//     explicit cfg.Listen beats the env var. This is the
//     "operator wins" rule.
//
//   - TestConfigApplyDefaultsNoEnvNoDefaultLeavesItAlone —
//     defence: an Enabled=false Config with empty Listen is
//     left alone (applyDefaults only fills the default for
//     enabled configs in spirit, but the actual code applies
//     the default unconditionally because that simplifies the
//     precedence chain; the test pins the observed behaviour).
//
//   - TestConfigValidateDisabledAcceptsZeroValue — Validate on
//     a zero-value Config returns nil. This is the runtime
//     half of the D21 promise: the disabled path is
//     provably no-validation-error.
//
//   - TestConfigValidateEnabledRequiresIdentityPath — the
//     Enabled=true branch enforces IdentityPath non-empty.
//
//   - TestConfigValidateEnabledRequiresKnownNodesPath — the
//     Enabled=true branch enforces KnownNodesPath non-empty.
//
//   - TestConfigValidateEnabledRequiresListen — the
//     Enabled=true branch enforces Listen non-empty (after
//     applyDefaults fills it; the test exercises the
//     resolved path).
//
//   - TestConfigValidateEnabledRequiresPeerHost — the
//     Enabled=true branch enforces each PeerConfig.Host
//     non-empty.
//
//   - TestConfigValidateEnabledRejectsIdentityDir — the
//     IdentityPath-points-at-a-directory check (carried over
//     from Q1's validate, preserved by K1).
//
// All tests are hermetic (no network, no real env mutation
// outside t.Setenv). Tests use t.Setenv (Go 1.17+) which
// restores the prior value at test cleanup, so concurrent
// tests do not race on env-var state.
package transport

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigZeroValueIsDisabled is the D21 promise at the
// struct level: a zero-value Config has Enabled == false.
//
// The "disabled = side-effect-free" guarantee is K2's
// concern (no goroutine, no listener); this test is the
// CONFIG-SIDE counterpart — the struct itself must
// default to "off" so a caller who never set Enabled
// cannot accidentally turn the transport on.
func TestConfigZeroValueIsDisabled(t *testing.T) {
	var cfg Config // zero value
	if cfg.Enabled {
		t.Fatal("zero-value Config.Enabled is true; D21 promise says it must be false")
	}
}

// TestConfigExplicitEnabledIsPreserved is the symmetry
// of the D21 promise: Enabled=true is preserved through
// applyDefaults and Validate. A buggy implementation that
// silently flipped Enabled to false would be caught here.
func TestConfigExplicitEnabledIsPreserved(t *testing.T) {
	cfg := Config{Enabled: true}
	resolved := applyDefaults(cfg)
	if !resolved.Enabled {
		t.Error("applyDefaults flipped Enabled from true to false")
	}
	if err := resolved.Validate(); err != nil {
		// Validation may fail for other reasons (e.g. empty
		// IdentityPath on a minimal config); that is OK
		// because the test only asserts the flag was
		// preserved through the resolution step. We test
		// the full Validate path below with a complete
		// config.
		t.Logf("Validate on minimal Enabled=true config returned %v (expected for empty required fields)", err)
	}
}

// TestConfigApplyDefaultsListenEnvOverride: empty cfg +
// env set → Listen = env value.
//
// The env var is set via t.Setenv (Go 1.17+), which
// restores the prior value at test cleanup. Concurrent
// tests in this package that also use ARXSENTINEL_TRANSPORT_LISTEN
// must not race because t.Setenv serializes per-test cleanup
// in the Go test framework.
func TestConfigApplyDefaultsListenEnvOverride(t *testing.T) {
	const want = "10.0.0.1:4097"
	t.Setenv(envTransportListen, want)

	cfg := Config{Enabled: true} // Listen intentionally left empty
	resolved := applyDefaults(cfg)
	if resolved.Listen != want {
		t.Errorf("applyDefaults: Listen = %q, want %q (env var override)", resolved.Listen, want)
	}
}

// TestConfigApplyDefaultsListenDefault: empty cfg + no env
// → Listen = the built-in loopback default.
//
// This is the bottom rung of the precedence chain (default).
// The exact value is documented in config.go as
// defaultListenAddr; the test references the constant
// directly so a future change to the default does not silently
// desync the test.
func TestConfigApplyDefaultsListenDefault(t *testing.T) {
	t.Setenv(envTransportListen, "") // ensure no env override

	cfg := Config{Enabled: true} // Listen intentionally left empty
	resolved := applyDefaults(cfg)
	if resolved.Listen != defaultListenAddr {
		t.Errorf("applyDefaults: Listen = %q, want %q (built-in default)", resolved.Listen, defaultListenAddr)
	}
}

// TestConfigApplyDefaultsExplicitWinsOverEnv: explicit
// cfg.Listen beats the env var. This is the top rung of
// the precedence chain ("operator wins"). A buggy
// implementation that read the env unconditionally
// would be caught here.
func TestConfigApplyDefaultsExplicitWinsOverEnv(t *testing.T) {
	t.Setenv(envTransportListen, "10.0.0.1:4097")

	const explicit = "192.0.2.1:7777"
	cfg := Config{Enabled: true, Listen: explicit}
	resolved := applyDefaults(cfg)
	if resolved.Listen != explicit {
		t.Errorf("applyDefaults overrode explicit Listen: got %q, want %q (explicit must win over env)",
			resolved.Listen, explicit)
	}
}

// TestConfigApplyDefaultsNoEnvNoDefault: a Listen value
// that is already set is preserved verbatim, regardless
// of env or default. This is the "explicit beats everything"
// test for the case where the operator set the value
// explicitly.
func TestConfigApplyDefaultsPreservesExplicit(t *testing.T) {
	t.Setenv(envTransportListen, "") // no env

	const explicit = "0.0.0.0:4097"
	cfg := Config{Enabled: true, Listen: explicit}
	resolved := applyDefaults(cfg)
	if resolved.Listen != explicit {
		t.Errorf("applyDefaults changed explicit Listen: got %q, want %q", resolved.Listen, explicit)
	}
}

// TestConfigApplyDefaultsDisabledLeavesListenAlone: when
// Enabled is false, applyDefaults still resolves Listen
// (the function is "applies defaults unconditionally"
// — the Enabled flag is Validate's concern, not the
// default-resolution step's). The test pins the observed
// behaviour so a future refactor that makes applyDefaults
// skip resolution for disabled configs is intentional, not
// accidental.
func TestConfigApplyDefaultsDisabledLeavesListenAlone(t *testing.T) {
	t.Setenv(envTransportListen, "")

	cfg := Config{} // zero value: disabled, no Listen
	resolved := applyDefaults(cfg)
	// applyDefaults unconditionally fills the default; the
	// Enabled=false gate lives in Validate, not here. The
	// test asserts the observed behaviour: Listen is filled
	// even on a disabled config. The disabled path then
	// never reads Listen (Run early-returns before any
	// listen construction), so filling it is harmless.
	if resolved.Listen != defaultListenAddr {
		t.Errorf("applyDefaults: Listen = %q on disabled cfg, want %q (default applies unconditionally)",
			resolved.Listen, defaultListenAddr)
	}
}

// TestConfigValidateDisabledAcceptsZeroValue: a zero-value
// Config validates clean. This is the runtime half of
// the D21 promise: a caller who constructs a
// transport.New(zero-value-Config) gets back a usable
// (but disabled) Transport with no validation error.
func TestConfigValidateDisabledAcceptsZeroValue(t *testing.T) {
	var cfg Config // zero value
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate on zero-value Config returned %v; D21 promise says disabled is always valid", err)
	}
}

// TestConfigValidateEnabledRequiresIdentityPath: Enabled=true
// with empty IdentityPath is a validation error.
func TestConfigValidateEnabledRequiresIdentityPath(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   "", // missing
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate on Enabled=true with empty IdentityPath returned nil; expected error")
	}
	if !strings.Contains(err.Error(), "IdentityPath") {
		t.Errorf("error %q does not mention IdentityPath", err.Error())
	}
}

// TestConfigValidateEnabledRequiresKnownNodesPath: Enabled=true
// with empty KnownNodesPath is a validation error.
func TestConfigValidateEnabledRequiresKnownNodesPath(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: "", // missing
		Listen:         "127.0.0.1:0",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate on Enabled=true with empty KnownNodesPath returned nil; expected error")
	}
	if !strings.Contains(err.Error(), "KnownNodesPath") {
		t.Errorf("error %q does not mention KnownNodesPath", err.Error())
	}
}

// TestConfigValidateEnabledRequiresListen: Enabled=true
// with empty Listen is a validation error. (applyDefaults
// fills the default in New; this test exercises the raw
// Validate call, which is the case where a caller skipped
// applyDefaults.)
func TestConfigValidateEnabledRequiresListen(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "", // missing
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate on Enabled=true with empty Listen returned nil; expected error")
	}
	if !strings.Contains(err.Error(), "Listen") {
		t.Errorf("error %q does not mention Listen", err.Error())
	}
}

// TestConfigValidateEnabledRequiresPeerHost: Enabled=true
// with a PeerConfig whose Host is empty is a validation
// error.
func TestConfigValidateEnabledRequiresPeerHost(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
		Peers: []PeerConfig{
			{Host: ""}, // missing
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate on Enabled=true with empty Peers[0].Host returned nil; expected error")
	}
	if !strings.Contains(err.Error(), "Peers[0]") {
		t.Errorf("error %q does not name the offending Peers index", err.Error())
	}
}

// TestConfigValidateEnabledAcceptsEmptyPeers: Enabled=true
// with no Peers at all is valid. The transport can run
// with zero configured peers (it just does not dial out).
// The bootstrap might add peers later via the v0.x live-
// reconfig flow (DECISION D25 forbids it for v0.1.0; but
// the validation step itself does not require non-empty
// Peers).
func TestConfigValidateEnabledAcceptsEmptyPeers(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
		Peers:          nil, // explicitly empty
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate on Enabled=true with empty Peers returned %v; empty is valid", err)
	}
}

// TestConfigValidateEnabledRejectsIdentityDir: an IdentityPath
// that points at an existing directory is rejected. This
// rule was preserved from Q1's validate; K1 keeps it.
func TestConfigValidateEnabledRejectsIdentityDir(t *testing.T) {
	dir := t.TempDir()
	// Use dir itself as the IdentityPath — it exists and
	// is a directory. Validate should reject this.
	cfg := Config{
		Enabled:        true,
		IdentityPath:   dir, // a directory
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate on IdentityPath=directory returned nil; expected error")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error %q does not explain the directory problem", err.Error())
	}
}

// TestConfigValidateEnabledAcceptsCompleteConfig: a
// well-formed Enabled=true Config validates clean. This
// is the "happy path" gate for the K1 validation story;
// every other test in this file exercises a specific
// failure mode, and this one asserts the all-fields-
// populated shape is accepted.
func TestConfigValidateEnabledAcceptsCompleteConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
		Peers: []PeerConfig{
			{Host: "10.0.0.1:4097", Fingerprint: "sha256:abc"},
			{Host: "10.0.0.2:4097", Fingerprint: ""}, // empty fingerprint = TOFU, valid
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate on a complete Enabled=true Config returned %v; expected nil", err)
	}
}

// TestNewAppliesDefaultsBeforeValidate: New(cfg) resolves
// defaults (env > built-in) BEFORE running Validate, so a
// caller who supplies a Config with empty Listen gets a
// successful New with the default Listen value baked in.
//
// The order matters: validating the un-defaulted config
// would produce a spurious "Listen is required" error on
// a config that would have been valid after env-var
// resolution. This test pins the order.
func TestNewAppliesDefaultsBeforeValidate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envTransportListen, "")

	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		// Listen intentionally left empty — applyDefaults should
		// fill it with the default before Validate runs.
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New with empty Listen and no env: %v (defaults should have filled it)", err)
	}
	if tr.listen != defaultListenAddr {
		t.Errorf("Transport.listen = %q, want %q (default applied)", tr.listen, defaultListenAddr)
	}
}

// TestNewEnvVarWinsOverDefault: ARXSENTINEL_TRANSPORT_LISTEN
// overrides the built-in default. The end-to-end form of
// TestConfigApplyDefaultsListenEnvOverride: the resolved
// value lands on the Transport's listen field.
func TestNewEnvVarWinsOverDefault(t *testing.T) {
	dir := t.TempDir()
	const want = "192.0.2.5:9999"
	t.Setenv(envTransportListen, want)

	cfg := Config{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		// Listen left empty — env should win.
	}

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New with env var: %v", err)
	}
	if tr.listen != want {
		t.Errorf("Transport.listen = %q, want %q (env var applied)", tr.listen, want)
	}
}

// TestNewDisabledZeroValueSucceeds: a zero-value Config
// (Enabled=false, no paths) goes through New successfully.
// The K2 regression test (TestRunDisabledReturnsImmediately)
// is the runtime half of the D21 promise; this is the
// construction half: a disabled Config is a valid input
// to New.
func TestNewDisabledZeroValueSucceeds(t *testing.T) {
	var cfg Config // zero value: Enabled=false, all paths empty

	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New on zero-value Config returned %v; D21 promise says disabled is always valid", err)
	}
	if tr == nil {
		t.Fatal("New on zero-value Config returned nil Transport")
	}
	if tr.enabled {
		t.Error("Transport.enabled = true on zero-value Config; D21 promise says it must be false")
	}
}
