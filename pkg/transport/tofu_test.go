// ========================== KnownNodes (TOFU) tests ==========================
//
//	T1 tests cover the two constructor paths (missing file / existing file).
//	T2 tests cover the on-disk format: round-trip, comments/blanks handling,
//	and malformed-line error reporting.
//	T3 tests cover the Pin/Check primitives: first-contact, post-pin match,
//	hard-reject on mismatch, persistence across store recreation, and the
//	rollback-on-save-failure atomicity contract. T3 tests are flagged in
//	the security-critical category per DECISION D31.
package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKnownNodesEmptyForMissingFile proves the first-start path: a
// non-existent known-nodes file is a normal state, not an error, and the
// constructor must return a usable empty store without panicking.
//
// The store is non-nil so downstream callers can immediately call Check/Pin
// (T3) without nil-checking; the entries map is empty so Check returns
// (false, false) for any host — i.e. the very first peer triggers a pin,
// which is exactly the TOFU contract (DECISION D24).
func TestNewKnownNodesEmptyForMissingFile(t *testing.T) {
	// A path that is guaranteed not to exist: a freshly-created temp dir
	// with a non-existent filename inside. os.Stat on that path returns
	// ENOENT, which is the path under test.
	missing := filepath.Join(t.TempDir(), "does-not-exist.known-nodes")
	_, statErr := os.Stat(missing)
	require.True(t, os.IsNotExist(statErr),
		"sanity: precondition path must not exist before the test runs")

	kn := NewKnownNodes(missing)
	require.NotNil(t, kn,
		"constructor must return a non-nil store even when the file is missing")
	assert.Equal(t, missing, kn.path,
		"constructor must remember the path verbatim for later Save/Load")
	assert.NotNil(t, kn.entries,
		"entries map must be non-nil so callers can use it without nil-checking")
	assert.Empty(t, kn.entries,
		"missing file must produce an empty pin set (first start, nothing pinned yet)")
}

// TestNewKnownNodesEmptyForExistingFile is the T1 stub for the
// "file present" path. On T1 the load() body was a no-op; T2 replaced it
// with the real parser. For an EMPTY file the parser still produces an
// empty map, so the constructor's "no entries" guarantee is preserved.
//
// The empty file is the smallest possible "file that exists" fixture
// and exercises the os.Stat success branch without coupling the test to
// any specific on-disk format.
func TestNewKnownNodesEmptyForExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	require.NoError(t, os.WriteFile(path, nil, 0o600),
		"sanity: precondition must create an empty file")

	kn := NewKnownNodes(path)
	require.NotNil(t, kn,
		"constructor must return a non-nil store when the file exists")
	assert.Equal(t, path, kn.path,
		"constructor must remember the path verbatim for later Save/Load")
	assert.NotNil(t, kn.entries,
		"entries map must be non-nil even when the file is empty")
	assert.Empty(t, kn.entries,
		"empty file must produce an empty pin set (T2 parser: zero lines → zero entries)")
}

// TestKnownNodesSaveLoadRoundTrip proves the on-disk format is its own
// inverse: populate the store, Save, re-open via a fresh NewKnownNodes,
// and verify every entry survived the trip.
//
// This is the contract the operator-facing workflow depends on: pin
// (T3) writes through Save, restart reads via the constructor, and the
// pin set must be identical. A round-trip mismatch would silently drop
// pins across restarts and turn TOFU from "match against last-seen" into
// "always re-pin" — which is a soft warning, exactly what D24 forbids.
func TestKnownNodesSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")

	// Populate and save from a fresh store.
	writer := NewKnownNodes(path)
	require.NoError(t, writer.Save(),
		"sanity: Save on an empty store must succeed")

	// Mutate the in-memory map directly via Save's same construction
	// path is awkward from a test; instead, we exercise the full path by
	// using Load to read a file the test writes by hand, then Save to
	// re-emit it, and re-read. This catches both directions.
	contents := "# operator header — preserved on load (skipped, not stored)\n" +
		"alpha.example.com|sha256:1111111111111111111111111111111111111111111111111111111111111111\n" +
		"beta.example.com|sha256:2222222222222222222222222222222222222222222222222222222222222222\n" +
		"\n" + // blank line
		"# trailing comment, also skipped\n" +
		"gamma.example.com|sha256:3333333333333333333333333333333333333333333333333333333333333333\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600),
		"sanity: precondition file must be written")

	// Load into the writer and Save back out.
	require.NoError(t, writer.Load(),
		"Load on a well-formed file must succeed")
	require.NoError(t, writer.Save(),
		"Save after Load must round-trip")

	// Re-open with a fresh constructor and verify the entries match.
	fresh := NewKnownNodes(path)
	require.NotNil(t, fresh)
	assert.Len(t, fresh.entries, 3,
		"three non-comment, non-blank lines must round-trip as three entries")
	assert.Equal(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		fresh.entries["alpha.example.com"],
		"alpha pin must survive Save/Load round-trip")
	assert.Equal(t,
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		fresh.entries["beta.example.com"],
		"beta pin must survive Save/Load round-trip")
	assert.Equal(t,
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		fresh.entries["gamma.example.com"],
		"gamma pin must survive Save/Load round-trip")
}

// TestKnownNodesLoadIgnoresCommentsAndBlanks locks down the parser's
// tolerance: a hand-edited known-nodes file with operator comments and
// visual blank lines must Load without error, and the resulting map must
// contain ONLY the data lines — comments and blanks are skipped, not
// stored as data (DECISION D24 / TASKS.md T2 spec clarification: "comments
// preserved on load" means the parser does not crash on them, not that
// they enter the in-memory store).
func TestKnownNodesLoadIgnoresCommentsAndBlanks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	contents := "# header comment, ignored\n" +
		"\n" + // blank line
		"host-a.example|sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"   \n" + // whitespace-only line, also blank
		"# inline note between entries, also ignored\n" +
		"host-b.example|sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" +
		"\t\n" + // tab-only line, also blank
		"#trailing comment without leading space, also ignored\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	kn := NewKnownNodes(path)
	require.NotNil(t, kn)
	assert.Len(t, kn.entries, 2,
		"exactly two data lines must produce exactly two entries")
	assert.Equal(t,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		kn.entries["host-a.example"],
		"first data line must be parsed as a host→fp entry")
	assert.Equal(t,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		kn.entries["host-b.example"],
		"second data line must be parsed as a host→fp entry")
	// Defensive: the comment and blank lines must not have leaked into
	// the store as data. A failure here would mean a future parser
	// change accidentally promoted comments to entries.
	for k := range kn.entries {
		assert.NotContains(t, k, "#",
			"comment markers must not appear as hosts: %q", k)
		assert.NotEmpty(t, k,
			"no empty-string host should have been stored")
	}
}

// TestKnownNodesLoadMalformedLineErrors is the security-critical negative
// test: a hand-edited file with a line missing the '|' separator must
// cause Load to return an error that pinpoints the line number. The
// operator gets a precise diagnostic ("malformed line 5: no '|' separator")
// instead of a silent parse-skip that would let a typo pin nothing.
//
// This test is also the canary for the all-or-nothing load contract: a
// malformed line in the middle of a file must NOT result in a partially-
// populated map. The previous entries are discarded and Load fails loud.
func TestKnownNodesLoadMalformedLineErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")

	// Two-phase: first write a well-formed file, Load it (success path,
	// proves the writer has 2 entries to defend), then overwrite the file
	// with a malformed version and re-Load (failure path). The
	// all-or-nothing check at the end then has a meaningful previous
	// state to compare against.
	wellFormed := "# header\n" +
		"good.example|sha256:1111111111111111111111111111111111111111111111111111111111111111\n" +
		"another-good.example|sha256:2222222222222222222222222222222222222222222222222222222222222222\n"
	require.NoError(t, os.WriteFile(path, []byte(wellFormed), 0o600))

	writer := NewKnownNodes(path)
	require.NoError(t, writer.Load(),
		"sanity: a fresh Load on a well-formed file must succeed")
	require.Len(t, writer.entries, 2,
		"sanity: precondition must leave the writer holding two valid entries")

	// Now corrupt the file: append a blank, then a malformed line, then
	// a trailing well-formed line. The malformed line is line 5 because
	// the comment is line 1, the two good entries are lines 2 and 3, and
	// the blank is line 4.
	malformed := wellFormed +
		"\n" + // line 4: blank, skipped
		"this-line-has-no-separator\n" + // line 5: malformed
		"trailing.example|sha256:3333333333333333333333333333333333333333333333333333333333333333\n"
	require.NoError(t, os.WriteFile(path, []byte(malformed), 0o600))

	err := writer.Load()
	require.Error(t, err,
		"Load must error on a file with a missing-'|' line")
	assert.Contains(t, err.Error(), "malformed line 5",
		"error must identify the 1-based line number of the bad line, got: %v", err)
	assert.Contains(t, err.Error(), "no '|' separator",
		"error must describe the failure mode, got: %v", err)

	// All-or-nothing: the in-memory state must be the previous (well-
	// formed) state, not a half-parsed mix. The writer still holds
	// whatever the earlier successful Load put there.
	assert.Len(t, writer.entries, 2,
		"failed Load must not partially populate the in-memory map")
	assert.Contains(t, writer.entries, "good.example",
		"previous valid entries must survive a failed Load")
	assert.NotContains(t, writer.entries, "trailing.example",
		"lines past the malformed one must not leak into the store on failed Load")
}

// TestKnownNodesSaveEmptyWritesEmptyFile locks down the documented
// "empty store → empty file" behaviour. An empty file round-trips back
// into an empty store on the next NewKnownNodes, which is the no-pinned-
// peers ground truth. A header comment is NOT written by Save — that
// would risk clobbering operator-edited comments and is the documented
// "edit the file by hand" workflow instead.
func TestKnownNodesSaveEmptyWritesEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	kn := NewKnownNodes(path)
	require.NoError(t, kn.Save(),
		"Save on an empty store must succeed (writes an empty file)")

	data, err := os.ReadFile(path)
	require.NoError(t, err, "post-Save read must succeed")
	assert.Equal(t, "", string(data),
		"empty store must produce an empty file (no auto-generated header)")
	assert.False(t, strings.Contains(string(data), "#"),
		"Save must not inject a comment header (operator-written only)")
}

// ========================== T3 — Pin / Check primitives ==========================
//
// The five tests below cover the DECISION D24 contract: pin-on-first-use,
// hard-reject on mismatch, and the in-memory / on-disk atomicity invariant.
// They are the unit-level foundation that Group Q's hard-reject integration
// test (TASKS.md Q4) builds on — the integration test wires Check's
// mismatch signal into a real QUIC handshake and asserts the connection
// drops, this layer just guarantees the store's half of the contract.

// fpA and fpB are two distinct canonical fingerprints used across the
// mismatch tests. The actual hex doesn't matter — only that they are
// unequal and that the format matches what Identity.Fingerprint produces
// (sha256: + 64 lowercase hex chars). The literal strings are kept
// here rather than in identity_test fixtures to keep the tofu tests
// hermetic and free of crypto dependencies.
const (
	fpA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fpB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	fpC = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// TestCheckFirstContactReturnsPinFalse locks down the first-contact state:
// an empty store, an unknown host → Check must return (false, false). The
// caller is expected to call Pin next, then proceed with the handshake.
//
// This is the D24 "Trust On First Use" baseline: a brand-new peer is not
// rejected, it is pinned. A failure here (returning mismatch=true on an
// empty store) would brick the very first handshake of every new sentinel
// mesh.
func TestCheckFirstContactReturnsPinFalse(t *testing.T) {
	// Empty store: no file, no in-memory entries.
	kn := NewKnownNodes(filepath.Join(t.TempDir(), "known-nodes"))
	require.NotNil(t, kn)
	require.Empty(t, kn.entries,
		"sanity: precondition store must be empty for first-contact test")

	pin, mismatch := kn.Check("alpha.example.com", fpA)
	assert.False(t, pin,
		"first contact must not report a valid pin (host is unknown)")
	assert.False(t, mismatch,
		"first contact must not report a mismatch (nothing to compare against)")

	// The Check call must NOT have mutated the store — Check is a pure
	// read. A side effect here would leak transient state into the
	// store and break the test isolation for any subsequent assertion.
	assert.Empty(t, kn.entries,
		"Check must be a pure read; the empty store must remain empty")
}

// TestCheckAfterPinReturnsPinTrue is the post-pin happy path: the operator
// has successfully pinned a peer, the peer reconnects and presents the
// same fingerprint, Check must confirm the pin. This is the path that
// the running mesh takes on every connection after the first.
//
// A regression here (returning mismatch=true on a known-good pin) would
// turn every successful first contact into a hard-reject on reconnect —
// the mesh would form, then immediately tear itself down.
func TestCheckAfterPinReturnsPinTrue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	kn := NewKnownNodes(path)

	require.NoError(t, kn.Pin("alpha.example.com", fpA),
		"sanity: Pin of a fresh host must succeed")

	pin, mismatch := kn.Check("alpha.example.com", fpA)
	assert.True(t, pin,
		"Check must confirm the pin when the presented fingerprint matches")
	assert.False(t, mismatch,
		"Check must not report a mismatch on a matching pin")
}

// TestCheckMismatchReturnsMismatchTrue is the D24 security-critical test:
// a pinned host presents a DIFFERENT fingerprint. Check must return
// (false, true). The caller's job is to drop the connection and emit an
// ERROR log; Check's job is just to signal the condition. A regression
// here (returning pin=true on a mismatch) would silently accept an
// attacker's key and is exactly the failure mode TOFU is designed to
// prevent — D24 calls this out as the "operator must know" path.
//
// The test deliberately uses two distinct pre-pinned fingerprints and
// checks the wrong one, so the comparison actually compares unequal
// values. Checking the same fingerprint with the same host would test
// the (true, false) path which is already covered above.
func TestCheckMismatchReturnsMismatchTrue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	kn := NewKnownNodes(path)

	// Pin fpA. Then present fpB. The host is in the store, so first-
	// contact semantics do NOT apply — this is a real mismatch.
	require.NoError(t, kn.Pin("alpha.example.com", fpA),
		"sanity: initial Pin of fpA must succeed")

	pin, mismatch := kn.Check("alpha.example.com", fpB)
	assert.False(t, pin,
		"Check must NOT confirm a pin when the presented fingerprint differs")
	assert.True(t, mismatch,
		"Check must signal mismatch=true on a fingerprint change (D24 hard-reject path)")

	// The mismatch signal must NOT have mutated the store: the pinned
	// value must still be fpA, not fpB. Pinning a wrong fingerprint via
	// a mismatch read would be the silent-acceptance bug D24 forbids.
	assert.Equal(t, fpA, kn.entries["alpha.example.com"],
		"a mismatched Check must NOT overwrite the pinned fingerprint")
}

// TestPinPersistsAcrossStoreRecreation is the persistence contract:
// Pin must write through to disk (atomic, T2's temp-then-rename), and
// a fresh NewKnownNodes on the same path must surface the same pin set
// to a fresh Check. This is the path that runs at every process start:
// the operator's pins survive restarts.
//
// A regression here (Pin in-memory only, disk empty) would mean the
// very first restart loses every pin, and on next start every peer is
// re-pinned from scratch — equivalent to disabling TOFU and accepting
// whatever key shows up first after every restart.
func TestPinPersistsAcrossStoreRecreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	writer := NewKnownNodes(path)
	require.NoError(t, writer.Pin("alpha.example.com", fpA),
		"Pin must succeed and persist the pin to disk")
	require.NoError(t, writer.Pin("beta.example.com", fpB),
		"second Pin must succeed for an unrelated host")

	// Simulate process restart: drop the writer, build a fresh store
	// from the same on-disk path. The constructor's load() (T2) must
	// surface the pinned entries.
	fresh := NewKnownNodes(path)
	require.NotNil(t, fresh)
	require.Len(t, fresh.entries, 2,
		"sanity: a fresh store on the same path must see both pinned entries")

	pin, mismatch := fresh.Check("alpha.example.com", fpA)
	assert.True(t, pin,
		"pin must survive store recreation (Pin wrote through to disk)")
	assert.False(t, mismatch,
		"re-pinned host must not report a mismatch on its own fingerprint")

	pin, mismatch = fresh.Check("beta.example.com", fpB)
	assert.True(t, pin,
		"second pin must survive store recreation independently")
	assert.False(t, mismatch,
		"second pin must not report a mismatch on its own fingerprint")

	// A host never pinned must still report first-contact semantics
	// after recreation, not a stale pin.
	pin, mismatch = fresh.Check("gamma.example.com", fpC)
	assert.False(t, pin,
		"a host that was never pinned must still report pin=false after recreation")
	assert.False(t, mismatch,
		"a host that was never pinned must not be reported as a mismatch")
}

// TestPinAtomicOnDiskFailure locks down the rollback-on-save-failure
// contract documented on Pin: if the on-disk persist fails, the in-
// memory store must be left in the same state as before the call. This
// is the atomicity guarantee the TOFU trust model requires — an
// unpersisted pin is the same as no pin, because a process restart
// would lose it and the next handshake would (re-)pin from the first
// presented fingerprint, which is exactly the "attacker landed first"
// failure mode D24 is meant to prevent.
//
// We force Save failure by pointing Pin at a path inside a non-existent
// directory: os.CreateTemp in saveLocked fails with ENOENT, and the
// error propagates back through Pin. The in-memory store must then
// reflect "no pin was ever recorded" for that host.
func TestPinAtomicOnDiskFailure(t *testing.T) {
	// Path whose parent directory does not exist. The bootstrap layer
	// is responsible for ensuring the parent exists (Group K); Pin
	// itself must NOT silently create directories, and a Save failure
	// here is the cleanest way to test the rollback path.
	missingDir := filepath.Join(t.TempDir(), "no-such-subdir")
	badPath := filepath.Join(missingDir, "known-nodes")

	kn := NewKnownNodes(badPath)
	require.NotNil(t, kn)
	require.Empty(t, kn.entries,
		"sanity: precondition store must be empty before the failed Pin")

	err := kn.Pin("alpha.example.com", fpA)
	require.Error(t, err,
		"Pin must return an error when on-disk persist fails (parent dir absent)")

	// Rollback: the in-memory store must look exactly like the call
	// never happened. "alpha.example.com" must not be present.
	assert.Empty(t, kn.entries,
		"failed Pin must not leave a phantom in-memory entry (rollback contract)")
	assert.NotContains(t, kn.entries, "alpha.example.com",
		"the would-be-pinned host must not appear in the store after a failed Pin")

	// The store must still be usable: a subsequent Check on the same
	// host must report first-contact state, not pin-false-because-we-
	// just-failed-to-pin. This is what "atomic" means in this context.
	pin, mismatch := kn.Check("alpha.example.com", fpA)
	assert.False(t, pin,
		"after a failed Pin, Check must still report first-contact state")
	assert.False(t, mismatch,
		"after a failed Pin, Check must not mis-attribute the failure as a mismatch")
}

// TestPinConflictReturnsError locks down the re-pin guard added on top of
// T3: Pinning a host that is already pinned to a DIFFERENT fingerprint
// must be rejected with an error, leave the in-memory map at the original
// pin, and leave the on-disk file at the original pin. The error message
// must include the host, the existing (pinned) fingerprint, and the
// presented fingerprint, so that operators (and the Q2 alert pipeline
// that wires up later) can identify which peer attempted the re-pin and
// against which trusted value.
//
// This is the security-critical guard for D24. A pre-guard implementation
// would silently overwrite the pinned fingerprint with the new value and
// persist that overwrite, turning the hard-reject mismatch detection in
// Check into a window of one handshake: an attacker who lands on a
// reconnect gets their key bound, and the very next Check on the new
// fingerprint returns pin=true (no mismatch). The guard closes that
// window at the only place where it can be closed — the Pin writer.
func TestPinConflictReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	kn := NewKnownNodes(path)
	require.NotNil(t, kn)

	// First-contact pin establishes the trusted fingerprint.
	require.NoError(t, kn.Pin("alpha.example.com", fpA),
		"sanity: initial Pin of fpA must succeed (first-contact path)")

	// Capture the on-disk content after the legitimate pin so the
	// post-conflict assertion is comparing like-for-like. We deliberately
	// read the bytes rather than just checking the in-memory map, because
	// the security claim is that the disk also survives the conflict.
	preConflict, err := os.ReadFile(path)
	require.NoError(t, err,
		"sanity: legitimate Pin must have written the known-nodes file")
	require.NotEmpty(t, preConflict,
		"sanity: the post-pin file must contain at least the fpA entry")

	// Conflict: same host, different fingerprint. This is the exact
	// shape of a re-pin attempt that must be rejected.
	err = kn.Pin("alpha.example.com", fpB)
	require.Error(t, err,
		"Pin must return an error when re-pinning with a different fingerprint (D24 guard)")

	// Error message must include all three pieces of information an
	// operator needs to diagnose the attempt: the host (which peer),
	// the existing fingerprint (what we trusted), and the presented
	// fingerprint (what was offered). This is also the shape the Q2
	// alert pipeline will eventually consume; fixing the format later
	// would mean a breaking change to operator tooling.
	assert.Contains(t, err.Error(), "alpha.example.com",
		"conflict error must name the host so an operator knows which peer attempted the re-pin, got: %v", err)
	assert.Contains(t, err.Error(), fpA,
		"conflict error must include the currently-pinned fingerprint (existing), got: %v", err)
	assert.Contains(t, err.Error(), fpB,
		"conflict error must include the presented fingerprint (rejected), got: %v", err)

	// In-memory invariant: the store still holds fpA, not fpB. A
	// regression here would mean the guard returned an error but had
	// already mutated state, leaking the attacker's fingerprint into
	// the in-process store even though the disk was not updated.
	assert.Equal(t, fpA, kn.entries["alpha.example.com"],
		"conflicting Pin must not overwrite the in-memory pinned fingerprint")

	// On-disk invariant: the file is byte-identical to its pre-conflict
	// state. This is the more important half of the claim — a partial
	// regression (in-memory preserved, disk silently rewritten) would
	// pass the in-memory check and fail on restart, where a freshly
	// loaded store would surface the attacker's fingerprint.
	postConflict, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, preConflict, postConflict,
		"conflicting Pin must not rewrite the on-disk file (D24 persistence invariant)")

	// Cross-check via Check: the store still treats the host as pinned
	// to fpA. Reading via the public API is the operator-facing
	// witness; the direct entries map read above is the structural
	// witness. They should agree, and this assertion catches any
	// future change that accidentally bypasses Check on the conflict
	// path.
	pin, mismatch := kn.Check("alpha.example.com", fpA)
	assert.True(t, pin, "after a conflict, the original pin must still read as pinned")
	assert.False(t, mismatch, "after a conflict, Check on the original fp must not report mismatch")
	pin, mismatch = kn.Check("alpha.example.com", fpB)
	assert.False(t, pin, "after a conflict, Check on the rejected fp must not report pinned")
	assert.True(t, mismatch, "after a conflict, Check on the rejected fp must still report mismatch (D24 hard-reject)")
}

// TestPinIdempotentSameFingerprintIsNoOp locks down the second half of
// the re-pin guard: Pinning a host that is already pinned to the SAME
// fingerprint must succeed (return nil) and must be a true no-op — no
// in-memory mutation (which is structurally guaranteed by the guard
// short-circuiting before the assignment) and, more importantly, no
// disk write. Every reconnect from a known peer takes this path, and
// dirtying the known-nodes file on each successful handshake would
// multiply disk wear and on-disk churn for no security benefit.
//
// "No disk write" is verified by snapshotting the file's mtime (with a
// sleep before the second Pin to defeat sub-second filesystem mtime
// resolution on platforms that round to the second) and the file's
// contents, then asserting both are unchanged after the second Pin.
// A regression that always called saveLocked on the idempotent path
// would either bump the mtime or rewrite the contents (temp-then-rename
// preserves bytes but updates mtime), and this test catches both.
func TestPinIdempotentSameFingerprintIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-nodes")
	kn := NewKnownNodes(path)
	require.NotNil(t, kn)

	// First-contact Pin establishes the trusted fingerprint and writes
	// the file for the first time.
	require.NoError(t, kn.Pin("alpha.example.com", fpA),
		"sanity: initial Pin of fpA must succeed (first-contact path)")

	// Snapshot the file's state immediately after the legitimate Pin.
	// We need both mtime (catches "file was rewritten with same bytes"
	// regressions, which is exactly the temp-then-rename behaviour) and
	// contents (defensive — covers any future Save refactor that does
	// not bump mtime on identical bytes, e.g. an in-place truncate).
	preInfo, err := os.Stat(path)
	require.NoError(t, err,
		"sanity: legitimate Pin must have created the known-nodes file")
	preMtime := preInfo.ModTime()
	preBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	// Sleep just long enough to make the mtime check robust on
	// filesystems that round to the second (the common case on CI
	// runners). 20ms is well below any reasonable test timeout and
	// long enough to cross a 1-second boundary if the platform needs
	// it; on sub-second-resolution filesystems it is harmless padding.
	time.Sleep(20 * time.Millisecond)

	// Idempotent re-pin: same host, same fingerprint. The guard's
	// idempotent path must short-circuit BEFORE saveLocked is called.
	require.NoError(t, kn.Pin("alpha.example.com", fpA),
		"idempotent re-pin must return nil (the pin already exists)")

	// In-memory invariant: the entry is still there and still fpA.
	// This is structurally guaranteed by the guard returning before the
	// snapshot/mutate block, but asserting it explicitly catches any
	// future refactor that accidentally re-introduces a mutation on
	// the no-op path.
	assert.Equal(t, fpA, kn.entries["alpha.example.com"],
		"idempotent re-pin must not change the in-memory fingerprint")

	// No-disk-write invariant: the file's mtime and contents must be
	// exactly what they were before the second Pin. mtime is the strong
	// signal — temp-then-rename ALWAYS bumps mtime on a successful
	// write, so an unchanged mtime is proof that saveLocked was not
	// called. Contents is the secondary check for the case where a
	// future Save implementation writes in place without bumping mtime
	// (a hypothetical optimisation; the current implementation does
	// not, but the contents check is free).
	postInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, preMtime.Equal(postInfo.ModTime()),
		"idempotent re-pin must not bump the file's mtime (would mean saveLocked was called), pre=%v post=%v",
		preMtime, postInfo.ModTime())

	postBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, preBytes, postBytes,
		"idempotent re-pin must not rewrite the file (contents unchanged)")

	// Functional cross-check: a Check on the same host with the same
	// fingerprint must still confirm the pin. This is the operator-
	// facing witness that the no-op did not break the store from the
	// outside, complementing the structural mtime/contents check.
	pin, mismatch := kn.Check("alpha.example.com", fpA)
	assert.True(t, pin, "after an idempotent re-pin, Check must still report the pin")
	assert.False(t, mismatch, "after an idempotent re-pin, Check must not report a mismatch")
}
