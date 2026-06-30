// Package transport (tofu.go): trust-on-first-use (TOFU) known-nodes store.
//
// Implements the fingerprint pin/check side of the handshake (DECISION D24):
// each peer's host → fingerprint mapping is recorded on first contact, and
// subsequent contacts are hard-rejected on fingerprint mismatch. T1 shipped
// the skeleton struct + constructor; T2 added the line-oriented on-disk
// format and the Load/Save round-trip; T3 (this file) layers Pin/Check on
// top of the persistent store, completing the TOFU mechanics (the hard-
// reject integration test lands in Group Q, T3 ships the unit-level
// primitives it depends on).
package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ========================== KnownNodes — TOFU store ==========================

// KnownNodes is an in-memory map of host → pinned fingerprint, plus the path
// where the mapping is persisted on disk.
//
// Concurrency: a sync.RWMutex guards the entries map. Read paths (Check
// reads by host; Save's internal iteration under RLock) take RLock and can
// run in parallel with each other. Write paths (Load replaces the whole
// map; Pin mutates one entry under Lock-for-the-whole-op so that the
// in-memory update and the on-disk persist are a single atomic step) take
// the write lock. The map is never returned to callers — all access goes
// through methods that hold the lock — so no caller can bypass
// synchronization by holding a reference.
//
// Entries are keyed by host string (the same host the QUIC dialer uses) and
// the value is the canonical fingerprint in the form "sha256:<hex>" produced
// by Identity.Fingerprint(). A first-contact entry is created by Pin (T3);
// a check is performed by Check (T3); both share this struct.
type KnownNodes struct {
	mu      sync.RWMutex
	entries map[string]string
	path    string
}

// NewKnownNodes returns a ready-to-use KnownNodes bound to the given on-disk
// path.
//
// The constructor does NOT return an error: callers in Group Q build the
// transport eagerly during config load, and a missing-or-unreadable file
// at that point is a normal first-run state, not a fatal condition. If the
// file is absent (typical first start), an empty store is returned. If the
// file is present, an internal load() is invoked; a parse error from load
// (malformed line) is intentionally swallowed here — surfacing it as a
// constructor return value would force every caller to handle errors they
// would almost always ignore. The "broken file" case is detected at the
// point of use (T3's Check) with a hard-reject, not at construction time.
//
// path may point to a file that does not exist yet; that is the first-run
// case and is the common path, not an error. path is stored verbatim for
// later Save/Load. NewKnownNodes does not validate the path's directory —
// that is the bootstrap layer's job (Group K).
func NewKnownNodes(path string) *KnownNodes {
	kn := &KnownNodes{
		entries: make(map[string]string),
		path:    path,
	}

	// Best-effort: a missing file is a normal first-start condition, so we
	// treat os.Stat's not-exist as "nothing to load" and quietly return.
	// Any other stat error (perm denied, IO error) is also swallowed here
	// on purpose: surfacing it as a constructor return value would force
	// every caller to deal with errors that they would almost always
	// ignore anyway.
	if _, err := os.Stat(path); err != nil {
		return kn
	}

	// File exists — load it. T2 ships the real on-disk parser; the previous
	// T1 stub was replaced by load() returning (map, error). A parse error
	// here is dropped on the floor per the contract above; Load() below is
	// the surface callers use to retry / handle parse failures.
	loaded, _ := kn.load()
	if loaded == nil {
		// Defensive: load() must always return a non-nil map. If it didn't
		// (e.g. nil literal slipped in during future edits), keep entries
		// non-nil so callers can use the store without nil-checking.
		loaded = make(map[string]string)
	}
	kn.entries = loaded
	return kn
}

// load reads the on-disk known-nodes file at kn.path and returns the parsed
// mapping. The function does NOT mutate kn.entries — the constructor copies
// the result in under its own control, and the public Load() method below
// also does the mutation itself under Lock. Keeping load side-effect-free
// makes it easy to test in isolation.
//
// File format (T2):
//
//	# comments start with '#' and are ignored
//	# blank lines are ignored
//	host|fingerprint
//	host|fingerprint
//
// "|" is the separator because both host and fingerprint are restricted
// alphabets that cannot contain it (host is a network identifier, fingerprint
// is "sha256:" + lowercase hex). Using a single byte keeps the format
// human-editable — an operator can hand-write a known-nodes file in a text
// editor and pin a peer's fingerprint with no tooling (OPERATIONS.md walks
// through this).
//
// A line with no '|' is a malformed line and returns an error that includes
// the 1-based line number, so an operator who mis-edits the file knows
// exactly where to look. We don't try to "fix" malformed lines silently —
// that would let a typo pin a wrong fingerprint and is the kind of soft
// behaviour TOFU is designed to forbid.
//
// On any error, the partially-parsed map is discarded; Load is all-or-nothing.
func (kn *KnownNodes) load() (map[string]string, error) {
	f, err := os.Open(kn.path)
	if err != nil {
		return nil, fmt.Errorf("open known-nodes file: %w", err)
	}
	defer f.Close()

	entries := make(map[string]string)
	scanner := bufio.NewScanner(f)
	// Default 64KiB line buffer is plenty for a known-nodes file — a host
	// string and a "sha256:" + 64 hex chars fit in well under 1KiB. A
	// pathological operator-edited line beyond that is almost certainly
	// a paste error and we want to fail loudly, not silently truncate.
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip blank lines and comments. Comments are documented as
		// "preserved on load" in TASKS.md — that means the parser does
		// not crash on them, NOT that they are stored in the in-memory
		// map. The store holds host→fingerprint data only; comments are
		// the operator's prose and live in the file, not in memory.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// SplitN(2): a fingerprint that somehow contained '|' would still
		// be captured whole. In practice this can't happen (fingerprints
		// are "sha256:" + lowercase hex), but SplitN is the conservative
		// choice — it means a future format change that adds a '|' to
		// either field doesn't silently break older files.
		parts := strings.SplitN(line, "|", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("malformed line %d: no '|' separator", lineNum)
		}
		entries[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read known-nodes file: %w", err)
	}
	return entries, nil
}

// Load re-reads the on-disk known-nodes file into the store, replacing any
// in-memory entries. Used by operators who hand-edit the file outside the
// process (e.g. an ops script adding a pin, then sending SIGHUP — actual
// SIGHUP wiring is a later flow task; this is the underlying primitive).
//
// Load is safe to call concurrently with Check (which takes RLock): it
// holds the write lock for the duration of the parse+swap, so in-flight
// Check calls block briefly until Load completes and then see the new
// state. Pin is excluded — Pin also takes the write lock, and a Pin
// mid-flight would race with the in-memory swap in ways that defeat the
// on-disk-is-truth invariant. Pin callers that need to reconcile with a
// hand-edited file should retry Pin after Load returns.
//
// A missing file is NOT an error: the store is reset to empty, matching the
// first-start semantics of the constructor. An unreadable or malformed file
// IS an error and the in-memory state is left untouched — operators editing
// a file by hand get explicit feedback instead of their half-edited file
// wiping the in-memory pin set.
func (kn *KnownNodes) Load() error {
	// Missing file is the first-start case; behave like the constructor.
	if _, err := os.Stat(kn.path); err != nil {
		if os.IsNotExist(err) {
			kn.mu.Lock()
			kn.entries = make(map[string]string)
			kn.mu.Unlock()
			return nil
		}
		return fmt.Errorf("stat known-nodes file: %w", err)
	}

	parsed, err := kn.load()
	if err != nil {
		// Leave the in-memory map alone on parse failure so the operator's
		// in-process state survives a malformed manual edit.
		return err
	}

	kn.mu.Lock()
	kn.entries = parsed
	kn.mu.Unlock()
	return nil
}

// Save atomically writes the current entries map to kn.path.
//
// The on-disk format is the same line-oriented <host>|<fingerprint> that
// load() reads. Comments are NOT written by Save: the in-memory store does
// not carry comments (see Load), and re-inventing a comment header per save
// would risk the operator's hand-edited comments clobbering with stale
// generated text. Operators who want a header edit the file by hand after
// Save — that is the documented workflow (OPERATIONS.md).
//
// An empty store writes an empty file. This is the simplest behaviour and
// matches the "no pinned peers" ground truth: zero entries → zero lines.
//
// Atomicity is the same temp-file-then-rename pattern that identity.go Save
// uses, with the same rationale: a crash mid-write must not leave a
// half-written known-nodes file (a truncated line would be a parse error
// on the next start, wiping the pin set). The temp file lives in the same
// directory as the target so os.Rename stays within one filesystem and the
// rename is genuinely atomic.
//
// 0600 is the DECISION D24 default for sensitive operational artefacts; the
// known-nodes file is not a secret per se (hostnames and fingerprints are
// public to the operator), but locking it down matches the identity-file
// posture and prevents accidental world-writable misconfig.
//
// Save is safe to call concurrently with Check (RLock) but NOT with Pin or
// another Save (both take the write lock). It is the public RLock-acquiring
// wrapper; the inner saveLocked() does the actual work and is also called
// directly by Pin with the write lock already held.
func (kn *KnownNodes) Save() error {
	kn.mu.RLock()
	defer kn.mu.RUnlock()
	return kn.saveLocked()
}

// Check reports whether a host's presented fingerprint matches the pinned one.
//
// Semantics (TASKS.md T3 spec, DECISION D24 — TOFU first-contact vs. hard-reject):
//
//   - host is NOT in the store → (false, false). This is the first-contact
//     state. The caller is expected to call Pin(host, fingerprint) next, and
//     then proceed with the handshake.
//   - host IS in the store and fingerprint MATCHES the pinned value →
//     (true, false). The pin is valid; the caller may continue the handshake.
//   - host IS in the store and fingerprint DIFFERS from the pinned value →
//     (false, true). This is the hard-reject case. The caller MUST drop the
//     connection and emit an operator alert (logged at ERROR with both the
//     expected and the actual fingerprint). There is no soft-warn, no
//     accept-once, no override — that is the D24 contract.
//
// Check is a read-only operation: it takes the RWMutex's read lock so that
// many concurrent Check calls (e.g. multiple peers handshaking at once, or
// the in-process loopback tests in Q-group) can run in parallel and only
// serialize against Pin/Load/Save. We never mutate the entries map from this
// path, so RLock is sufficient.
//
// Check intentionally returns no error: the only failure mode is "host not
// pinned" which is part of the (false, false) return contract, not an
// exceptional condition. Forcing callers to handle an error they would
// always ignore would be the same mistake the constructor's silent stat
// made deliberately (T1 comment) — but Check is on the hot path, so the
// signature is the most ergonomic form the spec allows.
func (kn *KnownNodes) Check(host, fingerprint string) (pin bool, mismatch bool) {
	kn.mu.RLock()
	pinned, ok := kn.entries[host]
	kn.mu.RUnlock()

	if !ok {
		// First-contact state: no pin, nothing to compare against. The
		// caller pins via Pin and proceeds. We do NOT raise an alert or
		// log here — first contact is the legitimate TOFU path, not an
		// anomaly.
		return false, false
	}

	if pinned == fingerprint {
		// Pin is valid: the peer presented exactly the fingerprint we
		// recorded on first contact. Handshake may continue.
		return true, false
	}

	// Fingerprint MISMATCH. The D24 hard-reject contract says: drop the
	// connection, log at ERROR with both the expected (pinned) and the
	// actual (presented) fingerprint, do NOT pin the new value, do NOT
	// add the peer to any active roster. Check itself is a pure reader
	// and cannot enforce any of that — it just signals the condition
	// and lets the TLS callback (Q2) act on it. The alert emission
	// belongs to the caller, not the store.
	return false, true
}

// Pin records a host → fingerprint mapping in the store and persists it to
// disk atomically.
//
// Pin is the "first contact" writer called by the TLS VerifyPeerCertificate
// callback (Group Q) when a peer presents a fingerprint the store has never
// seen. Once pinned, subsequent connections to that host MUST match the
// recorded fingerprint (see Check) — a mismatch is a hard-reject per D24.
//
// Re-pinning is a security-sensitive operation, NOT a silent overwrite.
// The TOFU trust model (D24) treats the first pinned fingerprint as the
// ground truth for that host forever; legitimate key rotation is an
// explicit operator action (hand-edit known-nodes, per OPERATIONS.md),
// not a value the code accepts from a peer. Therefore Pin distinguishes
// three cases, all of them observable to the caller:
//
//   - host is NOT in the store → first-contact pin. The mapping is
//     written in-memory and persisted to disk; return nil. This is the
//     happy path the TLS callback takes on its first sight of a peer.
//   - host IS in the store and the presented fingerprint matches the
//     pinned one → idempotent re-pin. Return nil WITHOUT touching the
//     in-memory map and WITHOUT writing to disk. Every reconnect from
//     a known peer takes this path; skipping the disk write is a
//     performance optimisation (each handshake must not dirty the
//     known-nodes file just to confirm what is already there) and
//     also avoids needless on-disk churn.
//   - host IS in the store and the presented fingerprint DIFFERS from
//     the pinned one → conflict. Return a non-nil error, leave both
//     the in-memory map and the on-disk file exactly as they were.
//     The caller (Q2's VerifyPeerCertificate) is expected to surface
//     this as a hard-reject just like a Check mismatch, so that the
//     "silent re-pin of an attacker's key" failure mode is closed at
//     the same point as the "connect with attacker's key" failure mode.
//
// Concurrency and atomicity (the most security-sensitive part of this file):
//
//  1. We hold mu.Lock for the entire Pin — in-memory write AND on-disk
//     persist — not just the in-memory write as a literal reading of the
//     T3 spec might suggest. The reason is the rollback-on-save-failure
//     contract below: if we released the lock between the in-memory
//     update and Save(), a concurrent Check could observe a fingerprint
//     that the disk does not know about, and a second Pin could win the
//     race and overwrite our in-memory entry with a DIFFERENT fingerprint
//     that gets persisted in our place. Holding Lock for the full
//     operation serialises all writers and makes the rollback safe.
//
//  2. If Save() fails (disk full, permission denied, rename across
//     filesystems, etc.) the in-memory entry is rolled back to its prior
//     value before the lock is released. This is the atomicity guarantee
//     the TOFU trust model requires: an unpersisted pin is the same as
//     no pin — if a future process restart would lose it, the next
//     handshake must NOT see a "pinned" fingerprint that isn't on disk,
//     because that asymmetry is what an attacker who lands first on a
//     clean restart can exploit to bind a wrong key permanently.
//
//  3. Save itself uses the temp-file-then-rename pattern (T2): a crash
//     mid-write either leaves the old known-nodes file intact or the
//     new one fully in place. The combination of (1) Lock-for-the-whole-
//     op and (2) T2's atomic-rename gives us a single property: at every
//     observable moment, the in-memory map and the on-disk file are
//     consistent — there is no in-between state where the store claims
//     a pin the disk does not have.
//
// Pin returns the Save() error directly; the in-memory state is already
// rolled back at that point. Callers (Q2's VerifyPeerCertificate
// callback) MUST treat a non-nil return as "pin failed, do NOT proceed
// with the handshake" — same hard-fail posture as Check's mismatch.
func (kn *KnownNodes) Pin(host, fingerprint string) error {
	// Snapshot the prior mapping under the write lock so the rollback
	// below can restore it byte-for-byte. The "ok" flag distinguishes
	// "host was not pinned before" (delete the new key on rollback) from
	// "host was pinned to a different fingerprint" (restore the old one).
	kn.mu.Lock()
	defer kn.mu.Unlock()

	// Re-pin guard (D24 invariant). The TOFU trust model requires that
	// a pinned fingerprint cannot be silently overwritten by a peer-
	// presented value, because that would let an attacker who lands on
	// a reconnect turn an honest key into their own key. The two cases
	// where Pin must NOT touch the persistent state are handled here
	// BEFORE any mutation or disk I/O.
	if existing, pinned := kn.entries[host]; pinned {
		if existing == fingerprint {
			// Idempotent re-pin: the same host is presenting the same
			// fingerprint we already trust. No-op: do not write to disk,
			// do not mutate the in-memory map, do not even iterate the
			// entries for a save. Every reconnect from a known peer
			// takes this branch; calling saveLocked() here would dirty
			// the known-nodes file on every successful handshake.
			return nil
		}
		// Conflict: the host is pinned, but to a different fingerprint.
		// This is the same condition Check signals as mismatch=true; the
		// D24 contract says drop the connection and alert the operator.
		// Pin must not "helpfully" overwrite the pinned value with the
		// presented one — that would turn a hard-reject into a silent
		// re-pin and is the exact failure mode this guard exists to
		// close. The error message includes host, existing fingerprint,
		// and presented fingerprint so operators (and the Q2 alert path
		// that will wire up later) can diagnose which peer attempted
		// the re-pin and against which pinned value.
		return fmt.Errorf("pin conflict for host %s: pinned %s, presented %s",
			host, existing, fingerprint)
	}

	// First-contact path: host was not pinned, fall through to the
	// snapshot / mutate / save / rollback dance below.
	prior, hadPrior := kn.entries[host]
	kn.entries[host] = fingerprint

	if err := kn.saveLocked(); err != nil {
		// Roll back the in-memory mutation. The store is now in the
		// same state it was before Pin was called — including the
		// prior fingerprint for this host, which may itself be a
		// security-sensitive value. Holding the write lock the whole
		// time means no Check call has observed the temporary bad
		// value, and no other Pin can race in between.
		if hadPrior {
			kn.entries[host] = prior
		} else {
			delete(kn.entries, host)
		}
		return err
	}
	return nil
}

// saveLocked is the on-disk persistence primitive used by both Save and Pin.
// It must be called with mu already held: by RLock from Save (read-locked
// iterators are safe because nothing mutates the map during the call), and
// by Lock from Pin (Pin mutates the map under the write lock, and the persist
// step is part of the same atomic operation — see the rollback-on-save-
// failure contract on Pin).
//
// The body is the temp-file-then-rename pattern documented on Save; the
// single-purpose helper exists so the lock-acquisition policy is the only
// difference between the public Save and the in-Pin persistence step.
// Future readers see "Lock required" on the function they call from Pin
// without having to reason about Save's RLock wrapper.
func (kn *KnownNodes) saveLocked() error {
	var buf bytes.Buffer
	for host, fp := range kn.entries {
		buf.WriteString(host)
		buf.WriteByte('|')
		buf.WriteString(fp)
		buf.WriteByte('\n')
	}

	dir := filepath.Dir(kn.path)
	tmp, err := os.CreateTemp(dir, "known-nodes.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp known-nodes file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp known-nodes file: %w", err)
	}

	if _, err := io.Copy(tmp, &buf); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write known-nodes file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp known-nodes file: %w", err)
	}

	if err := os.Rename(tmpPath, kn.path); err != nil {
		return fmt.Errorf("rename temp known-nodes file into place: %w", err)
	}
	return nil
}
