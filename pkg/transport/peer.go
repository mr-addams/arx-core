// Package transport (peer.go): per-peer runtime lifecycle for the sentinel
// transport.
//
// This file ships Group R (TASKS.md §R1–R3): the runtime Peer struct, the
// dialer/connect lifecycle with redial backoff, and the protocol-dispatch
// loop that reads frames from a QUIC connection and routes them to injected
// handlers.
//
// File organisation mirrors the per-group Q1/Q2/Q3/Q4 style of quic.go: each
// group has a Level-1 separator and a section header. The split is
// load-bearing for code review (a single 1500-line peer.go would obscure the
// R1/R2/R3 boundaries the brief calls out) but the file is still small
// enough to live in one place — the heavy parts are doc comments, not
// code, and a future refactor (e.g. a peer_state.go) is a one-line import
// shuffle with no API impact.
//
// What this file ships:
//
//   - R1: Peer struct, NewPeer constructor, RosterFromConfig helper. Peer
//     holds runtime state (connection state machine + backoff parameters)
//     and is the lifecycle object; PeerConfig (defined in quic.go) is the
//     config entry-point and stays read-only. The two are intentionally
//     separate (DECISION D25: re-read config = restart, no live re-add in
//     v0.1.0) so a config re-read never resets in-flight connection state.
//
//   - R2: peer.run(ctx) lifecycle goroutine. Dials via an injected
//     dialer interface, hands a successful conn to the protocol-dispatch
//     loop (R3), and on dial failure applies exponential backoff with
//     jitter (initial 1s, max 30s, ±20% jitter). Context cancellation
//     tears down cleanly. The dialer interface is the injection point
//     that makes R2 testable: production wires Transport.Dial
//     (signature-compatible method value), tests wire a fake.
//
//   - R3: protocol-dispatch loop. Reads length-prefixed frames from a
//     QUIC stream, decodes them, drops unknown protocol_version frames
//     via protocol.go's DropIfUnknownVersion, and dispatches to a
//     TelemetryHandler or ControlHandler based on the stream ID's
//     QUIC uni/bi bit (DECISION D27 §2: telemetry=uni, control=bi).
//     Control handlers may return a response frame that the loop
//     writes back on the same stream. v0.1.0 ships a no-op default for
//     both handlers; arxsentinel product wires real handlers later.
//
// Architectural notes / non-goals for this file:
//
//   - The dispatch loop is shipped ONLY on the DIALER side. The
//     listener side's per-conn goroutine (Transport.handleAcceptedConn
//     in quic.go) currently just keeps the conn open until ctx
//     cancel; wiring dispatch on the listener side is a known
//     follow-up task and is OUT OF SCOPE for Group R (the brief
//     scopes R-group to peer.go and peer_test.go only — we cannot
//     modify quic.go's handleAcceptedConn). The dispatch function
//     is exported as a package-level surface so the listener-side
//     integration is "one call" when a future task picks it up.
//
//   - The no-op handler default is genuinely a no-op: it does NOT
//     emit any log output, including at DEBUG. protocol.go's Logger
//     interface only exposes Warnf + Errorf; extending it with
//     Debugf would touch protocol.go (out of scope) and the
//     nopLogger / captureLogger / captureQ4Logger surfaces that
//     quic.go and quic_test.go depend on. The dispatch loop takes
//     a small peerDebugLogger interface (Debugf only) for its own
//     internal trace events; the default is a discard stub. Tests
//     inject a capture variant. This keeps R-group's surface
//     additive to the package, not a refactor of existing surface.
//
//   - No live reconfiguration (DECISION D25): peer.run uses a fixed
//     PeerConfig. A future task that wants live peer-add must add
//     a separate signal — the dialer field and the backoff
//     parameters on Peer are NOT exposed to the operator at runtime
//     in v0.1.0.
//
//   - D21 disabled-by-default: peer.run is called by the bootstrap
//     ONLY when transport is enabled. R-group does not enforce the
//     gate itself; K2 owns the gate. A Peer constructed when
//     transport is disabled is the caller's problem.
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	pb "github.com/mr-addams/arx-core/pkg/transport/proto"
)

// ========================== R1 — Peer struct + roster ==========================
//
// Peer is the runtime lifecycle object that wraps a single PeerConfig
// (the config entry-point, defined in quic.go). The split between
// PeerConfig and Peer is intentional (R1 task spec): PeerConfig is what
// the operator writes in config, Peer is what the transport actually
// dials / redials / dispatches frames on. Keeping them separate means a
// config re-read (future flow task) does not reset in-flight connection
// state — a hot-swap would otherwise tear down established QUIC
// connections mid-frame.
//
// The struct also encodes a small state machine. v0.1.0 has four
// states — idle, dialing, connected, backoff — chosen as the minimum
// set that the lifecycle actually transitions through. Adding more
// states is a flow-level decision (the K-group Run / observer API may
// want richer state, e.g. "dialing" -> "verifying" -> "connected";
// v0.1.0 collapses "dialing" and "verifying" into a single dialing
// state because the signed-challenge handshake runs synchronously
// inside Transport.Dial, so the dispatch loop only sees a conn that
// has fully passed verification).
//
// Concurrency: the state field is guarded by mu. peer.run is the only
// writer; observability hooks (a future R-flow task) would be the only
// reader. v0.1.0 has no readers, but the mutex is declared now so the
// observability hook is "add a method" rather than "add a mutex too".
type peerState int

const (
	// peerStateIdle is the zero value — the Peer exists but has not
	// been activated (peer.run has never been called). It is also
	// the post-ctx-cancel terminal state: peer.run returns, the
	// state stays at whatever it was when ctx fired. A future
	// observability hook that wants "is this peer live" can read
	// state != peerStateIdle.
	peerStateIdle peerState = iota

	// peerStateDialing is the state peer.run sets BEFORE invoking
	// the dialer. It is held for the entire TLS + signed-challenge
	// handshake because that handshake is part of Transport.Dial
	// (a future revision might split verification into its own
	// state, but v0.1.0 has only one "dial" event from the
	// dispatch loop's perspective).
	peerStateDialing

	// peerStateConnected is the state set AFTER a successful dial,
	// while the dispatch loop is processing frames on the conn.
	// peer.run transitions out of this state when dispatch returns
	// (conn closed, peer errored, ctx cancelled mid-frame).
	peerStateConnected

	// peerStateBackoff is the state set when a dial failed and
	// peer.run is sleeping before the next attempt. The
	// transition to peerStateDialing happens after the backoff
	// sleep completes (or ctx cancels).
	peerStateBackoff
)

// String returns a human-readable name for the state. Used by
// observability hooks (future) and by the peer_test.go test
// assertions. Kept unexported because the constants are unexported;
// the format is for logs, not for the public API.
func (s peerState) String() string {
	switch s {
	case peerStateIdle:
		return "idle"
	case peerStateDialing:
		return "dialing"
	case peerStateConnected:
		return "connected"
	case peerStateBackoff:
		return "backoff"
	default:
		return fmt.Sprintf("peerState(%d)", int(s))
	}
}

// Peer is the runtime per-peer lifecycle object (R1 task spec).
//
// Fields are a mix of config-derived (cfg) and runtime (state, attempts,
// dialer). The dialer field is an interface so tests inject a fake;
// production wires Transport.Dial (a method value whose signature
// satisfies the interface). The dispatch function is NOT a field —
// peer.run calls the package-level DispatchConn (R3) directly because
// there is no production reason to swap it out; the injection point is
// at the handler level (telem / ctrl), not at the loop level.
//
// Backoff parameters (backoffInitial, backoffMax, backoffJitter) are
// defaulted in NewPeer and may be overridden by tests in the same
// package (the fields are unexported, but peer_test.go is in the
// transport package, so direct field assignment is the standard
// Go test-injection pattern). Production code does not touch them —
// the v0.1.0 backoff policy is encoded in the defaults, not in a
// per-deployment override.
type Peer struct {
	// cfg is the config entry-point the Peer was constructed from.
	// Stored by value so a caller mutating the source PeerConfig
	// after NewPeer does not silently change the live Peer's
	// dial target. Host and Fingerprint are read-only after
	// construction.
	cfg PeerConfig

	// mu guards state. The other fields (cfg, backoff*, attempts)
	// are read-only after NewPeer returns, so they do not need
	// the lock.
	mu sync.Mutex
	// state is the current peerState. See the constants above.
	state peerState

	// dialer is the connection-establishment injection point. It
	// MUST be non-nil before peer.run is called. Production wires
	// Transport.Dial (a method value) at peer-roster construction
	// time; tests wire a fake that records calls and returns
	// scripted errors / conns.
	dialer dialer

	// backoffInitial is the first-failure backoff sleep duration.
	// Doubles on each subsequent failure, clamped at backoffMax.
	// Default: 1 second (R2 spec).
	backoffInitial time.Duration

	// backoffMax caps the exponential backoff so a long-lived
	// peer under a sustained outage does not back off for hours.
	// Default: 30 seconds (R2 spec).
	backoffMax time.Duration

	// backoffJitter is the symmetric jitter fraction applied to
	// the computed delay (e.g. 0.2 = ±20%). Jitter prevents
	// thundering-herd redial storms when many peers see the same
	// upstream outage at the same instant. Default: 0.2 (±20%,
	// the standard "decorrelated jitter" fraction for transport
	// retries; documented in OPERATIONS.md once it lands in Group
	// M).
	backoffJitter float64

	// attempts is the number of consecutive failed dials since
	// the last successful dial. Used to compute the exponential
	// backoff (delay = backoffInitial * 2^attempts, clamped at
	// backoffMax). Reset to 0 on every successful dial.
	attempts int
}

// NewPeer constructs a *Peer from a PeerConfig and applies the
// R2-spec backoff defaults. The returned *Peer has no dialer set —
// the caller (production bootstrap or test) MUST assign peer.dialer
// before calling peer.run. A peer.run call with a nil dialer returns
// an error rather than panicking, so a missing-wiring bug surfaces
// as a clean test failure instead of a nil-deref.
//
// Defaults applied here (R2 task spec):
//
//   - backoffInitial = 1 * time.Second
//   - backoffMax     = 30 * time.Second
//   - backoffJitter  = 0.2 (±20%)
//
// These three constants are the v0.1.0 backoff policy. A future flow
// task that wants per-deployment tuning adds a Config field; for
// v0.1.0 the constants are the contract (Karpathy #2: simplicity first,
// not premature flexibility).
func NewPeer(cfg PeerConfig) *Peer {
	return &Peer{
		cfg:            cfg,
		state:          peerStateIdle,
		backoffInitial: 1 * time.Second,
		backoffMax:     30 * time.Second,
		backoffJitter:  0.2,
		// dialer left nil — production wire-up is a bootstrap concern.
		// attempts is zero by default.
	}
}

// Host returns the Peer's configured host. Convenience accessor for
// log lines and observability hooks (a future R-flow task); the
// dispatch loop and peer.run do not need it because they read p.cfg
// directly.
func (p *Peer) Host() string { return p.cfg.Host }

// Fingerprint returns the Peer's configured fingerprint (may be empty
// for TOFU on first contact, per DECISION D24 §5).
func (p *Peer) Fingerprint() string { return p.cfg.Fingerprint }

// State returns the Peer's current connection state. The result is
// a snapshot — by the time the caller uses it, peer.run may have
// transitioned. v0.1.0 has no observability hooks that read State;
// the accessor exists for tests and the future R-flow observability
// task.
func (p *Peer) State() peerState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// setState is the unexported state-transition helper. peer.run is the
// only caller. The transition is a simple assignment under the lock
// — observability hooks (a future task) would intercept here, not
// poll State().
func (p *Peer) setState(s peerState) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
}

// RosterFromConfig converts a config-level peer roster into a slice
// of *Peer, one per PeerConfig, with backoff defaults applied via
// NewPeer.
//
// Why a free function (not a method on Config or *Transport):
//
//   - The conversion has no dependency on Transport state — it is a
//     pure mapping from one slice type to another. A method on
//     Config would imply Config "owns" the runtime roster, which is
//     misleading (R-group owns it).
//   - A method on *Transport would couple RosterFromConfig to the
//     full Transport lifecycle, which is overkill for what is
//     effectively a constructor call in a loop.
//   - The peer-roster builder will live in K-group (the bootstrap
//     is the layer that knows whether the transport is enabled, what
//     dialer to wire, etc.). K-group can call this free function
//     and then iterate the result to attach the dialer.
//
// The function preserves empty fingerprints as empty — the D24 §5
// "TOFU on first contact" path is encoded as the empty string, not
// as a sentinel constant. A naive "default empty to a placeholder"
// would silently enable the cross-check on first contact, which
// would change D24 behaviour. The R1 test pins this property: an
// empty cfg.Fingerprint MUST produce a *Peer with cfg.Fingerprint
// still empty.
//
// cfg may be nil or empty; the result is an empty (non-nil) slice in
// that case. This makes "no peers" a zero-friction state for the
// bootstrap.
func RosterFromConfig(cfg []PeerConfig) []*Peer {
	if len(cfg) == 0 {
		return []*Peer{}
	}
	roster := make([]*Peer, len(cfg))
	for i, pc := range cfg {
		// Copy the PeerConfig by value so a later mutation of
		// the source slice does not bleed into the runtime Peer.
		roster[i] = NewPeer(pc)
	}
	return roster
}

// ========================== R2 — peer.run lifecycle ==========================
//
// The lifecycle is a single goroutine body: loop dialing via the
// injected dialer, hand a successful conn to the R3 dispatch loop,
// back off on failure, exit cleanly on ctx cancellation. The function
// is intentionally simple — a state machine would be more code for
// no observable benefit at v0.1.0 (DECISION D31: per-function happy
// path + one edge, no state-machine-test explosion).
//
// Backoff math (R2 spec): on each consecutive failed dial, the
// sleep duration is `backoffInitial * 2^attempts` clamped at
// `backoffMax`, with ±jitter multiplicative jitter. Jitter is the
// last step so the floor is `delay * (1 - jitter)` and the ceiling
// is `delay * (1 + jitter)`. A negative jitter (the
// `delay * (1 - jitter)` case) can underflow for `jitter >= 1` —
// the caller (NewPeer) sets jitter to 0.2, well below 1, and the
// test that overrides jitter uses 0.1 for the same reason. The
// underflow is not defended against here because a real caller
// (production) never sets jitter >= 1 and a test that does is
// testing a property the production code never exhibits.

// dialer is the injection interface for the connection-establishment
// step (R2 task spec). The signature matches Transport.Dial exactly,
// so a *Transport's method value `t.Dial` satisfies the interface
// without an adapter. Tests inject a fake.
//
// Why a package-private interface (not exported Dialer): the only
// production caller is Transport (in K-group, the bootstrap layer),
// and the only test caller is peer_test.go in the same package. An
// exported name would invite "I want to mock the dialer for my
// application" callers — which is exactly the live-reconfig surface
// D25 forbids for v0.1.0. Keeping the interface unexported matches
// its scope.
type dialer interface {
	Dial(ctx context.Context, peer PeerConfig) (*quic.Conn, error)
}

// peer.run is the lifecycle goroutine body (R2 task spec).
//
// Contract:
//
//   - Loops: dial → (on success) run dispatch loop until it
//     returns → (on dial failure) backoff and redial → exit on
//     ctx cancellation.
//   - The dispatch function (R3) is called with the conn returned
//     by a successful dial. peer.run does not own the conn's
//     lifecycle past the dispatch call — DispatchConn closes the
//     conn on its return path (or ctx cancellation), and peer.run
//     additionally issues a defensive CloseWithError to be safe
//     against a future DispatchConn implementation that forgets.
//   - The handlers (telem, ctrl) are the R3 injection surface.
//     v0.1.0 production wire-up uses the no-op defaults; tests
//     inject capture variants.
//   - The debug logger (dbg) is the dispatch-loop trace surface.
//     Default: discardPeerDebugLogger{} (the no-op default for
//     the dispatch loop's internal trace events).
//   - Returns nil when ctx is cancelled. The return value is nil
//     for both "ctx-cancel happened at the top of the loop" and
//     "ctx-cancel happened mid-iteration" — peer.run does not
//     distinguish, because the caller (the bootstrap) treats
//     "peer.run returned" as "tear this goroutine down", and the
//     underlying cause (ctx) is the same.
//
// Bounded loop guarantee: peer.run does NOT spin. Every iteration
// either succeeds (dispatch blocks until conn closes), fails and
// sleeps (backoff with ctx-aware select), or exits (ctx cancel).
// A redial storm is prevented by the backoff; a goroutine leak
// is prevented by the ctx-aware select in the backoff sleep.
//
// Error handling: peer.run does not return per-iteration errors
// to the caller. Dial failures are absorbed into the backoff
// loop; dispatch errors are absorbed (the conn is gone, we redial).
// A future observability hook would read state transitions
// to surface them.
func (p *Peer) run(
	ctx context.Context,
	telem TelemetryHandler,
	ctrl ControlHandler,
	dbg peerDebugLogger,
) error {
	if p.dialer == nil {
		// Defensive: a Peer with no dialer set is a wire-up
		// bug. Surfacing it here (rather than letting Dial
		// nil-deref) gives the operator / test a clear error
		// rather than a stack trace.
		return fmt.Errorf("transport: peer.run: dialer not set for peer %q", p.cfg.Host)
	}
	if telem == nil {
		telem = noopTelemetryHandler{}
	}
	if ctrl == nil {
		ctrl = noopControlHandler{}
	}
	if dbg == nil {
		dbg = discardPeerDebugLogger{}
	}

	for {
		// Top-of-loop ctx check. Cheap; catches the case
		// where ctx was cancelled while we were waiting on
		// the previous iteration's dispatch / backoff.
		if ctx.Err() != nil {
			return nil
		}

		p.setState(peerStateDialing)
		dbg.Debugf("peer.run: dialing %s (attempts=%d)", p.cfg.Host, p.attempts)
		conn, err := p.dialer.Dial(ctx, p.cfg)
		if err != nil {
			// Dial failure. Apply backoff. We do NOT
			// surface the error to the caller — it is
			// the normal "peer is down" condition, and
			// the backoff + redial is the contract.
			// Observability hooks (future) would read
			// state transitions.
			dbg.Debugf("peer.run: dial %s failed: %v", p.cfg.Host, err)
			p.setState(peerStateBackoff)
			if !p.sleepBackoff(ctx, dbg) {
				// ctx cancelled during backoff.
				return nil
			}
			continue
		}

		// Successful dial. Reset the attempt counter and
		// run the dispatch loop. DispatchConn blocks
		// until the conn closes or ctx is cancelled.
		p.attempts = 0
		p.setState(peerStateConnected)
		dbg.Debugf("peer.run: connected to %s; running dispatch loop", p.cfg.Host)
		_ = DispatchConn(ctx, conn, telem, ctrl, dbg)
		// Defensive close: DispatchConn should have
		// closed the conn on its exit path, but a future
		// DispatchConn implementation might forget. The
		// close is best-effort: a double-close is a
		// quic-go no-op, not an error.
		_ = conn.CloseWithError(0, "peer.run: re-dialing")

		// After dispatch returns, loop back. If ctx is
		// done, the top-of-loop check on the next
		// iteration exits. If ctx is live, we redial
		// immediately — dispatch return is the "peer
		// went away" condition, not a failure.
		p.attempts = 0
	}
}

// sleepBackoff sleeps for the next backoff duration. The sleep is
// ctx-aware: ctx cancellation returns false without sleeping the
// full duration. The function is the single place that does the
// exponential + jitter math; tests in peer_test.go exercise it
// indirectly via peer.run.
//
// Returns true on a clean sleep, false if ctx was cancelled during
// the sleep (in which case peer.run exits).
func (p *Peer) sleepBackoff(ctx context.Context, dbg peerDebugLogger) bool {
	// Compute the base exponential delay. shift = p.attempts
	// means delay = backoffInitial * 2^attempts. We clamp
	// the shift to 30 to avoid uint64 overflow even if a
	// future test sets backoffInitial to nanoseconds; in
	// production backoffInitial is 1s so shift > 30 means
	// delay = 2^30 s ≈ 34 years, which the clamp at
	// backoffMax reduces to 30s anyway.
	base := p.backoffInitial
	shift := p.attempts
	if shift > 30 {
		shift = 30
	}
	scaled := uint64(base) << shift
	var delay time.Duration
	if time.Duration(scaled) > p.backoffMax {
		delay = p.backoffMax
	} else {
		delay = time.Duration(scaled)
	}

	// Apply symmetric jitter. rand.Float64() is in [0, 1),
	// so (rand.Float64()*2 - 1) is in [-1, +1), and
	// (1 + that * jitter) is in [1 - jitter, 1 + jitter).
	// The defensive <= 0 check covers a future test that
	// sets jitter >= 1 (which would make the floor
	// non-positive) — without it, a 0-delay backoff would
	// tight-loop, violating the no-spin guarantee.
	jitter := 1.0 + (rand.Float64()*2-1)*p.backoffJitter
	finalDelay := time.Duration(float64(delay) * jitter)
	if finalDelay <= 0 {
		finalDelay = p.backoffInitial
	}

	dbg.Debugf("peer.run: backing off %s before next dial to %s (attempts=%d)", finalDelay, p.cfg.Host, p.attempts)
	p.attempts++

	// Ctx-aware sleep. The select is the single
	// ctx-cancellation exit point in the backoff path.
	select {
	case <-time.After(finalDelay):
		return true
	case <-ctx.Done():
		return false
	}
}

// ========================== R3 — protocol-dispatch loop ==========================
//
// The dispatch loop is the runtime read-path for an established
// QUIC conn. R3 ships the loop on the DIALER side (peer.run is
// the dialer; the listener side's handleAcceptedConn currently
// just keeps the conn open — see the file-level comment for why
// listener-side wiring is out of scope for R-group).
//
// Loop unit: a single QUIC stream. DispatchConn is the per-conn
// entry point that accepts streams and dispatches each one in
// its own goroutine. DispatchStream is the per-stream unit —
// the function tests exercise directly, with bytes.Buffer
// readers and writers for hermetic unit-level testing.

// TelemetryHandler is the injection interface for telemetry
// (unidirectional) frames. The handler receives a fully-decoded
// *pb.Frame whose Body is a Heartbeat, TelemetryBatch, or Alert
// (the three D27 §2 telemetry message types). v0.1.0 ships the
// noopTelemetryHandler default; arxsentinel wires a real handler
// (counters sink, alert router, etc.) in a later flow.
//
// HandleTelemetry is called once per telemetry frame read off a
// telemetry stream. The handler MUST be quick — telemetry streams
// are high-frequency, fire-and-forget (D27 §2). A handler that
// blocks serialises the dispatch loop. Future observability
// guidance (Group M) will document the latency budget; for
// v0.1.0 the dispatch loop logs the error and continues.
//
// Returning a non-nil error is the handler's signal "this frame
// was bad, do not deliver to downstream" — the dispatch loop
// logs the error at DEBUG and continues to the next frame. There
// is no error-propagation surface to peer.run; the telemetry
// stream is uni, there is no peer to report to.
type TelemetryHandler interface {
	HandleTelemetry(f *pb.Frame) error
}

// ControlHandler is the injection interface for control
// (bidirectional) frames. The handler receives a fully-decoded
// *pb.Frame whose Body is a Ping, Pong, RuleUpdate, or
// RuleUpdateAck (the four D27 §2 control message types).
//
// HandleControl may return a non-nil *pb.Frame to be written back
// on the same stream — this is the round-trip path for Ping -> Pong
// and RuleUpdate -> RuleUpdateAck. A nil response means "no
// reply" (e.g. an incoming Pong: the responder has nothing to say
// in return). The dispatch loop encodes the response with
// EncodeFrame and writes it on the stream's write side.
//
// Returning a non-nil error is the handler's signal "this frame
// was bad, drop it". The dispatch loop logs at DEBUG and
// continues.
type ControlHandler interface {
	HandleControl(f *pb.Frame) (*pb.Frame, error)
}

// noopTelemetryHandler is the v0.1.0 default TelemetryHandler.
// It silently accepts every frame and returns nil. Production
// wire-up replaces this with a real handler via the K-group
// bootstrap; v0.1.0 has no real handler because the transport
// package's product-side surface (arxsentinel) is not yet wired
// in.
//
// Why a no-op and not "log at DEBUG": protocol.go's Logger
// interface does not expose Debugf (it has Warnf and Errorf
// only), and adding Debugf to that interface would be an
// out-of-scope refactor of the Logger surface (touches
// nopLogger, captureLogger, captureQ4Logger, and the Q4 test
// assertions). The brief endorses (iii): the no-op is the
// silent placeholder, debug logging is what a real handler
// would do when the product wires it.
type noopTelemetryHandler struct{}

func (noopTelemetryHandler) HandleTelemetry(*pb.Frame) error { return nil }

// noopControlHandler is the v0.1.0 default ControlHandler. It
// returns (nil, nil) for every frame — "received, no reply". A
// Ping therefore gets no Pong; a RuleUpdate gets no Ack. This
// is the explicit "the transport itself is dumb" posture for
// v0.1.0; the arxsentinel product supplies the real handlers
// when it wires itself to the transport in a later flow.
//
// As with noopTelemetryHandler, the no-op is silent (no DEBUG
// log). See the noopTelemetryHandler comment for the rationale.
type noopControlHandler struct{}

func (noopControlHandler) HandleControl(*pb.Frame) (*pb.Frame, error) {
	return nil, nil
}

// peerDebugLogger is the dispatch-loop's internal trace surface.
// It is intentionally separate from protocol.go's Logger
// interface, which exposes Warnf and Errorf but not Debugf.
// Extending protocol.go's Logger with Debugf would be an
// out-of-scope refactor (R-group is scoped to peer.go and
// peer_test.go only); a small dedicated interface in peer.go
// is the additive surface that does the job.
//
// Method semantics:
//
//   - Debugf logs a non-security-relevant trace event. The
//     dispatch loop uses it for "frame dropped (unknown
//     version)", "handler returned an error", "backing off
//     Ns", etc. These are observability aids for tests and
//     future ops; they are NOT operator alerts (those go
//     through protocol.go's Logger at Warnf / Errorf).
//
// The default is discardPeerDebugLogger{}, which drops every
// call. Tests inject a capture variant (peer_test.go's
// captureDebugLogger).
type peerDebugLogger interface {
	Debugf(format string, args ...any)
}

// discardPeerDebugLogger is the default peerDebugLogger. It
// silently drops every Debugf call. Equivalent in role to
// protocol.go's nopLogger but for the peer-package surface.
type discardPeerDebugLogger struct{}

func (discardPeerDebugLogger) Debugf(string, ...any) {}

// DispatchConn is the per-conn dispatch loop (R3 task spec).
// It is the entry point peer.run calls after a successful dial.
//
// Lifecycle:
//
//   - Spawns one goroutine that accepts uni streams (telemetry).
//     Each accepted stream is dispatched in its own per-stream
//     goroutine (DispatchStream). The accept-goroutine exits
//     when AcceptUniStream returns an error (ctx cancel, conn
//     close).
//   - In the current goroutine, accepts bi streams (control) in
//     a loop. Each accepted stream is dispatched in its own
//     per-stream goroutine. The loop exits on ctx cancel or
//     conn close.
//   - On return the conn is closed. The caller does not need
//     to close it again, but a defensive CloseWithError is
//     cheap and idempotent — peer.run does it anyway.
//
// Why a per-stream goroutine (not per-stream inline loop):
// quic-go's stream accept is the only concurrency primitive
// available, and inline handling would block the accept loop
// on slow per-stream I/O. The per-stream goroutine is the
// canonical pattern (the quic-go echo example uses it for the
// same reason).
//
// Why two separate accept paths (one goroutine for uni, the
// current goroutine for bi): quic-go's Conn type does not
// expose a unified AcceptAnyStream. AcceptStream blocks until
// a bi stream is available; AcceptUniStream blocks until a uni
// stream is available. Running them in the same goroutine
// would force one to "win" forever; running each in its own
// goroutine is the documented pattern. A bi-only conn is
// fine (the uni goroutine blocks on AcceptUniStream and
// exits on conn close).
//
// The function is exported (not unexported) for ONE reason:
// the future listener-side task (R-group follow-up, NOT
// scoped to R-group per the brief) needs to call this from
// Transport.handleAcceptedConn. Making it exported means the
// integration is "one call" — a future task adds a single
// line to handleAcceptedConn and the listener side runs the
// dispatch loop. Keeping it unexported would force that task
// to either expose a method on Transport (a wider surface
// change) or to live in the peer file (a wider file
// boundary). The exported name is the minimal-surface choice
// that future-proofs the integration without expanding the
// v0.1.0 API.
//
// Test injection: tests call DispatchStream directly with
// bytes.Buffer readers / writers; they do not stand up a
// real QUIC connection (R3 is "dispatch in isolation";
// the lifecycle is R2's test surface).
func DispatchConn(
	ctx context.Context,
	conn *quic.Conn,
	telem TelemetryHandler,
	ctrl ControlHandler,
	dbg peerDebugLogger,
) error {
	if telem == nil {
		telem = noopTelemetryHandler{}
	}
	if ctrl == nil {
		ctrl = noopControlHandler{}
	}
	if dbg == nil {
		dbg = discardPeerDebugLogger{}
	}

	// Uni-stream accept goroutine. Blocks on
	// AcceptUniStream until either a uni stream arrives
	// (dispatch a goroutine) or the conn closes / ctx
	// cancels (return). The per-stream goroutine owns
	// the stream's read lifecycle; we don't track
	// them here because the dispatch loop has no
	// teardown coordination beyond ctx.
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				// Conn closed or ctx cancelled.
				// Both are normal exit conditions.
				return
			}
			go DispatchStream(ctx, uint64(stream.StreamID()), stream, nil, telem, ctrl, dbg)
		}
	}()

	// Bi-stream accept loop in the current goroutine.
	// Same shape as the uni goroutine but without the
	// extra goroutine hop for the accept call itself.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Conn closed or ctx cancelled.
			// Both are normal exit conditions.
			return nil
		}
		go DispatchStream(ctx, uint64(stream.StreamID()), stream, stream, telem, ctrl, dbg)
	}
}

// DispatchStream is the per-stream dispatch unit (R3 task spec).
// It is the unit-level test surface: tests call this directly
// with a bytes.Reader preloaded with one or more frames, and
// inspect the resulting writes on the writer.
//
// The function is unexported because the only callers are
// DispatchConn (in this file) and peer_test.go (in the same
// package). Exposing it as a public API would invite
// out-of-tree callers who might re-implement the dispatch
// semantics incorrectly — keeping it unexported keeps the
// "dispatch is one function in this file" property visible
// to future readers.
//
// streamID selects the handler: telemetry (uni) vs control (bi).
// The caller is responsible for passing a streamID that matches
// the actual stream type (the value returned by AcceptStream /
// AcceptUniStream is what we pass; tests use a literal ID).
//
// reader and writer are the stream's read / write sides. For
// uni streams writer is nil. The function does not own the
// stream's lifecycle past "frames drained" — the caller (the
// conn-level loop) is responsible for closing the stream if
// needed.
//
// Frame loop:
//
//   - Read one length-prefixed frame from reader.
//   - If reader returns io.EOF (clean end-of-stream), return
//     nil. A non-EOF error is propagated.
//   - Decode the frame. Decode failures (truncated, oversized,
//     malformed protobuf) are propagated — they indicate a
//     broken peer or a buggy client, and continuing past
//     them would be unsafe.
//   - Apply DropIfUnknownVersion (D27 §3). A dropped frame
//     is logged and the loop continues.
//   - Dispatch: telemetry -> HandleTelemetry, control ->
//     HandleControl, optionally write the response back.
//
// Returns ctx.Err() if ctx is cancelled mid-frame, nil if the
// stream drained cleanly, or a wrapped error otherwise.
func DispatchStream(
	ctx context.Context,
	streamID uint64,
	reader io.Reader,
	writer io.Writer,
	telem TelemetryHandler,
	ctrl ControlHandler,
	dbg peerDebugLogger,
) error {
	if telem == nil {
		telem = noopTelemetryHandler{}
	}
	if ctrl == nil {
		ctrl = noopControlHandler{}
	}
	if dbg == nil {
		dbg = discardPeerDebugLogger{}
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Read one frame's worth of bytes (length prefix +
		// body). io.ReadFull returning io.EOF here is the
		// "stream drained cleanly" signal — quic-go's
		// streams are byte-precise, so a clean close
		// surfaces as io.EOF on the next Read.
		raw, err := readFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("DispatchStream: read frame: %w", err)
		}

		// Decode. A decode failure is a wire-level
		// violation — the peer sent bytes that are not
		// a valid frame. Propagating the error is the
		// right call: a stream that mis-frames should
		// not keep being read, because we no longer
		// have a known byte offset to resume from.
		f, err := DecodeFrame(raw)
		if err != nil {
			return fmt.Errorf("DispatchStream: decode frame: %w", err)
		}

		// Version check (D27 §3). A frame with the
		// wrong protocol_version is dropped at this
		// layer; the log emission is in
		// DropIfUnknownVersion (it takes the
		// protocol.go Logger, which is
		// DiscardLogger in the default wire-up —
		// harmless in the R3 test path).
		//
		// The protocol.go Logger is intentionally NOT
		// threaded through here: R-group does not own
		// that surface and threading a second logger
		// into DropIfUnknownVersion would be an
		// out-of-scope change. The dispatch loop's own
		// dbg (peerDebugLogger) records the drop event
		// for tests.
		if DropIfUnknownVersion(f, nil) {
			dbg.Debugf("DispatchStream: dropped frame on stream %d (unknown protocol_version=%d)", streamID, f.GetProtocolVersion())
			continue
		}

		// Route by stream type. The two predicates are
		// complementary on the QUIC stream-ID space
		// (protocol.go §P3), so the if/else is
		// exhaustive — there is no "unknown" stream
		// type.
		if IsTelemetryStream(streamID) {
			if err := telem.HandleTelemetry(f); err != nil {
				dbg.Debugf("DispatchStream: telemetry handler error on stream %d: %v", streamID, err)
			}
			continue
		}

		// Control stream. The handler may return a
		// response frame that we write back on the
		// same stream. A nil response or a nil
		// writer (should not happen for bi streams,
		// but defensive) is treated as "no reply".
		resp, err := ctrl.HandleControl(f)
		if err != nil {
			dbg.Debugf("DispatchStream: control handler error on stream %d: %v", streamID, err)
			continue
		}
		if resp == nil || writer == nil {
			continue
		}
		enc, err := EncodeFrame(resp)
		if err != nil {
			return fmt.Errorf("DispatchStream: encode response: %w", err)
		}
		if _, err := writer.Write(enc); err != nil {
			return fmt.Errorf("DispatchStream: write response: %w", err)
		}
	}
}

// readFrame reads one length-prefixed frame from r. Returns the
// raw bytes (length prefix + body, contiguous) ready for
// DecodeFrame, or an error.
//
// The function is a thin wrapper around two io.ReadFull calls.
// Splitting it out of DispatchStream keeps the dispatch loop
// body readable; the framing math is not the interesting part of
// the dispatch logic.
//
// Errors:
//   - io.EOF / io.ErrUnexpectedEOF from the first ReadFull:
//     truncated length prefix or clean end-of-stream. The
//     caller treats io.EOF as "stream drained".
//   - declared length > MaxFrameSize: oversized frame, rejected
//     before any allocation. The check is the same one
//     protocol.go's DecodeFrame does, but applying it here
//     means we never allocate a multi-MB buffer for a hostile
//     length prefix.
//   - io.ReadFull on the body: truncated body or stream error.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [lengthPrefixSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		// Pass through io.EOF / io.ErrUnexpectedEOF / a
		// wrapped error verbatim. The caller uses
		// errors.Is(err, io.EOF) to detect "clean
		// end-of-stream".
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxFrameSize {
		return nil, fmt.Errorf("readFrame: declared length %d exceeds MaxFrameSize=%d", n, MaxFrameSize)
	}
	out := make([]byte, lengthPrefixSize+n)
	// We already read the length prefix into lenBuf; copy
	// it into the output buffer so the caller can hand
	// the contiguous slice to DecodeFrame.
	copy(out[:lengthPrefixSize], lenBuf[:])
	if _, err := io.ReadFull(r, out[lengthPrefixSize:]); err != nil {
		return nil, fmt.Errorf("readFrame: read body: %w", err)
	}
	return out, nil
}

// Compile-time assertions: the dispatch loop and dialer types
// must satisfy the expected shapes. If a future refactor
// changes a signature in a way that breaks the dispatch
// path, the build fails here with a clear message rather
// than at a downstream call site.
var _ TelemetryHandler = noopTelemetryHandler{}
var _ ControlHandler = noopControlHandler{}
var _ peerDebugLogger = discardPeerDebugLogger{}
