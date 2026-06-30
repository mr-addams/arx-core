// Package transport (peer_test.go): tests for the R1/R2/R3
// peer-lifecycle primitives.
//
// The R1 tests are:
//
//   - TestRosterFromConfigPreservesEntries
//     — happy path: N PeerConfig entries → N *Peer with
//     matching Host / Fingerprint fields.
//   - TestRosterFromConfigEmptyFingerprintPreserved
//     — D24 §5: empty cfg.Fingerprint is the TOFU-on-first-
//     contact path; RosterFromConfig MUST NOT default it
//     to a placeholder.
//   - TestRosterFromConfigEmptyInput
//     — edge: nil / len-0 input → empty (non-nil) result.
//   - TestNewPeerBackoffDefaults
//     — R2 spec: NewPeer applies the documented defaults
//     (1s initial, 30s max, 0.2 jitter).
//
// The R2 tests are:
//
//   - TestPeerRunDialFailureTriggersBackoff
//     — fake dialer that always errors; with a short
//     backoff initial the test runs in well under a
//     second and asserts the dialer was called only
//     a handful of times (proving backoff is happening,
//     not tight-looping).
//   - TestPeerRunContextCancelDuringBackoffReturns
//     — start peer.run, wait for at least one dial
//     attempt, cancel ctx, assert peer.run returns
//     within 50ms (proving the backoff sleep is
//     ctx-aware).
//
// The R3 tests are:
//
//   - TestDispatchStreamTelemetryFrameReceived
//     — hermetic unit test: build a telemetry frame,
//     encode it, hand the bytes to DispatchStream as
//     a telemetry stream ID; assert the no-op
//     telemetry handler's capture variant recorded
//     the frame.
//   - TestDispatchStreamControlFrameRoundTrips
//     — hermetic unit test: build a Ping frame, hand
//     the bytes to DispatchStream as a control stream
//     ID; the echo-Pong handler returns a Pong;
//     DispatchStream writes it back; the test reads
//     the response from the writer buffer and asserts
//     Pong.Nonce == Ping.Nonce.
//   - TestDispatchStreamUnknownVersionDrops
//     — protocol.go's DropIfUnknownVersion contract:
//     a frame with the wrong protocol_version is
//     dropped, the handler is not called.
//
// All tests are hermetic: no real QUIC connections,
//no t.TempDir() (no on-disk state), no goroutines that
// survive past t.Cleanup. The dispatch tests use
// bytes.Buffer as the stream I/O surface, which is
// the standard pattern for unit-testing a function
// that reads from an io.Reader and writes to an
// io.Writer.
package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	pb "github.com/mr-addams/arx-core/pkg/transport/proto"
)

// ========================== R1 tests ==========================

// TestRosterFromConfigPreservesEntries is the R1 happy path:
// N PeerConfig entries produce N *Peer values, each with
// matching Host and Fingerprint fields. The Peer struct
// copies the PeerConfig by value (see RosterFromConfig's
// "Copy the PeerConfig by value" comment), so the assertion
// is a per-field equality, not a pointer-identity check —
// the function MUST produce distinct *Peer values, not
// aliases of the same backing array entry.
func TestRosterFromConfigPreservesEntries(t *testing.T) {
	input := []PeerConfig{
		{Host: "10.0.0.1:7000", Fingerprint: "sha256:aaaa"},
		{Host: "10.0.0.2:7000", Fingerprint: "sha256:bbbb"},
		{Host: "10.0.0.3:7000", Fingerprint: ""}, // TOFU
	}
	roster := RosterFromConfig(input)
	if len(roster) != len(input) {
		t.Fatalf("roster length = %d, want %d", len(roster), len(input))
	}
	for i, p := range roster {
		if p == nil {
			t.Errorf("roster[%d] is nil", i)
			continue
		}
		if p.cfg.Host != input[i].Host {
			t.Errorf("roster[%d].Host = %q, want %q", i, p.cfg.Host, input[i].Host)
		}
		if p.cfg.Fingerprint != input[i].Fingerprint {
			t.Errorf("roster[%d].Fingerprint = %q, want %q", i, p.cfg.Fingerprint, input[i].Fingerprint)
		}
	}
}

// TestRosterFromConfigEmptyFingerprintPreserved pins the
// D24 §5 "TOFU on first contact" behaviour at the
// RosterFromConfig layer: an empty PeerConfig.Fingerprint
// MUST survive RosterFromConfig as an empty
// Peer.Fingerprint. A naive "default to placeholder" would
// silently enable the cross-check on first contact, which
// would change D24's first-contact pin semantics.
//
// The test is the smallest possible assertion: one entry
// with empty fingerprint, one assertion on the output.
// Minimal because the property is binary — a regression
// here would be one misplaced `if cfg.Fingerprint == ""`
// branch.
func TestRosterFromConfigEmptyFingerprintPreserved(t *testing.T) {
	input := []PeerConfig{
		{Host: "10.0.0.1:7000", Fingerprint: ""},
	}
	roster := RosterFromConfig(input)
	if len(roster) != 1 {
		t.Fatalf("roster length = %d, want 1", len(roster))
	}
	if roster[0].cfg.Fingerprint != "" {
		t.Errorf("roster[0].Fingerprint = %q, want empty (TOFU on first contact, D24 §5)",
			roster[0].cfg.Fingerprint)
	}
}

// TestRosterFromConfigEmptyInput is the edge case: nil
// or len-0 input. The expected result is a non-nil empty
// slice. A nil result would force every caller to
// nil-check before iterating; an empty (non-nil) slice
// makes "no peers" a zero-friction state.
func TestRosterFromConfigEmptyInput(t *testing.T) {
	cases := []struct {
		name string
		in   []PeerConfig
	}{
		{"nil", nil},
		{"zero-length", []PeerConfig{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roster := RosterFromConfig(tc.in)
			if roster == nil {
				t.Errorf("RosterFromConfig(%v) returned nil; want empty (non-nil) slice", tc.in)
			}
			if len(roster) != 0 {
				t.Errorf("RosterFromConfig(%v) length = %d, want 0", tc.in, len(roster))
			}
		})
	}
}

// TestNewPeerBackoffDefaults is the R2 backoff-default
// assertion: NewPeer applies the documented defaults
// (initial 1s, max 30s, jitter 0.2). The test reads the
// unexported fields directly because it lives in the
// same package; this is the standard Go test-injection
// pattern for "verify the constructor set the right
// values".
func TestNewPeerBackoffDefaults(t *testing.T) {
	p := NewPeer(PeerConfig{Host: "x", Fingerprint: "y"})
	if p.backoffInitial != 1*time.Second {
		t.Errorf("backoffInitial = %v, want 1s", p.backoffInitial)
	}
	if p.backoffMax != 30*time.Second {
		t.Errorf("backoffMax = %v, want 30s", p.backoffMax)
	}
	if p.backoffJitter != 0.2 {
		t.Errorf("backoffJitter = %v, want 0.2", p.backoffJitter)
	}
	if p.state != peerStateIdle {
		t.Errorf("initial state = %v, want peerStateIdle", p.state)
	}
	if p.dialer != nil {
		t.Errorf("dialer should be nil after NewPeer; got %v", p.dialer)
	}
}

// ========================== R2 tests ==========================

// fakeDialer is the test injection point for R2's dialer
// interface. It records every call (for "backoff is
// happening" assertions) and returns scripted responses.
//
// The "dial count" uses atomic.Int64 because peer.run
// may call Dial from a goroutine the test's main thread
// observes (the typical pattern for "wait until N
// attempts have been made" polling loops).
type fakeDialer struct {
	calls atomic.Int64
	// err, when non-nil, is returned by every Dial call.
	// When nil, Dial returns a nil conn — the test that
	// wants a successful dial would set this and assert
	// the conn is ignored / the dispatch loop is not
	// called. v0.1.0 R2 tests only exercise the
	// failure path; the success path is R3's test
	// surface.
	err error
}

func (f *fakeDialer) Dial(ctx context.Context, peer PeerConfig) (*quic.Conn, error) {
	// The fake dialer never returns a real conn — the
	// R2 test path only exercises the error branch
	// (peer.run on a permanently-down peer). The
	// (*quic.Conn)(nil) return is a typed nil, which
	// peer.run never dereferences because it always
	// short-circuits on the non-nil err. If a future
	// test wants the success branch, it would need a
	// different fake that constructs a *quic.Conn (not
	// possible in pure-Go unit tests — the conn comes
	// from a real handshake). v0.1.0 R2 has no
	// success-branch test; the dispatch-loop test
	// (R3) is the place where a real conn exists.
	f.calls.Add(1)
	return nil, f.err
}

// TestPeerRunDialFailureTriggersBackoff proves that
// peer.run applies backoff on dial failure, instead of
// tight-looping and re-dialling on every iteration.
//
// The test uses a short backoff initial (50ms) to keep
// the runtime under a second. The fake dialer always
// returns an error, so peer.run is in the
// dial-fail-then-backoff path for the entire test
// window. After 200ms we expect 2-3 dial attempts
// (one immediately, one after ~50ms backoff, one after
// ~100ms backoff) — NOT the 1000+ attempts a tight
// loop would produce.
//
// The 2-3 bound is conservative: a jittered 50ms
// backoff with ±20% jitter has a floor of ~40ms and a
// ceiling of ~60ms on the first failure. Two backoffs
// (after the first two failures) would have produced
// ~40-60ms each, so after 200ms we expect at least
// 1 + 2 = 3 attempts and at most ~5. We assert
// "less than 50" as a generous upper bound that proves
// backoff is happening (a tight loop would have
// produced thousands of attempts in 200ms).
func TestPeerRunDialFailureTriggersBackoff(t *testing.T) {
	// Construct a Peer directly (bypassing NewPeer)
	// so we can override backoffInitial to 50ms.
	// NewPeer would have set 1s, which makes the test
	// take 1s+ for the first backoff cycle — too slow
	// for a unit test.
	p := &Peer{
		cfg:            PeerConfig{Host: "test:1234"},
		state:          peerStateIdle,
		backoffInitial: 50 * time.Millisecond,
		backoffMax:     1 * time.Second,
		backoffJitter:  0.1, // small jitter for deterministic bounds
	}
	d := &fakeDialer{err: errors.New("simulated dial failure")}
	p.dialer = d

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		_ = p.run(ctx, nil, nil, nil) // nil handlers -> no-op defaults
		close(done)
	}()

	// Wait 200ms for several backoff cycles to elapse.
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Wait for peer.run to exit (with a generous deadline
	// — the backoff sleep at the moment of cancel might
	// be up to ~60ms, plus the close channel roundtrip).
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("peer.run did not return within 500ms after ctx cancel")
	}

	gotCalls := d.calls.Load()
	if gotCalls < 2 {
		t.Errorf("fake dialer called %d times in 200ms; expected at least 2 (proving peer.run made progress before the first backoff)", gotCalls)
	}
	if gotCalls > 50 {
		t.Errorf("fake dialer called %d times in 200ms; expected at most 50 (a tight loop would produce thousands)", gotCalls)
	}
}

// TestPeerRunContextCancelDuringBackoffReturns proves the
// backoff sleep is ctx-aware: cancelling ctx during the
// sleep returns peer.run within a short deadline, not
// after the full backoff duration.
//
// The test uses a 500ms backoff initial so the test
// has a clear "would have slept for 500ms" baseline.
// We start peer.run in a goroutine, wait for the first
// dial attempt (so peer.run is in the backoff sleep),
// cancel ctx, and assert peer.run returns within 50ms.
//
// The 50ms return deadline is the assertion: a
// non-ctx-aware sleep would have taken ~500ms to
// return. 50ms is generous enough to absorb the
// goroutine-scheduling latency on a busy CI host but
// tight enough to catch a `time.Sleep` regression.
func TestPeerRunContextCancelDuringBackoffReturns(t *testing.T) {
	p := &Peer{
		cfg:            PeerConfig{Host: "test:1234"},
		state:          peerStateIdle,
		backoffInitial: 500 * time.Millisecond,
		backoffMax:     1 * time.Second,
		backoffJitter:  0,
	}
	d := &fakeDialer{err: errors.New("simulated dial failure")}
	p.dialer = d

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// We want to cancel during the backoff sleep, NOT
	// during the dial call. The fake dialer returns
	// immediately, so the first iteration of peer.run is:
	//   1. dial (immediate fail)
	//   2. enter backoff sleep (500ms)
	// Run peer.run in a goroutine and observe its
	// return via a channel. Wait for at least one
	// dial before cancelling so we are sure the
	// goroutine is in the sleep, not in the dial.
	done := make(chan struct{})
	go func() {
		_ = p.run(ctx, nil, nil, nil)
		close(done)
	}()

	// Poll for the first dial. Ceiling: 1s, well above
	// the immediate-fake-dial latency and well below
	// the 500ms backoff.
	deadline := time.Now().Add(1 * time.Second)
	for d.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("fake dialer was never called within 1s; peer.run is not making progress")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// peer.run is now in the 500ms backoff sleep.
	// Cancel ctx and measure how long it takes to
	// return. The select on `<-done` is bounded by
	// 50ms; a non-ctx-aware sleep would block for
	// the full 500ms and the select would time out.
	started := time.Now()
	cancel()

	select {
	case <-done:
		elapsed := time.Since(started)
		if elapsed > 50*time.Millisecond {
			t.Errorf("peer.run took %v to return after ctx cancel; want < 50ms (proving backoff sleep is ctx-aware)", elapsed)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("peer.run did not return within 50ms of ctx cancel; backoff sleep is not ctx-aware")
	}
}

// TestPeerRunNilDialerErrors is the wire-up guard: a Peer
// with no dialer set must return an error from peer.run
// rather than nil-deref'ing inside the loop. The
// constructor (NewPeer) does not set a dialer — the
// bootstrap is responsible for that — so a missing
// dialer is a real wire-up bug, and a clear error
// message is the test contract.
func TestPeerRunNilDialerErrors(t *testing.T) {
	p := NewPeer(PeerConfig{Host: "test:1234"})
	err := p.run(context.Background(), nil, nil, nil)
	if err == nil {
		t.Fatal("peer.run with nil dialer returned nil; expected a wire-up error")
	}
}

// ========================== R3 tests ==========================

// captureTelemetryHandler is the test-injection variant
// of TelemetryHandler. It records every frame it
// receives so the test can assert "the dispatch loop
// delivered this frame to the handler".
type captureTelemetryHandler struct {
	mu     sync.Mutex
	frames []*pb.Frame
}

func (h *captureTelemetryHandler) HandleTelemetry(f *pb.Frame) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.frames = append(h.frames, f)
	return nil
}

func (h *captureTelemetryHandler) received() []*pb.Frame {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*pb.Frame, len(h.frames))
	copy(out, h.frames)
	return out
}

// echoPongControlHandler is the test-injection variant
// of ControlHandler that returns a Pong for every Ping.
// The Pong's nonce equals the Ping's nonce so the test
// can assert "the response is the right Pong".
type echoPongControlHandler struct {
	mu     sync.Mutex
	frames []*pb.Frame
}

func (h *echoPongControlHandler) HandleControl(f *pb.Frame) (*pb.Frame, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.frames = append(h.frames, f)
	ping := f.GetPing()
	if ping == nil {
		return nil, nil
	}
	return &pb.Frame{
		ProtocolVersion: CurrentProtocolVersion,
		Body: &pb.Frame_Pong{Pong: &pb.Pong{Nonce: ping.GetNonce()}},
	}, nil
}

func (h *echoPongControlHandler) received() []*pb.Frame {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*pb.Frame, len(h.frames))
	copy(out, h.frames)
	return out
}

// captureDebugLogger is the test-injection variant of
// peerDebugLogger. It records every message for
// assertions on dispatch-loop trace events.
type captureDebugLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *captureDebugLogger) Debugf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Format lazily to avoid the cost when no
	// assertion reads the log. Tests that assert
	// on the log call l.messages() and compare.
	_ = format
	_ = args
	// We do NOT call fmt.Sprintf here for the
	// "messages" slice — instead we store the
	// raw format + args and let the test assert
	// on the formatted string. Storing the
	// formatted string would lose the format
	// verb info that tests might want.
	l.msgs = append(l.msgs, format)
}

func (l *captureDebugLogger) messages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.msgs))
	copy(out, l.msgs)
	return out
}

// telemetryStreamID is a stream ID whose low bit 1 is
// set, marking it as a unidirectional telemetry stream
// per protocol.go's IsTelemetryStream contract. The
// exact value is arbitrary; the bit pattern is what
// IsTelemetryStream tests. Value 3 is the third stream
// opened by a client (the client-initiated uni-stream
// counter is per-conn; 3 is a representative value, not
// a wire contract).
const telemetryStreamID uint64 = 3

// controlStreamID is a stream ID whose low bit 1 is
// clear, marking it as a bidirectional control stream
// per protocol.go's IsControlStream contract. Value 0
// is the first bi stream a client opens (the
// client-initiated bidi-stream counter starts at 0).
const controlStreamID uint64 = 0

// TestDispatchStreamTelemetryFrameReceived proves the
// dispatch loop reads a telemetry frame off a
// unidirectional stream and delivers it to the
// TelemetryHandler.
//
// The test is hermetic: bytes.Buffer as the stream
// reader (preloaded with one encoded Heartbeat), nil
// writer (uni streams have no write side), and a
// captureTelemetryHandler. After DispatchStream
// returns (it returns when the reader is exhausted),
// the test asserts the handler received exactly one
// frame and that the frame is the Heartbeat we sent.
func TestDispatchStreamTelemetryFrameReceived(t *testing.T) {
	heartbeat := &pb.Frame{
		ProtocolVersion: CurrentProtocolVersion,
		Body: &pb.Frame_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				SenderNodeId:      "test-node",
				MonotonicClockMs: 42,
			},
		},
	}
	enc, err := EncodeFrame(heartbeat)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	reader := bytes.NewReader(enc)

	telem := &captureTelemetryHandler{}
	ctrl := &echoPongControlHandler{}
	dbg := &captureDebugLogger{}

	err = DispatchStream(context.Background(), telemetryStreamID, reader, nil, telem, ctrl, dbg)
	if err != nil {
		t.Fatalf("DispatchStream: %v", err)
	}

	frames := telem.received()
	if len(frames) != 1 {
		t.Fatalf("telemetry handler received %d frames, want 1", len(frames))
	}
	got := frames[0]
	if got.GetHeartbeat() == nil {
		t.Errorf("received frame is not a Heartbeat: %T", got.GetBody())
	} else {
		if got.GetHeartbeat().GetSenderNodeId() != "test-node" {
			t.Errorf("Heartbeat.SenderNodeId = %q, want %q",
				got.GetHeartbeat().GetSenderNodeId(), "test-node")
		}
		if got.GetHeartbeat().GetMonotonicClockMs() != 42 {
			t.Errorf("Heartbeat.MonotonicClockMs = %d, want 42",
				got.GetHeartbeat().GetMonotonicClockMs())
		}
	}
}

// TestDispatchStreamControlFrameRoundTrips proves the
// dispatch loop's control round-trip path: a Ping on a
// bi stream is read, the handler returns a Pong, the
// dispatch loop encodes the Pong and writes it back to
// the same stream. The test reads the response from
// the writer buffer and asserts Pong.Nonce ==
// Ping.Nonce.
//
// Hermetic: bytes.Buffer for the input (preloaded with
// a Ping), bytes.Buffer for the output (the dispatch
// loop writes the Pong here; the test reads it back).
// No real QUIC stream needed.
func TestDispatchStreamControlFrameRoundTrips(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ping := &pb.Frame{
		ProtocolVersion: CurrentProtocolVersion,
		Body: &pb.Frame_Ping{
			Ping: &pb.Ping{
				Nonce:            nonce,
				MonotonicClockMs: 100,
			},
		},
	}
	enc, err := EncodeFrame(ping)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	reader := bytes.NewReader(enc)
	writer := &bytes.Buffer{}

	telem := &captureTelemetryHandler{}
	ctrl := &echoPongControlHandler{}
	dbg := &captureDebugLogger{}

	err = DispatchStream(context.Background(), controlStreamID, reader, writer, telem, ctrl, dbg)
	if err != nil {
		t.Fatalf("DispatchStream: %v", err)
	}

	// Decode the response.
	respBytes, err := io.ReadAll(writer)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(respBytes) == 0 {
		t.Fatal("dispatch loop wrote no response; control round-trip failed")
	}
	resp, err := DecodeFrame(respBytes)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	pong := resp.GetPong()
	if pong == nil {
		t.Fatalf("response is not a Pong: %T", resp.GetBody())
	}
	if !bytes.Equal(pong.GetNonce(), nonce) {
		t.Errorf("Pong.Nonce = %x, want %x", pong.GetNonce(), nonce)
	}

	// Also assert the handler saw exactly one frame
	// (the Ping) and the telemetry handler saw none.
	ctrlFrames := ctrl.received()
	if len(ctrlFrames) != 1 {
		t.Errorf("control handler received %d frames, want 1", len(ctrlFrames))
	}
	if len(telem.received()) != 0 {
		t.Errorf("telemetry handler received %d frames, want 0 (this was a control stream)", len(telem.received()))
	}
}

// TestDispatchStreamUnknownVersionDrops proves the
// D27 §3 contract: a frame with a non-current
// protocol_version is dropped, the handler is NOT
// called. The test uses a telemetry stream ID (so the
// handler is the telemetry one) and a frame with
// protocol_version=999 (anything != 1).
func TestDispatchStreamUnknownVersionDrops(t *testing.T) {
	frame := &pb.Frame{
		ProtocolVersion: 999, // anything != CurrentProtocolVersion
		Body: &pb.Frame_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				SenderNodeId: "should-be-dropped",
			},
		},
	}
	enc, err := EncodeFrame(frame)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	reader := bytes.NewReader(enc)

	telem := &captureTelemetryHandler{}
	ctrl := &echoPongControlHandler{}
	dbg := &captureDebugLogger{}

	err = DispatchStream(context.Background(), telemetryStreamID, reader, nil, telem, ctrl, dbg)
	if err != nil {
		t.Fatalf("DispatchStream: %v", err)
	}
	if got := len(telem.received()); got != 0 {
		t.Errorf("telemetry handler received %d frames; want 0 (frame should have been dropped)", got)
	}
}

// TestDispatchStreamReadErrorPropagates proves the
// read-error path: a non-EOF error from the reader
// (e.g. a broken connection) is propagated from
// DispatchStream, not silently swallowed.
//
// The test uses a reader that always returns a
// sentinel error other than io.EOF. DispatchStream
// should wrap and return the error.
func TestDispatchStreamReadErrorPropagates(t *testing.T) {
	sentinel := errors.New("synthetic read error")
	reader := &erroringReader{err: sentinel}

	telem := &captureTelemetryHandler{}
	ctrl := &echoPongControlHandler{}
	dbg := &captureDebugLogger{}

	err := DispatchStream(context.Background(), telemetryStreamID, reader, nil, telem, ctrl, dbg)
	if err == nil {
		t.Fatal("DispatchStream returned nil; want a wrapped error from the reader")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("DispatchStream error = %v, want it to wrap %v", err, sentinel)
	}
}

// erroringReader is a test helper: an io.Reader that
// returns a fixed error on every Read call.
type erroringReader struct {
	err error
}

func (r *erroringReader) Read(p []byte) (int, error) {
	return 0, r.err
}

// TestDispatchStreamCleanEOFReturns proves the clean
// end-of-stream path: a reader that returns io.EOF
// immediately (no frames) results in DispatchStream
// returning nil (no error). This is the "stream
// drained before any frames were sent" case.
func TestDispatchStreamCleanEOFReturns(t *testing.T) {
	reader := bytes.NewReader(nil) // empty buffer; Read returns io.EOF immediately

	telem := &captureTelemetryHandler{}
	ctrl := &echoPongControlHandler{}
	dbg := &captureDebugLogger{}

	err := DispatchStream(context.Background(), telemetryStreamID, reader, nil, telem, ctrl, dbg)
	if err != nil {
		t.Errorf("DispatchStream on empty reader returned %v, want nil", err)
	}
	if got := len(telem.received()); got != 0 {
		t.Errorf("telemetry handler received %d frames; want 0 (empty stream)", got)
	}
}
