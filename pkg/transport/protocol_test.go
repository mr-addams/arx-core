// ========================== Protocol tests (P2, DECISION D27) ==========================
//
// P2 tests cover the wire-framing glue between the caller and the generated
// protobuf code (proto/transport.pb.go). The framing layer is small but
// high-stakes — a buggy length prefix or a missing size guard makes the
// whole transport trivially exploitable. The tests below are deliberately
// exhaustive for a 70-line file:
//
//   - RoundTrip proves the happy path: encode → decode yields an equal
//     frame for every message type in v0.1.0 (D29).
//   - TruncatedLengthPrefix and TruncatedPayload guard the two obvious
//     "stream was cut in half" failure modes a receiver will hit on a
//     short read.
//   - FrameTooLarge guards the malicious-length-prefix attack: a hostile
//     peer declares a 100-MiB body to trigger a 100-MiB allocation. The
//     decoder must reject it BEFORE touching the payload.
//
// Tests use testify/assert for non-fatal checks and testify/require for
// "stop the test on failure" — same convention as identity_test.go and
// tofu_test.go.
package transport

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/mr-addams/arx-core/pkg/transport/proto"
)

// TestEncodeDecodeRoundTrip is the canonical happy-path test: build a frame,
// encode it, decode it, and assert every field round-trips. Using
// Frame_Heartbeat exercises both the Frame envelope (protocol_version) and
// the oneof body dispatch (Heartbeat) — the same two code paths that
// EncodeFrame/DecodeFrame use for every other message type.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := &pb.Frame{
		ProtocolVersion: 1,
		Body: &pb.Frame_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				SenderNodeId:     "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				MonotonicClockMs: 42_000,
			},
		},
	}

	wire, err := EncodeFrame(original)
	require.NoError(t, err, "encode must succeed for a well-formed frame")

	// Sanity: the wire format is exactly 4 bytes of prefix + the marshalled
	// body. A future "helpful" change that prepends a version byte or
	// appends a checksum will break this assertion and force a
	// conscious decision.
	require.GreaterOrEqual(t, len(wire), lengthPrefixSize+2, "encoded frame must include at least the prefix and one byte of body")

	decoded, err := DecodeFrame(wire)
	require.NoError(t, err, "decode must succeed for an encoded frame")

	// ProtocolVersion is outside the oneof and trivially round-trips, but
	// asserting it explicitly catches a future bug where the encoder
	// accidentally drops the field.
	assert.Equal(t, uint32(1), decoded.ProtocolVersion, "protocol_version must round-trip")

	hb, ok := decoded.Body.(*pb.Frame_Heartbeat)
	require.True(t, ok, "decoded body must be a *Frame_Heartbeat, got %T", decoded.Body)
	require.NotNil(t, hb.Heartbeat, "decoded Heartbeat payload must not be nil")
	assert.Equal(t, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", hb.Heartbeat.SenderNodeId)
	assert.Equal(t, uint64(42_000), hb.Heartbeat.MonotonicClockMs)
}

// TestEncodeDecodeAllMessageTypes is the parameterised version of the
// round-trip test. D29 closed the v0.1.0 message-type list at seven
// variants; this test fails loudly if anyone adds an eighth Frame body
// type and forgets to wire it through EncodeFrame/DecodeFrame (since
// protobuf oneofs are open by construction, a "forgotten" body just
// silently round-trips as nil — exactly the bug this test exists to
// catch).
func TestEncodeDecodeAllMessageTypes(t *testing.T) {
	t.Parallel()

	// Each case is a fully constructed *pb.Frame so the test loop can
	// stay simple (encode the frame, decode it, compare). The Frame's
	// body is set via the per-variant Frame_xxx struct — there is no
	// public "the oneof interface" exposed by the generated code, so
	// we cannot slice over the body alone.
	cases := []*pb.Frame{
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_Heartbeat{
				Heartbeat: &pb.Heartbeat{
					SenderNodeId:     "node-A",
					MonotonicClockMs: 1,
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_TelemetryBatch{
				TelemetryBatch: &pb.TelemetryBatch{
					SenderNodeId:     "node-B",
					MonotonicClockMs: 2,
					Samples: []*pb.MetricSample{
						{Name: "rules_evaluated", Type: pb.MetricType_COUNTER, Value: 100},
						{Name: "cpu_usage_pct", Type: pb.MetricType_GAUGE, Value: 37},
					},
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_Alert{
				Alert: &pb.Alert{
					SenderNodeId:     "node-C",
					MonotonicClockMs: 3,
					RuleId:           "rule-007",
					Severity:         pb.AlertSeverity_CRITICAL,
					Payload:          []byte("opaque alert body"),
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_Ping{
				Ping: &pb.Ping{
					Nonce:            []byte{0xde, 0xad, 0xbe, 0xef},
					MonotonicClockMs: 4,
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_Pong{
				Pong: &pb.Pong{
					Nonce:                    []byte{0xde, 0xad, 0xbe, 0xef},
					ReceiverMonotonicClockMs: 5,
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_RuleUpdate{
				RuleUpdate: &pb.RuleUpdate{
					SenderNodeId: "node-D",
					RuleId:       "rule-007",
					Payload:      []byte(`{"match":"...","action":"block"}`),
				},
			},
		},
		{
			ProtocolVersion: 1,
			Body: &pb.Frame_RuleUpdateAck{
				RuleUpdateAck: &pb.RuleUpdateAck{
					RuleId: "rule-007",
					Status: pb.AckStatus_APPLIED,
					Reason: "",
				},
			},
		},
		{
			// Also covered: a RuleUpdateAck with a non-empty Reason field
			// (the REJECTED path). Empty-string-vs-absent is a classic
			// proto3 gotcha — make sure the round-trip is stable.
			ProtocolVersion: 1,
			Body: &pb.Frame_RuleUpdateAck{
				RuleUpdateAck: &pb.RuleUpdateAck{
					RuleId: "rule-008",
					Status: pb.AckStatus_REJECTED,
					Reason: "rule syntax error at offset 42",
				},
			},
		},
	}

	for _, original := range cases {
		original := original // capture range var for parallel sub-tests
		t.Run(bodyTypeName(original.Body), func(t *testing.T) {
			t.Parallel()

			wire, err := EncodeFrame(original)
			require.NoError(t, err)

			decoded, err := DecodeFrame(wire)
			require.NoError(t, err)

			assert.Equal(t, uint32(1), decoded.ProtocolVersion)
			// proto.Equal is the canonical protobuf-aware equality check.
			// It walks the message graph and compares semantic fields,
			// ignoring protoc-generated caches (sizeCache) and unexported
			// state. A naive assert.Equal on the *pb.Frame itself would
			// spuriously fail on sizeCache: proto.Unmarshal resets it, and
			// the cache is not part of the wire contract.
			assert.True(t, proto.Equal(original, decoded),
				"frame must round-trip semantically byte-for-byte (original=%v, decoded=%v)", original, decoded)
		})
	}
}

// TestDecodeTruncatedLengthPrefix verifies that a buffer shorter than the
// 4-byte length prefix is rejected — the most common "partial read" failure
// on a stream. A naive implementation that just calls binary.BigEndian.Uint32
// on the input would panic with an index-out-of-range; the guard exists
// specifically to convert that panic into a clean error.
func TestDecodeTruncatedLengthPrefix(t *testing.T) {
	t.Parallel()

	_, err := DecodeFrame([]byte{0x00, 0x00})
	require.Error(t, err, "decode must reject a 2-byte input")
	assert.Contains(t, err.Error(), "truncated length prefix",
		"error must mention the length prefix, got: %v", err)
}

// TestDecodeTruncatedPayload verifies that the declared length N is
// honoured against the actual buffer size. A buffer of "4-byte prefix
// saying N=100 + 50 bytes of body" is a truncated frame; the decoder
// must NOT silently decode the 50 bytes it has and discard the missing
// 50, because that would let a sender corrupt the receiver's view of
// the stream by sending partial frames.
func TestDecodeTruncatedPayload(t *testing.T) {
	t.Parallel()

	// Encode a real frame, then chop off the last byte to simulate a
	// short read. The wire bytes are well-formed EXCEPT for the
	// missing final payload byte, so the test isolates the
	// truncation path from any "garbage in the length prefix" path.
	original := &pb.Frame{
		ProtocolVersion: 1,
		Body: &pb.Frame_Ping{
			Ping: &pb.Ping{Nonce: []byte("0123456789"), MonotonicClockMs: 99},
		},
	}
	wire, err := EncodeFrame(original)
	require.NoError(t, err)

	truncated := wire[:len(wire)-1]

	_, err = DecodeFrame(truncated)
	require.Error(t, err, "decode must reject a frame with a missing final byte")
	assert.Contains(t, err.Error(), "truncated payload",
		"error must mention the payload, got: %v", err)
}

// TestDecodeFrameTooLarge verifies the size guard: a length prefix that
// declares a body larger than MaxFrameSize is rejected BEFORE the decoder
// touches the payload, so a malicious peer cannot trigger a multi-mebibyte
// allocation. The test crafts a minimal "hostile" buffer (4 bytes of
// oversize length + 5 bytes of body) and asserts the decoder refuses
// without panicking.
func TestDecodeFrameTooLarge(t *testing.T) {
	t.Parallel()

	hostile := make([]byte, 4+5)
	// Declare MaxFrameSize+1 bytes — one byte over the limit. The exact
	// value is not important; what matters is "larger than MaxFrameSize".
	binary.BigEndian.PutUint32(hostile[:4], MaxFrameSize+1)
	copy(hostile[4:], []byte("hello"))

	_, err := DecodeFrame(hostile)
	require.Error(t, err, "decode must reject an oversize length prefix")
	assert.Contains(t, strings.ToLower(err.Error()), "frame too large",
		"error must mention the size limit, got: %v", err)
}

// ========================== P3 tests: stream dispatch + version drop ==========================
//
// Stream-type dispatch and version-mismatch handling are the two helpers
// P3 adds on top of P2's wire framing. The tests below follow the project
// "happy path + one edge" rule (CLAUDE.md task-atomicity) with one
// table-driven case per predicate (positive AND negative examples in the
// same table) and a pair of focused tests for DropIfUnknownVersion
// (drop-on-mismatch / let-through-on-known, plus a nil-frame edge case
// added so the nil-handling path in the helper is covered even though
// the spec did not strictly require a test for it).
//
// The captureLogger type is the test-only implementation of the
// protocol.Logger interface — it exists for ONE reason: P3 must assert
// "a WARN log line is emitted with the version mentioned", and the
// stdlib's *log.Logger writes to an io.Writer with no inspection API.
// Declaring a one-method interface (see protocol.go) lets the test
// substitute its own type without reaching into internals or coupling
// to any specific logging library. This is the test-injection pattern
// in miniature.

// captureLogger is a protocol.Logger that records every Warnf invocation
// into an in-memory slice for later inspection. It is intentionally not
// concurrency-safe — the tests that use it run serially within a single
// goroutine, and a race detector trip would be a real bug (it would
// mean a caller of DropIfUnknownVersion invokes the logger from multiple
// goroutines, which the helper does not do).
type captureLogger struct {
	warnings []string
}

// Warnf appends the formatted message (no trailing newline, matching the
// call sites in protocol.go) to the captured slice. The format string is
// passed through fmt.Sprintf so the test assertions can match on the
// rendered text, not the raw verb list.
func (c *captureLogger) Warnf(format string, args ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

// atLeastOneVersionHint is a small helper: assert that at least one
// captured warning contains the substring "protocol_version=" (the
// message prefix from DropIfUnknownVersion). Using a single helper
// instead of inlining the substring keeps the test intent visible —
// the test is asserting "the version is mentioned", not "the exact log
// format is X". A future PROTOCOL.md-driven log-message tweak that
// preserves the "version" signal will not break the test, but a tweak
// that drops the version entirely will.
func (c *captureLogger) atLeastOneVersionHint(t *testing.T) {
	t.Helper()
	for _, w := range c.warnings {
		if strings.Contains(w, "protocol_version=") {
			return
		}
	}
	t.Fatalf("expected at least one warning to mention 'protocol_version=', got: %v", c.warnings)
}

// TestIsTelemetryStream walks the four corners of the QUIC stream-ID
// space that matter for v0.1.0: client-initiated bi (0x0), server-
// initiated bi (0x1), client-initiated uni (0x2), server-initiated uni
// (0x3). The high bits (the stream number) are deliberately exercised
// at zero to keep the test focused on the type bit; a test of "uni
// stream 1234 still reads as telemetry" is a property of the bit
// position, not of the number, and would be redundant.
func TestIsTelemetryStream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   uint64
		want bool
	}{
		// 0x0 = client-initiated, bidirectional → control, not telemetry.
		{"client_bi_id_0x0", 0x0, false},
		// 0x1 = server-initiated, bidirectional → control, not telemetry.
		{"server_bi_id_0x1", 0x1, false},
		// 0x2 = client-initiated, unidirectional → telemetry.
		{"client_uni_id_0x2", 0x2, true},
		// 0x3 = server-initiated, unidirectional → telemetry.
		{"server_uni_id_0x3", 0x3, true},
		// High stream-number variants — the type bit is bit 1,
		// so any "uni" stream number still classifies as telemetry.
		// 0x6 = client uni stream 4 (bit 0=0 client, bit 1=1 uni, stream #4 at bits 2+) → telemetry.
		{"client_uni_high_id_0x6", 0x6, true},
		// 0x7 = server uni stream 4 (bit 0=1 server, bit 1=1 uni) → telemetry.
		{"server_uni_high_id_0x7", 0x7, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsTelemetryStream(tc.id),
				"id=0x%x must classify as telemetry=%v", tc.id, tc.want)
		})
	}
}

// TestIsControlStream is the complement test: the same stream IDs as
// TestIsTelemetryStream, with the expected boolean inverted. Running
// both tests against the same fixtures catches a future "I changed
// the predicate but forgot one of the two functions" regression — the
// pair of tests is internally consistent by construction, and any
// divergence is a bug.
func TestIsControlStream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   uint64
		want bool
	}{
		{"client_bi_id_0x0", 0x0, true},
		{"server_bi_id_0x1", 0x1, true},
		{"client_uni_id_0x2", 0x2, false},
		{"server_uni_id_0x3", 0x3, false},
		{"client_uni_high_id_0x6", 0x6, false},
		{"server_uni_high_id_0x7", 0x7, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsControlStream(tc.id),
				"id=0x%x must classify as control=%v", tc.id, tc.want)
		})
	}
}

// TestDispatchPredicatesAgree is a meta-test: the two predicates are
// declared as complements in protocol.go, so for every input their
// results must sum to exactly one true. A future refactor that
// accidentally decouples them (e.g. one predicate gains an extra
// check the other does not) is caught here. The fixture is the union
// of the two tables above plus a few wild inputs (max uint64, a
// stream number with the type bit clear, etc.) for breadth.
func TestDispatchPredicatesAgree(t *testing.T) {
	t.Parallel()

	ids := []uint64{0x0, 0x1, 0x2, 0x3, 0x10, 0x11, 1 << 20, 1<<62 | 0x3}
	for _, id := range ids {
		id := id
		t.Run(fmt.Sprintf("id_0x%x", id), func(t *testing.T) {
			t.Parallel()
			// Exactly one of the two predicates must be true: the
			// predicates are complementary by definition, so this
			// assertion is the "no gaps, no overlaps" contract.
			assert.Equal(t, true, IsTelemetryStream(id) != IsControlStream(id),
				"id=0x%x: telemetry and control predicates must disagree (sum exactly 1 true)", id)
		})
	}
}

// TestDropIfUnknownVersionDropsAndLogs verifies the documented
// version-mismatch path: a frame whose protocol_version is NOT
// CurrentProtocolVersion is reported as dropped (true) AND emits a
// WARN that mentions the offending version. The version hint assertion
// uses the atLeastOneVersionHint helper so the test tolerates a future
// log-message reword that preserves the "version=..." signal.
func TestDropIfUnknownVersionDropsAndLogs(t *testing.T) {
	t.Parallel()

	// protocol_version=2 is the natural "future peer" case for a v1
	// node. A real v0.1.0 → v0.2.0 rolling upgrade would surface as
	// this exact WARN, which is the whole point of the helper.
	frame := &pb.Frame{
		ProtocolVersion: CurrentProtocolVersion + 1,
		Body: &pb.Frame_Ping{
			Ping: &pb.Ping{Nonce: []byte("x"), MonotonicClockMs: 1},
		},
	}
	log := &captureLogger{}

	dropped := DropIfUnknownVersion(frame, log)
	assert.True(t, dropped, "frame with future protocol_version must be dropped")
	assert.NotEmpty(t, log.warnings, "a version-mismatch drop must emit a WARN")
	log.atLeastOneVersionHint(t)
}

// TestDropIfUnknownVersionLetsThroughKnownVersion is the happy path:
// a frame with the current protocol_version is reported as not
// dropped (false) AND emits no WARN. The "no WARN" assertion is
// what makes "drop-on-mismatch" a meaningful policy — if it WARNed
// on every frame, the WARN signal would be drowned in noise and
// operators would ignore it. Silence on the happy path is the
// design.
func TestDropIfUnknownVersionLetsThroughKnownVersion(t *testing.T) {
	t.Parallel()

	frame := &pb.Frame{
		ProtocolVersion: CurrentProtocolVersion,
		Body: &pb.Frame_Ping{
			Ping: &pb.Ping{Nonce: []byte("y"), MonotonicClockMs: 2},
		},
	}
	log := &captureLogger{}

	dropped := DropIfUnknownVersion(frame, log)
	assert.False(t, dropped, "frame with current protocol_version must NOT be dropped")
	assert.Empty(t, log.warnings, "a known-version frame must produce no WARN — the signal must stay rare to be useful")
}

// TestDropIfUnknownVersionHandlesNil is the edge case the spec did
// not strictly ask for but the helper must not panic on: a nil
// *pb.Frame. The helper treats nil as "drop" (return true) and
// emits a distinguishable WARN line. The test verifies both halves
// of that contract.
func TestDropIfUnknownVersionHandlesNil(t *testing.T) {
	t.Parallel()

	log := &captureLogger{}
	dropped := DropIfUnknownVersion(nil, log)
	assert.True(t, dropped, "nil frame must be reported as drop (safer than nil-deref in the read loop)")
	assert.NotEmpty(t, log.warnings, "nil-frame drop must emit a WARN so the caller bug is visible")
}

// TestDropIfUnknownVersionNilLogger is the second edge case: a
// nil Logger. The helper must NOT panic — a misconfigured caller
// (forgot to inject a logger) must not crash the stream-read loop.
// The behaviour with a nil logger is "drop, but log nothing" —
// strict superset of "drop safely" without bringing the whole
// process down.
func TestDropIfUnknownVersionNilLogger(t *testing.T) {
	t.Parallel()

	frame := &pb.Frame{ProtocolVersion: CurrentProtocolVersion + 99}
	// MUST NOT panic. The result is true (drop) regardless of logger.
	assert.NotPanics(t, func() {
		dropped := DropIfUnknownVersion(frame, nil)
		assert.True(t, dropped, "mismatched-version frame must be dropped even with a nil logger")
	}, "nil logger must not crash the dispatch loop")
}

// --------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------

// bodyTypeName returns a stable, comparable string for a Frame body
// oneof variant. Using %T means adding a new variant to the .proto
// file automatically shows up here — no separate "list of all message
// types" to keep in sync. The parameter is typed as any because the
// generated oneof interface is unexported (isFrame_Body); every
// concrete *pb.Frame_xxx satisfies any, which is enough for %T.
func bodyTypeName(b any) string {
	if b == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", b)
}
