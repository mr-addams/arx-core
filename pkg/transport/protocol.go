// Package transport (protocol.go): wire-format glue around the generated
// Protobuf code (DECISION D27).
//
// This file holds:
//   - the //go:generate directive that runs protoc against
//     proto/transport.proto to (re)produce proto/transport.pb.go.
//   - Go-side type aliases that the rest of the transport package uses
//     to talk about frames WITHOUT importing the proto subpackage at
//     every call site.
//
// Encode/Decode + length-prefix framing are in P2; stream-type dispatch
// is in P3. P1 is schema-only — the empty package compiles, builds, and
// has the generate directive in place so future maintainers can re-run
// `go generate ./...` after editing the .proto file.
//
// The generated file is committed to the repo (D27 §4: "buildable from
// a clean checkout without protoc installed") so a fresh clone does not
// need protoc to compile.
package transport

// //go:generate regenerates proto/transport.pb.go from
// proto/transport.proto. Run from the repo root:
//
//	go generate ./pkg/transport/...
//
// Requirements:
//   - `protoc` (the protobuf compiler) on $PATH.
//   - `protoc-gen-go` (Go output plugin) on $PATH, installable via
//     `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`.
//
// The .pb.go file is committed; the generator is only needed when the
// .proto schema changes. CI / drift checks for generated-file freshness
// are a future-flow concern (DECISIONS.md Open Question 4).
//
// `go generate` runs from the package directory, so the proto path is
// relative to ./pkg/transport/, not the repo root. The directive below
// generates into ./proto/ alongside the schema.
//
//go:generate protoc --proto_path=proto --go_out=proto --go_opt=paths=source_relative proto/transport.proto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	pb "github.com/mr-addams/arx-core/pkg/transport/proto"
)

// ========================== Wire framing (P2, DECISION D27) ==========================
//
// On-wire format for one frame:
//
//	+----------------+-------------------+
//	| 4 bytes, BE    |  N bytes,         |
//	| length prefix  |  marshalled Frame |
//	+----------------+-------------------+
//
// The length prefix counts ONLY the marshalled Frame body; the prefix itself
// is not counted. The marshal/unmarshal call is the canonical protobuf wire
// encoding (google.golang.org/protobuf/proto) — no custom tags, no field
// reordering, no payload transformations.

// MaxFrameSize is the largest marshalled Frame body the decoder will accept
// from the wire. One mebibyte is generous for v0.1.0 frames (the heaviest
// real message is a TelemetryBatch with a few hundred metrics — well under
// 64 KiB in practice) and tight enough to make a maliciously-large length
// prefix fail fast instead of triggering a multi-gigabyte allocation.
//
// Bump it via a new flow if a real use-case needs it; do NOT make it
// configurable in v0.1.0 (premature flexibility, see Karpathy #2).
const MaxFrameSize = 1 << 20 // 1 MiB

// lengthPrefixSize is the size, in bytes, of the big-endian length prefix
// that precedes every marshalled frame body. 4 bytes == 32 bits == up to
// 4 GiB per frame, which exceeds MaxFrameSize by a wide margin.
const lengthPrefixSize = 4

// EncodeFrame serialises f into a length-prefixed byte slice ready to be
// written to a QUIC stream.
//
// Wire format: [4 bytes big-endian length N] [N bytes protobuf-marshalled Frame].
//
// The length prefix is big-endian (network byte order) so two implementations
// in different languages/architectures agree on the framing — little-endian
// would be fine on amd64 but ambiguous when ported to a big-endian platform.
//
// nil f is rejected: proto.Marshal(nil) panics, and a sentinel "no frame"
// must surface as an error rather than a wire-level crash.
func EncodeFrame(f *pb.Frame) ([]byte, error) {
	if f == nil {
		return nil, errors.New("EncodeFrame: nil frame")
	}
	body, err := proto.Marshal(f)
	if err != nil {
		// proto.Marshal on a generated message almost never fails; the only
		// realistic path is a programmatic bug (e.g. an Any with an
		// unregistered type). Wrap with context so the caller doesn't have
		// to guess which side of the encoder failed.
		return nil, fmt.Errorf("EncodeFrame: marshal Frame: %w", err)
	}
	if len(body) > MaxFrameSize {
		// Defensive: a single frame over MaxFrameSize is a bug, not a wire
		// condition (the decoder would reject the same input). Surface the
		// error at encode time so the caller sees it before hitting the wire.
		return nil, fmt.Errorf("EncodeFrame: marshalled frame is %d bytes, exceeds MaxFrameSize=%d", len(body), MaxFrameSize)
	}
	out := make([]byte, lengthPrefixSize+len(body))
	binary.BigEndian.PutUint32(out[:lengthPrefixSize], uint32(len(body)))
	copy(out[lengthPrefixSize:], body)
	return out, nil
}

// DecodeFrame parses a single length-prefixed frame from b and returns the
// reconstructed *Frame.
//
// The caller passes the EXACT bytes of one frame — including the 4-byte
// length prefix. The typical caller is a stream reader that has already
// framed its input (e.g. a varint-prefixed QUIC read, or a contiguous
// in-memory buffer containing exactly one frame for testing).
//
// Errors:
//   - truncated length prefix        (b has fewer than 4 bytes)
//   - truncated payload              (b is shorter than 4 + N)
//   - frame too large                (declared N > MaxFrameSize)
//   - malformed protobuf             (proto.Unmarshal returned an error)
//
// All errors are wrapped with a leading "DecodeFrame:" prefix so callers can
// tell the framing layer from the protobuf layer in logs without inspecting
// the chain.
func DecodeFrame(b []byte) (*pb.Frame, error) {
	if len(b) < lengthPrefixSize {
		return nil, fmt.Errorf("DecodeFrame: truncated length prefix: have %d bytes, need %d", len(b), lengthPrefixSize)
	}
	// Safe: the length check above guarantees we can read 4 bytes.
	n := binary.BigEndian.Uint32(b[:lengthPrefixSize])

	// Reject oversize frames BEFORE looking at the payload, so a malicious
	// length prefix can never trigger a multi-gigabyte allocation. The
	// constant is named in the error so operators searching logs for the
	// limit can find this code path quickly.
	if n > MaxFrameSize {
		return nil, fmt.Errorf("DecodeFrame: frame too large: declared %d bytes, max %d", n, MaxFrameSize)
	}
	if uint64(lengthPrefixSize)+uint64(n) > uint64(len(b)) {
		return nil, fmt.Errorf("DecodeFrame: truncated payload: declared %d bytes, have %d", n, len(b)-lengthPrefixSize)
	}
	body := b[lengthPrefixSize : lengthPrefixSize+n]
	f := &pb.Frame{}
	if err := proto.Unmarshal(body, f); err != nil {
		return nil, fmt.Errorf("DecodeFrame: unmarshal Frame: %w", err)
	}
	return f, nil
}

// ========================== Stream-type dispatch (P3, DECISION D27 §2) ==========================
//
// QUIC stream IDs carry type information in their low two bits (RFC 9000
// §2.1 / §19.11): bit 0 marks client- vs server-initiated, bit 1 marks
// bidirectional vs unidirectional. D27 §2 distinguishes sentinel stream
// types by QUIC stream ID — telemetry on unidirectional streams, control
// on bidirectional streams — so a single bit test is the entire dispatch
// mechanism. The exact bit pattern is fixed in PROTOCOL.md (DECISIONS.md
// Open Question 5) and reproduced verbatim here; a change in PROTOCOL.md
// MUST be mirrored in the predicate below and re-tested.
//
// Stream-ID is exposed as uint64 (not quic.StreamID) so this file does not
// pull in quic-go as a dependency at the protocol layer — quic-go joins
// the build only in Group Q, where the QUIC listener/dialer converts
// quic.StreamID to uint64 at the boundary. The library-level predicates
// stay vendor-agnostic until the wire layer arrives (Karpathy #2:
// simplicity first — depend on the smallest surface that does the job).

// streamIDUniBit is the QUIC stream-ID bit that distinguishes unidirectional
// (bit set) from bidirectional (bit clear) streams. See RFC 9000 §2.1.
const streamIDUniBit uint64 = 0x02

// IsTelemetryStream reports whether id is the ID of a telemetry (unidirectional)
// stream per DECISION D27 §2 and PROTOCOL.md (Open Question 5 — stream-ID
// convention).
//
// The predicate is a single bit test on purpose: stream-type discrimination
// is a property of the QUIC stream ID itself, not a tag carried inside the
// frame. Doing it at the ID level lets QUIC's stream multiplexing do the work
// — a telemetry stream and a control stream are genuinely different QUIC
// streams, not different payloads on the same stream (D27 §2 rationale).
func IsTelemetryStream(id uint64) bool {
	return id&streamIDUniBit != 0
}

// IsControlStream reports whether id is the ID of a control (bidirectional)
// stream. It is exactly the complement of IsTelemetryStream — the two
// predicates cover the whole QUIC stream-ID space without overlap, because
// bit 1 of the stream ID is a single binary value.
func IsControlStream(id uint64) bool {
	return id&streamIDUniBit == 0
}

// ========================== Version handling (P3, DECISION D27 §3) ==========================
//
// D27 §3 fixes v0.1.0 protocol_version at 1. A frame that arrives with a
// different version is dropped silently + logged at WARN (not error).
// "Silently" here means: the frame is not delivered to the dispatch loop
// and no application-level error is surfaced. The WARN log is the operator's
// signal that a peer speaks a future version of the protocol — expected
// during a rolling upgrade, surprising in a steady-state mesh.

// CurrentProtocolVersion is the protocol_version value this node emits and
// accepts. It is exposed as a const (not a build flag, not a var) because
// the value is part of the on-wire contract: a v0.1.0 node will reject a
// peer that advertises the same const as a different number. Bumping it
// is a wire-format change and MUST be reviewed against DECISION D29 (closed
// v0.1.0 surface, evolution is forward-only).
const CurrentProtocolVersion uint32 = 1

// Logger is the minimal logging surface the protocol layer needs to
// surface a version-mismatch WARN. It is an interface (not *log.Logger or
// *slog.Logger directly) for one reason: test injection. P3's tests verify
// that a version-mismatched frame produces a WARN log entry with the
// version mentioned in the message; stdlib loggers write to io.Writer and
// have no inspection API. By declaring the surface this layer needs (one
// method, one variadic-args format) we can pass in a capture-Logger in
// tests and the real logger in production without coupling the protocol
// layer to any specific logging library. The transport package's real
// logger adapter (in Group Q) implements this same one-method interface
// and is wired in by the caller — protocol.go stays logger-agnostic.
type Logger interface {
	// Warnf logs a non-fatal anomaly. The format string follows the
	// conventions of package log / slog: %-verbs interpolate args, the
	// trailing newline is appended by the implementation. Protocol
	// code never logs an Error or Fatal through this surface — version
	// mismatches are NOT errors (D27 §3) and a library must not pretend
	// otherwise.
	Warnf(format string, args ...any)
}

// nopLogger is the zero-value Logger for callers that genuinely have no
// logger to inject. It silently discards every Warnf call. Exposed via
// DiscardLogger() so callers in Group Q / R can opt into "no logging"
// without writing their own no-op implementation.
type nopLogger struct{}

func (nopLogger) Warnf(string, ...any) {}

// DiscardLogger returns a Logger that drops every Warnf call. Useful for
// tests that exercise paths OTHER than the version-mismatch branch and
// have no interest in capturing log output.
func DiscardLogger() Logger { return nopLogger{} }

// DropIfUnknownVersion reports whether f should be dropped because its
// protocol_version is not the version this node understands (D27 §3).
//
// The function returns true (caller MUST drop) for two cases:
//
//  1. f.ProtocolVersion != CurrentProtocolVersion — the documented
//     version-mismatch path. The function emits exactly one WARN log
//     line that includes the offending version so operators can tell
//     "future peer on a rolling upgrade" (version 2, expected) from
//     "garbled stream or a downgrade attack" (version 0, or a wild
//     number) by reading the log. Not an error: protocol evolution is
//     expected and graceful drop is the contract (D27 §3).
//  2. f is nil. A nil frame carries no version to inspect, so the
//     "version is wrong" test cannot be evaluated; treating it as
//     "drop" is the safe default (the alternative is a nil-deref panic,
//     which is unacceptable in a library surface that lives next to a
//     QUIC read loop). The log line for nil is distinguishable from
//     the version-mismatch line so an operator chasing the warning can
//     tell the two cases apart.
//
// The function returns false (caller may proceed with dispatch) when
// f.ProtocolVersion == CurrentProtocolVersion and f is non-nil. No log
// is emitted on the happy path — successful dispatches are not an event
// worth logging at WARN.
//
// DropIfUnknownVersion is a pure function: it does not mutate f, it
// does not own a logger, it does not allocate beyond the single Warnf
// call. Safe to call from a hot stream-read loop.
func DropIfUnknownVersion(f *pb.Frame, log Logger) (dropped bool) {
	if f == nil {
		// Distinguishable log line so an operator chasing a Warnf
		// entry can tell a nil frame from a mismatched version. The
		// "nil frame" path is almost always a caller bug (forgot to
		// check DecodeFrame's error return) — the log makes the bug
		// visible without crashing the stream-read loop.
		if log != nil {
			log.Warnf("dropping nil frame: caller bug or torn stream read")
		}
		return true
	}
	if f.ProtocolVersion == CurrentProtocolVersion {
		return false
	}
	// Version mismatch: log the offending version explicitly. Operators
	// triaging a steady-state mesh will want to know "is this a known
	// future version (rolling upgrade) or an unknown value (malformed
	// stream)?" — the %d makes that distinction visible in the log.
	if log != nil {
		log.Warnf("dropping frame: unsupported protocol_version=%d, expected %d", f.ProtocolVersion, CurrentProtocolVersion)
	}
	return true
}
