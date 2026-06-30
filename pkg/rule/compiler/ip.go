// ========================== pkg/rule/compiler — IP functions ===================================
//   IP family for the v0.3.0 function registry (DECISION D16, DECISION D17, Group E —
//   Task E1).
//
//   This file registers the IP functions:
//
//     ip_to_int(ip)        -> int   (alloc-free; reads existing bytes + constructs an
//                                   int64 Value, which is struct-typed)
//     cidr_matches(ip, cidr) -> bool (alloc-free on the compile-time path; the
//                                     *net.IPNet is resolved at compile time when
//                                     cidr is a literal string, so eval calls
//                                     Contains directly with zero ParseCIDR)
//
//   IPv4 INT CONVERSION:
//     ip_to_int treats the IP as a network-byte-order 32-bit value and returns it as
//     an int64. For a 4-byte IPv4 address this is the conventional integer form
//     (e.g. 127.0.0.1 -> 0x7F000001 == 2130706433).
//
//   IPv6 INT CONVERSION:
//     ip_to_int returns ONLY the low 64 bits of the address as an int64, bit-
//     interpreted. This is deliberate: IPv6 addresses do not fit in 64 bits, so the
//     engine exposes the host identifier portion (the lower half) as the scalar
//     representation. Callers who need the full address must keep it as KindIP.
//     See the flow DECISIONS.md addendum for the rationale.
//
//   CIDR MATCHING:
//     cidr_matches(ip, cidr) answers `network.Contains(ip)`. When `cidr` is a string
//     literal the network is parsed ONCE at compile time and stored on the op
//     (DECISION D17); the evaluator then calls Contains directly with zero ParseCIDR
//     per call. A non-literal cidr argument still works — the evaluator parses it per
//     call. A malformed CIDR (literal or runtime) does NOT error; the engine surfaces
//     false (the same defensive contract as the rest of the evaluator).
//
//   WHAT IS NOT HERE:
//     - Timestamp / coercion / string functions — they live in their own files.
//     - The function registry itself — functions.go.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): encoding/binary, net. Plus sibling pkg/rule (Value / Kind).
//
//   ALLOCATION CONTRACT (D16 §4):
//     ip_to_int is marked Allocating=false — reads bytes and returns a value-typed
//     int64 Value.
//     cidr_matches is marked Allocating=false because the DOMINANT hot path (the
//     compile-time literal-CIDR fast path) is alloc-free: the *net.IPNet is
//     resolved once at compile time and Contains is called directly per eval. The
//     registry-side Eval entry point (evalCIDRMatches) is a defensive parity hook
//     for hand-built ops that bypass the compiler; it parses the CIDR per call
//     because it has no access to the compile-time *net.IPNet. Production callers
//     always go through compileCIDRMatcher → evalCIDRMatcherValue, so the flag
//     describes the contract that actually runs at scale.
//     The per-call overhead for cidr_matches on the compile-time path is the
//     AsIP defensive copy from the input Value (inherent to accessing a stored
//     net.IP and not engine-side bookkeeping).

package compiler

import (
	"encoding/binary"
	"net"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the E1 IP functions into the package-level registry. Called at
// package init time — the registry is fully populated before any Compile call.
func init() {
	registerFunc(FuncSpec{
		Name:       "ip_to_int",
		ParamKinds: []rule.Kind{rule.KindIP},
		ReturnKind: rule.KindInt,
		Allocating: false,
		Eval:       evalIPToInt,
	})
	registerFunc(FuncSpec{
		Name:       "cidr_matches",
		ParamKinds: []rule.Kind{rule.KindIP, rule.KindString},
		ReturnKind: rule.KindBool,
		Allocating: false,
		Eval:       evalCIDRMatches,
	})
}

// ========================== ip_to_int =======================================================

// evalIPToInt converts a KindIP Value into an int64.
//
// The conversion is Kind-aware and deliberate:
//   - An IPv4 address is converted from its 4-byte network-byte-order form into a
//     32-bit unsigned value, then returned as a positive int64. net.IP values that
//     are stored as 16-byte IPv4-mapped addresses are normalised with To4() first.
//   - An IPv6 address returns only the LOW 64 bits (bytes 8..15) as an int64, bit-
//     interpreted. This means an address whose low 64 bits have the high bit set will
//     appear as a negative int64, which is the natural result of reinterpreting a
//     uint64 as int64. This contract is identical to the IP branch of evalToInt in
//     coerce.go.
//   - A nil or empty IP returns 0. The KindIP Value with an empty slice is distinct
//     from KindInvalid; it is treated as “no address” and maps to the integer zero.
//
// The function does not allocate beyond the int64 Value struct that the caller
// receives; the input IP is accessed through AsIP, which already performs its own
// defensive copy.
func evalIPToInt(args []rule.Value) rule.Value {
	ip, _ := args[0].AsIP()
	return rule.NewInt(ipToInt64(ip))
}

// ipToInt64 converts a net.IP to the rule-engine's scalar int64 representation.
// See evalIPToInt for the exact contract (IPv4 full 32 bits, IPv6 low 64 bits,
// nil/empty -> 0). This helper is shared with evalToInt so coercion matches the
// dedicated ip_to_int function exactly.
func ipToInt64(ip net.IP) int64 {
	if len(ip) == 0 {
		return 0
	}
	if v4 := ip.To4(); v4 != nil {
		return int64(binary.BigEndian.Uint32(v4))
	}
	if len(ip) == 16 {
		return int64(binary.BigEndian.Uint64(ip[8:16]))
	}
	return 0
}

// ipLowUint64 returns the low 64 bits of an IP address as a uint64. For IPv4 this
// is the full 32-bit address zero-extended to 64 bits. It is used by evalToFloat so
// the float coercion interprets the low bits as unsigned (per the Group E3
// contract), which differs from the signed int64 interpretation used by ip_to_int
// and to_int.
func ipLowUint64(ip net.IP) uint64 {
	if len(ip) == 0 {
		return 0
	}
	if v4 := ip.To4(); v4 != nil {
		return uint64(binary.BigEndian.Uint32(v4))
	}
	if len(ip) == 16 {
		return binary.BigEndian.Uint64(ip[8:16])
	}
	return 0
}

// ========================== cidr_matches ======================================================

// evalCIDRMatches is the registry-side Eval entry point for cidr_matches. The
// compiler's literal fast-path bypasses it (opCIDRMatcher in compiler.go stores a
// pre-parsed *net.IPNet), but this entry point is still reachable for hand-built
// ops and for any caller that bypasses the compiler special-case. It implements
// the same contract as the compile-time fast path: parse the CIDR per call and
// answer Contains, returning false when the IP or CIDR is malformed/unresolved.
func evalCIDRMatches(args []rule.Value) rule.Value {
	ip, _ := args[0].AsIP()
	cidrText, _ := args[1].AsString()
	return rule.NewBool(cidrContainsIP(ip, cidrText, nil))
}

// cidrContainsIP is the shared implementation for CIDR membership tests. When
// cidrNet is non-nil (the compile-time literal fast path) it is used directly;
// otherwise cidrText is parsed per call. The function intentionally never errors:
// malformed CIDRs or missing IPs are surfaced as false, matching the evaluator's
// no-panic defensive contract.
func cidrContainsIP(ip net.IP, cidrText string, cidrNet *net.IPNet) bool {
	if len(ip) == 0 {
		return false
	}
	if cidrNet != nil {
		return cidrNet.Contains(ip)
	}
	_, ipnet, err := net.ParseCIDR(cidrText)
	if err != nil {
		return false
	}
	return ipnet.Contains(ip)
}
