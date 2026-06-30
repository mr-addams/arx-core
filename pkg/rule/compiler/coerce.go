// ========================== pkg/rule/compiler — coercion functions ===========================
//   Coercion family for the v0.3.0 function registry (DECISION D16, Group E — Task E3).
//
//   This file registers the scalar coercion functions:
//
//     to_int(v:any)     -> int    (alloc-free)
//     to_float(v:any)   -> float  (alloc-free)
//
//   ParamKinds declares KindInvalid for the argument, which is the engine's convention
//   for "any Kind". The compiler therefore accepts any argument Kind; the per-Kind
//   semantics are implemented at eval time by switching on the runtime Value kind.
//
//   to_int SEMANTICS:
//     - KindInt     : identity.
//     - KindFloat   : truncate toward zero for finite values via Go's int64(f). For
//                     NaN / -Inf the result is math.MinInt64; for +Inf it is
//                     math.MaxInt64 (normalised, because Go's raw int64(f) for
//                     non-finite values is implementation-dependent across
//                     architectures).
//     - KindString  : strconv.ParseInt(s, 10, 64); parse failure returns 0.
//     - KindBool    : true -> 1, false -> 0.
//     - KindIP      : low 64 bits as int64, exactly like ip_to_int.
//     - KindTimestamp : t.Unix() seconds, exactly like unix_time.
//     - KindDuration  : int64(d) nanoseconds.
//     - KindBytes / KindArray / KindMap / KindInvalid : 0 (unsupported).
//
//   to_float SEMANTICS:
//     - KindInt     : float64(i).
//     - KindFloat   : identity.
//     - KindString  : strconv.ParseFloat(s, 64); parse failure returns 0.
//     - KindBool    : true -> 1.0, false -> 0.0.
//     - KindIP      : float64 of the low 64 bits as a uint64.
//     - KindDuration / KindTimestamp / KindBytes / KindArray / KindMap / KindInvalid : 0.
//
//   The exact rationale and fallback policy for these rules is recorded in the flow
//   DECISIONS.md addendum "D19 — Group E coercion semantics".
//
//   WHAT IS NOT HERE:
//     - IP / timestamp / string functions — they live in adjacent files.
//     - The function registry itself — functions.go.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): math, strconv. Plus sibling pkg/rule (Value / Kind) and
//     sibling ip.go (ipToInt64 / ipLowUint64 helpers).
//
//   ALLOCATION CONTRACT (D16 §4):
//     Both functions are marked Allocating=false. The result is a value-typed
//     Value; no new string, slice, or map is allocated on the hot path. The input
//     accessors (AsInt, AsFloat, etc.) are header reads or defensive copies that
//     already belong to the Value type.

package compiler

import (
	"math"
	"strconv"
	"time"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the E3 coercion functions into the package-level registry.
// Called at package init time — the registry is fully populated before any
// Compile call.
func init() {
	registerFunc(FuncSpec{
		Name:       "to_int",
		ParamKinds: []rule.Kind{rule.KindInvalid}, // KindInvalid = "any" Kind
		ReturnKind: rule.KindInt,
		Allocating: false,
		Eval:       evalToInt,
	})
	registerFunc(FuncSpec{
		Name:       "to_float",
		ParamKinds: []rule.Kind{rule.KindInvalid}, // KindInvalid = "any" Kind
		ReturnKind: rule.KindFloat,
		Allocating: false,
		Eval:       evalToFloat,
	})
}

// ========================== to_int ===========================================================

// evalToInt coerces a Value of any Kind to a KindInt Value.
//
// The contract is per-Kind and defensive:
//   - Int is returned unchanged.
//   - Float is truncated toward zero for finite values via Go's int64(f). NaN and
//     -Inf map to math.MinInt64; +Inf maps to math.MaxInt64 (normalised because
//     Go's raw int64(f) for non-finite values is implementation-dependent).
//   - String is parsed as base-10 int64; parse failure returns 0.
//   - Bool returns 1 for true and 0 for false.
//   - IP returns the low 64 bits as int64 (same contract as ip_to_int).
//   - Timestamp returns Unix seconds (same contract as unix_time).
//   - Duration returns int64 nanoseconds.
//   - Bytes, Array, Map, and KindInvalid return 0 because the engine does not
//     define a scalar numeric interpretation for these Kinds.
//
// The function never errors; an unsupported Kind is surfaced as zero, matching
// the rest of the engine's "no panic" Eval contract.
func evalToInt(args []rule.Value) rule.Value {
	v := args[0]
	switch v.Kind() {
	case rule.KindInt:
		n, _ := v.AsInt()
		return rule.NewInt(n)
	case rule.KindFloat:
		f, _ := v.AsFloat()
		return rule.NewInt(floatToInt64(f))
	case rule.KindString:
		s, _ := v.AsString()
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return rule.NewInt(n)
		}
		return rule.NewInt(0)
	case rule.KindBool:
		b, _ := v.AsBool()
		if b {
			return rule.NewInt(1)
		}
		return rule.NewInt(0)
	case rule.KindIP:
		ip, _ := v.AsIP()
		return rule.NewInt(ipToInt64(ip))
	case rule.KindTimestamp:
		ts, _ := v.AsTimestamp()
		return rule.NewInt(ts.Unix())
	case rule.KindDuration:
		d, _ := v.AsDuration()
		return rule.NewInt(int64(d))
	default:
		return rule.NewInt(0)
	}
}

// floatToInt64 converts a float64 to int64 with the Group E3 contract:
//   - NaN      -> math.MinInt64
//   - +Inf     -> math.MaxInt64
//   - -Inf     -> math.MinInt64
//   - finite values -> truncate toward zero (Go's int64(f))
//
// Go's raw int64(f) conversion of non-finite values is implementation-
// dependent, so we normalise it here to the documented contract.
func floatToInt64(f float64) int64 {
	if math.IsNaN(f) {
		return math.MinInt64
	}
	if math.IsInf(f, 1) {
		return math.MaxInt64
	}
	if math.IsInf(f, -1) {
		return math.MinInt64
	}
	return int64(f)
}

// ========================== to_float =========================================================

// evalToFloat coerces a Value of any Kind to a KindFloat Value.
//
// The contract is per-Kind and defensive:
//   - Float is returned unchanged.
//   - Int is converted via float64(i).
//   - String is parsed via strconv.ParseFloat(s, 64); parse failure returns 0.
//   - Bool returns 1.0 for true and 0.0 for false.
//   - IP returns float64 of the low 64 bits as a uint64 (so the value is
//     non-negative even when the signed int64 interpretation would be negative).
//   - Timestamp, Duration, Bytes, Array, Map, and KindInvalid return 0.0.
//
// The function never errors; unsupported Kinds and parse failures are surfaced
// as zero, matching the engine's no-panic Eval contract.
func evalToFloat(args []rule.Value) rule.Value {
	v := args[0]
	switch v.Kind() {
	case rule.KindFloat:
		f, _ := v.AsFloat()
		return rule.NewFloat(f)
	case rule.KindInt:
		n, _ := v.AsInt()
		return rule.NewFloat(float64(n))
	case rule.KindString:
		s, _ := v.AsString()
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return rule.NewFloat(f)
		}
		return rule.NewFloat(0)
	case rule.KindBool:
		b, _ := v.AsBool()
		if b {
			return rule.NewFloat(1)
		}
		return rule.NewFloat(0)
	case rule.KindIP:
		ip, _ := v.AsIP()
		return rule.NewFloat(float64(ipLowUint64(ip)))
	default:
		return rule.NewFloat(0)
	}
}

// ========================== no-op import anchors ==============================================

// time is used directly only in the to_int KindTimestamp branch (ts.Unix()). The no-op
// anchor keeps the import honest; remove it if the reference becomes indirect.
var _ = time.Now

// math is referenced in the doc comment and in the int64(f) contract. The no-op
// anchor keeps the import honest.
var _ = math.MaxInt64
