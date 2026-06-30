// ========================== pkg/rule/compiler — timestamp functions ===========================
//   Timestamp family for the v0.3.0 function registry (DECISION D16, Group E — Task E2).
//
//   This file registers the time functions:
//
//     now()                       -> timestamp   (allocating; time.Now + Value copy)
//     unix_time(ts:timestamp)       -> int          (alloc-free; NewInt is value-typed)
//     format_time(ts, layout)     -> string       (allocating; time.Format returns a new string)
//
//   TIME REPRESENTATION:
//     The rule engine stores timestamps as time.Time and durations as
//     time.Duration. now() returns the current wall-clock time at eval time; it
//     is intentionally non-deterministic and is best used for relative checks
//     against other timestamps or for logging.
//
//   FORMAT CONTRACT:
//     format_time passes the layout argument through to Go's time.Format. The
//     caller is responsible for providing a valid reference layout
//     ("Mon Jan 2 15:04:05 MST 2006"). The engine does NOT validate layouts in
//     advance and does NOT error on a non-reference layout: Go's parser is
//     permissive and will produce some deterministic string for any input.
//     Malformed layouts are therefore caller error, surfaced as an unexpected
//     formatted result rather than a runtime panic or compile error.
//
//   WHAT IS NOT HERE:
//     - IP / coercion / string functions — they live in adjacent files.
//     - The function registry itself — functions.go.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): time. Plus sibling pkg/rule (Value / Kind).
//
//   ALLOCATION CONTRACT (D16 §4):
//     now() and format_time() are marked Allocating=true because they produce a
//     new time.Time or a new string per call. unix_time() is marked
//     Allocating=false because ts.Unix() is a header read and NewInt returns a
//     struct-valued Value with no engine-side heap bookkeeping.

package compiler

import (
	"time"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the E2 timestamp functions into the package-level registry.
// Called at package init time — the registry is fully populated before any
// Compile call.
func init() {
	registerFunc(FuncSpec{
		Name:       "now",
		ParamKinds: []rule.Kind{},
		ReturnKind: rule.KindTimestamp,
		Allocating: true,
		Eval:       evalNow,
	})
	registerFunc(FuncSpec{
		Name:       "unix_time",
		ParamKinds: []rule.Kind{rule.KindTimestamp},
		ReturnKind: rule.KindInt,
		Allocating: false,
		Eval:       evalUnixTime,
	})
	registerFunc(FuncSpec{
		Name:       "format_time",
		ParamKinds: []rule.Kind{rule.KindTimestamp, rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalFormatTime,
	})
}

// ========================== now =============================================================

// evalNow returns the current time as a KindTimestamp Value.
//
// The function is intentionally non-deterministic: each eval call captures the
// wall-clock time via time.Now(). This matches the obvious semantics of `now()`
// and is the reason the function is marked Allocating=true (a new time.Time is
// produced per call). Tests that exercise now() therefore assert boundaries
// rather than an exact value.
func evalNow(args []rule.Value) rule.Value {
	return rule.NewTimestamp(time.Now())
}

// ========================== unix_time ========================================================

// evalUnixTime returns the Unix time (seconds since 1970-01-01 UTC) of the
// input timestamp.
//
// This is a header read on a time.Time stored in the Value union. The returned
// int64 Value is struct-typed, so the function is alloc-free: no new string,
// slice, or map is created on the hot path.
func evalUnixTime(args []rule.Value) rule.Value {
	ts, _ := args[0].AsTimestamp()
	return rule.NewInt(ts.Unix())
}

// ========================== format_time ======================================================

// evalFormatTime formats the input timestamp according to the supplied layout.
//
// The layout is passed verbatim to time.Format. Go requires the layout to be the
// reference time "Mon Jan 2 15:04:05 MST 2006"; if the caller passes something
// that does not match that reference, time.Format still returns a deterministic
// string (it interprets the layout as a format string in the reference-time
// vocabulary). The engine does not validate the layout because there is no
// reliable way to detect a misdesigned layout in general, and Go's contract is
// to return a string rather than an error. Callers must therefore supply a valid
// reference layout; bad layouts are caller error and appear as unexpected output.
//
// Empty layout defaults to time.RFC3339: Go's time.Format("") returns "" (zero
// useful representation), but rule authors frequently write format_time(...)
// with an unparameterised layout and expect a sensible ISO-8601 timestamp back.
// Falling back to RFC3339 keeps the result non-empty and round-trippable.
func evalFormatTime(args []rule.Value) rule.Value {
	ts, _ := args[0].AsTimestamp()
	layout, _ := args[1].AsString()
	if layout == "" {
		layout = time.RFC3339
	}
	return rule.NewString(ts.Format(layout))
}
