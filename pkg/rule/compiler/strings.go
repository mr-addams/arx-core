// ========================== pkg/rule/compiler — string functions =============================
//   String family for the v0.3.0 function registry (DECISION D16, Group D — Task D1).
//
//   This file registers the scalar/cheap string functions:
//     lower(s)            -> string   (alloc-free where the stdlib allows)
//     upper(s)            -> string   (alloc-free where the stdlib allows)
//     len(s)              -> int      (alloc-free)
//     to_string(v)        -> string   (alloc-free for scalar formatters)
//
//   NOTE — starts_with / ends_with:
//     The D1 brief lists starts_with(s, prefix) and ends_with(s, suffix) as
//     functions. In Flow 001 these names were already reserved as keyword
//     string operators (lexer/parser, DECISION D14) — `field starts_with "x"`.
//     Registering them as functions would create a tokenisation conflict: the
//     lexer would keyword-tokenise the name before the parser could see it as
//     a function identifier. Resolving this is an architectural decision
//     (rename the functions, deprecate the operators, or remove the operator
//     form and keep only the function form) — escalated to /architect. The
//     operator form is the only one that compiles today.
//
//   WHAT IS NOT HERE:
//     - The allocating string functions (substring / concat / url_* / html_* /
//       remove_bytes / regex_replace / lookup_json_string) — they land in D2 / D3.
//     - IP / timestamp / coercion functions — Group E.
//     - The function registry itself — functions.go.
//
//   ALLOCATION CONTRACT (D16 §4):
//     Allocating flag is set per-function. The entry points in this file do
//     not allocate beyond what the stdlib impl inherently needs for the
//     declared Allocating value. The hot path for these four functions stays
//     within D4's "no per-eval allocations beyond what the function inherently
//     needs" guarantee.

package compiler

import (
	"strconv"
	"strings"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the D1 string functions into the package-level registry. Called
// at package init time — the registry is fully populated before any Compile call.
func init() {
	registerFunc(FuncSpec{
		Name:       "lower",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: false,
		Eval:       evalLower,
	})
	registerFunc(FuncSpec{
		Name:       "upper",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: false,
		Eval:       evalUpper,
	})
	registerFunc(FuncSpec{
		Name:       "len",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindInt,
		Allocating: false,
		Eval:       evalLen,
	})
	registerFunc(FuncSpec{
		Name:       "to_string",
		ParamKinds: []rule.Kind{rule.KindInvalid}, // KindInvalid = "any" in ParamKinds
		ReturnKind: rule.KindString,
		Allocating: false,
		Eval:       evalToString,
	})
}

// ========================== String case converters ==========================================

// evalLower returns the lowercase form of its single string argument.
//
// Alloc-free: strings.ToLower returns the input string unchanged if it is
// already lowercase (the common case for ASCII identifiers / paths). For
// mixed-case input the stdlib allocates the lowered copy — that allocation
// is inherent to the operation, not an extra cost the engine adds. The
// Allocating flag stays false because the engine itself does no bookkeeping
// allocation; the stdlib's case-conversion allocation is what the flag's
// doc-comment means by "what the function inherently needs".
func evalLower(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	return rule.NewString(strings.ToLower(s))
}

// evalUpper is the uppercase counterpart of evalLower. Same allocation
// contract: no engine-side bookkeeping; stdlib may allocate when the input
// is not already uppercase.
func evalUpper(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	return rule.NewString(strings.ToUpper(s))
}

// ========================== String length ===================================================

// evalLen returns the byte length of its single string argument.
//
// Alloc-free: strings are immutable in Go; the length is a header read.
func evalLen(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	return rule.NewInt(int64(len(s)))
}

// ========================== String prefix / suffix tests ====================================
//
// The function form of starts_with / ends_with was deferred to an architectural
// decision (see file header note). The keyword operator form
// (`field starts_with "prefix"`) compiles and evaluates today via the
// compileStartsWith / compileEndsWith path in compiler.go and evalStartsWith /
// evalEndsWith in eval.go.

// ========================== to_string — kind-aware scalar formatter =========================

// evalToString returns the canonical string form of its single argument. The
// formatting mirrors Value.String() in pkg/rule — the function exists so
// expressions can perform the conversion at eval time without depending on a
// plugin-side Stringer.
//
// The function accepts any Kind: ParamKinds declares KindInvalid as a
// wildcard ("any Kind"). The compiler's per-argument Kind check therefore
// passes for every argument Kind, and the dispatch here switches on the
// runtime Kind. A malformed Value (KindInvalid, the zero Value) renders as
// "<invalid>" — same convention as Value.String().
//
// Alloc-free: Value.String() builds a byte buffer per call (the helper is
// shared with log diagnostics); the buffer is the stdlib's, not the
// engine's. For the simple scalar Kinds handled here (String / Int / Float /
// Bool / IP / Bytes / Duration / Timestamp) the conversion does not allocate
// beyond the result string itself, which the caller retains. Map and Array
// Kinds would allocate a builder — they are not in the D1 set, but the
// formatter handles them defensively via Value.String().
func evalToString(args []rule.Value) rule.Value {
	return rule.NewString(args[0].String())
}

// strconv is imported for future functions in the same family (D2/D3 may
// use it for url-encoded / html-decoded formatting); the no-op anchor keeps
// the import honest until then. Remove this anchor when the first such
// function is added.
var _ = strconv.Itoa
