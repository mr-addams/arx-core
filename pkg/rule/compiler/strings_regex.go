// ========================== pkg/rule/compiler — regex / JSON functions =====================
//   String family for the v0.3.0 function registry (DECISION D16, Group D — Task D3).
//
//   This file registers two further string-returning functions:
//
//     regex_replace(s, pattern, repl) -> string
//         Compile-time fast-path: when the pattern is a literal string, the
//         regex is precompiled to *regexp.Regexp at COMPILE time (DECISION D4).
//         A non-literal pattern is compiled per-eval (slower but unavoidable
//         for runtime-supplied patterns). The function uses Go's RE2 engine
//         (regexp package) — there is no backreference support, by design.
//
//     lookup_json_string(json, key) -> string
//         Parses the json argument as a top-level JSON object and returns the
//         string value at the given key. Misses (key absent, value not a
//         string, invalid JSON) return "" — the same defensive contract as the
//         rest of the engine.
//
//   WHAT IS NOT HERE:
//     - The compile-time precompile of regex_replace's pattern lives in
//       compiler.go's compileRegexReplace; the runtime dispatch lives in
//       eval.go's evalRegexReplace. This file only owns the registry entry
//       and the runtime fallback for non-literal patterns.
//
//   DEPENDENCY RULE:
//     stdlib only (D3): encoding/json, regexp, fmt.

package compiler

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the D3 string functions into the package-level registry.
// Called at package init time — the registry is fully populated before any
// Compile call.
//
// Note on regex_replace: the registry entry is present so that compileFuncCall
// can resolve the name and the per-arg Kind check can run. The actual compile
// path is special-cased in compileFuncCall because the pattern argument is
// precompiled when literal (DECISION D4). The runtime Eval here is a fallback
// for non-literal patterns AND for any hand-built op that bypasses the
// compiler (defensive parity).
func init() {
	registerFunc(FuncSpec{
		Name:       "regex_replace",
		ParamKinds: []rule.Kind{rule.KindString, rule.KindString, rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalRegexReplaceFallback,
	})
	registerFunc(FuncSpec{
		Name:       "lookup_json_string",
		ParamKinds: []rule.Kind{rule.KindString, rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalLookupJSONString,
	})
}

// evalRegexReplaceFallback is the registry-side Eval entry point. The
// compiler's literal fast-path bypasses it (opRegexReplace.dispatch in
// eval.go handles the compiled case directly), and the non-literal path
// invokes it implicitly when the evaluator falls through. We provide a
// working implementation so a hand-built op can use the registry's
// Lookup/eval contract.
func evalRegexReplaceFallback(args []rule.Value) rule.Value {
	subject, _ := args[0].AsString()
	pattern, _ := args[1].AsString()
	repl, _ := args[2].AsString()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return rule.NewString(subject)
	}
	return rule.NewString(re.ReplaceAllString(subject, repl))
}

// ========================== lookup_json_string =============================================

// evalLookupJSONString parses json as a top-level JSON object and returns the
// string value at the given key. Misses (invalid JSON, key absent, value not
// a string) return the empty string — the same defensive contract as the rest
// of the engine (no panic, no error path on the function Eval signature).
//
// Non-string values at the key are converted via fmt.Sprint (so `{"k": 42}`
// yields "42"). This matches Value.String() in pkg/rule and keeps the engine's
// "always return a string" contract for this function.
func evalLookupJSONString(args []rule.Value) rule.Value {
	jsonStr, _ := args[0].AsString()
	key, _ := args[1].AsString()

	if jsonStr == "" || key == "" {
		return rule.NewString("")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		return rule.NewString("")
	}
	v, ok := doc[key]
	if !ok {
		return rule.NewString("")
	}
	switch s := v.(type) {
	case string:
		return rule.NewString(s)
	default:
		return rule.NewString(fmt.Sprint(s))
	}
}
