// ========================== pkg/rule/compiler — allocating string functions =================
//   Allocating string family for the v0.3.0 function registry (DECISION D16, Group D —
//   Task D2).
//
//   This file registers the allocating string functions. The D1 set in strings.go is
//   alloc-free where the stdlib allows; the D2 set is intrinsically allocating because
//   the operation itself produces a new string (substring / concat / percent-decode /
//   percent-encode / html-entity-decode / byte-set removal).
//
//   Functions registered here:
//
//     substring(s, start, end)         -> string   (bounds-clamped; never panics)
//     concat(args... :string)          -> string   (variadic; zero or more args)
//     url_decode(s)                    -> string   (net/url QueryUnescape; bad % → "")
//     url_encode(s)                    -> string   (net/url QueryEscape)
//     html_entity_decode(s)            -> string   (html.UnescapeString)
//     remove_bytes(s, set)             -> string   (drops every byte of s that is in set)
//
//   BOUNDS POLICY (substring):
//     start and end are clamped into [0, len(s)]. If start > end after clamping, or
//     if start == end, the result is the empty string. Out-of-range inputs do NOT
//     panic — substring is documented as bounds-safe and the clamp is the contract.
//
//   ENCODE / DECODE POLICY (url_*):
//     url_encode uses url.QueryEscape (percent-encodes everything that is not
//     unreserved per RFC 3986). url_decode uses url.QueryUnescape (the inverse).
//     A malformed percent-encoding (e.g. "%zz") is surfaced as "" rather than an
//     error — function Eval returns a Value, not (Value, error), and "best-effort
//     decode" matches the rest of the engine's "no panic" contract.
//
//   VARIADIC POLICY (concat):
//     concat accepts zero or more string arguments. The empty-arg case yields "".
//     The minimum-arity is 0; the compiler rejects fewer than 0 (impossible).
//     ParamKinds has a single KindString element with IsVariadic=true, so each
//     argument is type-checked against KindString individually.
//
//   REMOVE_BYTES POLICY (remove_bytes):
//     set is interpreted as a set of BYTES, not runes — the operation is a byte-level
//     filter. The contract is documented in evalRemoveBytes and pinned by a test.
//     A nil/empty set is the identity (returns s unchanged).
//
//   WHAT IS NOT HERE:
//     - regex_replace and lookup_json_string — they land in D3 (strings_regex.go).
//     - The non-allocating scalar functions (lower / upper / len / to_string) — they
//       live in strings.go.
//     - IP / timestamp / coercion functions — Group E.

package compiler

import (
	"html"
	"net/url"
	"strings"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// init registers the D2 allocating string functions into the package-level registry.
// Called at package init time — the registry is fully populated before any Compile call.
func init() {
	registerFunc(FuncSpec{
		Name:       "substring",
		ParamKinds: []rule.Kind{rule.KindString, rule.KindInt, rule.KindInt},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalSubstring,
	})
	registerFunc(FuncSpec{
		Name:       "concat",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		IsVariadic: true,
		Eval:       evalConcat,
	})
	registerFunc(FuncSpec{
		Name:       "url_decode",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalURLDecode,
	})
	registerFunc(FuncSpec{
		Name:       "url_encode",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalURLEncode,
	})
	registerFunc(FuncSpec{
		Name:       "html_entity_decode",
		ParamKinds: []rule.Kind{rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalHTMLEntityDecode,
	})
	registerFunc(FuncSpec{
		Name:       "remove_bytes",
		ParamKinds: []rule.Kind{rule.KindString, rule.KindString},
		ReturnKind: rule.KindString,
		Allocating: true,
		Eval:       evalRemoveBytes,
	})
}

// ========================== substring =====================================================

// evalSubstring returns the substring of s from start (inclusive) to end (exclusive),
// after clamping both indices into [0, len(s)]. The result is s itself if the clamped
// range covers the whole string.
//
// Bounds policy:
//   - start < 0              → clamped to 0
//   - end   > len(s)         → clamped to len(s)
//   - start > end (post-clamp) → "" (empty string)
//   - start == end (post-clamp) → "" (empty string)
//
// substring never panics on out-of-range inputs; the clamp is the contract. The
// language grammar has no unary minus, so a literal start < 0 is a parse error —
// the runtime clamp is defensive for runtime-supplied Values (a field of KindInt)
// and is not reachable from a literal.
func evalSubstring(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	start, _ := args[1].AsInt()
	end, _ := args[2].AsInt()

	n := int64(len(s))
	if start < 0 {
		start = 0
	}
	if end > n {
		end = n
	}
	if start >= end {
		return rule.NewString("")
	}
	return rule.NewString(s[start:end])
}

// ========================== concat ========================================================

// evalConcat concatenates all argument strings in order. Empty / no-arg concat returns "".
//
// The function is variadic (DECISION D16; IsVariadic=true). The compiler has already
// type-checked every argument as KindString before this entry point is invoked, so no
// per-arg Kind check is needed here.
func evalConcat(args []rule.Value) rule.Value {
	if len(args) == 0 {
		return rule.NewString("")
	}
	// Pre-size the buffer to the sum of all arg lengths — strings.Builder then
	// allocates exactly once. Empty / single-arg cases are handled naturally.
	total := 0
	for i := range args {
		s, _ := args[i].AsString()
		total += len(s)
	}
	var b strings.Builder
	b.Grow(total)
	for i := range args {
		s, _ := args[i].AsString()
		b.WriteString(s)
	}
	return rule.NewString(b.String())
}

// ========================== url_decode / url_encode =======================================

// evalURLDecode applies net/url QueryUnescape to s. A malformed percent-encoding (e.g.
// "%zz" without trailing hex digits) is surfaced as the empty string — the Eval
// signature returns Value, not (Value, error), and "best-effort decode with safe
// fallback" matches the engine's no-panic contract.
func evalURLDecode(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return rule.NewString("")
	}
	return rule.NewString(decoded)
}

// evalURLEncode applies net/url QueryEscape to s. The encoding is the form used in
// query strings (RFC 3986 unreserved chars preserved, everything else percent-encoded
// including '/'). Always succeeds — no error path.
func evalURLEncode(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	return rule.NewString(url.QueryEscape(s))
}

// ========================== html_entity_decode =============================================

// evalHTMLEntityDecode applies html.UnescapeString to s. The stdlib unescapes every
// named entity (&amp;, &lt;, &gt;, &quot;, &#39;, ...) and numeric entities (&#NNN;
// &#xHH;). Unknown entities are passed through unchanged. The operation always
// succeeds — no error path.
func evalHTMLEntityDecode(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	return rule.NewString(html.UnescapeString(s))
}

// ========================== remove_bytes ==================================================

// evalRemoveBytes returns s with every byte that appears in set removed.
//
// set is interpreted as a SET OF BYTES, not a set of runes: a multi-byte UTF-8
// character whose bytes ALL appear in set is removed entirely; if even one byte
// of the rune is not in set, the rune is kept verbatim. This matches the
// byte-level semantics implied by the function name ("bytes", not "chars") and
// the stdlib's strings.NewReplacer behaviour when used with single-byte pairs.
//
// The empty-set case returns s unchanged (nothing to remove). The implementation
// is O(len(s) * len(set)) — acceptable for the typical "remove spaces / control
// chars" use case where both inputs are short. A future flow that needs to handle
// very large sets can swap in a [256]bool lookup table.
func evalRemoveBytes(args []rule.Value) rule.Value {
	s, _ := args[0].AsString()
	set, _ := args[1].AsString()
	if set == "" {
		return rule.NewString(s)
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		keep := true
		for j := 0; j < len(set); j++ {
			if c == set[j] {
				keep = false
				break
			}
		}
		if keep {
			b = append(b, c)
		}
	}
	return rule.NewString(string(b))
}
