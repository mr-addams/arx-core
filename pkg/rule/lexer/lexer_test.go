// ========================== pkg/rule/lexer — tests ========================================
//   Coverage goals (from the task spec):
//     1. Every token kind has at least one positive test.
//     2. TString escape round-trip + unknown escape rejection.
//     3. Dotted identifier lexing (http.uri.path → ONE TIdent).
//     4. Reserved word disambiguation (bare vs qualified; true/false vs keyword).
//     5. Numbers (int / float / malformed).
//     6. Duration ambiguity (5s vs 5 s, 5x, 1h30m, 100ms, 250ns, 1h2m3s500ms).
//     7. Prefix-string literals (ts, ip, 0x).
//     8. Comments (# to EOL).
//     9. Newline handling (\n, \r\n, bare \r).
//    10. Position tracking.
//    11. Multiple tokens per input (real expression).
//    12. Empty input.
//    13. Lexical errors do not stop lexing.
//    14. Concurrent Lex calls (race detector smoke test).
//
//   Stdlib only — no external test deps. Comparison via reflect.DeepEqual.
//
//   Style note: White-box tests in `package lexer` to access unexported helpers
//   (pendingErr, keywords, lexer struct) without exposing them in the public
//   surface.

package lexer

import (
	"reflect"
	"sync"
	"testing"
)

// ========================== Helpers =======================================================

// kinds extracts just the Kind fields from a token slice — convenient for the
// tests that want to assert the SHAPE of the stream without repeating every
// payload field. Use kindsEqual for that style of comparison.
func kinds(toks []Token) []TokenKind {
	out := make([]TokenKind, len(toks))
	for i, t := range toks {
		out[i] = t.Kind
	}
	return out
}

// kindsEqual compares two []TokenKind values for equality.
func kindsEqual(a, b []TokenKind) bool {
	return reflect.DeepEqual(a, b)
}

// ========================== 1. Per-kind positive coverage ================================

func TestLex_Kinds(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []Token
	}{
		// --- TIdent ---
		{
			name: "ident_simple",
			src:  "http",
			want: []Token{
				{Kind: TIdent, Value: "http", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},
		{
			name: "ident_with_underscore_and_digits",
			src:  "h2_x",
			want: []Token{
				{Kind: TIdent, Value: "h2_x", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},

		// --- TString ---
		{
			name: "string_empty",
			src:  `""`,
			want: []Token{
				{Kind: TString, Value: "", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 3},
			},
		},
		{
			name: "string_plain",
			src:  `"hello"`,
			want: []Token{
				{Kind: TString, Value: "hello", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 8},
			},
		},

		// --- TInt ---
		{
			name: "int_zero",
			src:  "0",
			want: []Token{
				{Kind: TInt, Value: "0", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 2},
			},
		},
		{
			name: "int_multi",
			src:  "42",
			want: []Token{
				{Kind: TInt, Value: "42", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 3},
			},
		},

		// --- TFloat ---
		{
			name: "float_basic",
			src:  "3.14",
			want: []Token{
				{Kind: TFloat, Value: "3.14", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},
		{
			name: "float_with_exponent",
			src:  "1e10",
			want: []Token{
				{Kind: TFloat, Value: "1e10", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},
		{
			name: "float_with_signed_exponent",
			src:  "1.5e-3",
			want: []Token{
				{Kind: TFloat, Value: "1.5e-3", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 7},
			},
		},

		// --- TDuration ---
		{
			name: "duration_simple_s",
			src:  "5s",
			want: []Token{
				{Kind: TDuration, Value: "5s", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 3},
			},
		},
		{
			name: "duration_composite",
			src:  "1h30m",
			want: []Token{
				{Kind: TDuration, Value: "1h30m", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 6},
			},
		},

		// --- TTimestamp ---
		{
			name: "timestamp_basic",
			src:  `ts"2026-06-29T10:30:00Z"`,
			want: []Token{
				{Kind: TTimestamp, Value: "2026-06-29T10:30:00Z", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 25},
			},
		},

		// --- TIP ---
		{
			name: "ip_cidr",
			src:  `ip"10.0.0.0/8"`,
			want: []Token{
				{Kind: TIP, Value: "10.0.0.0/8", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 15},
			},
		},
		{
			name: "ip_plain",
			src:  `ip"192.168.1.1"`,
			want: []Token{
				{Kind: TIP, Value: "192.168.1.1", Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 16},
			},
		},

		// --- TBytes ---
		{
			name: "bytes_basic",
			src:  `0x"deadbeef"`,
			want: []Token{
				{Kind: TBytes, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}, Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 13},
			},
		},
		{
			name: "bytes_uppercase_hex",
			src:  `0x"DEADBEEF"`,
			want: []Token{
				{Kind: TBytes, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}, Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 13},
			},
		},
		{
			name: "bytes_empty",
			src:  `0x""`,
			want: []Token{
				{Kind: TBytes, Bytes: []byte{}, Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},

		// --- TBool ---
		{
			name: "bool_true",
			src:  "true",
			want: []Token{
				{Kind: TBool, Bool: true, Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 5},
			},
		},
		{
			name: "bool_false",
			src:  "false",
			want: []Token{
				{Kind: TBool, Bool: false, Line: 1, Column: 1},
				{Kind: TEOF, Line: 1, Column: 6},
			},
		},

		// --- TKeyword (every reserved word) ---
		{
			name: "keyword_and", src: "and",
			want: []Token{{Kind: TKeyword, Value: "and", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 4}},
		},
		{
			name: "keyword_or", src: "or",
			want: []Token{{Kind: TKeyword, Value: "or", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_not", src: "not",
			want: []Token{{Kind: TKeyword, Value: "not", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 4}},
		},
		{
			name: "keyword_in", src: "in",
			want: []Token{{Kind: TKeyword, Value: "in", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_eq", src: "eq",
			want: []Token{{Kind: TKeyword, Value: "eq", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_ne", src: "ne",
			want: []Token{{Kind: TKeyword, Value: "ne", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_lt", src: "lt",
			want: []Token{{Kind: TKeyword, Value: "lt", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_le", src: "le",
			want: []Token{{Kind: TKeyword, Value: "le", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_gt", src: "gt",
			want: []Token{{Kind: TKeyword, Value: "gt", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_ge", src: "ge",
			want: []Token{{Kind: TKeyword, Value: "ge", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 3}},
		},
		{
			name: "keyword_contains", src: "contains",
			want: []Token{{Kind: TKeyword, Value: "contains", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 9}},
		},
		{
			name: "keyword_starts_with", src: "starts_with",
			want: []Token{{Kind: TKeyword, Value: "starts_with", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 12}},
		},
		{
			name: "keyword_ends_with", src: "ends_with",
			want: []Token{{Kind: TKeyword, Value: "ends_with", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 10}},
		},
		{
			name: "keyword_matches", src: "matches",
			want: []Token{{Kind: TKeyword, Value: "matches", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 8}},
		},
		{
			name: "keyword_wildcard", src: "wildcard",
			want: []Token{{Kind: TKeyword, Value: "wildcard", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 9}},
		},
		{
			name: "keyword_strict", src: "strict",
			want: []Token{{Kind: TKeyword, Value: "strict", Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 7}},
		},

		// --- Punctuation ---
		{
			name: "punct_lparen", src: "(",
			want: []Token{{Kind: TLParen, Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 2}},
		},
		{
			name: "punct_rparen", src: ")",
			want: []Token{{Kind: TRParen, Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 2}},
		},
		{
			name: "punct_lbrack", src: "[",
			want: []Token{{Kind: TLBrack, Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 2}},
		},
		{
			name: "punct_rbrack", src: "]",
			want: []Token{{Kind: TRBrack, Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 2}},
		},
		{
			name: "punct_comma", src: ",",
			want: []Token{{Kind: TComma, Line: 1, Column: 1}, {Kind: TEOF, Line: 1, Column: 2}},
		},

		// --- TEOF on empty input ---
		{
			name: "empty_input",
			src:  "",
			want: []Token{{Kind: TEOF, Line: 1, Column: 1}},
		},
		{
			name: "whitespace_only",
			src:  "   \t\n",
			want: []Token{{Kind: TEOF, Line: 2, Column: 1}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Lex(tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Lex(%q):\n got  %#v\n want %#v", tc.src, got, tc.want)
			}
		})
	}
}

// ========================== 2. String escape round-trip ===================================

func TestLex_StringEscapes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // decoded value
	}{
		{"newline", `"\n"`, "\n"},
		{"tab", `"\t"`, "\t"},
		{"carriage_return", `"\r"`, "\r"},
		{"escaped_quote", `"\""`, `"`},
		{"escaped_backslash", `"\\"`, `\`},
		{"mixed", `"a\nb\tc\rd\"e\\f"`, "a\nb\tc\rd\"e\\f"},
		{"empty", `""`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks := Lex(tc.src)
			if len(toks) < 2 {
				t.Fatalf("Lex(%q): expected at least 2 tokens, got %d (%#v)", tc.src, len(toks), toks)
			}
			if toks[0].Kind != TString {
				t.Fatalf("Lex(%q): first token Kind = %v, want TString", tc.src, toks[0].Kind)
			}
			if toks[0].Value != tc.want {
				t.Fatalf("Lex(%q): decoded Value = %q, want %q", tc.src, toks[0].Value, tc.want)
			}
		})
	}
}

func TestLex_StringUnknownEscape(t *testing.T) {
	toks := Lex(`"\q"`)
	// Expect: TError + TEOF (the lexer consumes the rest of the string on error).
	if !kindsEqual(kinds(toks), []TokenKind{TError, TEOF}) {
		t.Fatalf("expected [TError TEOF], got kinds=%v toks=%#v", kinds(toks), toks)
	}
	if toks[0].Kind == TError && toks[0].Value == "" {
		t.Fatalf("TError token has empty message")
	}
}

// ========================== 3. Dotted identifier ==========================================

func TestLex_DottedIdentifier(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // expected TIdent value (the full dotted text)
	}{
		{"two_segments", "http.uri", "http.uri"},
		{"three_segments", "http.uri.path", "http.uri.path"},
		{"core_stream", "core.stream", "core.stream"},
		{"underscore_in_segment", "http.x_y.z", "http.x_y.z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks := Lex(tc.src)
			if len(toks) < 2 {
				t.Fatalf("expected at least 2 tokens, got %d (%#v)", len(toks), toks)
			}
			if toks[0].Kind != TIdent {
				t.Fatalf("first token Kind = %v, want TIdent (full=%#v)", toks[0].Kind, toks)
			}
			if toks[0].Value != tc.want {
				t.Fatalf("TIdent Value = %q, want %q", toks[0].Value, tc.want)
			}
			// Critical assertion: dotted identifiers must be ONE token.
			if kindsEqual(kinds(toks), []TokenKind{TIdent, TEOF}) == false {
				t.Fatalf("dotted ident should produce exactly [TIdent TEOF], got %v", kinds(toks))
			}
		})
	}
}

// ========================== 4. Reserved word disambiguation ==============================

func TestLex_ReservedDisambiguation(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantKind TokenKind
		wantVal  string
	}{
		{"bare_eq_is_keyword", "eq", TKeyword, "eq"},
		{"bare_contains_is_keyword", "contains", TKeyword, "contains"},
		{"bare_and_is_keyword", "and", TKeyword, "and"},
		{"qualified_eq_is_ident", "core.eq", TIdent, "core.eq"},
		{"qualified_contains_is_ident", "http.contains", TIdent, "http.contains"},
		{"bare_true_is_bool", "true", TBool, ""},
		{"bare_false_is_bool", "false", TBool, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks := Lex(tc.src)
			if len(toks) < 2 {
				t.Fatalf("expected at least 2 tokens, got %d (%#v)", len(toks), toks)
			}
			if toks[0].Kind != tc.wantKind {
				t.Fatalf("first token Kind = %v, want %v (full=%#v)", toks[0].Kind, tc.wantKind, toks)
			}
			if tc.wantVal != "" && toks[0].Value != tc.wantVal {
				t.Fatalf("Value = %q, want %q", toks[0].Value, tc.wantVal)
			}
			if tc.wantKind == TBool {
				expectedBool := tc.src == "true"
				if toks[0].Bool != expectedBool {
					t.Fatalf("Bool = %v, want %v", toks[0].Bool, expectedBool)
				}
			}
		})
	}
}

// ========================== 5. Numbers ====================================================

func TestLex_Numbers(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantKind TokenKind
		wantVal  string
	}{
		{"int_simple", "42", TInt, "42"},
		{"int_zero", "0", TInt, "0"},
		{"float_basic", "3.14", TFloat, "3.14"},
		{"float_int_part_zero", "0.5", TFloat, "0.5"},
		{"float_with_positive_exp", "1e10", TFloat, "1e10"},
		{"float_with_signed_exp", "1.5e-3", TFloat, "1.5e-3"},
		{"float_with_positive_exp_sign", "2.5e+3", TFloat, "2.5e+3"},
		{"float_with_uppercase_E", "1E10", TFloat, "1E10"},
		// Malformed cases:
		{"int_then_dot_no_digits_is_error", "42.", TError, ""},
		{"dot_only_no_int_is_error", ".5", TError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toks := Lex(tc.src)
			if len(toks) < 2 {
				t.Fatalf("expected at least 2 tokens, got %d (%#v)", len(toks), toks)
			}
			if toks[0].Kind != tc.wantKind {
				t.Fatalf("first token Kind = %v, want %v (full=%#v)", toks[0].Kind, tc.wantKind, toks)
			}
			if tc.wantKind != TError && toks[0].Value != tc.wantVal {
				t.Fatalf("Value = %q, want %q", toks[0].Value, tc.wantVal)
			}
		})
	}
}

// ========================== 6. Duration ambiguity =========================================

func TestLex_DurationAmbiguity(t *testing.T) {
	t.Run("simple_durations_are_one_token", func(t *testing.T) {
		cases := []string{"5s", "1h30m", "100ms", "250ns", "1h2m3s500ms", "1us", "1µs", "5m"}
		for _, src := range cases {
			toks := Lex(src)
			if !kindsEqual(kinds(toks), []TokenKind{TDuration, TEOF}) {
				t.Fatalf("Lex(%q): expected [TDuration TEOF], got kinds=%v toks=%#v", src, kinds(toks), toks)
			}
			if toks[0].Value != src {
				t.Fatalf("Lex(%q): Value = %q, want %q", src, toks[0].Value, src)
			}
		}
	})

	t.Run("space_between_digits_and_unit", func(t *testing.T) {
		toks := Lex("5 s")
		want := []TokenKind{TInt, TIdent, TEOF}
		if !kindsEqual(kinds(toks), want) {
			t.Fatalf("Lex(`5 s`): expected kinds=%v, got %v (full=%#v)", want, kinds(toks), toks)
		}
		if toks[0].Value != "5" || toks[0].Kind != TInt {
			t.Fatalf("toks[0] = %#v, want TInt(5)", toks[0])
		}
		if toks[1].Value != "s" || toks[1].Kind != TIdent {
			t.Fatalf("toks[1] = %#v, want TIdent(\"s\")", toks[1])
		}
	})

	t.Run("non_unit_letter_after_digits", func(t *testing.T) {
		// 'x' is not a duration unit, so '5' becomes TInt and 'x' becomes TIdent.
		toks := Lex("5x")
		want := []TokenKind{TInt, TIdent, TEOF}
		if !kindsEqual(kinds(toks), want) {
			t.Fatalf("Lex(`5x`): expected kinds=%v, got %v (full=%#v)", want, kinds(toks), toks)
		}
		if toks[0].Value != "5" || toks[1].Value != "x" {
			t.Fatalf("toks[0]=%#v toks[1]=%#v", toks[0], toks[1])
		}
	})

	t.Run("newline_between_digits_and_unit", func(t *testing.T) {
		toks := Lex("5\ns")
		want := []TokenKind{TInt, TIdent, TEOF}
		if !kindsEqual(kinds(toks), want) {
			t.Fatalf("Lex(`5\\ns`): expected kinds=%v, got %v (full=%#v)", want, kinds(toks), toks)
		}
	})
}

// ========================== 7. Prefix-string literals =====================================

func TestLex_PrefixStrings(t *testing.T) {
	t.Run("ts_basic", func(t *testing.T) {
		toks := Lex(`ts"2026-06-29T10:30:00Z"`)
		want := []Token{
			{Kind: TTimestamp, Value: "2026-06-29T10:30:00Z", Line: 1, Column: 1},
			{Kind: TEOF, Line: 1, Column: 25},
		}
		if !reflect.DeepEqual(toks, want) {
			t.Fatalf("got %#v want %#v", toks, want)
		}
	})

	t.Run("ip_cidr", func(t *testing.T) {
		toks := Lex(`ip"10.0.0.0/8"`)
		want := []Token{
			{Kind: TIP, Value: "10.0.0.0/8", Line: 1, Column: 1},
			{Kind: TEOF, Line: 1, Column: 15},
		}
		if !reflect.DeepEqual(toks, want) {
			t.Fatalf("got %#v want %#v", toks, want)
		}
	})

	t.Run("bytes_valid", func(t *testing.T) {
		toks := Lex(`0x"deadbeef"`)
		want := []Token{
			{Kind: TBytes, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}, Line: 1, Column: 1},
			{Kind: TEOF, Line: 1, Column: 13},
		}
		if !reflect.DeepEqual(toks, want) {
			t.Fatalf("got %#v want %#v", toks, want)
		}
	})

	t.Run("bytes_empty", func(t *testing.T) {
		toks := Lex(`0x""`)
		if toks[0].Kind != TBytes {
			t.Fatalf("toks[0].Kind = %v, want TBytes (full=%#v)", toks[0].Kind, toks)
		}
		if toks[0].Bytes == nil {
			t.Fatalf("toks[0].Bytes is nil; expected non-nil empty slice")
		}
		if len(toks[0].Bytes) != 0 {
			t.Fatalf("toks[0].Bytes length = %d, want 0", len(toks[0].Bytes))
		}
	})

	t.Run("bytes_invalid_hex", func(t *testing.T) {
		toks := Lex(`0x"xy"`)
		if toks[0].Kind != TError {
			t.Fatalf("toks[0].Kind = %v, want TError (full=%#v)", toks[0].Kind, toks)
		}
	})

	t.Run("space_between_prefix_and_quote_does_NOT_make_prefix_string", func(t *testing.T) {
		// `ts "x"` should lex as TIdent("ts") + TString("x"), NOT TTimestamp.
		toks := Lex(`ts "x"`)
		want := []TokenKind{TIdent, TString, TEOF}
		if !kindsEqual(kinds(toks), want) {
			t.Fatalf("Lex(`ts \"x\"`): expected kinds=%v, got %v (full=%#v)", want, kinds(toks), toks)
		}
		if toks[0].Value != "ts" {
			t.Fatalf("toks[0].Value = %q, want %q", toks[0].Value, "ts")
		}
		if toks[1].Value != "x" {
			t.Fatalf("toks[1].Value = %q, want %q", toks[1].Value, "x")
		}
	})

	t.Run("ip_space_then_string", func(t *testing.T) {
		toks := Lex(`ip "10.0.0.1"`)
		want := []TokenKind{TIdent, TString, TEOF}
		if !kindsEqual(kinds(toks), want) {
			t.Fatalf("Lex(`ip \"10.0.0.1\"`): expected kinds=%v, got %v", want, kinds(toks))
		}
	})
}

// ========================== 8. Comments ===================================================

func TestLex_Comments(t *testing.T) {
	t.Run("full_line_comment", func(t *testing.T) {
		toks := Lex("# this is a comment\n")
		if !kindsEqual(kinds(toks), []TokenKind{TEOF}) {
			t.Fatalf("expected only [TEOF], got kinds=%v", kinds(toks))
		}
	})

	t.Run("trailing_comment_after_int", func(t *testing.T) {
		toks := Lex("42 # trailing\n")
		if !kindsEqual(kinds(toks), []TokenKind{TInt, TEOF}) {
			t.Fatalf("expected [TInt TEOF], got kinds=%v (full=%#v)", kinds(toks), toks)
		}
		if toks[0].Value != "42" {
			t.Fatalf("toks[0].Value = %q, want %q", toks[0].Value, "42")
		}
	})

	t.Run("comment_after_code_no_newline", func(t *testing.T) {
		toks := Lex("42 # no newline at EOF")
		if !kindsEqual(kinds(toks), []TokenKind{TInt, TEOF}) {
			t.Fatalf("expected [TInt TEOF], got kinds=%v", kinds(toks))
		}
	})

	t.Run("comment_with_hash_inside_string_is_NOT_a_comment", func(t *testing.T) {
		// The '#' is inside a string literal; the comment rule does NOT apply.
		toks := Lex(`"hello # world"`)
		if !kindsEqual(kinds(toks), []TokenKind{TString, TEOF}) {
			t.Fatalf("expected [TString TEOF], got kinds=%v (full=%#v)", kinds(toks), toks)
		}
		if toks[0].Value != "hello # world" {
			t.Fatalf("Value = %q, want %q", toks[0].Value, "hello # world")
		}
	})

	t.Run("comment_after_expression_keeps_position", func(t *testing.T) {
		toks := Lex("42\n# comment\nfoo")
		if !kindsEqual(kinds(toks), []TokenKind{TInt, TIdent, TEOF}) {
			t.Fatalf("expected [TInt TIdent TEOF], got kinds=%v", kinds(toks))
		}
		if toks[1].Line != 3 || toks[1].Column != 1 {
			t.Fatalf("toks[1] position = (%d, %d), want (3, 1)", toks[1].Line, toks[1].Column)
		}
	})
}

// ========================== 9. Newline handling ===========================================

func TestLex_Newlines(t *testing.T) {
	t.Run("lf_is_whitespace", func(t *testing.T) {
		toks := Lex("a\nb")
		if !kindsEqual(kinds(toks), []TokenKind{TIdent, TIdent, TEOF}) {
			t.Fatalf("expected [TIdent TIdent TEOF], got kinds=%v", kinds(toks))
		}
	})

	t.Run("crlf_is_one_newline", func(t *testing.T) {
		toks := Lex("a\r\nb")
		if !kindsEqual(kinds(toks), []TokenKind{TIdent, TIdent, TEOF}) {
			t.Fatalf("expected [TIdent TIdent TEOF], got kinds=%v", kinds(toks))
		}
		if toks[1].Line != 2 {
			t.Fatalf("toks[1].Line = %d, want 2 (CRLF should advance line once)", toks[1].Line)
		}
	})

	t.Run("bare_cr_is_error", func(t *testing.T) {
		toks := Lex("a\rb")
		// Expect: TIdent, TError, TIdent, TEOF — the bare CR yields an inline error
		// but the lexer does not stop.
		if !kindsEqual(kinds(toks), []TokenKind{TIdent, TError, TIdent, TEOF}) {
			t.Fatalf("expected [TIdent TError TIdent TEOF], got kinds=%v (full=%#v)", kinds(toks), toks)
		}
		if toks[1].Value == "" {
			t.Fatalf("TError token has empty message")
		}
	})
}

// ========================== 10. Position tracking =========================================

func TestLex_PositionTracking(t *testing.T) {
	t.Run("line2_col1_after_newline", func(t *testing.T) {
		toks := Lex("# line1\nhttp.uri\n")
		// Tokens after the comment: just one TIdent ("http.uri") on line 2.
		if len(toks) < 2 {
			t.Fatalf("expected at least 2 tokens, got %d (%#v)", len(toks), toks)
		}
		ident := toks[0]
		if ident.Kind != TIdent {
			t.Fatalf("toks[0].Kind = %v, want TIdent (full=%#v)", ident.Kind, toks)
		}
		if ident.Line != 2 || ident.Column != 1 {
			t.Fatalf("TIdent position = (%d, %d), want (2, 1)", ident.Line, ident.Column)
		}
	})

	t.Run("column_advances_after_indent", func(t *testing.T) {
		toks := Lex("   foo")
		if toks[0].Column != 4 {
			t.Fatalf("toks[0].Column = %d, want 4 (three spaces then 'foo')", toks[0].Column)
		}
	})
}

// ========================== 11. Real expression ============================================

func TestLex_RealExpression(t *testing.T) {
	// A representative WAF-style expression mixing several token kinds.
	src := `ip.src eq ip"10.0.0.0/8"`
	toks := Lex(src)

	wantKinds := []TokenKind{
		TIdent,   // ip.src
		TKeyword, // eq
		TIP,      // ip"10.0.0.0/8"
		TEOF,
	}
	if !kindsEqual(kinds(toks), wantKinds) {
		t.Fatalf("kinds: got %v want %v (full=%#v)", kinds(toks), wantKinds, toks)
	}
	if toks[0].Value != "ip.src" {
		t.Fatalf("toks[0].Value = %q, want %q", toks[0].Value, "ip.src")
	}
	if toks[1].Value != "eq" {
		t.Fatalf("toks[1].Value = %q, want %q", toks[1].Value, "eq")
	}
	if toks[2].Value != "10.0.0.0/8" {
		t.Fatalf("toks[2].Value = %q, want %q", toks[2].Value, "10.0.0.0/8")
	}
}

// ========================== 12. (covered by TestLex_Kinds "empty_input") =================

// ========================== 13. Errors do not stop lexing =================================

func TestLex_ErrorsDontStop(t *testing.T) {
	// The lexer advances past the SINGLE offending byte (@) and surfaces it as
	// a TError; the subsequent bytes ("bad 42") are then tokenized normally.
	src := "@bad 42"
	toks := Lex(src)
	wantKinds := []TokenKind{TError, TIdent, TInt, TEOF}
	if !kindsEqual(kinds(toks), wantKinds) {
		t.Fatalf("kinds: got %v want %v (full=%#v)", kinds(toks), wantKinds, toks)
	}
	if toks[2].Value != "42" {
		t.Fatalf("after TError the lexer must continue — toks[2] = %#v", toks[2])
	}
}

// ========================== 14. Concurrency safety ========================================

func TestLex_Concurrent(t *testing.T) {
	// Each goroutine lexes a different source on a different goroutine. Because Lex
	// allocates a fresh lexer per call, there is no shared state — this is a smoke
	// test for the race detector. We compare each goroutine's output to its expected
	// token slice to also catch any cross-call contamination.
	srcs := []string{
		"ip.src eq ip\"10.0.0.0/8\"",
		"http.uri.path contains \"admin\"",
		"core.stream in [\"a\", \"b\"]",
		"count ge 100",
	}
	expected := [][]Token{
		Lex(srcs[0]),
		Lex(srcs[1]),
		Lex(srcs[2]),
		Lex(srcs[3]),
	}

	var wg sync.WaitGroup
	results := make([][]Token, len(srcs))
	errs := make([]error, len(srcs))
	for i, src := range srcs {
		i, src := i, src
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = Lex(src)
		}()
	}
	wg.Wait()

	for i := range srcs {
		if errs[i] != nil {
			t.Fatalf("src[%d]: %v", i, errs[i])
		}
		if !reflect.DeepEqual(results[i], expected[i]) {
			t.Fatalf("src[%d] = %q: concurrent result differs from sequential baseline\n got  %#v\n want %#v",
				i, srcs[i], results[i], expected[i])
		}
	}
}

// ========================== Bonus: TokenKind.String and IsReserved =======================

func TestTokenKind_String(t *testing.T) {
	cases := []struct {
		k    TokenKind
		want string
	}{
		{TEOF, "eof"},
		{TError, "error"},
		{TIdent, "ident"},
		{TString, "string"},
		{TInt, "int"},
		{TFloat, "float"},
		{TDuration, "duration"},
		{TTimestamp, "timestamp"},
		{TIP, "ip"},
		{TBytes, "bytes"},
		{TBool, "bool"},
		{TKeyword, "keyword"},
		{TLParen, "lparen"},
		{TRParen, "rparen"},
		{TLBrack, "lbrack"},
		{TRBrack, "rbrack"},
		{TComma, "comma"},
		{TokenKind(255), "unknown(255)"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("TokenKind(%d).String() = %q, want %q", tc.k, got, tc.want)
		}
	}
}

func TestIsReserved(t *testing.T) {
	reserved := []string{"and", "or", "not", "in", "eq", "ne", "lt", "le", "gt", "ge",
		"contains", "starts_with", "ends_with", "matches", "wildcard", "strict"}
	for _, s := range reserved {
		if !IsReserved(s) {
			t.Errorf("IsReserved(%q) = false, want true", s)
		}
	}

	notReserved := []string{"http", "core", "stream", "ip", "ts", "true", "false",
		"foo", "eq_", "_eq", "AND", ""}
	for _, s := range notReserved {
		if IsReserved(s) {
			t.Errorf("IsReserved(%q) = true, want false", s)
		}
	}
}

func TestError_constructor(t *testing.T) {
	tok := Error(7, 3, "boom")
	if tok.Kind != TError {
		t.Fatalf("Kind = %v, want TError", tok.Kind)
	}
	if tok.Value != "boom" {
		t.Fatalf("Value = %q, want %q", tok.Value, "boom")
	}
	if tok.Line != 7 || tok.Column != 3 {
		t.Fatalf("position = (%d, %d), want (7, 3)", tok.Line, tok.Column)
	}
}

// ========================== Bonus: LexSingle convenience =================================

func TestLexSingle(t *testing.T) {
	t.Run("empty_input", func(t *testing.T) {
		tok, err := LexSingle("")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if tok.Kind != TEOF {
			t.Fatalf("Kind = %v, want TEOF", tok.Kind)
		}
	})

	t.Run("single_ident", func(t *testing.T) {
		tok, err := LexSingle("http")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if tok.Kind != TIdent || tok.Value != "http" {
			t.Fatalf("got (%v, %q), want (TIdent, \"http\")", tok.Kind, tok.Value)
		}
	})

	t.Run("lexical_error_before_first_token", func(t *testing.T) {
		_, err := LexSingle("@bad")
		if err == nil {
			t.Fatalf("expected error for bad input, got nil")
		}
	})

	t.Run("trivia_before_first_token_is_ok", func(t *testing.T) {
		tok, err := LexSingle("   \n# c\n42")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if tok.Kind != TInt || tok.Value != "42" {
			t.Fatalf("got (%v, %q), want (TInt, \"42\")", tok.Kind, tok.Value)
		}
	})
}

// Compile-time assertion: `kindsEqual` is currently unreferenced (no test compares
// []TokenKind directly), but is kept as a readable helper alongside `kinds` for
// future cases. This line stops linters from flagging it as dead code.
var _ = kindsEqual
