// ========================== pkg/rule/lexer — token types =================================
//   WHAT IS HERE:
//     - TokenKind — closed enum of every token the lexer can emit (D14). Bumping the
//       enum is a breaking change to the parser (B2); do NOT add kinds speculatively.
//     - Token — the value carrier. One struct per token; payload fields (Value / Bytes /
//       Bool) are valid only for the corresponding Kind — the lexer always sets them
//       to their zero value otherwise so callers can rely on a stable shape.
//     - TokenKind.String() — stable lowercase diagnostic name. Mirrors the Kind.String()
//       pattern in pkg/rule/types.go.
//     - IsReserved() — exported lookup for the parser to share. Reserved words are the
//       operator keywords (and, or, not, in, eq, ne, lt, le, gt, ge, contains,
//       starts_with, ends_with, matches, wildcard, strict). true / false are TBool, NOT
//       TKeyword, so they are NOT in this set.
//     - Error() — helper to build a TError token at a given source position; reused
//       by the lexer internally and exposed for tests / future parser-driven diagnostics.
//
//   WHAT IS NOT HERE:
//     - The lexer state machine (lexer.go).
//     - Source-to-token conversion (Lex in lexer.go).
//     - Any semantic validation — duration strings, RFC3339 timestamps, IP addresses,
//       and CIDR ranges are validated by the parser / compiler, NOT here. The lexer
//       only enforces lexical well-formedness.
//
//   DEPENDENCY RULE:
//     stdlib only (D2). No external imports beyond what the Go standard library ships.
//
//   CONCURRENCY:
//     Token is a plain value type. TokenKind is a typed uint8 constant enum.
//     Tokens may be shared across goroutines without synchronization.

package lexer

import "strconv"

// ========================== TokenKind — closed enum =======================================

// TokenKind enumerates every token the lexer emits. It is a typed uint8 wrapper so the
// type system catches accidental mixing with raw integers (mirrors Kind in
// pkg/rule/types.go). The set is CLOSED — adding a kind requires updating the parser
// (B2) and the compiler (C1) in lockstep.
type TokenKind uint8

const (
	// TEOF marks end of input. Lex always returns exactly one TEOF as the last token,
	// even when the input is empty or when earlier tokens were TError.
	TEOF TokenKind = iota

	// TError carries a lexical error message in Value. The lexer does NOT stop on
	// the first TError — it advances past the offending bytes and continues, so
	// downstream passes get a complete token picture.
	TError

	// TIdent is a lowercase identifier, optionally dotted (e.g. "http.uri.path").
	// Dotted form is lexed as a SINGLE token — the dot is part of the identifier
	// grammar, not a separator. Reserved words (and, or, ...) lex as TKeyword, not
	// TIdent, when they appear as bare barewords.
	TIdent

	// TString is a double-quoted string with backslash escapes (\n \t \r \" \\).
	// Value carries the DECODED string — escape sequences are resolved by the lexer.
	TString

	// TInt is an unsigned integer literal [0-9]+. Value carries the digit string;
	// the parser does the signed conversion via strconv.ParseInt.
	TInt

	// TFloat is a float literal — [0-9]+\.[0-9]+([eE][-+]?[0-9]+)? or
	// [0-9]+[eE][-+]?[0-9]+. Value carries the literal text verbatim; the parser
	// does strconv.ParseFloat. The lexer DOES distinguish TInt vs TFloat syntactically
	// so downstream code does not need to re-decide.
	TFloat

	// TDuration is a Go-style duration literal — "<int><unit>" pairs with unit in
	// {ns, us, µs, ms, s, m, h}, optionally chained (e.g. "1h30m"). Value carries the
	// raw matched string; validation via time.ParseDuration is deferred to the parser.
	TDuration

	// TTimestamp is a "ts"..." prefix-string literal. Value carries the INNER string
	// (without the ts prefix and without the surrounding quotes); RFC3339 validation
	// is the parser's job.
	TTimestamp

	// TIP is an "ip"..." prefix-string literal. Value carries the INNER string
	// verbatim — the lexer does NOT distinguish IP from CIDR; the compiler does.
	TIP

	// TBytes is a 0x"..." hex-byte literal. The hex is decoded at lex time; Bytes
	// carries the raw bytes. Empty hex (0x"") yields an empty (non-nil) byte slice.
	// Invalid hex (odd length, non-hex chars) yields TError, NOT TBytes.
	TBytes

	// TBool is a boolean literal — true / false. These are reserved; the lexer
	// never emits them as TIdent or TKeyword. Bool carries the parsed value.
	TBool

	// TKeyword is a reserved operator word. Value carries the keyword text verbatim
	// (e.g. "and", "eq", "contains"). A namespace-qualified identifier like
	// "core.eq" is always TIdent, even if one of its components happens to match a
	// reserved word — only bare standalone words become TKeyword.
	TKeyword

	// TLParen / TRParen — parentheses "(", ")".
	TLParen
	TRParen

	// TLBrack / TRBrack — square brackets "[", "]".
	TLBrack
	TRBrack

	// TComma — "," separator.
	TComma

	// TComment is intentionally absent from the public token set. Line comments
	// ("# ...") are consumed silently by the lexer and NEVER appear in the token
	// stream (D14).
)

// String returns the canonical lowercase diagnostic name of the TokenKind. The output
// is stable across versions — it is part of the engine's diagnostic surface (error
// messages, log lines, debug output). Unknown / future kinds render via
// "unknown(<n>)" so the formatter never panics on an out-of-range value.
func (k TokenKind) String() string {
	switch k {
	case TEOF:
		return "eof"
	case TError:
		return "error"
	case TIdent:
		return "ident"
	case TString:
		return "string"
	case TInt:
		return "int"
	case TFloat:
		return "float"
	case TDuration:
		return "duration"
	case TTimestamp:
		return "timestamp"
	case TIP:
		return "ip"
	case TBytes:
		return "bytes"
	case TBool:
		return "bool"
	case TKeyword:
		return "keyword"
	case TLParen:
		return "lparen"
	case TRParen:
		return "rparen"
	case TLBrack:
		return "lbrack"
	case TRBrack:
		return "rbrack"
	case TComma:
		return "comma"
	default:
		return "unknown(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
}

// ========================== Token — value carrier =========================================

// Token is one lexer output unit. The payload fields are kind-specific:
//
//   - Value  — decoded/normalized text for TString, TInt, TFloat, TDuration,
//     TTimestamp, TIP, TIdent, TKeyword, TError. Empty for punctuation and
//     TEOF.
//   - Bytes  — decoded hex for TBytes (never nil for TBytes; an empty hex yields an
//     empty slice). nil for every other kind.
//   - Bool   — the parsed boolean for TBool. False for every other kind.
//   - Line   — 1-indexed source line where the token starts.
//   - Column — 1-indexed column within Line where the token starts.
//
// The lexer guarantees a stable shape: every Token has all fields set, even if the
// payload field is not meaningful for that Kind. This lets callers use a single struct
// type across the whole pipeline.
type Token struct {
	Kind   TokenKind
	Value  string
	Bytes  []byte
	Bool   bool
	Line   int
	Column int
}

// ========================== Reserved words ================================================

// keywords is the closed set of operator words that lex as TKeyword when they appear as
// bare standalone words. Namespace-qualified identifiers (e.g. "core.eq") never match —
// they are TIdent, with the dot serving as the disambiguator.
//
// true / false are deliberately excluded — they are TBool (a distinct Kind), not
// TKeyword. They are still reserved in the sense that they cannot be used as bare field
// names, but the lexer emits them under a different Kind.
var keywords = map[string]struct{}{
	"and":         {},
	"or":          {},
	"not":         {},
	"in":          {},
	"eq":          {},
	"ne":          {},
	"lt":          {},
	"le":          {},
	"gt":          {},
	"ge":          {},
	"contains":    {},
	"starts_with": {},
	"ends_with":   {},
	"matches":     {},
	"wildcard":    {},
	"strict":      {},
}

// IsReserved reports whether s is a reserved operator word. Exported so the parser (B2)
// can share the same definition rather than re-declaring it. Excludes true / false
// (those are TBool and have their own check path).
func IsReserved(s string) bool {
	_, ok := keywords[s]
	return ok
}

// ========================== Error constructor =============================================

// Error builds a TError token at the given source position. Useful from tests and from
// future code that needs to fabricate an error token without going through the lexer
// (e.g. a parser checking pre-conditions). The lexer uses this internally too.
func Error(line, col int, msg string) Token {
	return Token{Kind: TError, Value: msg, Line: line, Column: col}
}
