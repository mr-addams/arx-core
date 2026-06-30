// ========================== pkg/rule/lexer — lexer ========================================
//   WHAT IS HERE:
//     - Lex — full-source tokenizer. Returns the complete token slice (always terminated
//       by a single TEOF). Lexical errors are emitted as inline TError tokens so the
//       parser gets a complete picture; Lex never stops on the first error.
//     - LexSingle — convenience wrapper used by tests / single-word lookups.
//     - The unexported lexer struct — single-goroutine, one Lex call per instance.
//       A fresh lexer is allocated on every Lex invocation, so concurrent callers
//       never share state.
//     - Per-Kind scan functions (scanIdent, scanNumber, scanString, scanBytes,
//       scanTimestamp, scanIP) — each consumes its slice and returns exactly one token.
//
//   WHAT IS NOT HERE:
//     - TokenKind / Token types — those live in token.go so the parser (B2) can import
//       them without dragging the scanner implementation.
//     - Semantic validation — the lexer does NOT parse RFC3339 timestamps, IP addresses,
//       CIDR ranges, or duration values via time.ParseDuration. It only enforces lexical
//       well-formedness. The parser / compiler owns validation (D14).
//     - Error recovery policy — the lexer emits TError tokens inline but does NOT
//       attempt sophisticated recovery (e.g. synchronization to the next statement).
//       The downstream parser decides how to react to a TError sequence.
//
//   DEPENDENCY RULE:
//     stdlib only (D2). Imported packages are limited to encoding/hex (for 0x"..."
//     decoding) and fmt (for error message formatting). No third-party deps.
//
//   CONCURRENCY:
//     A fresh lexer is allocated on every Lex() call, so concurrent callers
//     never share state. Lex and LexSingle are safe for concurrent use.

package lexer

import (
	"encoding/hex"
	"fmt"
)

// ========================== Public API ====================================================

// Lex tokenizes src into a slice of tokens. The result always ends with exactly one
// TEOF token, even when src is empty or earlier tokens are TError. Lexical errors do
// not stop the scan — they are recorded as TError tokens and the lexer advances past
// the offending bytes, so the returned slice gives the parser a complete view of the
// source (including the positions of every error).
//
// Lex allocates a fresh internal lexer per call. It is safe to call Lex concurrently
// from multiple goroutines with independent sources.
func Lex(src string) []Token {
	l := &lexer{
		src:  []byte(src),
		line: 1,
		col:  1,
	}
	// Pre-size to avoid grow-and-copy in the common case (expressions are short;
	// the average token count is well below 100 for typical rules).
	tokens := make([]Token, 0, 16)
	for {
		l.skipTrivia()
		// Drain any error stashed by skipTrivia (currently only bare '\r'). Emit
		// the token inline so it appears at its source position, then continue.
		if l.pendingErr != nil {
			tokens = append(tokens, *l.pendingErr)
			l.pendingErr = nil
		}
		if l.pos >= len(l.src) {
			tokens = append(tokens, Token{Kind: TEOF, Line: l.line, Column: l.col})
			return tokens
		}
		tok := l.scanToken()
		tokens = append(tokens, tok)
		// TEOF terminates — scanToken only emits it when the source is exhausted.
		if tok.Kind == TEOF {
			return tokens
		}
	}
}

// LexSingle returns the first non-EOF token from Lex(src) and an error if any TError
// token appeared before that first non-EOF token. Useful for one-token checks in
// tests and for tooling that needs a "look at the first thing" primitive without
// walking the whole slice.
//
// LexSingle allocates internally via Lex — there is no shared state with other calls.
func LexSingle(src string) (Token, error) {
	toks := Lex(src)
	if len(toks) == 0 {
		// Should not happen — Lex always emits TEOF — but defend anyway.
		return Token{}, fmt.Errorf("lexer: empty token stream")
	}
	for _, t := range toks {
		if t.Kind == TError {
			return t, fmt.Errorf("%d:%d: %s", t.Line, t.Column, t.Value)
		}
		if t.Kind != TEOF {
			return t, nil
		}
	}
	// Only TEOF in the stream (e.g. empty input).
	return Token{Kind: TEOF}, nil
}

// ========================== lexer state ===================================================

// lexer is a single-goroutine source scanner. One instance per Lex call — no shared
// state across invocations. Position tracking uses 1-indexed line and column, both
// reset at construction.
type lexer struct {
	src  []byte
	pos  int // current byte offset; l.src[pos:] is the unconsumed suffix
	line int // 1-indexed source line of the byte at l.pos
	col  int // 1-indexed column within line of the byte at l.pos

	// pendingErr is non-nil iff skipTrivia has detected a bare '\r' that the main
	// loop still needs to surface as an inline TError token. Cleared after emission.
	// The indirection exists because Lex needs to APPEND the error to its token
	// slice — skipTrivia alone cannot do that without coupling to the main loop.
	pendingErr *Token
}

// ========================== Trivia ========================================================

// skipTrivia advances past whitespace and comments. Whitespace includes space, tab,
// newline, and CRLF (treated as one newline). A lone CR (not followed by LF) is a
// lexical error — skipTrivia stashes a TError in l.pendingErr for the main loop
// to surface inline, then continues skipping past the offending byte.
//
// Comments start with '#' and run to the next '\n' (or EOF). The '#' and everything
// up to (but not including) the newline is consumed silently — no token is emitted.
func (l *lexer) skipTrivia() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case ' ', '\t':
			l.advance(1)
		case '\n':
			l.advance(1)
		case '\r':
			// CRLF is one newline. Bare CR is an error.
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n' {
				l.advance(2)
				continue
			}
			line, col := l.line, l.col
			l.advance(1)
			l.pendingErr = &Token{
				Kind:   TError,
				Value:  "bare carriage return (\\r) — use \\n or \\r\\n",
				Line:   line,
				Column: col,
			}
		case '#':
			// Line comment: consume until '\n' (or EOF). Do NOT consume the '\n' —
			// let the outer loop's next iteration handle it as whitespace.
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance(1)
			}
		default:
			return
		}
	}
}

// ========================== Position tracking =============================================

// advance moves the cursor forward by n bytes, updating line/col. '\n' resets col to 1
// and bumps line; every other byte just bumps col. Callers must ensure n >= 1 and
// n does not cross past src (the caller should have already bounds-checked).
func (l *lexer) advance(n int) {
	for i := 0; i < n; i++ {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
		l.pos++
	}
}

// here returns the current source position as (line, col). Captured at the START of
// each token scan so the position reflects where the token begins, not where it ends.
func (l *lexer) here() (int, int) {
	return l.line, l.col
}

// ========================== Token dispatcher ==============================================

// scanToken reads one token starting at l.pos and returns it. The cursor is advanced
// past the token's bytes (or, in the error cases, past the offending byte). Trivia
// MUST have been skipped by the caller — this function expects l.pos to point at a
// real token-start character.
func (l *lexer) scanToken() Token {
	line, col := l.here()
	c := l.src[l.pos]
	switch {
	case c == '"':
		return l.scanString(line, col)
	case c == '0':
		// 0x"...", or 0 (digit start).
		if l.pos+2 < len(l.src) && l.src[l.pos+1] == 'x' && l.src[l.pos+2] == '"' {
			return l.scanBytes(line, col)
		}
		return l.scanNumber(line, col)
	case c >= '1' && c <= '9':
		return l.scanNumber(line, col)
	case c == 't':
		// ts"..." prefix-string, or bare identifier starting with 't' (incl. the
		// reserved boolean "true").
		if l.pos+2 < len(l.src) && l.src[l.pos+1] == 's' && l.src[l.pos+2] == '"' {
			return l.scanTimestamp(line, col)
		}
		return l.scanIdentOrKeyword(line, col)
	case c == 'i':
		// ip"..." prefix-string, or bare identifier starting with 'i' (incl. the
		// reserved keyword "in", which would still lex as TKeyword via scanIdent).
		if l.pos+2 < len(l.src) && l.src[l.pos+1] == 'p' && l.src[l.pos+2] == '"' {
			return l.scanIP(line, col)
		}
		return l.scanIdentOrKeyword(line, col)
	case isLowerLetter(c):
		return l.scanIdentOrKeyword(line, col)
	case c >= 'A' && c <= 'Z':
		// Uppercase is forbidden by the identifier grammar — emit TError and advance
		// one byte so the next token-start is not on the same offending character.
		l.advance(1)
		return Error(line, col, "uppercase letter in identifier — rule language is lowercase-only")
	case c == '(':
		l.advance(1)
		return Token{Kind: TLParen, Line: line, Column: col}
	case c == ')':
		l.advance(1)
		return Token{Kind: TRParen, Line: line, Column: col}
	case c == '[':
		l.advance(1)
		return Token{Kind: TLBrack, Line: line, Column: col}
	case c == ']':
		l.advance(1)
		return Token{Kind: TRBrack, Line: line, Column: col}
	case c == ',':
		l.advance(1)
		return Token{Kind: TComma, Line: line, Column: col}
	case c == '&':
		// Bitwise AND operator — tokenized as punctuation (no reserved-word
		// handling). Bound to the `value & mask` all-bits-set bitmask test on
		// KindBytes; see DECISION D19 and the BitAnd AST / opBitAnd plumbing
		// in parser / compiler / evaluator.
		l.advance(1)
		return Token{Kind: TAmpersand, Line: line, Column: col}
	default:
		// Any other byte is unrecognized — emit TError and advance one byte. This
		// keeps the lexer moving past unknown bytes so the parser can report a
		// complete error set instead of looping forever on the same character.
		l.advance(1)
		return Error(line, col, fmt.Sprintf("unexpected character %q", rune(c)))
	}
}

// ========================== Identifier / keyword / bool ==================================

// scanIdentOrKeyword consumes a lowercase identifier (with optional dotted segments)
// and returns TIdent / TKeyword / TBool depending on what was read. The caller must
// have verified that l.src[l.pos] is a lowercase letter.
//
//   - Bare reserved operator word (e.g. "and", "eq", "contains") → TKeyword
//   - Bare "true" / "false" → TBool
//   - Anything else (incl. namespace-qualified names like "core.eq") → TIdent
func (l *lexer) scanIdentOrKeyword(line, col int) Token {
	start := l.pos
	// First segment: [a-z][a-z0-9_]*
	l.advance(1) // consume the lowercase letter we already verified
	for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
		l.advance(1)
	}
	// Subsequent segments: ".[a-z][a-z0-9_]*" — only if the dot is followed by a
	// lowercase letter (so "foo.42" or "foo." are NOT continued — they will become
	// a TError on the dot in the next iteration of Lex's main loop).
	for l.pos+1 < len(l.src) && l.src[l.pos] == '.' && isLowerLetter(l.src[l.pos+1]) {
		l.advance(1) // consume '.'
		l.advance(1) // consume the leading lowercase letter of the next segment
		for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
			l.advance(1)
		}
	}
	text := string(l.src[start:l.pos])

	// Reserved-word disambiguation: only BARE words (no dot) become TKeyword. A
	// qualified name like "core.eq" is always TIdent — the dot is the structural
	// separator that prevents accidental collisions.
	hasDot := false
	for i := 0; i < len(text); i++ {
		if text[i] == '.' {
			hasDot = true
			break
		}
	}
	if !hasDot {
		// Booleans are checked first so "true" / "false" never accidentally become
		// TKeyword (they are reserved words in a different sense — the lexer emits
		// a distinct Kind for them).
		if text == "true" {
			return Token{Kind: TBool, Bool: true, Line: line, Column: col}
		}
		if text == "false" {
			return Token{Kind: TBool, Bool: false, Line: line, Column: col}
		}
		if IsReserved(text) {
			return Token{Kind: TKeyword, Value: text, Line: line, Column: col}
		}
	}
	return Token{Kind: TIdent, Value: text, Line: line, Column: col}
}

// ========================== Number (int / float / duration) ===============================

// scanNumber consumes an unsigned numeric literal — TInt, TFloat, or TDuration —
// depending on what follows the digit run. The caller must have verified that the
// current byte is a digit (0–9).
//
// Disambiguation rule (D14):
//   - digits "." digits [eE][+-]?digits → TFloat (fractional form, optional exponent)
//   - digits [eE][+-]?digits           → TFloat (pure exponent form, no fractional part)
//   - digits (duration unit) (digits duration unit)* → TDuration (greedy chain)
//   - everything else                   → TInt
//
// Float is checked before Duration so that pure-exponent forms like "1e10" lex as
// TFloat, not TDuration. The Duration unit set does not contain 'e' / 'E', so this
// ordering does not produce ambiguity — but the explicit check keeps the rule clear.
func (l *lexer) scanNumber(line, col int) Token {
	start := l.pos
	l.scanDigits()

	// Fractional float form: digits "." digits ([eE][+-]?digits)?
	if l.pos < len(l.src) && l.src[l.pos] == '.' {
		if l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1]) {
			l.advance(1) // consume '.'
			l.scanDigits()
			if l.scanOptionalExponent() {
				return Error(line, col, "malformed float literal: digits required after exponent")
			}
			return Token{Kind: TFloat, Value: string(l.src[start:l.pos]), Line: line, Column: col}
		}
		// '.' NOT followed by a digit — malformed float (D14 explicitly rejects "42.").
		l.advance(1) // consume '.'
		return Error(line, col, "malformed float literal: digits required after '.'")
	}

	// Pure-exponent float form: digits [eE][+-]?digits (no fractional part).
	// This branch must be evaluated BEFORE the Duration branch so that "1e10"
	// becomes TFloat, not a broken Duration attempt.
	if l.pos < len(l.src) && (l.src[l.pos] == 'e' || l.src[l.pos] == 'E') {
		// Save the position so we can rewind if the exponent is malformed (e.g.
		// "1e" with no digits after) — though D14 implies we should still emit
		// TError rather than TInt, the rewind keeps the diagnostic message anchored
		// to the start of the literal.
		saved := l.pos
		l.advance(1) // consume 'e'/'E'
		if l.pos < len(l.src) && (l.src[l.pos] == '+' || l.src[l.pos] == '-') {
			l.advance(1)
		}
		if l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.scanDigits()
			return Token{Kind: TFloat, Value: string(l.src[start:l.pos]), Line: line, Column: col}
		}
		// Malformed exponent (no digits after [eE][+-]?) — rewind so the duration
		// branch can still inspect the byte. If the duration branch does not match
		// either, we fall through to TInt with the original digits.
		l.pos = saved
	}

	// Duration form: greedy "<unit><digits>" chain. We COMMIT to TDuration the
	// moment we see a duration unit char at the current position — even if no
	// "<unit><digits>" pair follows (e.g. "5s" with nothing after 's' is a valid
	// duration). The reverse case ("5x" where x is not a unit) is handled by
	// matchDurationUnit returning 0 — we then fall back to TInt.
	if unitLen := matchDurationUnit(l.src, l.pos); unitLen > 0 {
		l.advance(unitLen)
		// Greedily consume as many "<digits><unit>" pairs as we can. The loop is
		// structured as: digits-required → unit-required → repeat. We break out
		// when either the digits or the unit is missing, leaving the cursor at
		// the byte that stopped the scan (so the main loop picks it up as the
		// next token if it is meaningful on its own — e.g. an identifier letter).
		for {
			// A unit must be FOLLOWED by digits to extend the chain. Without
			// following digits, we stop — the trailing unit is part of the
			// literal but the chain ends.
			if l.pos >= len(l.src) || !isDigit(l.src[l.pos]) {
				break
			}
			l.scanDigits()
			// After digits, peek for another unit. If none, the chain ends here.
			next := matchDurationUnit(l.src, l.pos)
			if next == 0 {
				break
			}
			l.advance(next)
			// Loop again — the next iteration will demand digits after this unit.
		}
		return Token{Kind: TDuration, Value: string(l.src[start:l.pos]), Line: line, Column: col}
	}

	return Token{Kind: TInt, Value: string(l.src[start:l.pos]), Line: line, Column: col}
}

// scanOptionalExponent handles the optional "[eE][+-]?digits" suffix on a fractional
// float literal. Caller has already consumed the fractional digits and l.src[l.pos]
// is at the candidate exponent byte (or past EOF). Returns true on a malformed
// exponent (no digits after [eE][+-]?) — the caller surfaces the TError, anchored
// at the literal's own start (line, col) so the message is positioned where the bad
// float began rather than at the trailing 'e'.
//
// Extracted into a helper so the pure-exponent branch in scanNumber stays readable
// without duplicating the sign + digit logic.
func (l *lexer) scanOptionalExponent() bool {
	if l.pos >= len(l.src) || (l.src[l.pos] != 'e' && l.src[l.pos] != 'E') {
		return false
	}
	l.advance(1) // consume 'e' / 'E'
	if l.pos < len(l.src) && (l.src[l.pos] == '+' || l.src[l.pos] == '-') {
		l.advance(1)
	}
	if l.pos >= len(l.src) || !isDigit(l.src[l.pos]) {
		return true // malformed — caller emits TError
	}
	l.scanDigits()
	return false
}

// scanDigits consumes one or more ASCII digits starting at l.pos. The caller must
// have verified that l.src[l.pos] is a digit (or that we are at EOF — but then the
// loop body never executes, which is fine).
func (l *lexer) scanDigits() {
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.advance(1)
	}
}

// ========================== String literal ================================================

// scanString consumes a double-quoted string with backslash escapes. The decoded
// content is returned in TString.Value. On lexical error (unterminated string,
// unknown escape, embedded newline) it returns TError and advances past the
// offending portion so the main loop can continue.
//
// Recognized escapes: \n \t \r \" \\ — exactly these, per D14. Any other backslash
// sequence is a lexical error.
func (l *lexer) scanString(line, col int) Token {
	l.advance(1) // consume opening '"'
	var buf []byte
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '"' {
			l.advance(1) // consume closing '"'
			return Token{Kind: TString, Value: string(buf), Line: line, Column: col}
		}
		if c == '\n' {
			return Error(line, col, "newline inside string literal")
		}
		if c == '\\' {
			if l.pos+1 >= len(l.src) {
				return Error(line, col, "unterminated string literal (escape at EOF)")
			}
			esc := l.src[l.pos+1]
			switch esc {
			case 'n':
				buf = append(buf, 0x0A)
			case 't':
				buf = append(buf, 0x09)
			case 'r':
				buf = append(buf, 0x0D)
			case '"':
				buf = append(buf, '"')
			case '\\':
				buf = append(buf, '\\')
			default:
				// Unknown escape — consume up to the closing quote (or newline) so
				// the next iteration of Lex's main loop does not see garbage bytes.
				msg := fmt.Sprintf("unknown escape sequence: \\%c", rune(esc))
				for l.pos < len(l.src) && l.src[l.pos] != '"' && l.src[l.pos] != '\n' {
					l.advance(1)
				}
				if l.pos < len(l.src) && l.src[l.pos] == '"' {
					l.advance(1)
				}
				return Error(line, col, msg)
			}
			l.advance(2) // consume '\' and the escape char
			continue
		}
		buf = append(buf, c)
		l.advance(1)
	}
	// Reached EOF without a closing quote.
	return Error(line, col, "unterminated string literal")
}

// ========================== Prefix-string literals ========================================

// scanTimestamp consumes ts"..." — the caller has already verified that the prefix is
// present. The returned TTimestamp.Value is the inner string (without the ts prefix
// and without the surrounding quotes). RFC3339 validation is the parser's job (D14).
func (l *lexer) scanTimestamp(line, col int) Token {
	return l.scanPrefixString(line, col, TTimestamp)
}

// scanIP consumes ip"..." — same semantics as scanTimestamp, just a different Kind.
// IP vs CIDR distinction is the parser/compiler's concern, not the lexer's.
func (l *lexer) scanIP(line, col int) Token {
	return l.scanPrefixString(line, col, TIP)
}

// scanPrefixString is the shared body for ts"..." and ip"...". The prefix bytes are
// consumed up front (the caller verified they are present and immediately followed
// by '"'); then the inner string is read with the same escape rules as a regular
// TString. The closing '"' terminates the literal.
//
// Error cases: unterminated literal, embedded newline — both yield TError and the
// cursor is left pointing past the offending bytes (either at the next char or at
// EOF, depending on where the error fired).
func (l *lexer) scanPrefixString(line, col int, kind TokenKind) Token {
	l.advance(3) // consume "ts\"" or "ip\""
	var buf []byte
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '"' {
			l.advance(1)
			return Token{Kind: kind, Value: string(buf), Line: line, Column: col}
		}
		if c == '\n' {
			return Error(line, col, "newline inside prefix-string literal")
		}
		if c == '\\' {
			if l.pos+1 >= len(l.src) {
				return Error(line, col, "unterminated prefix-string literal (escape at EOF)")
			}
			esc := l.src[l.pos+1]
			switch esc {
			case 'n':
				buf = append(buf, 0x0A)
			case 't':
				buf = append(buf, 0x09)
			case 'r':
				buf = append(buf, 0x0D)
			case '"':
				buf = append(buf, '"')
			case '\\':
				buf = append(buf, '\\')
			default:
				msg := fmt.Sprintf("unknown escape sequence: \\%c", rune(esc))
				for l.pos < len(l.src) && l.src[l.pos] != '"' && l.src[l.pos] != '\n' {
					l.advance(1)
				}
				if l.pos < len(l.src) && l.src[l.pos] == '"' {
					l.advance(1)
				}
				return Error(line, col, msg)
			}
			l.advance(2)
			continue
		}
		buf = append(buf, c)
		l.advance(1)
	}
	return Error(line, col, "unterminated prefix-string literal")
}

// ========================== Bytes literal =================================================

// scanBytes consumes 0x"<hex>" — the caller verified the prefix and the opening quote.
// The hex payload is decoded via encoding/hex; on success TBytes.Bytes holds the raw
// bytes. Empty hex (0x"") yields an empty (non-nil) byte slice. On hex error (odd
// length, non-hex char) the function returns TError and consumes up through the
// closing quote.
func (l *lexer) scanBytes(line, col int) Token {
	l.advance(3) // consume 0x"
	// Capture the start of the hex payload so we can slice it out without
	// allocating an intermediate buffer for each character.
	hexStart := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '"' && l.src[l.pos] != '\n' {
		l.advance(1)
	}
	if l.pos >= len(l.src) {
		return Error(line, col, "unterminated bytes literal")
	}
	if l.src[l.pos] == '\n' {
		return Error(line, col, "newline inside bytes literal")
	}
	hexStr := string(l.src[hexStart:l.pos])
	l.advance(1) // consume closing '"'

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return Error(line, col, fmt.Sprintf("invalid hex in bytes literal: %s", err.Error()))
	}
	return Token{Kind: TBytes, Bytes: decoded, Line: line, Column: col}
}

// ========================== Character-class helpers ======================================

// isLowerLetter reports whether c is in [a-z] — the only allowed identifier-start
// character. Uppercase is a lexical error (handled by scanToken's dispatch).
func isLowerLetter(c byte) bool { return c >= 'a' && c <= 'z' }

// isDigit reports whether c is in [0-9].
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isIdentCont reports whether c can appear in the body of an identifier segment —
// lowercase letter, digit, or underscore. Hyphen, uppercase, dot, etc. are not
// allowed inside a segment (they end the segment).
func isIdentCont(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

// matchDurationUnit returns the byte length of the duration unit suffix starting at
// src[pos], or 0 if src[pos] does not start a unit. Recognized units and lengths:
//
//	ns (2) — nanoseconds
//	us (2) — microseconds
//	µs (3) — microseconds, UTF-8 of µ is 0xC2 0xB5
//	ms (2) — milliseconds
//	s  (1) — seconds
//	m  (1) — minutes (NOT 'ms' — that is checked first)
//	h  (1) — hours
//
// Ambiguity resolution: when the current byte is 'm', we check src[pos+1] == 's'
// first to match 'ms'; otherwise we fall back to bare 'm' (1 byte). This mirrors
// Go's own time.ParseDuration behavior.
func matchDurationUnit(src []byte, pos int) int {
	if pos >= len(src) {
		return 0
	}
	switch src[pos] {
	case 'n':
		if pos+1 < len(src) && src[pos+1] == 's' {
			return 2
		}
		return 0
	case 'u':
		if pos+1 < len(src) && src[pos+1] == 's' {
			return 2
		}
		return 0
	case 'm':
		if pos+1 < len(src) && src[pos+1] == 's' {
			return 2
		}
		return 1
	case 's':
		return 1
	case 'h':
		return 1
	}
	// µ — UTF-8 0xC2 0xB5, followed by 's' for the unit.
	if src[pos] == 0xC2 && pos+2 < len(src) && src[pos+1] == 0xB5 && src[pos+2] == 's' {
		return 3
	}
	return 0
}
