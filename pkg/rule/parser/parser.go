// ========================== pkg/rule/parser — recursive-descent parser ====================
//   WHAT IS HERE:
//     - Parse(src) — the public entry point. Tokenises src via the B1 lexer and runs
//       the recursive-descent parser to produce a root AST Node.
//     - NewParser(src) / (*Parser).Parse() — alternate construction useful for tests
//       that want to assert on intermediate parser state without going through the
//       full Lex+Parse pipeline.
//     - The recursive-descent grammar itself, structured exactly as in DECISION D14
//       and TASKS.md B2:
//         expression    := or_expr
//         or_expr       := and_expr ("or" and_expr)*
//         and_expr      := unary_and ("and" unary_and)*
//         unary_and     := "not" unary_and | comparison
//         comparison    := in_expr strict_modifier?
//         in_expr       := primary "in" array_literal | cmp_or_string_op | primary
//         cmp_or_string_op := primary ("eq"|"ne"|"lt"|"le"|"gt"|"ge") primary
//                           | primary ("contains"|"starts_with"|"ends_with"|"matches"|"wildcard") primary
//         array_literal := "[" [expression ("," expression)*] "]"
//         primary       := literal | field_ref | bracket_access | func_call | "(" expression ")"
//         literal       := TString | TInt | TFloat | TDuration | TTimestamp | TIP | TBytes | TBool
//         field_ref     := TIdent
//         func_call     := TIdent "(" [expression ("," expression)*] ")"
//         bracket_access := primary "[" expression "]"
//         strict_modifier := "strict"
//       See the "strict placement" note below for the exact syntactic positions
//       where `strict` is accepted.
//
//   WHAT IS NOT HERE:
//     - Type-checking against the Scheme — that is the compiler's job (C1). The
//       parser only validates LEXICAL shape of literals (time.ParseDuration,
//       net.ParseIP, ...); semantic validation (does this field exist in the
//       Scheme? is this FuncCall name in the function table? are the operand types
//       compatible?) lives in C1.
//     - Source round-tripping — there is no formatter that re-emits the AST as
//       source text. Each node's String() is a stable diagnostic form, NOT a
//       parser input.
//
//   DEPENDENCY RULE:
//     stdlib + sibling pkg/rule (for the Value constructors) + sibling pkg/rule/lexer
//     (for the Token stream). No third-party packages — DECISION D2.
//
//   CONCURRENCY:
//     A Parser instance is single-goroutine. NewParser + Parse are independent of
//     each other and safe for concurrent use across instances; the Parser's internal
//     state (the token slice + the cursor) is never shared.

package parser

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/lexer"
)

// ========================== Public API ====================================================

// Parse tokenises src and parses it into a root AST Node. On success the node is
// non-nil and the error is nil. On failure the returned node is nil and the error
// carries the source position of the offending token (see Errorf below for format).
//
// Empty input is treated as a parse error: a rule expression MUST have at least one
// operand. This is a deliberate fail-fast — silent zero-Value returns would hide
// configuration mistakes.
func Parse(src string) (Node, error) {
	toks := lexer.Lex(src)
	p := &Parser{toks: toks}
	return p.parseExpression()
}

// NewParser constructs a Parser over the token stream produced by lexer.Lex(src).
// Exposed for tests that want to drive the parser incrementally or to assert on
// intermediate state. Most callers should use Parse directly.
func NewParser(src string) *Parser {
	return &Parser{toks: lexer.Lex(src)}
}

// Parse runs the recursive-descent parser over the parser's token stream. The result
// is the root AST node; an error is returned for any grammar failure or for leftover
// tokens after the top-level expression.
func (p *Parser) Parse() (Node, error) {
	return p.parseExpression()
}

// ========================== Parser state ==================================================

// Parser is a single-goroutine recursive-descent driver. It owns the token slice
// emitted by lexer.Lex and the cursor position. It is intentionally NOT safe for
// concurrent use — Parse() is the single externally visible operation, and the
// parser does not expose any shared mutable state.
type Parser struct {
	toks []lexer.Token
	pos  int // index of the next token to consume
}

// ========================== Error helpers =================================================

// errorf returns a formatted parse error anchored to the parser's current cursor.
// The format mirrors the lexer error style (line:col: message) so a parser error
// reads naturally next to lexer diagnostics in user-facing tools.
func (p *Parser) errorf(format string, args ...any) error {
	tok := p.peek()
	return fmt.Errorf("parse error at line %d, col %d: %s",
		tok.Line, tok.Column, fmt.Sprintf(format, args...))
}

// errorAt returns a formatted parse error anchored to a specific token's source
// position. Used when reporting an error from a position that has already been
// advanced past.
func (p *Parser) errorAt(t lexer.Token, format string, args ...any) error {
	return fmt.Errorf("parse error at line %d, col %d: %s",
		t.Line, t.Column, fmt.Sprintf(format, args...))
}

// ========================== Cursor helpers ================================================

// peek returns the token at the cursor without consuming it. It is safe to call
// past the end of the slice — peek returns a synthesised TEOF token positioned
// one column past the last real token.
func (p *Parser) peek() lexer.Token {
	if p.pos >= len(p.toks) {
		last := p.toks[len(p.toks)-1]
		return lexer.Token{Kind: lexer.TEOF, Line: last.Line, Column: last.Column + 1}
	}
	return p.toks[p.pos]
}

// consume returns the token at the cursor and advances the cursor by one. The
// return value is always defined; at EOF the synthesised TEOF token is returned
// repeatedly without further cursor advance.
func (p *Parser) consume() lexer.Token {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

// expect consumes a token of the given kind. On a kind mismatch it returns an
// error positioned at the offending token; otherwise it returns the consumed
// token. Used for closing punctuation ("expected ]") and for keyword tokens
// where the spelling matters ("expected 'and'").
func (p *Parser) expect(kind lexer.TokenKind) (lexer.Token, error) {
	t := p.peek()
	if t.Kind != kind {
		return t, p.errorAt(t, "expected %s, got %s (%q)", kind, t.Kind, t.Value)
	}
	return p.consume(), nil
}

// expectKeyword consumes a TKeyword token and verifies its spelling matches want.
// On mismatch (wrong keyword or non-keyword token) it returns an error. This is
// the path for parsing operator keywords where the TKind alone is not enough —
// "eq" vs "ne" both come through as TKeyword.
func (p *Parser) expectKeyword(want string) (lexer.Token, error) {
	t := p.peek()
	if t.Kind != lexer.TKeyword || t.Value != want {
		return t, p.errorAt(t, "expected keyword %q, got %s (%q)", want, t.Kind, t.Value)
	}
	return p.consume(), nil
}

// ========================== Grammar entry =================================================

// parseExpression parses one full expression. It is the top-level production and
// the public entry point for the grammar.
//
// Rules: an empty expression (EOF immediately) is an error. Trailing tokens after
// the top-level expression are an error — every token in the source must be
// consumed.
func (p *Parser) parseExpression() (Node, error) {
	if p.peek().Kind == lexer.TEOF {
		return nil, p.errorf("empty expression")
	}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.Kind != lexer.TEOF {
		return nil, p.errorAt(t, "unexpected token after expression: %s (%q)", t.Kind, t.Value)
	}
	return root, nil
}

// parseOr parses a disjunction of AND-ed operands. Left-associative.
func (p *Parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Kind == lexer.TKeyword && p.peek().Value == "or" {
		opTok := p.consume()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Or{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}
	}
	return left, nil
}

// parseAnd parses a conjunction of NOT / comparison operands. Left-associative.
func (p *Parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().Kind == lexer.TKeyword && p.peek().Value == "and" {
		opTok := p.consume()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &And{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}
	}
	return left, nil
}

// parseNot parses a possibly-negated operand. Chains naturally: `not not x` is
// parsed as `not(not(x))`. Right-associative by virtue of recursion.
func (p *Parser) parseNot() (Node, error) {
	if p.peek().Kind == lexer.TKeyword && p.peek().Value == "not" {
		opTok := p.consume()
		operand, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Not{Line: opTok.Line, Col: opTok.Column, Operand: operand}, nil
	}
	return p.parseComparison()
}

// parseComparison is the umbrella production for binary operator expressions.
// It defers to parseBinaryOp, which uses 1-token lookahead on the first operand's
// trailing token to disambiguate the operator family (in / cmp / string-op).
//
// `strict` placement note: the modifier can appear BEFORE or AFTER the binary
// operator keyword, wrapping the immediately adjacent operand. This matches the
// common reading: `a eq strict b` and `strict a eq b` both feel natural, and
// there is no semantic reason to forbid either. The wrapper is recorded on the
// Strict node with position anchored at the `strict` keyword itself.
func (p *Parser) parseComparison() (Node, error) {
	return p.parseBinaryOp()
}

// parseBinaryOp parses a primary and then checks whether the next token is one of
// the operator keywords. If so, it consumes the operator (and optional `strict`
// modifier on either side) and parses the right operand. If the next token is a
// keyword that does NOT begin a binary operator (e.g. `and`, `or`, `not`,
// `strict` standing alone), the primary is returned as-is.
//
// Postfix productions on the LEFT operand — `[ expression ]` for BracketAccess
// (chained: `a[b][c]`) and `strict` for modifier wrapping — are applied here so
// any binary expression can have its left side be a member-access or a
// strict-wrapped sub-expression without requiring parentheses.
//
// `strict` placement — see parsePrimary for the rationale; `strict` is accepted
// in exactly two syntactic positions: as a prefix to the LEFT operand (handled
// below via the leading-token check) and as an infix between a cmp operator and
// its RIGHT operand (handled in parseCmpTail).
func (p *Parser) parseBinaryOp() (Node, error) {
	// Leading `strict` — wraps the left operand as a whole. Position is anchored at
	// the strict keyword itself.
	var strictWrap *Strict
	if p.peek().Kind == lexer.TKeyword && p.peek().Value == "strict" {
		kw := p.consume()
		strictWrap = &Strict{Line: kw.Line, Col: kw.Column}
	}

	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	// Chain BracketAccess — `attrs["key"]`, `a[b][c]`, etc.
	left, err = p.maybeBracketAccess(left)
	if err != nil {
		return nil, err
	}

	// Apply strict wrapper around the (possibly bracket-extended) left operand.
	if strictWrap != nil {
		strictWrap.Inner = left
		left = strictWrap
	}

	tok := p.peek()
	if tok.Kind != lexer.TKeyword && tok.Kind != lexer.TAmpersand {
		return left, nil
	}

	// `&` is the bytes bitmask-test operator (DECISION D19). It is bound to a
	// distinct TAmpersand punct token — it does not share the TKeyword path
	// because it is not a word. Both branches share the comparison-tier
	// precedence: tighter than `not` / `and` / `or`, looser than primary.
	if tok.Kind == lexer.TAmpersand {
		return p.parseBitAndTail(left, tok)
	}

	switch tok.Value {
	case "in":
		return p.parseInTail(left, tok)
	case "eq", "ne", "lt", "le", "gt", "ge":
		return p.parseCmpTail(left, tok)
	case "contains", "starts_with", "ends_with", "matches", "wildcard":
		return p.parseStringOpTail(left, tok)
	default:
		// `and`, `or`, `not`, `strict` (when not already absorbed) — none of these
		// begin a binary operand. Return left as-is.
		return left, nil
	}
}

// parseInTail completes the `in` operator once the left operand and the `in`
// keyword have been consumed. The right operand is an array literal; any other
// expression on the right is rejected with a clear diagnostic.
func (p *Parser) parseInTail(left Node, opTok lexer.Token) (Node, error) {
	p.consume() // consume the `in` keyword (opTok already holds the position)
	right, err := p.parseArrayLiteral()
	if err != nil {
		return nil, err
	}
	return &In{Line: opTok.Line, Col: opTok.Column, Element: left, Set: right}, nil
}

// parseCmpTail completes a comparison expression once the left operand and the
// comparison keyword (eq / ne / lt / le / gt / ge) have been consumed. The right
// operand is a primary, with optional `strict` wrapping either side.
//
// `strict` placement — the modifier can appear BETWEEN the cmp operator and the
// right operand (`a eq strict b`). It is consumed here so parsePrimary does not
// see it as a stray TKeyword.
func (p *Parser) parseCmpTail(left Node, opTok lexer.Token) (Node, error) {
	p.consume() // consume the cmp keyword

	// Optional `strict` BEFORE the right operand — wraps the right operand.
	var strictRight *Strict
	if p.peek().Kind == lexer.TKeyword && p.peek().Value == "strict" {
		kw := p.consume()
		strictRight = &Strict{Line: kw.Line, Col: kw.Column}
	}

	right, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	if strictRight != nil {
		strictRight.Inner = right
		right = strictRight
	}

	var op CmpOp
	switch opTok.Value {
	case "eq":
		op = CmpEq
	case "ne":
		op = CmpNe
	case "lt":
		op = CmpLt
	case "le":
		op = CmpLe
	case "gt":
		op = CmpGt
	case "ge":
		op = CmpGe
	}

	// If either side was wrapped in Strict, the whole Cmp takes the Strict keyword's
	// position (it dominates the operator's position semantically — the author wrote
	// `strict` to call out a particular concern).
	wrapLine, wrapCol := opTok.Line, opTok.Column
	if s, ok := left.(*Strict); ok {
		wrapLine, wrapCol = s.Line, s.Col
	} else if s, ok := right.(*Strict); ok {
		wrapLine, wrapCol = s.Line, s.Col
	}
	return &Cmp{Line: wrapLine, Col: wrapCol, Op: op, Left: left, Right: right}, nil
}

// parseStringOpTail completes a string-operator expression once the left operand
// and the operator keyword have been consumed.
func (p *Parser) parseStringOpTail(left Node, opTok lexer.Token) (Node, error) {
	p.consume() // consume the string-op keyword
	right, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	switch opTok.Value {
	case "contains":
		return &Contains{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
	case "starts_with":
		return &StartsWith{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
	case "ends_with":
		return &EndsWith{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
	case "matches":
		return &Matches{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
	case "wildcard":
		return &Wildcard{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
	}
	// Unreachable: parseBinaryOp dispatches only on the cases above.
	return nil, p.errorAt(opTok, "internal: unknown string-op keyword %q", opTok.Value)
}

// parseBitAndTail completes the bytes bitmask-test expression once the left
// operand and the `&` punct token have been consumed. The right operand is
// a primary (no `strict` placement; D19 does not give `&` a strict modifier).
// Source position is anchored at the `&` so error messages point at the
// operator (not at the operands).
func (p *Parser) parseBitAndTail(left Node, opTok lexer.Token) (Node, error) {
	p.consume() // consume the '&' punct
	right, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return &BitAnd{Line: opTok.Line, Col: opTok.Column, Left: left, Right: right}, nil
}

// parseArrayLiteral parses a `[ expression ("," expression)* ]` array literal. The
// empty literal `[]` is allowed and yields an empty LitArray.
func (p *Parser) parseArrayLiteral() (Node, error) {
	openTok, err := p.expect(lexer.TLBrack)
	if err != nil {
		return nil, err
	}

	// Empty array: immediate ].
	if p.peek().Kind == lexer.TRBrack {
		closeTok, _ := p.expect(lexer.TRBrack)
		return &LitArray{Line: openTok.Line, Col: openTok.Column, Elements: nil}, closeTok_unused(closeTok)
	}

	elements := make([]Node, 0, 4)
	first, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	elements = append(elements, first)
	for p.peek().Kind == lexer.TComma {
		p.consume()
		next, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		elements = append(elements, next)
	}

	// Trailing comma — allowed-but-discouraged? D14 does not explicitly forbid; for
	// v1 we REJECT trailing commas because they introduce ambiguity (the parser has
	// no way to distinguish a trailing comma from a missing element). Error is
	// informative enough for the author to remove the comma.
	if _, err := p.expect(lexer.TRBrack); err != nil {
		return nil, err
	}
	return &LitArray{Line: openTok.Line, Col: openTok.Column, Elements: elements}, nil
}

// closeTok_unused silences the linter for the unused closeTok in the empty-array
// branch; it exists purely to consume the ] so the cursor advances correctly.
func closeTok_unused(_ lexer.Token) error { return nil }

// parsePrimary parses one atomic operand. The disambiguation between FieldRef and
// FuncCall is done by 1-token lookahead: if the TIdent is followed by `(`, it is a
// function call; otherwise it is a field reference.
//
// `strict` is NOT accepted at the primary level here — it is handled explicitly in
// the two syntactic positions where it reads naturally: as a prefix to the LEFT
// operand of a binary operator (handled in parseBinaryOp) and as an infix between
// a cmp operator and its RIGHT operand (handled in parseCmpTail). Accepting
// `strict` here would create a precedence ambiguity (should `strict a eq b`
// parse as `Cmp{Eq, Strict{a}, b}` or `Strict{Cmp{Eq, a, b}}`?). Resolving the
// ambiguity belongs to the compiler (C1); for v1 we keep the syntax restricted
// to the two natural positions.
func (p *Parser) parsePrimary() (Node, error) {
	tok := p.peek()
	switch tok.Kind {
	case lexer.TString:
		p.consume()
		return &LitString{Line: tok.Line, Col: tok.Column, Value: rule.NewString(tok.Value)}, nil

	case lexer.TInt:
		p.consume()
		n, err := strconv.ParseInt(tok.Value, 10, 64)
		if err != nil {
			return nil, p.errorAt(tok, "invalid int literal %q: %s", tok.Value, err.Error())
		}
		return &LitInt{Line: tok.Line, Col: tok.Column, Value: rule.NewInt(n)}, nil

	case lexer.TFloat:
		p.consume()
		f, err := strconv.ParseFloat(tok.Value, 64)
		if err != nil {
			return nil, p.errorAt(tok, "invalid float literal %q: %s", tok.Value, err.Error())
		}
		return &LitFloat{Line: tok.Line, Col: tok.Column, Value: rule.NewFloat(f)}, nil

	case lexer.TDuration:
		p.consume()
		d, err := time.ParseDuration(tok.Value)
		if err != nil {
			return nil, p.errorAt(tok, "invalid duration literal %q: %s", tok.Value, err.Error())
		}
		return &LitDuration{Line: tok.Line, Col: tok.Column, Value: rule.NewDuration(d)}, nil

	case lexer.TTimestamp:
		p.consume()
		ts, err := time.Parse(time.RFC3339, tok.Value)
		if err != nil {
			return nil, p.errorAt(tok, "invalid RFC3339 timestamp %q: %s", tok.Value, err.Error())
		}
		return &LitTimestamp{Line: tok.Line, Col: tok.Column, Value: rule.NewTimestamp(ts)}, nil

	case lexer.TIP:
		p.consume()
		return p.parseIPLiteral(tok)

	case lexer.TBytes:
		p.consume()
		// Lexer already decoded the hex; bytes.Clone makes a defensive copy in
		// rule.NewBytes. tok.Bytes is never nil for TBytes (an empty hex yields []).
		return &LitBytes{Line: tok.Line, Col: tok.Column, Value: rule.NewBytes(tok.Bytes)}, nil

	case lexer.TBool:
		p.consume()
		return &LitBool{Line: tok.Line, Col: tok.Column, Value: rule.NewBool(tok.Bool)}, nil

	case lexer.TIdent:
		// Disambiguate: FieldRef vs FuncCall.
		if p.pos+1 < len(p.toks) && p.toks[p.pos+1].Kind == lexer.TLParen {
			return p.parseFuncCallTail(tok)
		}
		p.consume()
		return &FieldRef{Line: tok.Line, Col: tok.Column, Name: tok.Value}, nil

	case lexer.TLParen:
		return p.parseParenthesised()

	default:
		return nil, p.errorAt(tok, "unexpected token %s (%q) — expected expression", tok.Kind, tok.Value)
	}
}

// parseIPLiteral consumes an already-peeked TIP token and produces a LitIP. The
// IsCIDR flag is computed at parse time so the compiler does not have to re-scan
// the raw string — DECISION D14 leaves the IP-vs-CIDR distinction to the parser
// and compiler.
func (p *Parser) parseIPLiteral(tok lexer.Token) (Node, error) {
	raw := tok.Value
	isCIDR := strings.Contains(raw, "/")

	if isCIDR {
		// CIDR — net.ParseCIDR returns (ip, network, err). The network is what the
		// compiler/evaluator will use for membership checks; we discard it here
		// because the Value system carries only the IP form (D5) and the CIDR mask
		// length is recoverable from raw at eval time. Validating with
		// net.ParseCIDR catches malformed CIDRs (out-of-range prefix, address bits
		// set past the mask).
		ip, _, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, p.errorAt(tok, "invalid CIDR %q: %s", raw, err.Error())
		}
		return &LitIP{
			Line: tok.Line, Col: tok.Column,
			Raw: raw, IsCIDR: true,
			Value: rule.NewIP(ip),
		}, nil
	}

	// Plain IP — net.ParseIP returns nil for malformed input.
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, p.errorAt(tok, "invalid IP address %q", raw)
	}
	return &LitIP{
		Line: tok.Line, Col: tok.Column,
		Raw: raw, IsCIDR: false,
		Value: rule.NewIP(ip),
	}, nil
}

// parseFuncCallTail parses the function name (already peeked) plus the opening
// paren, the comma-separated argument list, and the closing paren.
func (p *Parser) parseFuncCallTail(nameTok lexer.Token) (Node, error) {
	// Consume the TIdent (function name) and the opening paren.
	p.consume()
	if _, err := p.expect(lexer.TLParen); err != nil {
		return nil, err
	}

	// No-arg call: func().
	if p.peek().Kind == lexer.TRParen {
		closeTok, _ := p.expect(lexer.TRParen)
		return &FuncCall{
			Line: nameTok.Line, Col: nameTok.Column,
			Name: nameTok.Value, Args: nil,
		}, closeTok_unused(closeTok)
	}

	args := make([]Node, 0, 2)
	first, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	args = append(args, first)
	for p.peek().Kind == lexer.TComma {
		p.consume()
		next, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, next)
	}
	if _, err := p.expect(lexer.TRParen); err != nil {
		return nil, err
	}
	return &FuncCall{
		Line: nameTok.Line, Col: nameTok.Column,
		Name: nameTok.Value, Args: args,
	}, nil
}

// parseParenthesised parses a parenthesised sub-expression — the natural override
// for operator precedence.
func (p *Parser) parseParenthesised() (Node, error) {
	openTok, err := p.expect(lexer.TLParen)
	if err != nil {
		return nil, err
	}
	inner, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(lexer.TRParen); err != nil {
		return nil, err
	}
	// The BracketAccess grammar lets `primary "[" expr "]"` follow any primary. To
	// keep the parser simple, we re-enter the bracket loop here: if the very next
	// token is `[`, we treat the parenthesised expression as the Object of a
	// BracketAccess. The position is anchored at the opening paren — that matches
	// "the source position of the FIRST token that constitutes the node".
	_ = openTok
	return p.maybeBracketAccess(inner)
}

// maybeBracketAccess consumes an optional `[ expression ]` after the given base
// expression and returns a BracketAccess if the bracket is present. The base is
// returned unchanged if the next token is not `[`. Recursive: chained accesses
// like `a[b][c]` are built up as `BracketAccess(BracketAccess(a, b), c)`.
func (p *Parser) maybeBracketAccess(base Node) (Node, error) {
	if p.peek().Kind != lexer.TLBrack {
		return base, nil
	}
	openTok := p.consume()
	key, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(lexer.TRBrack); err != nil {
		return nil, err
	}
	wrapped := &BracketAccess{
		Line: openTok.Line, Col: openTok.Column,
		Object: base, Key: key,
	}
	return p.maybeBracketAccess(wrapped)
}
