// ========================== pkg/rule/parser — AST node types =============================
//   WHAT IS HERE:
//     - Node — the universal AST interface implemented by every concrete node type.
//       Pos() returns the source position of the FIRST token that constitutes the node;
//       String() returns a stable, human-readable rendering used by error messages and
//       debug output. The format is NOT designed to round-trip back into source — a
//       lossless round-trip is explicitly NOT a v1 requirement (see TASKS.md B3).
//     - Literal nodes — one per closed Value Kind (see DECISION D5 / D11), except for
//       KindMap which has no literal form in the expression language (D11). Each
//       literal node carries a parsed rule.Value built at parse time — the parser
//       validates the lexical shape via stdlib helpers (time.ParseDuration,
//       net.ParseIP, ...) and wraps any decode failure as a parse error so the
//       downstream compiler never sees a malformed Value.
//     - Composite / reference nodes — LitArray (heterogeneous literal list used by
//       the `in` operator), FieldRef (qualified dotted name stored as a raw string;
//       the compiler resolves it to a field ID via Scheme), BracketAccess (Map
//       member access), and FuncCall (function invocation).
//     - Operator nodes — one type per logical operator, matching the closed set of
//       operator keywords from DECISION D14. The Cmp family shares a single node
//       shape with a CmpOp enum; every other operator has its own node type so the
//       compiler can dispatch on the concrete type without inspecting a string.
//     - Strict — a transparent wrapper that records the presence of the `strict`
//       modifier keyword (D14 reserved-word set). The wrapper is syntactically
//       transparent: it carries no semantic binding of its own; the compiler (C1)
//       decides what `strict` means in a given operator context.
//
//   WHAT IS NOT HERE:
//     - Type-checking against Scheme (D6) — that is the compiler's job (C1). The
//       parser never inspects a Scheme and never references a Catalog.
//     - Evaluation — there is no Eval / Match method on any node; the engine has a
//       separate evaluator package (C2).
//     - Source-position tracking infrastructure — each node carries its own Line /
//       Col pair directly. A shared Pos struct would add an indirection without
//       reducing memory footprint (the per-node Line/Col pair is 16 bytes vs the
//       16-byte Pos wrapper).
//
//   DEPENDENCY RULE:
//     pkg/rule/parser → stdlib + sibling pkg/rule (for Value / Kind) + sibling
//     pkg/rule/lexer (NOT imported here — Token references are carried in via
//     pkg/rule/parser.go at parse time, never stored on nodes).
//
//   CONCURRENCY:
//     AST nodes are plain value types built once at parse time and read-only
//     thereafter. They are safe to share across goroutines without synchronization,
//     matching the immutability convention of compiled plans (DECISION D4).

package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// ========================== Node interface ================================================

// Node is the universal interface implemented by every AST node type. Pos returns the
// source position (1-indexed line, 1-indexed column) of the FIRST token that
// constitutes the node; the column tracks the start of the construct, not the end.
// String returns a stable, human-readable rendering for diagnostics — the format is
// NOT round-trippable back into source.
type Node interface {
	// Pos returns (line, col) of the first token that constitutes this node.
	// Used for error messages and debug rendering.
	Pos() (int, int)

	// String returns a stable, human-readable form (NOT round-trippable source).
	String() string
}

// ========================== Literal nodes =================================================

// LitString is a TString literal. The parsed Value carries KindString; Value.AsString()
// returns the decoded bytes (lexer already resolved backslash escapes).
type LitString struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitString) Pos() (int, int) { return n.Line, n.Col }
func (n *LitString) String() string {
	s, _ := n.Value.AsString()
	return fmt.Sprintf("LitString(%q)", s)
}

// LitInt is a TInt literal. Value carries KindInt with the int64 form.
type LitInt struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitInt) Pos() (int, int) { return n.Line, n.Col }
func (n *LitInt) String() string {
	i, _ := n.Value.AsInt()
	return "LitInt(" + strconv.FormatInt(i, 10) + ")"
}

// LitFloat is a TFloat literal. Value carries KindFloat with the float64 form.
type LitFloat struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitFloat) Pos() (int, int) { return n.Line, n.Col }
func (n *LitFloat) String() string {
	f, _ := n.Value.AsFloat()
	return "LitFloat(" + strconv.FormatFloat(f, 'g', -1, 64) + ")"
}

// LitBool is a TBool literal. Value carries KindBool.
type LitBool struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitBool) Pos() (int, int) { return n.Line, n.Col }
func (n *LitBool) String() string {
	b, _ := n.Value.AsBool()
	return "LitBool(" + strconv.FormatBool(b) + ")"
}

// LitDuration is a TDuration literal. The lexer matched the Go-style duration grammar
// (D14); the parser validates via time.ParseDuration and packs the result as a
// KindDuration Value.
type LitDuration struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitDuration) Pos() (int, int) { return n.Line, n.Col }
func (n *LitDuration) String() string {
	d, _ := n.Value.AsDuration()
	return "LitDuration(" + d.String() + ")"
}

// LitTimestamp is a TTimestamp literal. The lexer matched the ts"..." prefix form;
// the parser validates the inner string via time.Parse(time.RFC3339, ...) and packs
// the result as a KindTimestamp Value.
//
// TODO(nano): the lexer does not currently distinguish RFC3339 from RFC3339Nano
// payloads; if a future grammar extension allows fractional seconds, this node
// must learn to negotiate both layouts (or the lexer must tag the token).
type LitTimestamp struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitTimestamp) Pos() (int, int) { return n.Line, n.Col }
func (n *LitTimestamp) String() string {
	ts, _ := n.Value.AsTimestamp()
	return "LitTimestamp(" + ts.Format(time_RFC3339_FOR_AST) + ")"
}

// LitIP is a TIP literal. Raw holds the inner string exactly as the lexer captured
// it (the compiler is the only consumer that distinguishes IP from CIDR via the `/`
// separator — DECISION D14). The parser ALSO computes IsCIDR for convenience so the
// compiler does not have to re-scan the raw string. Value carries KindIP with the
// parsed net.IP.
type LitIP struct {
	Line, Col int
	Raw       string
	IsCIDR    bool
	Value     rule.Value
}

func (n *LitIP) Pos() (int, int) { return n.Line, n.Col }
func (n *LitIP) String() string {
	if n.IsCIDR {
		return "LitIP(CIDR=" + n.Raw + ")"
	}
	return "LitIP(" + n.Raw + ")"
}

// LitBytes is a TBytes literal. The lexer already decoded the hex payload; the parser
// just packs it as a KindBytes Value. No further validation is necessary — invalid
// hex would have surfaced as a TError at lex time.
type LitBytes struct {
	Line, Col int
	Value     rule.Value
}

func (n *LitBytes) Pos() (int, int) { return n.Line, n.Col }
func (n *LitBytes) String() string {
	bs, _ := n.Value.AsBytes()
	return "LitBytes(0x" + hex_EncodeToString_ForAST(bs) + ")"
}

// ========================== Array literal ================================================

// LitArray is a heterogeneous array literal — the right operand of the `in` operator
// for set-membership tests (DECISION D14). Elements are stored as a slice of Node so
// the parser does NOT commit to a single Value Kind per slot; the compiler (C1) is
// responsible for confirming element-type compatibility with the operator.
type LitArray struct {
	Line, Col int
	Elements  []Node
}

func (n *LitArray) Pos() (int, int) { return n.Line, n.Col }
func (n *LitArray) String() string {
	parts := make([]string, len(n.Elements))
	for i, e := range n.Elements {
		parts[i] = e.String()
	}
	return "LitArray[" + strings.Join(parts, ", ") + "]"
}

// ========================== References ====================================================

// FieldRef is a dotted field reference. Name holds the FULLY-QUALIFIED dotted form
// (e.g. "http.uri.path") verbatim — the parser does NOT split it into namespace /
// local segments, and it does NOT consult the Scheme to confirm existence. The
// compiler (C1) is the single point that resolves a FieldRef into a field ID via
// the active Scheme (DECISION D6 / D7 / D9).
type FieldRef struct {
	Line, Col int
	Name      string
}

func (n *FieldRef) Pos() (int, int) { return n.Line, n.Col }
func (n *FieldRef) String() string {
	return "FieldRef(" + n.Name + ")"
}

// BracketAccess is a map member access — typically applied to a Map-typed FieldRef to
// fetch a value by string key. Object is the expression on the left of `[`; Key is
// the expression inside `[...]`. The parser does NOT enforce that Object is a Map-
// typed field or that Key is a LitString — the compiler (C1) handles both
// type-checks.
type BracketAccess struct {
	Line, Col int
	Object    Node
	Key       Node
}

func (n *BracketAccess) Pos() (int, int) { return n.Line, n.Col }
func (n *BracketAccess) String() string {
	return "BracketAccess(" + n.Object.String() + "[" + n.Key.String() + "])"
}

// FuncCall is a function call — Name holds the bare-identifier function name
// (e.g. "lower", "ip_to_int", ... — DECISION D14 reserved-word set does not include
// function names, so they are always TIdent at lex time). The parser does NOT
// validate Name against any function table — the compiler (C1) owns that check.
type FuncCall struct {
	Line, Col int
	Name      string
	Args      []Node
}

func (n *FuncCall) Pos() (int, int) { return n.Line, n.Col }
func (n *FuncCall) String() string {
	parts := make([]string, len(n.Args))
	for i, a := range n.Args {
		parts[i] = a.String()
	}
	return "FuncCall(" + n.Name + "(" + strings.Join(parts, ", ") + "))"
}

// ========================== Operators =====================================================

// And is the logical AND of two operands.
type And struct {
	Line, Col   int
	Left, Right Node
}

func (n *And) Pos() (int, int) { return n.Line, n.Col }
func (n *And) String() string {
	return "And(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// Or is the logical OR of two operands.
type Or struct {
	Line, Col   int
	Left, Right Node
}

func (n *Or) Pos() (int, int) { return n.Line, n.Col }
func (n *Or) String() string {
	return "Or(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// Not is the logical NOT of a single operand (DECISION D14 keyword).
type Not struct {
	Line, Col int
	Operand   Node
}

func (n *Not) Pos() (int, int) { return n.Line, n.Col }
func (n *Not) String() string {
	return "Not(" + n.Operand.String() + ")"
}

// CmpOp enumerates the six comparison operators from the closed keyword set
// (DECISION D14: eq, ne, lt, le, gt, ge).
type CmpOp uint8

const (
	// CmpEq is `eq` — semantic equality.
	CmpEq CmpOp = iota

	// CmpNe is `ne` — semantic inequality.
	CmpNe

	// CmpLt is `lt` — strict less-than.
	CmpLt

	// CmpLe is `le` — less-than-or-equal.
	CmpLe

	// CmpGt is `gt` — strict greater-than.
	CmpGt

	// CmpGe is `ge` — greater-than-or-equal.
	CmpGe
)

// String returns the canonical lowercase operator name matching the lexical keyword.
func (op CmpOp) String() string {
	switch op {
	case CmpEq:
		return "eq"
	case CmpNe:
		return "ne"
	case CmpLt:
		return "lt"
	case CmpLe:
		return "le"
	case CmpGt:
		return "gt"
	case CmpGe:
		return "ge"
	default:
		return "unknown(" + strconv.FormatUint(uint64(op), 10) + ")"
	}
}

// Cmp is a comparison expression. Op selects one of the six CmpOp values; Left and
// Right are the operands. The parser does NOT type-check operand compatibility —
// that is the compiler's job (C1).
type Cmp struct {
	Line, Col   int
	Op          CmpOp
	Left, Right Node
}

func (n *Cmp) Pos() (int, int) { return n.Line, n.Col }
func (n *Cmp) String() string {
	return "Cmp(" + n.Op.String() + ", " + n.Left.String() + ", " + n.Right.String() + ")"
}

// Contains is a substring membership test (`contains` keyword, D14).
type Contains struct {
	Line, Col   int
	Left, Right Node
}

func (n *Contains) Pos() (int, int) { return n.Line, n.Col }
func (n *Contains) String() string {
	return "Contains(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// StartsWith is a prefix test (`starts_with` keyword, D14).
type StartsWith struct {
	Line, Col   int
	Left, Right Node
}

func (n *StartsWith) Pos() (int, int) { return n.Line, n.Col }
func (n *StartsWith) String() string {
	return "StartsWith(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// EndsWith is a suffix test (`ends_with` keyword, D14).
type EndsWith struct {
	Line, Col   int
	Left, Right Node
}

func (n *EndsWith) Pos() (int, int) { return n.Line, n.Col }
func (n *EndsWith) String() string {
	return "EndsWith(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// Matches is a regex match test (`matches` keyword, D14). Right is the TString
// regex source — the parser does NOT compile it; the compiler (C1) builds the
// regexp.Regexp via stdlib regex compilation (D2).
type Matches struct {
	Line, Col   int
	Left, Right Node
}

func (n *Matches) Pos() (int, int) { return n.Line, n.Col }
func (n *Matches) String() string {
	return "Matches(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// Wildcard is a wildcard pattern test (`wildcard` keyword, D14). Right is the
// TString wildcard template; semantic interpretation is the compiler's concern.
type Wildcard struct {
	Line, Col   int
	Left, Right Node
}

func (n *Wildcard) Pos() (int, int) { return n.Line, n.Col }
func (n *Wildcard) String() string {
	return "Wildcard(" + n.Left.String() + ", " + n.Right.String() + ")"
}

// In is a set membership test (`in` keyword, D14). Element is the value being
// tested; Set is typically a LitArray. The parser does NOT type-check Element /
// Set compatibility — the compiler (C1) confirms it.
type In struct {
	Line, Col    int
	Element, Set Node
}

func (n *In) Pos() (int, int) { return n.Line, n.Col }
func (n *In) String() string {
	return "In(" + n.Element.String() + ", " + n.Set.String() + ")"
}

// Strict is a transparent wrapper carrying the `strict` modifier (D14 reserved
// keyword). The parser does NOT bind any semantic meaning to it; the compiler (C1)
// decides what `strict` means in each operator context (e.g. strict equality vs
// coercive equality). Strict can wrap either side of a binary operator or a whole
// sub-expression; the parser accepts it in the natural syntactic positions where
// `strict` reads well to a human author.
//
// Position (Line, Col) tracks the location of the `strict` keyword itself, so error
// messages point at the modifier rather than at the wrapped expression.
type Strict struct {
	Line, Col int
	Inner     Node
}

func (n *Strict) Pos() (int, int) { return n.Line, n.Col }
func (n *Strict) String() string {
	return "Strict(" + n.Inner.String() + ")"
}

// ========================== Internal helpers =============================================
//   These tiny wrappers keep the imports in this file small and the formatting
//   consistent with pkg/rule/types.go. They are intentionally unexported — they are
//   internal helpers, not part of the public AST surface.

// time_RFC3339_FOR_AST mirrors time.RFC3339 without dragging the time package into
// every render site of LitTimestamp.String(). Pulling in time here would be fine,
// but keeping it out of ast.go matches the layering: ast.go is pure data shapes;
// stdlib calls live in parser.go.
const time_RFC3339_FOR_AST = "2006-01-02T15:04:05Z07:00"

// hex_EncodeToString_ForAST mirrors encoding/hex.EncodeToString without importing
// the package here. The performance impact is zero (this path is debug-only) and
// the indirection keeps ast.go free of stdlib data-encoding dependencies.
func hex_EncodeToString_ForAST(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0F]
	}
	return string(out)
}

// ========================== Compile-time interface conformance ===========================
//
// Each *Struct declaration below is a no-op assignment that fails at compile time
// if the type's *Pos method does not match the Node interface signature. This is
// the cheapest possible contract assertion — it costs nothing at runtime.

// var _ Node = (*LitString)(nil) and so on for every concrete node type. The block
// below is split into multiple declarations so a single interface-mismatch failure
// points at the offending type via its own line.

var (
	_ Node = (*LitString)(nil)
	_ Node = (*LitInt)(nil)
	_ Node = (*LitFloat)(nil)
	_ Node = (*LitBool)(nil)
	_ Node = (*LitDuration)(nil)
	_ Node = (*LitTimestamp)(nil)
	_ Node = (*LitIP)(nil)
	_ Node = (*LitBytes)(nil)
	_ Node = (*LitArray)(nil)
	_ Node = (*FieldRef)(nil)
	_ Node = (*BracketAccess)(nil)
	_ Node = (*FuncCall)(nil)
	_ Node = (*And)(nil)
	_ Node = (*Or)(nil)
	_ Node = (*Not)(nil)
	_ Node = (*Cmp)(nil)
	_ Node = (*Contains)(nil)
	_ Node = (*StartsWith)(nil)
	_ Node = (*EndsWith)(nil)
	_ Node = (*Matches)(nil)
	_ Node = (*Wildcard)(nil)
	_ Node = (*In)(nil)
	_ Node = (*Strict)(nil)
)

// fmt.Stringer conformance for CmpOp — picked up by %s / %v formatters if a logger
// ever needs to render a Cmp directly (the Cmp.String() method already calls this).
var _ fmt.Stringer = CmpEq
