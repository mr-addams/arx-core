// ========================== pkg/rule/compiler — type checker / compiler =====================
//   The compiler (Task C1) is the bridge between the parser (Group B) and the evaluator
//   (Task C2). It walks an AST and, with the help of a Scheme, produces a typed Plan —
//   an immutable tree of pre-validated, pre-resolved op nodes. The evaluator then walks
//   the Plan against a FieldResolver and a plugin.Event, doing zero allocations on the
//   hot path (DECISION D4).
//
//   LOCATION — note for reviewers:
//     This file lives in the subpackage `pkg/rule/compiler` rather than directly in
//     `pkg/rule` because Go forbids an import cycle: `pkg/rule/parser` already imports
//     `pkg/rule` (for rule.Value), and the compiler needs `parser.Node`. Placing the
//     compiler in a subpackage breaks the cycle naturally — the subpackage imports
//     both `pkg/rule` and `pkg/rule/parser`. A future cleanup that decouples parser
//     from rule can hoist this file back into pkg/rule; the public API of Compile /
//     NewCompiler / Plan is package-agnostic at the call-site level.
//
//   WHAT IS HERE:
//     - Plan — the public, immutable output. Carries the root op and the Scheme
//       revision it was compiled against (D13 stale-detection).
//     - op — the closed internal interface for plan nodes. Each op type is an
//       unexported struct with package-visible fields. The evaluator type-switches
//       on the concrete type, not on the interface (cheaper on the hot path).
//     - opKind — small uint8 tag for fast type-switching by the evaluator. Stable
//       across versions — the enum order is the contract.
//     - Compile / NewCompiler / (*Compiler).Compile — the public entry points.
//     - CompileError — typed error carrying Line, Col, Code, and Message. The Code
//       is the machine-readable category (e.g. "unknown_field", "type_mismatch");
//       the Message is the human-readable diagnostic. Code is closed; tooling that
//       dispatches on it can rely on the set not drifting silently.
//     - FieldInfo lookup helper — pre-walks the Scheme to build a map[FullName]→id
//       so per-reference Has() lookups are O(1).
//
//   WHAT IS NOT HERE:
//     - Evaluation — the engine has a separate evaluator (C2, to be added in this
//       package). The compiler produces the typed plan; the evaluator executes it.
//     - Implicit type coercion (DECISION D14 / D15): v1 is strict-typed. The only
//       special case is IP `eq` CIDR / IP `in` [CIDR...] on the right operand.
//     - Function implementations (DECISION D16): the v0.3.0 function table is
//       a closed, package-internal registry (functions.go); compile-time signature
//       checking rejects unknown names, wrong arity, and per-argument Kind
//       mismatches before eval is reached.
//     - Parser / lexer (Group B). The compiler consumes parser.Node values only.
//     - Map-key validation (DECISION D11). Map keys are eval-time resolved.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): fmt, regexp, net. Plus sibling pkg/rule (Value / Kind /
//     FieldType / Scheme) and sibling pkg/rule/parser (AST). pkg/rule/lexer is
//     intentionally NOT imported — token positions come from parser.Node.Pos() only.
//
//   CONCURRENCY:
//     - A *Compiler is immutable once constructed: the Scheme is captured, no
//       further state is added per Compile call. Safe for concurrent Compile calls
//       from multiple goroutines (verified by TestCompiler_Concurrent).
//     - A *Plan is immutable and safe for concurrent Eval. The Plan carries the
//       Scheme revision it was compiled against; if the source Catalog is mutated,
//       the evaluator can detect staleness by comparing Plan.Rev against
//       Scheme.Revision().

package compiler

import (
	"fmt"
	"net"
	"regexp"
	"sync"

	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== CompileError — typed diagnostic =================================

// CompileError is the typed diagnostic produced by the compiler. It carries the source
// position, a stable machine-readable Code, and a human-readable Message.
//
// Code values are a closed set (see the constants below). Tooling that wants to react
// programmatically to a specific failure (e.g. surface an inline marker in an editor)
// dispatches on Code, not on Message. The Message is intentionally free-form.
type CompileError struct {
	Line    int
	Col     int
	Code    string
	Message string
}

// Error renders a single-line, human-readable form. The format is stable — it is part
// of the engine's diagnostic surface alongside lexer/parser errors.
func (e *CompileError) Error() string {
	return fmt.Sprintf("compile error at line %d, col %d: %s [%s]", e.Line, e.Col, e.Message, e.Code)
}

// CompileError.Code — closed set. New codes are added by introducing a new constant
// here; the constant string is the public contract. The block is split so a future
// addition does not perturb the existing line numbers.
const (
	CodeUnknownField     = "unknown_field"        // FieldRef.Name not in Scheme
	CodeTypeMismatch     = "type_mismatch"        // operand Kind / operator mismatch
	CodeBadRegex         = "bad_regex"            // `matches` with invalid regex
	CodeUnknownFunction  = "unknown_function"     // FuncCall.Name not in function table
	CodeBadFuncArity     = "bad_func_arity"       // wrong number of args
	CodeBadFuncArgType   = "bad_func_arg_type"    // function arg type mismatch
	CodeBadArrayElement  = "bad_array_element"    // non-literal in array literal
	CodeBadStrictPlace   = "bad_strict_placement" // strict modifier misplaced
	CodeBadBracketAccess = "bad_bracketaccess"    // object not Map-typed, or key not string literal
	CodeInvalidLiteral   = "invalid_literal"      // parser missed a malformed literal
	CodeNilScheme        = "nil_scheme"           // Compile / NewCompiler called with nil scheme
)

// ========================== Plan — public, immutable output =================================

// Plan is the immutable, typed representation of a compiled expression. The evaluator
// (Task C2, in this same package) walks the Plan against a FieldResolver and a
// plugin.Event. Plans are safe for concurrent Eval (DECISION D4).
//
// The root op and the captured Scheme revision are the only state. Plans do not retain
// a reference to the Scheme itself — once a Plan is built, the source Scheme can be
// garbage-collected. The Rev field is sufficient for the evaluator to detect a stale
// base (Plan.Rev vs. live Scheme.Revision() at evaluation time).
type Plan struct {
	// root is the topmost op node. The evaluator type-switches on its concrete type.
	// unexported because Plan consumers (the evaluator) read it via the package's
	// internal accessors, not by reflection on a public field.
	root op

	// Rev is the Scheme.Revision() at the moment of compilation. Combined with the
	// live Scheme's Revision(), it lets the evaluator (or a product API layer)
	// detect a stale-plan condition: a Catalog mutation after compile invalidates
	// the Plan (DECISION D13).
	Rev uint64
}

// Root returns the root op of the Plan. The evaluator (C2) calls this to start its
// dispatch. The op interface is unexported; only code in this package can construct or
// consume concrete op types.
func (p *Plan) Root() op { return p.root }

// ========================== op — closed internal interface ===================================

// op is the closed internal interface for plan nodes. The concrete implementers are
// unexported structs (opLitString, opLitInt, opField, opCmp, ...). The evaluator (C2)
// type-switches on the concrete type — not on the interface — for hot-path speed.
//
// The kind() method exists to give the evaluator a fast discriminator when it wants to
// avoid the deeper concrete-type switch. The integer tag is part of the contract; the
// enum order is stable.
type op interface {
	kind() opKind
}

// opKind is a small uint8 tag identifying the concrete op type. Stable across versions
// — adding a new opKind is a breaking change to the evaluator's dispatch table, so
// bump deliberately.
type opKind uint8

const (
	kLitBool opKind = iota
	kLitInt
	kLitFloat
	kLitString
	kLitIP
	kLitBytes
	kLitDuration
	kLitTimestamp
	kLitArray
	kField
	kBracket
	kFunc
	kAnd
	kOr
	kNot
	kCmp
	kContains
	kStartsWith
	kEndsWith
	kMatches
	kWildcard
	kIn
	kStrict
)

// ========================== Literal op nodes ================================================

// pos is an internal (line, col) pair used by op nodes that need a position for
// diagnostics. Mirrors the AST's Pos() convention but kept private to this package
// so Plan does not depend on parser internals at the API surface.
type pos struct{ line, col int }

// opLitString carries a KindString Value.
type opLitString struct {
	pos pos
	v   rule.Value
}

func (o *opLitString) kind() opKind { return kLitString }

// opLitInt carries a KindInt Value.
type opLitInt struct {
	pos pos
	v   rule.Value
}

func (o *opLitInt) kind() opKind { return kLitInt }

// opLitFloat carries a KindFloat Value.
type opLitFloat struct {
	pos pos
	v   rule.Value
}

func (o *opLitFloat) kind() opKind { return kLitFloat }

// opLitBool carries a KindBool Value.
type opLitBool struct {
	pos pos
	v   rule.Value
}

func (o *opLitBool) kind() opKind { return kLitBool }

// opLitIP carries a KindIP Value plus the CIDR distinction. For non-CIDR, mask == 0
// and the evaluator performs plain IP equality. For CIDR, mask is the prefix length
// (0..32 for IPv4, 0..128 for IPv6) and the evaluator performs CIDR membership.
type opLitIP struct {
	pos  pos
	v    rule.Value
	cidr bool
	mask int // 0 for plain IP, otherwise prefix length
}

func (o *opLitIP) kind() opKind { return kLitIP }

// opLitBytes carries a KindBytes Value.
type opLitBytes struct {
	pos pos
	v   rule.Value
}

func (o *opLitBytes) kind() opKind { return kLitBytes }

// opLitDuration carries a KindDuration Value.
type opLitDuration struct {
	pos pos
	v   rule.Value
}

func (o *opLitDuration) kind() opKind { return kLitDuration }

// opLitTimestamp carries a KindTimestamp Value.
type opLitTimestamp struct {
	pos pos
	v   rule.Value
}

func (o *opLitTimestamp) kind() opKind { return kLitTimestamp }

// opLitArray is the right operand of `in`. Each element is a pre-typed scalar op
// (the compiler rejects non-literal elements, see CodeBadArrayElement).
type opLitArray struct {
	pos      pos
	elements []op
}

func (o *opLitArray) kind() opKind { return kLitArray }

// ========================== Field / bracket / function ops ==================================

// opField is a pre-resolved field reference. id is the index into Scheme.Fields();
// name is the original qualified name (preserved for diagnostics); fieldType is
// cached from the Scheme so the evaluator can dispatch on type without consulting
// the Scheme on every call.
type opField struct {
	pos       pos
	id        int
	name      string
	fieldType rule.FieldType
}

func (o *opField) kind() opKind { return kField }

// opBracket is a Map member access — `field["key"]`. The compiler validates that
// the underlying field is Map-typed; map keys themselves are eval-time resolved
// (DECISION D11). key is a literal string captured at compile time.
type opBracket struct {
	pos pos
	obj *opField
	key string
}

func (o *opBracket) kind() opKind { return kBracket }

// opFunc is a function call. The compiled op carries the function name, the
// compiled argument ops, and the FuncSpec resolved at compile time (DECISION
// D16 §2 — compile-time signature checking). The evaluator dispatches via
// spec.Eval directly; it does not re-look-up the name or re-validate the
// arity / argument Kinds.
type opFunc struct {
	pos  pos
	name string
	args []op
	spec FuncSpec
}

func (o *opFunc) kind() opKind { return kFunc }

// ========================== Logic ops =======================================================

type opAnd struct {
	pos         pos
	left, right op
}

func (o *opAnd) kind() opKind { return kAnd }

type opOr struct {
	pos         pos
	left, right op
}

func (o *opOr) kind() opKind { return kOr }

type opNot struct {
	pos     pos
	operand op
}

func (o *opNot) kind() opKind { return kNot }

// ========================== Comparison op ===================================================

// opCmpOp enumerates the six comparison operators. Mirrors parser.CmpOp.
type opCmpOp uint8

const (
	opCmpEq opCmpOp = iota
	opCmpNe
	opCmpLt
	opCmpLe
	opCmpGt
	opCmpGe
)

type opCmp struct {
	pos         pos
	op          opCmpOp
	left, right op
}

func (o *opCmp) kind() opKind { return kCmp }

// ========================== String ops ======================================================

type opContains struct {
	pos         pos
	left, right op
}

func (o *opContains) kind() opKind { return kContains }

type opStartsWith struct {
	pos         pos
	left, right op
}

func (o *opStartsWith) kind() opKind { return kStartsWith }

type opEndsWith struct {
	pos         pos
	left, right op
}

func (o *opEndsWith) kind() opKind { return kEndsWith }

type opMatches struct {
	pos   pos
	left  op
	regex *regexp.Regexp // pre-compiled at compile time (D4)
}

func (o *opMatches) kind() opKind { return kMatches }

type opWildcard struct {
	pos     pos
	left    op
	pattern string // pre-validated literal string

	// Изменение (Задача C2, evaluator): ленивая компиляция wildcard-паттерна в
	// *regexp.Regexp. Компилятор (C1) НЕ компилирует regexp на этом этапе —
	// compileWildcard остаётся без изменений (pattern валидируется как строка,
	// не как regex). Эвалюатор компилирует паттерн при первом Eval через
	// compileOnce, чтобы не платить за regexp.Compile на каждом Eval-вызове и
	// при этом не делать compile-time compile (что потребовало бы расширения
	// contract-стабильного C1 — sync.Once здесь держит compiler.go неизменным
	// по поведению). Два новых поля additive: opWildcard неэкспортирован,
	// публичный API не затронут.
	regex       *regexp.Regexp
	compileOnce sync.Once
}

func (o *opWildcard) kind() opKind { return kWildcard }

// ========================== In / Strict ops =================================================

type opIn struct {
	pos     pos
	element op
	set     op // must be *opLitArray after compile
}

func (o *opIn) kind() opKind { return kIn }

type opStrict struct {
	pos   pos
	inner op // must be opCmp / op*StringOp / opIn after compile
}

func (o *opStrict) kind() opKind { return kStrict }

// ========================== Compiler ========================================================

// Compiler is the stateless, Scheme-bound type checker. Construct with NewCompiler;
// reuse across many Compile calls (and across goroutines — it is safe).
type Compiler struct {
	// scheme is captured at construction. The compiler reads it through the public
	// Fields() / Has() / Revision() methods; it never mutates it.
	scheme *rule.Scheme

	// fieldIdx is a pre-computed map[FullName]→index-into-Scheme.Fields(). Built
	// once at construction so per-reference resolution is O(1). The map is
	// read-only after construction — safe for concurrent use.
	fieldIdx map[string]int
}

// NewCompiler returns a reusable Compiler bound to scheme. The Scheme is captured at
// construction; the compiler is otherwise stateless and safe for concurrent Compile
// calls from multiple goroutines.
//
// NewCompiler returns a typed *CompileError (CodeNilScheme) when scheme is nil, so
// the caller can fail-fast at construction rather than at the first Compile call.
func NewCompiler(scheme *rule.Scheme) (*Compiler, *CompileError) {
	if scheme == nil {
		return nil, &CompileError{Line: 0, Col: 0, Code: CodeNilScheme, Message: "compiler requires a non-nil scheme"}
	}
	fields := scheme.Fields()
	c := &Compiler{
		scheme:   scheme,
		fieldIdx: make(map[string]int, len(fields)),
	}
	for i, fi := range fields {
		c.fieldIdx[fi.FullName()] = i
	}
	return c, nil
}

// Compile validates ast against the compiler's Scheme and returns a typed Plan. On
// success the Plan is non-nil and the error is nil. On failure the Plan is nil and
// the error is a *CompileError with Code, Line, Col, and Message populated.
//
// Compile is safe to call from multiple goroutines on the same *Compiler.
func (c *Compiler) Compile(ast parser.Node) (*Plan, error) {
	if ast == nil {
		return nil, &CompileError{Line: 0, Col: 0, Code: CodeInvalidLiteral, Message: "nil AST"}
	}
	root, err := c.compileNode(ast)
	if err != nil {
		return nil, err
	}
	return &Plan{root: root, Rev: c.scheme.Revision()}, nil
}

// Compile is the package-level convenience constructor + compile in one call. It
// allocates a fresh Compiler internally; for repeated compile calls against the same
// Scheme, prefer NewCompiler + (*Compiler).Compile to amortize the field index build.
func Compile(ast parser.Node, scheme *rule.Scheme) (*Plan, *CompileError) {
	c, cerr := NewCompiler(scheme)
	if cerr != nil {
		return nil, cerr
	}
	p, err := c.Compile(ast)
	if err != nil {
		if ce, ok := err.(*CompileError); ok {
			return nil, ce
		}
		// Defensive: Compile is typed to return *CompileError, so this branch is
		// reachable only if a future change broadens the return type.
		return nil, &CompileError{Line: 0, Col: 0, Code: CodeInvalidLiteral, Message: err.Error()}
	}
	return p, nil
}

// ========================== Node dispatch ===================================================

// compileNode is the type-switch driver. Every concrete AST node type is handled;
// the final default branch is unreachable in v1 (the parser never emits an
// unknown Node implementation) but the compiler keeps it for defensive readability.
func (c *Compiler) compileNode(n parser.Node) (op, *CompileError) {
	switch nn := n.(type) {
	case *parser.LitString:
		return &opLitString{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitInt:
		return &opLitInt{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitFloat:
		return &opLitFloat{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitBool:
		return &opLitBool{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitIP:
		return c.compileLitIP(nn)
	case *parser.LitBytes:
		return &opLitBytes{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitDuration:
		return &opLitDuration{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitTimestamp:
		return &opLitTimestamp{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitArray:
		return c.compileLitArray(nn)
	case *parser.FieldRef:
		return c.compileFieldRef(nn)
	case *parser.BracketAccess:
		return c.compileBracketAccess(nn)
	case *parser.FuncCall:
		return c.compileFuncCall(nn)
	case *parser.And:
		return c.compileAnd(nn)
	case *parser.Or:
		return c.compileOr(nn)
	case *parser.Not:
		return c.compileNot(nn)
	case *parser.Cmp:
		return c.compileCmp(nn)
	case *parser.Contains:
		return c.compileContains(nn)
	case *parser.StartsWith:
		return c.compileStartsWith(nn)
	case *parser.EndsWith:
		return c.compileEndsWith(nn)
	case *parser.Matches:
		return c.compileMatches(nn)
	case *parser.Wildcard:
		return c.compileWildcard(nn)
	case *parser.In:
		return c.compileIn(nn)
	case *parser.Strict:
		return c.compileStrict(nn)
	default:
		return nil, &CompileError{
			Line: 0, Col: 0, Code: CodeInvalidLiteral,
			Message: "compiler: unknown AST node type",
		}
	}
}

// posOf extracts the (line, col) pair from a parser.Node. Used to attach a position
// to every plan op so the evaluator (C2) can produce positional error messages for
// any future runtime signals without re-walking the AST.
func posOf(n parser.Node) pos {
	line, col := n.Pos()
	return pos{line: line, col: col}
}

// ========================== Literal compilation ==============================================

// compileLitIP packages a parser LitIP into an opLitIP. The IsCIDR / mask pre-computation
// lives here so the evaluator does not have to re-parse the IP / split the CIDR on the
// hot path.
func (c *Compiler) compileLitIP(nn *parser.LitIP) (op, *CompileError) {
	if !nn.IsCIDR {
		return &opLitIP{pos: posOf(nn), v: nn.Value, cidr: false, mask: 0}, nil
	}
	// CIDR — re-parse the raw string to recover the mask. The parser already validated
	// it (and stored the net.IP in nn.Value); the regex is cheap relative to the rest
	// of compile.
	_, ipnet, err := net.ParseCIDR(nn.Raw)
	if err != nil {
		// Should be unreachable: the parser already called net.ParseCIDR successfully.
		// Guarded for defensive completeness.
		return nil, &CompileError{
			Line: nn.Line, Col: nn.Col, Code: CodeInvalidLiteral,
			Message: fmt.Sprintf("invalid CIDR %q: %s", nn.Raw, err.Error()),
		}
	}
	mask, _ := ipnet.Mask.Size()
	return &opLitIP{pos: posOf(nn), v: nn.Value, cidr: true, mask: mask}, nil
}

// compileLitArray validates the array literal: every element must be a scalar literal.
// The set of accepted element Kinds matches what the evaluator can dispatch over without
// type ambiguity. FieldRef and other non-literals are rejected (CodeBadArrayElement)
// because their value is runtime-resolved and not enumerable for membership tests.
func (c *Compiler) compileLitArray(nn *parser.LitArray) (op, *CompileError) {
	if len(nn.Elements) == 0 {
		// Empty array is well-formed; `x in []` is always false at eval time. We
		// keep the empty case as a compile success — the operator semantics at
		// eval time make it equivalent to false. The `in` operator later validates
		// non-emptiness for its own purposes (see uniformArrayElementKind).
		return &opLitArray{pos: posOf(nn), elements: nil}, nil
	}
	elements := make([]op, 0, len(nn.Elements))
	for _, e := range nn.Elements {
		compiled, err := c.compileArrayElement(e)
		if err != nil {
			return nil, err
		}
		elements = append(elements, compiled)
	}
	return &opLitArray{pos: posOf(nn), elements: elements}, nil
}

// compileArrayElement is the per-element gate for array literals. Only scalar literal
// nodes (KindString, KindInt, KindFloat, KindBool, KindIP, KindBytes, KindTimestamp,
// KindDuration) are accepted. FieldRef, BracketAccess, FuncCall, and any composite
// expression are rejected with CodeBadArrayElement.
func (c *Compiler) compileArrayElement(n parser.Node) (op, *CompileError) {
	switch nn := n.(type) {
	case *parser.LitString:
		return &opLitString{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitInt:
		return &opLitInt{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitFloat:
		return &opLitFloat{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitBool:
		return &opLitBool{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitIP:
		return c.compileLitIP(nn)
	case *parser.LitBytes:
		return &opLitBytes{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitDuration:
		return &opLitDuration{pos: posOf(n), v: nn.Value}, nil
	case *parser.LitTimestamp:
		return &opLitTimestamp{pos: posOf(n), v: nn.Value}, nil
	default:
		ln, col := n.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeBadArrayElement,
			Message: "array literal must contain only constant literals",
		}
	}
}

// ========================== Field resolution =================================================

// compileFieldRef resolves the dotted name to a field ID via the Scheme (D9) and
// captures the field's declared type for the evaluator. Unknown field names are a
// compile error (CodeUnknownField) — this is the primary D9 enforcement gate.
func (c *Compiler) compileFieldRef(nn *parser.FieldRef) (op, *CompileError) {
	id, ok := c.fieldIdx[nn.Name]
	if !ok {
		return nil, &CompileError{
			Line: nn.Line, Col: nn.Col, Code: CodeUnknownField,
			Message: fmt.Sprintf("field %q is not in the active scheme", nn.Name),
		}
	}
	fields := c.scheme.Fields()
	return &opField{pos: posOf(nn), id: id, name: nn.Name, fieldType: fields[id].Type}, nil
}

// compileBracketAccess validates that the Object resolves to a Map-typed field and that
// the Key is a string literal. The Map keys themselves are eval-time resolved (D11) —
// the compiler does NOT validate that the key exists in the field's value space.
func (c *Compiler) compileBracketAccess(nn *parser.BracketAccess) (op, *CompileError) {
	// Object must be a plain FieldRef on a Map-typed field.
	ref, ok := nn.Object.(*parser.FieldRef)
	if !ok {
		ln, col := nn.Object.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeBadBracketAccess,
			Message: "bracket access object must be a field reference",
		}
	}
	id, found := c.fieldIdx[ref.Name]
	if !found {
		return nil, &CompileError{
			Line: ref.Line, Col: ref.Col, Code: CodeUnknownField,
			Message: fmt.Sprintf("field %q is not in the active scheme", ref.Name),
		}
	}
	fields := c.scheme.Fields()
	if fields[id].Type != rule.TypeMap {
		return nil, &CompileError{
			Line: ref.Line, Col: ref.Col, Code: CodeBadBracketAccess,
			Message: fmt.Sprintf("field %q is not a map (type %s)", ref.Name, fields[id].Type),
		}
	}

	// Key must be a LitString.
	keyStr, ok := nn.Key.(*parser.LitString)
	if !ok {
		ln, col := nn.Key.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeBadBracketAccess,
			Message: "bracket access key must be a string literal",
		}
	}
	s, _ := keyStr.Value.AsString()
	return &opBracket{
		pos: posOf(nn),
		obj: &opField{pos: posOf(ref), id: id, name: ref.Name, fieldType: rule.TypeMap},
		key: s,
	}, nil
}

// ========================== Function calls ==================================================

// compileFuncCall resolves the function name against the registry, validates the
// argument count and per-argument Kind against the registered FuncSpec, and emits an
// opFunc carrying the resolved spec (DECISION D16 §2 — compile-time signature
// checking).
//
// Errors:
//   - CodeUnknownFunction: name is not in the registry.
//   - CodeBadFuncArity: argument count does not match ParamKinds.
//   - CodeBadFuncArgType: per-argument Kind does not match the declared ParamKinds.
//
// Note: a parameter declared as KindInvalid in the registry (e.g. to_string's
// single "any" parameter) accepts any argument Kind. This is how to_string is
// polymorphic without special-casing the compiler's per-argument check.
//
// The resolved spec is stored on the opFunc so the evaluator dispatches directly
// to spec.Eval without re-looking-up the name or re-validating the signature.
func (c *Compiler) compileFuncCall(nn *parser.FuncCall) (op, *CompileError) {
	// Resolve the function name in the registry first — a bad name is the most
	// common error and short-circuits arg compilation (no point validating args
	// for a function that doesn't exist).
	spec, ok := Lookup(nn.Name)
	if !ok {
		return nil, &CompileError{
			Line: nn.Line, Col: nn.Col, Code: CodeUnknownFunction,
			Message: fmt.Sprintf("function %q is not in the function table", nn.Name),
		}
	}

	// Arity check — comes before arg compilation so a wrong count is reported as
	// CodeBadFuncArity, not as a confusing downstream type error.
	if len(nn.Args) != len(spec.ParamKinds) {
		return nil, &CompileError{
			Line: nn.Line, Col: nn.Col, Code: CodeBadFuncArity,
			Message: fmt.Sprintf("function %q expects %d argument(s), got %d", nn.Name, len(spec.ParamKinds), len(nn.Args)),
		}
	}

	// Compile args and check per-argument Kind against the declared ParamKinds.
	// KindInvalid in ParamKinds acts as "any" — the argument's Kind is accepted
	// unconditionally. For every other declared Kind the argument's compile-time
	// Kind must match exactly.
	args := make([]op, 0, len(nn.Args))
	for i, a := range nn.Args {
		compiled, err := c.compileNode(a)
		if err != nil {
			return nil, err
		}
		want := spec.ParamKinds[i]
		got := c.nodeKind(compiled)
		if want != rule.KindInvalid && got != want {
			return nil, &CompileError{
				Line: nn.Line, Col: nn.Col, Code: CodeBadFuncArgType,
				Message: fmt.Sprintf("function %q argument %d: expected %s, got %s", nn.Name, i+1, want, got),
			}
		}
		args = append(args, compiled)
	}

	return &opFunc{pos: posOf(nn), name: nn.Name, args: args, spec: spec}, nil
}

// ========================== Logic ops =======================================================

func (c *Compiler) compileAnd(nn *parser.And) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	return &opAnd{pos: posOf(nn), left: left, right: right}, nil
}

func (c *Compiler) compileOr(nn *parser.Or) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	return &opOr{pos: posOf(nn), left: left, right: right}, nil
}

func (c *Compiler) compileNot(nn *parser.Not) (op, *CompileError) {
	operand, err := c.compileNode(nn.Operand)
	if err != nil {
		return nil, err
	}
	return &opNot{pos: posOf(nn), operand: operand}, nil
}

// ========================== Comparison op ===================================================

// compileCmp type-checks the operands against the comparison operator. v1 is strict
// typed (D14 / D15): same-Kind operands for eq / ne; Orderable-Kind operands for
// lt / le / gt / ge; special IP-in-CIDR for eq / ne / in when right is a CIDR
// literal. No implicit Int↔Float coercion.
func (c *Compiler) compileCmp(nn *parser.Cmp) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	if err := c.checkCmpOperands(nn.Op, left, right, nn); err != nil {
		return nil, err
	}
	cmp := &opCmp{pos: posOf(nn), op: c.cmpOpOf(nn.Op), left: left, right: right}
	// Strict-flatten: if either side carried the `strict` modifier (parser allows
	// it on the right side of cmp, and as a leading keyword before the whole binary
	// expression), hoist the wrapper onto the Cmp. This collapses syntactic variants
	// (`a eq strict b`, `strict a eq b`) into a single canonical Plan shape.
	if _, ok := left.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: cmp}, nil
	}
	if _, ok := right.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: cmp}, nil
	}
	return cmp, nil
}

// cmpOpOf mirrors parser.CmpOp → opCmpOp. Centralised so a future op-set expansion
// touches exactly one map.
func (c *Compiler) cmpOpOf(p parser.CmpOp) opCmpOp {
	switch p {
	case parser.CmpEq:
		return opCmpEq
	case parser.CmpNe:
		return opCmpNe
	case parser.CmpLt:
		return opCmpLt
	case parser.CmpLe:
		return opCmpLe
	case parser.CmpGt:
		return opCmpGt
	case parser.CmpGe:
		return opCmpGe
	}
	return opCmpEq
}

// checkCmpOperands enforces the type rules. The check is centralised so every Cmp
// (including the inner op of a Strict) is validated identically.
//
// Rules (v1, strict):
//
//   - eq / ne: same-Kind operands. Special case: left = KindIP, right = KindIP with
//     cidr=true → IP-in-CIDR equality (the right side is a CIDR network; equality
//     becomes "is left a member of right's network").
//   - lt / le / gt / ge: both operands must be Orderable (Int, Float, Timestamp,
//     Duration, String). Timestamp vs Duration is rejected: arithmetic and
//     comparison across those Kinds is not defined in v1.
//   - IP, Bool, Bytes, Array, Map: not Orderable; eq / ne are the only allowed
//     comparisons.
//   - opBracket: the operand Kind is dynamic (Map element); for compile-time type
//     checking we treat it as a wildcard — either side may be opBracket, and the
//     other side's concrete Kind determines the comparison. The runtime evaluator
//     surfaces a type error if the resolved value's Kind is incompatible.
func (c *Compiler) checkCmpOperands(op parser.CmpOp, left, right op, src *parser.Cmp) *CompileError {
	leftKind := c.nodeKind(left)
	rightKind := c.nodeKind(right)

	// Strict-flatten: if either side is opStrict wrapping a literal, the inner op is
	// the actual operand. The wrapper is metadata, not a type.
	if s, ok := left.(*opStrict); ok {
		left = s.inner
		leftKind = c.nodeKind(left)
	}
	if s, ok := right.(*opStrict); ok {
		right = s.inner
		rightKind = c.nodeKind(right)
	}

	// opBracket is a wildcard: either side may be a Map access whose Kind is dynamic.
	leftIsBracket := isBracketOp(left)
	rightIsBracket := isBracketOp(right)
	if leftIsBracket {
		leftKind = rule.KindInvalid
	}
	if rightIsBracket {
		rightKind = rule.KindInvalid
	}

	switch op {
	case parser.CmpEq, parser.CmpNe:
		// Special case: IP `eq` IP-CIDR → IP-in-CIDR membership.
		if leftKind == rule.KindIP && rightKind == rule.KindIP && isCIDRLit(right) {
			return nil
		}
		// If one side is a wildcard (KindInvalid from opBracket), accept.
		if leftKind == rule.KindInvalid || rightKind == rule.KindInvalid {
			return nil
		}
		if leftKind != rightKind {
			return typeMismatchErr(src, "%s and %s are not comparable with %s", leftKind, rightKind, op.String())
		}
		return nil
	case parser.CmpLt, parser.CmpLe, parser.CmpGt, parser.CmpGe:
		if !isOrderable(leftKind) || !isOrderable(rightKind) {
			return typeMismatchErr(src, "%s is not orderable; %s requires orderable operands", leftKind, op.String())
		}
		if leftKind != rightKind {
			return typeMismatchErr(src, "cannot orderably compare %s and %s with %s", leftKind, rightKind, op.String())
		}
		return nil
	}
	return &CompileError{
		Line: src.Line, Col: src.Col, Code: CodeTypeMismatch,
		Message: fmt.Sprintf("unknown comparison operator %s", op.String()),
	}
}

// isBracketOp reports whether o is a *opBracket. Used by checkCmpOperands to
// dynamic-Kind-handle Map element accesses.
func isBracketOp(o op) bool {
	_, ok := o.(*opBracket)
	return ok
}

// isOrderable reports whether Kind is comparable with < / <= / > / >=. Array and Map
// have no natural order; Bool has no semantic order; IP has no order. Timestamp and
// Duration are orderable in their natural time sense; Int and Float are numeric;
// String is lexicographic.
func isOrderable(k rule.Kind) bool {
	switch k {
	case rule.KindInt, rule.KindFloat, rule.KindString, rule.KindTimestamp, rule.KindDuration:
		return true
	}
	return false
}

// isCIDRLit reports whether the op is a CIDR literal IP. Used by checkCmpOperands
// to switch IP `eq` IP into IP-in-CIDR semantics.
func isCIDRLit(o op) bool {
	if ip, ok := o.(*opLitIP); ok {
		return ip.cidr
	}
	return false
}

// typeMismatchErr builds a CodeTypeMismatch error anchored at the source Cmp node.
func typeMismatchErr(src *parser.Cmp, format string, args ...any) *CompileError {
	return &CompileError{
		Line: src.Line, Col: src.Col, Code: CodeTypeMismatch,
		Message: fmt.Sprintf(format, args...),
	}
}

// nodeKind extracts the underlying Value Kind from a plan op. For literal ops the
// Kind is taken from the stored Value. For non-literal ops the Kind is what the
// op WOULD produce at evaluation time: Bool for logic ops, Bool for the boolean-
// returning operators, the function's declared ReturnKind for opFunc, etc.
//
// This is a compile-time concept, not a runtime evaluation — it tells the type
// checker what Kind each op has, so it can match against operator signatures.
func (c *Compiler) nodeKind(o op) rule.Kind {
	switch n := o.(type) {
	case *opLitString:
		return n.v.Kind()
	case *opLitInt:
		return n.v.Kind()
	case *opLitFloat:
		return n.v.Kind()
	case *opLitBool:
		return n.v.Kind()
	case *opLitIP:
		return n.v.Kind()
	case *opLitBytes:
		return n.v.Kind()
	case *opLitDuration:
		return n.v.Kind()
	case *opLitTimestamp:
		return n.v.Kind()
	case *opLitArray:
		return rule.KindArray
	case *opField:
		return kindFromFieldType(n.fieldType)
	case *opBracket:
		// BracketAccess on a Map field produces a Value whose Kind is determined
		// at evaluation time. For compile-time type checking purposes we treat
		// it as KindInvalid — the operator's type rule must accept any.
		return rule.KindInvalid
	case *opAnd, *opOr:
		return rule.KindBool
	case *opNot:
		return rule.KindBool
	case *opCmp, *opContains, *opStartsWith, *opEndsWith, *opMatches, *opWildcard, *opIn, *opStrict:
		return rule.KindBool
	case *opFunc:
		// Return the function's declared return Kind (D16 §2). The spec is
		// populated by compileFuncCall at compile time, so downstream operators
		// and comparisons type-check against the function's actual return.
		return n.spec.ReturnKind
	}
	return rule.KindInvalid
}

// kindFromFieldType maps a Scheme FieldType to the runtime Kind it represents. The
// mapping is the inverse of the FieldType constants in scheme.go.
func kindFromFieldType(ft rule.FieldType) rule.Kind {
	switch ft {
	case rule.TypeString:
		return rule.KindString
	case rule.TypeInt:
		return rule.KindInt
	case rule.TypeFloat:
		return rule.KindFloat
	case rule.TypeBool:
		return rule.KindBool
	case rule.TypeIP:
		return rule.KindIP
	case rule.TypeBytes:
		return rule.KindBytes
	case rule.TypeTimestamp:
		return rule.KindTimestamp
	case rule.TypeDuration:
		return rule.KindDuration
	case rule.TypeArray:
		return rule.KindArray
	case rule.TypeMap:
		return rule.KindMap
	}
	return rule.KindInvalid
}

// ========================== String ops ======================================================

// All five string operators follow the same shape: left must be String, right must be
// String (or a literal regex pattern for `matches`). The five compileX helpers exist
// so each operator's type rule reads cleanly; the shared shape avoids a single
// large switch.

func (c *Compiler) compileContains(nn *parser.Contains) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	if c.nodeKind(left) != rule.KindString {
		return nil, stringOpErr(nn, "contains: left operand must be string, got %s", c.nodeKind(left))
	}
	if c.nodeKind(right) != rule.KindString {
		return nil, stringOpErr(nn, "contains: right operand must be string, got %s", c.nodeKind(right))
	}
	co := &opContains{pos: posOf(nn), left: left, right: right}
	if _, ok := left.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: co}, nil
	}
	if _, ok := right.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: co}, nil
	}
	return co, nil
}

func (c *Compiler) compileStartsWith(nn *parser.StartsWith) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	if c.nodeKind(left) != rule.KindString {
		return nil, stringOpErr(nn, "starts_with: left operand must be string, got %s", c.nodeKind(left))
	}
	if c.nodeKind(right) != rule.KindString {
		return nil, stringOpErr(nn, "starts_with: right operand must be string, got %s", c.nodeKind(right))
	}
	so := &opStartsWith{pos: posOf(nn), left: left, right: right}
	if _, ok := left.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: so}, nil
	}
	if _, ok := right.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: so}, nil
	}
	return so, nil
}

func (c *Compiler) compileEndsWith(nn *parser.EndsWith) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	right, err := c.compileNode(nn.Right)
	if err != nil {
		return nil, err
	}
	if c.nodeKind(left) != rule.KindString {
		return nil, stringOpErr(nn, "ends_with: left operand must be string, got %s", c.nodeKind(left))
	}
	if c.nodeKind(right) != rule.KindString {
		return nil, stringOpErr(nn, "ends_with: right operand must be string, got %s", c.nodeKind(right))
	}
	eo := &opEndsWith{pos: posOf(nn), left: left, right: right}
	if _, ok := left.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: eo}, nil
	}
	if _, ok := right.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: eo}, nil
	}
	return eo, nil
}

// compileMatches compiles the regex pattern at compile time (D4 — pre-compiled
// regex literals). The Plan stores the *regexp.Regexp directly, not the string,
// so the evaluator's hot path does no regex compilation per call.
//
// Left operand must be String or Bytes. The right operand is the regex pattern
// itself — we accept a LitString and compile it; any other right-side node is
// rejected (we do not support dynamic regexes — they would be a security hazard
// and a per-call compilation cost).
func (c *Compiler) compileMatches(nn *parser.Matches) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	leftKind := c.nodeKind(left)
	if leftKind != rule.KindString && leftKind != rule.KindBytes {
		return nil, stringOpErr(nn, "matches: left operand must be string or bytes, got %s", leftKind)
	}

	rightNode, ok := nn.Right.(*parser.LitString)
	if !ok {
		ln, col := nn.Right.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeBadRegex,
			Message: "matches: right operand must be a string literal regex pattern",
		}
	}
	pattern, _ := rightNode.Value.AsString()
	re, rerr := regexp.Compile(pattern)
	if rerr != nil {
		return nil, &CompileError{
			Line: rightNode.Line, Col: rightNode.Col, Code: CodeBadRegex,
			Message: fmt.Sprintf("invalid regex pattern %q: %s", pattern, rerr.Error()),
		}
	}
	return &opMatches{pos: posOf(nn), left: left, regex: re}, nil
}

// compileWildcard validates the wildcard pattern is a LitString and stores it for
// the evaluator. The evaluator (C2) interprets the pattern — for v1 the pattern
// grammar is "?" (any single char) and "*" (any sequence of chars). The compiler
// does not validate the pattern content beyond confirming it is a string literal.
func (c *Compiler) compileWildcard(nn *parser.Wildcard) (op, *CompileError) {
	left, err := c.compileNode(nn.Left)
	if err != nil {
		return nil, err
	}
	if c.nodeKind(left) != rule.KindString {
		return nil, stringOpErr(nn, "wildcard: left operand must be string, got %s", c.nodeKind(left))
	}
	rightNode, ok := nn.Right.(*parser.LitString)
	if !ok {
		ln, col := nn.Right.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeTypeMismatch,
			Message: "wildcard: right operand must be a string literal pattern",
		}
	}
	pattern, _ := rightNode.Value.AsString()
	return &opWildcard{pos: posOf(nn), left: left, pattern: pattern}, nil
}

// stringOpErr builds a CodeTypeMismatch error anchored at the source string-op node.
func stringOpErr(n parser.Node, format string, args ...any) *CompileError {
	ln, col := n.Pos()
	return &CompileError{
		Line: ln, Col: col, Code: CodeTypeMismatch,
		Message: fmt.Sprintf(format, args...),
	}
}

// ========================== In op ===========================================================

// compileIn validates that the Set is a LitArray of scalars and that the Element is
// compatible with the array element Kinds. The element-vs-set compatibility rule is:
//   - All elements must share a common Kind (or be all IP, in which case CIDR
//     literals are also accepted for IP-in-CIDR membership).
//   - The element's Kind must match the elements' common Kind.
//
// Mixed-Kind arrays are a compile error (CodeTypeMismatch). The check is done
// after the array is compiled, so each element's Kind is known.
func (c *Compiler) compileIn(nn *parser.In) (op, *CompileError) {
	element, err := c.compileNode(nn.Element)
	if err != nil {
		return nil, err
	}
	setCompiled, err := c.compileNode(nn.Set)
	if err != nil {
		return nil, err
	}
	set, ok := setCompiled.(*opLitArray)
	if !ok {
		// Parser normally always produces LitArray on the right of `in`; this
		// branch is a defensive guard.
		ln, col := nn.Set.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeTypeMismatch,
			Message: "in: right operand must be an array literal",
		}
	}

	// Determine the array's element Kind. Mixed-Kind arrays are rejected.
	elemKind, cerr := c.uniformArrayElementKind(set)
	if cerr != nil {
		return nil, cerr
	}

	// Element vs set compatibility. IP element allows IP or IP-CIDR array; plain
	// element Kind must match.
	elemKindOfOp := c.nodeKind(element)
	if elemKindOfOp == rule.KindInvalid {
		// Element is something whose Kind is not statically determinable (BracketAccess
		// on a Map). Reject — `in` requires a typed element to compare against typed
		// array slots.
		ln, col := nn.Element.Pos()
		return nil, &CompileError{
			Line: ln, Col: col, Code: CodeTypeMismatch,
			Message: "in: element kind is not statically determinable",
		}
	}

	if elemKind == rule.KindIP {
		// IP element accepts any IP array (with or without CIDR members).
		if elemKindOfOp != rule.KindIP {
			ln, col := nn.Element.Pos()
			return nil, &CompileError{
				Line: ln, Col: col, Code: CodeTypeMismatch,
				Message: fmt.Sprintf("in: element kind %s does not match array kind %s", elemKindOfOp, elemKind),
			}
		}
	} else {
		if elemKindOfOp != elemKind {
			ln, col := nn.Element.Pos()
			return nil, &CompileError{
				Line: ln, Col: col, Code: CodeTypeMismatch,
				Message: fmt.Sprintf("in: element kind %s does not match array kind %s", elemKindOfOp, elemKind),
			}
		}
	}

	inOp := &opIn{pos: posOf(nn), element: element, set: set}
	// Strict-flatten: parser allows `strict` before the Element (`strict x in [...]`)
	// but not in any other position. Hoist the wrapper onto the opIn.
	if _, ok := element.(*opStrict); ok {
		return &opStrict{pos: posOf(nn), inner: inOp}, nil
	}
	return inOp, nil
}

// uniformArrayElementKind returns the single common Kind of the array's elements,
// or CodeTypeMismatch if the array is empty or has mixed Kinds.
func (c *Compiler) uniformArrayElementKind(arr *opLitArray) (rule.Kind, *CompileError) {
	if len(arr.elements) == 0 {
		// Empty array — `x in []` is always false; we report a soft type error to
		// surface the oddity, but a v1 author may legitimately want an empty set.
		// Reject to keep the semantic unambiguous.
		return rule.KindInvalid, &CompileError{
			Line: arr.pos.line, Col: arr.pos.col, Code: CodeTypeMismatch,
			Message: "in: array literal must contain at least one element",
		}
	}
	first := c.nodeKind(arr.elements[0])
	for i := 1; i < len(arr.elements); i++ {
		k := c.nodeKind(arr.elements[i])
		if k != first {
			return rule.KindInvalid, &CompileError{
				Line: arr.pos.line, Col: arr.pos.col, Code: CodeTypeMismatch,
				Message: fmt.Sprintf("in: array has mixed element kinds (%s and %s)", first, k),
			}
		}
	}
	return first, nil
}

// ========================== Strict op =======================================================

// compileStrict compiles a parser.Strict node. The wrapper is a syntactic marker
// (D14) — semantically a no-op in v1 (the default behavior is already strict-typed),
// but the parser records the modifier and the compiler preserves it in the Plan.
//
// The strict-placement validation (Strict may only wrap a binary operator, possibly
// via wrapping a literal that lives in a binary op's right-operand slot) is enforced
// in two layers:
//
//  1. compileStrict accepts the wrapper whenever its Inner is a binary op
//     (Cmp / string-op / In) or a literal (so the wrapper can later be hoisted by
//     a parent binary op's compileX helper).
//  2. The top-level dispatch (compileNode) does NOT accept a *opStrict whose
//     inner is a logic op (And / Or / Not) — those are not strict-eligible
//     contexts and the wrapper would have nothing to hoist to.
//
// The two-layer rule ensures: `strict 200` is accepted (literal will be hoisted by
// a parent cmp), `a eq strict b` is accepted (Strict{literal} hoisted to Cmp),
// `strict (a or b)` is rejected (no binary op parent to hoist to).
func (c *Compiler) compileStrict(nn *parser.Strict) (op, *CompileError) {
	inner, err := c.compileNode(nn.Inner)
	if err != nil {
		return nil, err
	}
	switch inner.(type) {
	case *opCmp, *opContains, *opStartsWith, *opEndsWith, *opMatches, *opWildcard, *opIn:
		// Strict directly wraps a binary op — no hoisting needed.
		return &opStrict{pos: posOf(nn), inner: inner}, nil
	case *opLitString, *opLitInt, *opLitFloat, *opLitBool, *opLitIP, *opLitBytes, *opLitDuration, *opLitTimestamp:
		// Strict wraps a literal — the parent binary op's compileX helper will
		// see this opStrict on the right-operand slot and hoist it onto the op.
		return &opStrict{pos: posOf(nn), inner: inner}, nil
	default:
		return nil, &CompileError{
			Line: nn.Line, Col: nn.Col, Code: CodeBadStrictPlace,
			Message: "strict modifier can only wrap comparison / string / in operators",
		}
	}
}

// ========================== CompileError conformance ========================================
//
// *CompileError must satisfy the error interface. The declaration is a no-op
// assignment that fails at compile time if Error() drifts.

var _ error = (*CompileError)(nil)
