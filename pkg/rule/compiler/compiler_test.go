// ========================== pkg/rule/compiler — tests ========================================
//   Coverage goals (from TASKS.md F4):
//     1.  Unknown field compile error (waf profile expression uses syslog-only field).
//     2.  Type mismatch on cmp: e.g. http.status eq "abc".
//     3.  Type match on cmp: e.g. http.status eq 200.
//     4.  String op on non-string: e.g. http.method contains 42.
//     5.  IP eq IP / IP eq CIDR — happy paths.
//     6.  IP in [IP, ...] — happy path.
//     7.  IP in [mixed kinds] — compile error.
//     8.  matches with valid regex / matches with bad regex "[unclosed".
//     9.  in with non-literal in array.
//    10.  in with literal array.
//    11.  Strict placement OK: http.status eq strict 200.
//    12.  Strict placement error: strict (a or b).
//    13.  FuncCall unknown name rejected (Flow 002 D16): no_such_function(...) → unknown_function.
//    14.  BracketAccess OK on Map field.
//    15.  BracketAccess error: object not Map-typed.
//    16.  BracketAccess error: key not string literal.
//    17.  Scheme revision captured in Plan.
//    18.  Compile against nil scheme → error.
//    19.  Complex real expression: range check + not + IP-in-CIDR. Whitebox test:
//         walk the Plan and assert on concrete op types.
//    20.  Concurrent Compile from multiple goroutines — race detector pass.
//
//   Style note: white-box tests in `package compiler` so we can compare against the
//   concrete op types without reflecting. The standard test package pattern follows
//   parser_test.go and scheme_test.go (table-driven, t.Errorf with "%v, want %v").

package compiler

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== Helpers =========================================================

// wafScheme returns a Scheme with the WAF profile field set: core.* (Envelope)
// + http.* (typical WAF use cases). syslog.* fields are deliberately excluded to
// exercise the D9 profile-gating error in test 1.
//
// Additional fields used by Group E function tests (client_ip / ratio) are
// registered here as TEST FIXTURES only — a production WAF scheme does NOT
// require them; they live in this helper so that the per-family E1/E2/E3
// tests can reference a single shared Scheme. Future flows that change the
// field set must keep the test fixtures stable unless they also update the
// affected test files.
func wafScheme(t *testing.T) *rule.Scheme {
	t.Helper()
	cat := rule.NewCatalog()
	mustRegister(t, cat, "core", "timestamp", rule.TypeTimestamp)
	mustRegister(t, cat, "core", "stream", rule.TypeString)
	mustRegister(t, cat, "core", "source", rule.TypeString)
	mustRegister(t, cat, "core", "source_type", rule.TypeString)
	mustRegister(t, cat, "core", "level", rule.TypeString)
	mustRegister(t, cat, "http", "method", rule.TypeString)
	mustRegister(t, cat, "http", "uri", rule.TypeString)
	mustRegister(t, cat, "http", "status", rule.TypeInt)
	mustRegister(t, cat, "http", "client_ip", rule.TypeIP) // E1 test fixture
	mustRegister(t, cat, "http", "ratio", rule.TypeFloat)  // E3 test fixture
	mustRegister(t, cat, "http", "headers", rule.TypeMap)
	mustRegister(t, cat, "http", "ua", rule.TypeString)
	mustRegister(t, cat, "http", "body", rule.TypeBytes) // F1 bitmask-test fixture
	return cat.Project("core", "http")
}

// syslogScheme returns a Scheme with syslog.* fields for cross-profile test 1.
func syslogScheme(t *testing.T) *rule.Scheme {
	t.Helper()
	cat := rule.NewCatalog()
	mustRegister(t, cat, "syslog", "facility", rule.TypeString)
	mustRegister(t, cat, "syslog", "severity", rule.TypeString)
	return cat.Project("syslog")
}

// mustRegister registers a field in cat, failing the test on error. Setup helper for
// the Scheme builders — registration errors here are test fixture bugs and must surface
// loudly instead of being silently discarded.
func mustRegister(t *testing.T, cat *rule.Catalog, ns, name string, typ rule.FieldType) {
	t.Helper()
	if err := cat.Register(ns, name, typ); err != nil {
		t.Fatalf("Register(%q, %q, %v): %v", ns, name, typ, err)
	}
}

// mustParse is a test helper — calls parser.Parse and fails the test on error. Returns
// the root Node so the compiler test can call Compile on it.
func mustParse(t *testing.T, src string) parser.Node {
	t.Helper()
	n, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("parser.Parse(%q): %v", src, err)
	}
	if n == nil {
		t.Fatalf("parser.Parse(%q) returned nil node", src)
	}
	return n
}

// compileOK compiles src against scheme and fails the test on any error. Returns the
// Plan for structural inspection.
func compileOK(t *testing.T, src string, scheme *rule.Scheme) *Plan {
	t.Helper()
	p, err := Compile(mustParse(t, src), scheme)
	if err != nil {
		t.Fatalf("Compile(%q) returned unexpected error: %v", src, err)
	}
	if p == nil {
		t.Fatalf("Compile(%q) returned nil plan with nil error", src)
	}
	return p
}

// compileErr compiles src against scheme and fails the test if the error is nil. Returns
// the *CompileError for Code / Line / Col inspection.
func compileErr(t *testing.T, src string, scheme *rule.Scheme) *CompileError {
	t.Helper()
	_, err := Compile(mustParse(t, src), scheme)
	if err == nil {
		t.Fatalf("Compile(%q) expected error, got nil", src)
	}
	return err
}

// ========================== 1. Unknown field (D9 profile gating) ============================

// TestCompiler_UnknownField exercises the primary D9 enforcement gate. The waf scheme
// does NOT include syslog.facility; an expression that references it must be a compile
// error with CodeUnknownField — caught at compile time, not at eval time.
func TestCompiler_UnknownField(t *testing.T) {
	ce := compileErr(t, `syslog.facility eq "auth"`, wafScheme(t))
	if ce.Code != CodeUnknownField {
		t.Errorf("got Code %q, want %q", ce.Code, CodeUnknownField)
	}
	if !strings.Contains(ce.Message, "syslog.facility") {
		t.Errorf("Message %q should mention the offending field name", ce.Message)
	}
}

// ========================== 2-3. Type mismatch / type match on cmp ==========================

// TestCompiler_TypeMismatch_Cmp covers test 2: comparing an Int field against a string
// literal must be a compile-time type error. http.status is TypeInt in wafScheme.
func TestCompiler_TypeMismatch_Cmp(t *testing.T) {
	ce := compileErr(t, `http.status eq "abc"`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "int") {
		t.Errorf("Message %q should mention int kind", ce.Message)
	}
	if !strings.Contains(ce.Message, "string") {
		t.Errorf("Message %q should mention string kind", ce.Message)
	}
}

// TestCompiler_TypeMatch_Cmp covers test 3: comparing an Int field against an Int
// literal must compile cleanly. Whitebox: root op is *opCmp with opCmpEq.
func TestCompiler_TypeMatch_Cmp(t *testing.T) {
	p := compileOK(t, `http.status eq 200`, wafScheme(t))
	cmp, ok := p.Root().(*opCmp)
	if !ok {
		t.Fatalf("root op = %T, want *opCmp", p.Root())
	}
	if cmp.op != opCmpEq {
		t.Errorf("cmp.op = %d, want opCmpEq (%d)", cmp.op, opCmpEq)
	}
	// Right-hand side should be a *opLitInt.
	if _, ok := cmp.right.(*opLitInt); !ok {
		t.Errorf("cmp.right = %T, want *opLitInt", cmp.right)
	}
}

// ========================== 4. String op on non-string ======================================

// TestCompiler_StringOpOnNonString covers test 4: `contains` requires both operands to
// be string-typed. http.method is TypeString, but a numeric literal on the right side
// produces CodeTypeMismatch.
func TestCompiler_StringOpOnNonString(t *testing.T) {
	ce := compileErr(t, `http.method contains 42`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "string") {
		t.Errorf("Message %q should mention string kind", ce.Message)
	}
}

// ========================== 5-7. IP operators ===============================================

// TestCompiler_IPEqIP covers test 5a: plain IP equality between two IP literals.
func TestCompiler_IPEqIP(t *testing.T) {
	p := compileOK(t, `ip"10.0.0.1" eq ip"10.0.0.1"`, wafScheme(t))
	if _, ok := p.Root().(*opCmp); !ok {
		t.Errorf("root = %T, want *opCmp", p.Root())
	}
}

// TestCompiler_IPEqCIDR covers test 5b: IP `eq` CIDR is special — the right side is a
// CIDR, and the operation becomes membership. The compiler accepts the same-Kind
// comparison (IP vs IP) and flags the right side as cidr=true. The Plan op is still
// *opCmp; the runtime semantics differ (C2's job), but the Plan structure is identical.
func TestCompiler_IPEqCIDR(t *testing.T) {
	p := compileOK(t, `ip"10.0.0.1" eq ip"10.0.0.0/8"`, wafScheme(t))
	cmp, ok := p.Root().(*opCmp)
	if !ok {
		t.Fatalf("root = %T, want *opCmp", p.Root())
	}
	ipLit, ok := cmp.right.(*opLitIP)
	if !ok {
		t.Fatalf("right = %T, want *opLitIP", cmp.right)
	}
	if !ipLit.cidr {
		t.Error("right op should be flagged as cidr=true")
	}
}

// TestCompiler_IPInCIDRArray covers test 6: an `in` expression with a uniform IP array
// (mixing plain IPs and CIDR literals) is allowed by the compiler.
func TestCompiler_IPInCIDRArray(t *testing.T) {
	p := compileOK(t, `ip"10.0.0.1" in [ip"10.0.0.0/8", ip"172.16.0.0/12"]`, wafScheme(t))
	in, ok := p.Root().(*opIn)
	if !ok {
		t.Fatalf("root = %T, want *opIn", p.Root())
	}
	arr, ok := in.set.(*opLitArray)
	if !ok {
		t.Fatalf("set = %T, want *opLitArray", in.set)
	}
	if len(arr.elements) != 2 {
		t.Errorf("arr.elements len = %d, want 2", len(arr.elements))
	}
	// Each element should be a *opLitIP.
	for i, e := range arr.elements {
		if _, ok := e.(*opLitIP); !ok {
			t.Errorf("arr.elements[%d] = %T, want *opLitIP", i, e)
		}
	}
}

// TestCompiler_IPInMixedArray covers test 7: mixing kinds in an `in` array is rejected.
func TestCompiler_IPInMixedArray(t *testing.T) {
	ce := compileErr(t, `ip"10.0.0.1" in [ip"10.0.0.1", "abc"]`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "mixed") {
		t.Errorf("Message %q should mention mixed kinds", ce.Message)
	}
}

// ========================== 8. matches — happy path and bad regex ============================

// TestCompiler_MatchesHappy covers test 8a: `matches` with a valid regex pattern
// compiles cleanly. The Plan stores the pre-compiled *regexp.Regexp directly, not the
// pattern string.
func TestCompiler_MatchesHappy(t *testing.T) {
	p := compileOK(t, `http.uri matches "^/api/.*"`, wafScheme(t))
	m, ok := p.Root().(*opMatches)
	if !ok {
		t.Fatalf("root = %T, want *opMatches", p.Root())
	}
	if m.regex == nil {
		t.Fatal("opMatches.regex is nil — compiler should have pre-compiled")
	}
	if m.regex.String() != "^/api/.*" {
		t.Errorf("regex = %q, want %q", m.regex.String(), "^/api/.*")
	}
}

// TestCompiler_MatchesBad covers test 8b: a malformed regex pattern is a compile error
// with CodeBadRegex. We do NOT want to fail at evaluation time.
func TestCompiler_MatchesBad(t *testing.T) {
	ce := compileErr(t, `http.uri matches "[unclosed"`, wafScheme(t))
	if ce.Code != CodeBadRegex {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadRegex)
	}
}

// ========================== 9-10. in — array element validation =============================

// TestCompiler_InWithNonLiteral covers test 9: a field reference inside an array literal
// is rejected with CodeBadArrayElement. The `in` set must be enumerable at compile time.
func TestCompiler_InWithNonLiteral(t *testing.T) {
	ce := compileErr(t, `ip"10.0.0.1" in [ip.src]`, wafScheme(t))
	if ce.Code != CodeBadArrayElement {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadArrayElement)
	}
}

// TestCompiler_InWithLiteralArray covers test 10: a uniform literal array compiles
// cleanly. The Plan structure asserts that the array's elements are scalar ops.
func TestCompiler_InWithLiteralArray(t *testing.T) {
	p := compileOK(t, `http.status in [200, 404, 500]`, wafScheme(t))
	in, ok := p.Root().(*opIn)
	if !ok {
		t.Fatalf("root = %T, want *opIn", p.Root())
	}
	arr, ok := in.set.(*opLitArray)
	if !ok {
		t.Fatalf("set = %T, want *opLitArray", in.set)
	}
	if len(arr.elements) != 3 {
		t.Errorf("arr.elements len = %d, want 3", len(arr.elements))
	}
	for i, e := range arr.elements {
		if _, ok := e.(*opLitInt); !ok {
			t.Errorf("arr.elements[%d] = %T, want *opLitInt", i, e)
		}
	}
}

// ========================== 11-12. Strict placement ==========================================

// TestCompiler_StrictPlacementOK covers test 11: `strict` wrapping a Cmp compiles
// cleanly. The Plan's root is *opStrict wrapping *opCmp.
func TestCompiler_StrictPlacementOK(t *testing.T) {
	p := compileOK(t, `http.status eq strict 200`, wafScheme(t))
	s, ok := p.Root().(*opStrict)
	if !ok {
		t.Fatalf("root = %T, want *opStrict", p.Root())
	}
	if _, ok := s.inner.(*opCmp); !ok {
		t.Errorf("inner = %T, want *opCmp", s.inner)
	}
}

// TestCompiler_StrictPlacementError covers test 12: `strict` wrapping a logic operator
// is rejected. Only binary operators (Cmp / string-op / In) may be strict-wrapped.
func TestCompiler_StrictPlacementError(t *testing.T) {
	ce := compileErr(t, `strict (http.status eq 200 or http.status eq 404)`, wafScheme(t))
	if ce.Code != CodeBadStrictPlace {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadStrictPlace)
	}
}

// TestCompiler_StrictOnRightOfCmp covers a syntactic variant the parser accepts:
// `a eq strict b`. The compiler must accept it (v1 strict is the default behavior),
// and the Plan shape is *opStrict{opCmp{...}} — the strict wrapper is hoisted from
// the right operand onto the whole Cmp expression.
func TestCompiler_StrictOnRightOfCmp(t *testing.T) {
	p := compileOK(t, `http.status eq strict 200`, wafScheme(t))
	s, ok := p.Root().(*opStrict)
	if !ok {
		t.Fatalf("root = %T, want *opStrict", p.Root())
	}
	if _, ok := s.inner.(*opCmp); !ok {
		t.Errorf("inner = %T, want *opCmp", s.inner)
	}
}

// ========================== 13. Function registry compile errors ===========================

// TestCompiler_FuncCall_UnknownName covers test 13a: a function name that is not in
// the registry is rejected with CodeUnknownFunction. The negative surface is split
// from the original TestCompiler_FuncCallRejected because the registry now has real
// entries; arity / arg-type negatives land below (TestCompiler_FuncCall_BadArity,
// TestCompiler_FuncCall_BadArgType) and depend on a real registered function.
//
// This is the only D16 §2 negative that can run without depending on a specific
// registered function — every other negative tests against a function that exists.
func TestCompiler_FuncCall_UnknownName(t *testing.T) {
	ce := compileErr(t, `no_such_function(http.method)`, wafScheme(t))
	if ce.Code != CodeUnknownFunction {
		t.Errorf("got Code %q, want %q", ce.Code, CodeUnknownFunction)
	}
	if !strings.Contains(ce.Message, "no_such_function") {
		t.Errorf("Message %q should mention the function name", ce.Message)
	}
}

// ========================== 14-16. BracketAccess ===========================================

// TestCompiler_BracketAccessOK covers test 14: bracket access on a Map-typed field with
// a string-literal key compiles cleanly. The Plan's root is *opBracket.
func TestCompiler_BracketAccessOK(t *testing.T) {
	p := compileOK(t, `http.headers["x-foo"] eq "bar"`, wafScheme(t))
	// Root is the Cmp wrapping the BracketAccess — the Cmp is the outermost construct.
	cmp, ok := p.Root().(*opCmp)
	if !ok {
		t.Fatalf("root = %T, want *opCmp", p.Root())
	}
	br, ok := cmp.left.(*opBracket)
	if !ok {
		t.Fatalf("cmp.left = %T, want *opBracket", cmp.left)
	}
	if br.key != "x-foo" {
		t.Errorf("br.key = %q, want %q", br.key, "x-foo")
	}
	if br.obj.fieldType != rule.TypeMap {
		t.Errorf("br.obj.fieldType = %s, want map", br.obj.fieldType)
	}
}

// TestCompiler_BracketAccessNonMap covers test 15: bracket access on a non-Map-typed
// field is rejected with CodeBadBracketAccess.
func TestCompiler_BracketAccessNonMap(t *testing.T) {
	ce := compileErr(t, `http.method["x"]`, wafScheme(t))
	if ce.Code != CodeBadBracketAccess {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadBracketAccess)
	}
	if !strings.Contains(ce.Message, "not a map") {
		t.Errorf("Message %q should mention 'not a map'", ce.Message)
	}
}

// TestCompiler_BracketAccessNonStringKey covers test 16: bracket access with a non-
// string-literal key is rejected with CodeBadBracketAccess.
func TestCompiler_BracketAccessNonStringKey(t *testing.T) {
	ce := compileErr(t, `http.headers[http.method]`, wafScheme(t))
	if ce.Code != CodeBadBracketAccess {
		t.Errorf("got Code %q, want %q", ce.Code, CodeBadBracketAccess)
	}
	if !strings.Contains(ce.Message, "string literal") {
		t.Errorf("Message %q should mention 'string literal'", ce.Message)
	}
}

// ========================== 17. Scheme revision captured ===================================

// TestCompiler_SchemeRevisionCaptured covers test 17: the Plan carries the Scheme
// revision it was compiled against (D13 stale-detection seed).
func TestCompiler_SchemeRevisionCaptured(t *testing.T) {
	scheme := wafScheme(t)
	before := scheme.Revision()
	p := compileOK(t, `http.status eq 200`, scheme)
	if p.Rev != before {
		t.Errorf("Plan.Rev = %d, want %d (Scheme.Revision at compile time)", p.Rev, before)
	}
	// Plan.Rev is captured at compile time. If we mutate the underlying Catalog
	// after the compile, the Scheme's revision does NOT change (Scheme is an
	// immutable snapshot) — so the captured Rev stays equal to Scheme.Revision().
	// This is the D13 invariant.
}

// ========================== 18. Nil scheme handling ========================================

// TestCompiler_NilScheme covers test 18: Compile against a nil scheme returns a
// CodeNilScheme error. NewCompiler also returns the same error. The caller can
// fail-fast at construction or at the first compile call.
func TestCompiler_NilScheme(t *testing.T) {
	_, err := NewCompiler(nil)
	if err == nil {
		t.Fatal("NewCompiler(nil) returned nil error")
	}
	if err.Code != CodeNilScheme {
		t.Errorf("NewCompiler(nil) Code = %q, want %q", err.Code, CodeNilScheme)
	}

	// And via the package-level convenience constructor.
	_, err2 := Compile(mustParse(t, `http.status eq 200`), nil)
	if err2 == nil {
		t.Fatal("Compile(_, nil) returned nil error")
	}
	if err2.Code != CodeNilScheme {
		t.Errorf("Compile(_, nil) Code = %q, want %q", err2.Code, CodeNilScheme)
	}
}

// ========================== 19. Complex real expression (whitebox) ==========================

// TestCompiler_ComplexExpression covers test 19: a realistic WAF rule (4xx status
// range check combined with a non-CIDR-membership test) compiles cleanly, and the
// resulting Plan has the expected structural shape.
//
// Expression:
//
//	http.status ge 400 and http.status lt 500 and not (ip"192.168.1.1" in [ip"10.0.0.0/8"])
//
// Expected Plan tree (root-down):
//
//	opAnd
//	  left: opAnd
//	    left:  opCmp ge (http.status, 400)
//	    right: opCmp lt (http.status, 500)
//	  right: opNot
//	    inner: opIn (ip"192.168.1.1", [opLitIP])
//
// The structure is left-associative AND: `(a AND b) AND c`, with the AND nodes arranged
// as a left-leaning binary tree.
func TestCompiler_ComplexExpression(t *testing.T) {
	src := `http.status ge 400 and http.status lt 500 and not (ip"192.168.1.1" in [ip"10.0.0.0/8"])`
	p := compileOK(t, src, wafScheme(t))

	// Walk the Plan and assert on the structure. The test is whitebox: we type-assert
	// on the unexported op types directly.
	topAnd, ok := p.Root().(*opAnd)
	if !ok {
		t.Fatalf("root = %T, want *opAnd", p.Root())
	}
	// topAnd.right must be *opNot.
	not, ok := topAnd.right.(*opNot)
	if !ok {
		t.Fatalf("topAnd.right = %T, want *opNot", topAnd.right)
	}
	// not.operand must be *opIn.
	in, ok := not.operand.(*opIn)
	if !ok {
		t.Fatalf("not.operand = %T, want *opIn", not.operand)
	}
	// in.set must be *opLitArray of *opLitIP.
	arr, ok := in.set.(*opLitArray)
	if !ok {
		t.Fatalf("in.set = %T, want *opLitArray", in.set)
	}
	if len(arr.elements) != 1 {
		t.Errorf("arr.elements len = %d, want 1", len(arr.elements))
	}
	if arr.elements[0].(*opLitIP).cidr != true {
		t.Error("the single array element should be a CIDR literal (cidr=true)")
	}

	// topAnd.left must be *opAnd (the inner AND of the two cmp expressions).
	innerAnd, ok := topAnd.left.(*opAnd)
	if !ok {
		t.Fatalf("topAnd.left = %T, want *opAnd", topAnd.left)
	}
	// Both sides of innerAnd must be *opCmp.
	leftCmp, ok := innerAnd.left.(*opCmp)
	if !ok {
		t.Fatalf("innerAnd.left = %T, want *opCmp", innerAnd.left)
	}
	if leftCmp.op != opCmpGe {
		t.Errorf("leftCmp.op = %d, want opCmpGe (%d)", leftCmp.op, opCmpGe)
	}
	rightCmp, ok := innerAnd.right.(*opCmp)
	if !ok {
		t.Fatalf("innerAnd.right = %T, want *opCmp", innerAnd.right)
	}
	if rightCmp.op != opCmpLt {
		t.Errorf("rightCmp.op = %d, want opCmpLt (%d)", rightCmp.op, opCmpLt)
	}
}

// ========================== 20. Concurrent compile (race detector) ==========================

// TestCompiler_Concurrent covers test 20: a *Compiler must be safe for concurrent
// Compile calls. We run N goroutines compiling distinct expressions; the race detector
// (`go test -race`) reports any data race in compiler internal state.
//
// We use WaitGroup + a barrier to maximise contention: all goroutines start at roughly
// the same time, then each compiles a small batch of expressions.
func TestCompiler_Concurrent(t *testing.T) {
	scheme := wafScheme(t)
	c, err := NewCompiler(scheme)
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}

	const goroutines = 16
	const iters = 50

	sources := []string{
		`http.status eq 200`,
		`http.method eq "GET"`,
		`http.status ge 400 and http.status lt 500`,
		`http.uri contains "/api"`,
		`http.headers["x-foo"] eq "bar"`,
		`http.status in [200, 404, 500]`,
		`http.uri matches "^/api/.*"`,
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				src := sources[(seed+i)%len(sources)]
				_, err := c.Compile(mustParse(t, src))
				if err != nil {
					t.Errorf("goroutine %d iter %d: Compile(%q) error: %v", seed, i, src, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// ========================== Extra coverage — opKind tags ====================================

// TestOpKind_TableEnumerated pins the closed set of opKind constants. Adding a new
// opKind is a breaking change to the evaluator's dispatch table; this test forces the
// review to happen by failing loudly on any drift.
//
// Note on intentional sharing: opRegexReplace shares kFunc with opFunc. The reason
// is dispatch reuse — the evaluator's kFunc branch already handles the "function
// call" path, and adding a new opKind would force a new branch in both the
// evaluator and nodeKind. Instead, opRegexReplace is a special-case of opFunc
// (same shape from the evaluator's perspective: a call that returns a value),
// with the compile-time optimisation that the regex is precompiled when the
// pattern is a literal. The "shared kind" assertion below is therefore
// INTENTIONALLY RELAXED — it is the reviewer's job to keep this comment
// honest as the op surface evolves.
func TestOpKind_TableEnumerated(t *testing.T) {
	// We don't enumerate the numeric values here (those are part of the wire
	// contract between Compile and Eval — pinning them is a TestOpKind_Stable below).
	// This test only asserts that every op type implements the op interface, which
	// is verified statically by the `var _ op = (*opX)(nil)` declarations in
	// compiler.go. The runtime test below is a defensive round-trip.
	want := []op{
		&opLitBool{}, &opLitInt{}, &opLitFloat{}, &opLitString{},
		&opLitIP{}, &opLitBytes{}, &opLitDuration{}, &opLitTimestamp{}, &opLitArray{},
		&opField{}, &opBracket{}, &opFunc{}, &opRegexReplace{},
		&opAnd{}, &opOr{}, &opNot{},
		&opCmp{},
		&opContains{}, &opStartsWith{}, &opEndsWith{}, &opMatches{}, &opWildcard{},
		&opIn{}, &opBitAnd{}, &opStrict{},
	}
	gotKinds := make([]opKind, 0, len(want))
	for _, o := range want {
		gotKinds = append(gotKinds, o.kind())
	}
	// Distinct tag assertion, minus the intentional opRegexReplace↔opFunc
	// sharing documented above. We expect len(seen) == len(want) - 1.
	seen := make(map[opKind]string, len(gotKinds))
	for i, k := range gotKinds {
		if other, dup := seen[k]; dup {
			// opRegexReplace shares kFunc with opFunc — that is the ONE
			// permitted duplication. Anything else is a regression.
			if !(k == kFunc &&
				(strings.Contains(reflect.TypeOf(want[i]).String(), "opRegexReplace") ||
					strings.Contains(other, "opRegexReplace"))) {
				t.Errorf("opKind %d is shared between op types (%s and the one at index %d)", k, other, i)
			}
		}
		seen[k] = reflect.TypeOf(want[i]).String()
	}
	if len(seen) != len(want)-1 {
		t.Errorf("opKind tags: got %d distinct, want %d (opRegexReplace↔opFunc share kFunc)", len(seen), len(want)-1)
	}
}

// TestCompileError_ErrorFormat pins the human-readable rendering of *CompileError.
// The format is part of the engine's diagnostic surface — drift here would break
// user-facing tooling that pattern-matches on the message.
func TestCompileError_ErrorFormat(t *testing.T) {
	ce := &CompileError{Line: 7, Col: 12, Code: CodeUnknownField, Message: "field x is missing"}
	want := "compile error at line 7, col 12: field x is missing [unknown_field]"
	if got := ce.Error(); got != want {
		t.Errorf("CompileError.Error() = %q, want %q", got, want)
	}
}

// TestCompileError_NilScheme_Message is a defensive check that the nil-scheme path
// produces a non-empty error string.
func TestCompileError_NilScheme_Message(t *testing.T) {
	ce := compileErr(t, `http.status eq 200`, nil)
	if ce.Code != CodeNilScheme {
		t.Errorf("got Code %q, want %q", ce.Code, CodeNilScheme)
	}
	if ce.Error() == "" {
		t.Error("Error() returned empty string for CodeNilScheme")
	}
}

// TestCompiler_NilAST verifies that Compile on a nil AST returns a CodeInvalidLiteral
// error. Defensive — the parser normally never returns a nil node with a nil error,
// but the public API contract must be total.
func TestCompiler_NilAST(t *testing.T) {
	c, err := NewCompiler(wafScheme(t))
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	_, cerr := c.Compile(nil)
	if cerr == nil {
		t.Fatal("Compile(nil) returned nil error")
	}
	ce, ok := cerr.(*CompileError)
	if !ok {
		t.Fatalf("Compile(nil) error is not *CompileError: %T (%v)", cerr, cerr)
	}
	if ce.Code != CodeInvalidLiteral {
		t.Errorf("got Code %q, want %q", ce.Code, CodeInvalidLiteral)
	}
}

// TestCompiler_OrderableCmp exercises the orderable-operand rule for lt / le / gt / ge.
// Comparing an Int to a String must fail; comparing an Int to an Int must pass.
func TestCompiler_OrderableCmp(t *testing.T) {
	ce := compileErr(t, `http.status lt "abc"`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("int < string: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	// And a valid orderable comparison.
	p := compileOK(t, `http.status lt 500`, wafScheme(t))
	if _, ok := p.Root().(*opCmp); !ok {
		t.Errorf("root = %T, want *opCmp", p.Root())
	}
}

// TestCompiler_OrderableNonOrderable verifies that non-orderable Kinds (Bool, IP,
// Array, Map) are rejected for lt / le / gt / ge — only eq / ne is allowed.
func TestCompiler_OrderableNonOrderable(t *testing.T) {
	// Bool field — we use a LitBool literal on the left since the wafScheme does
	// not register a Bool field. The compiler must reject lt on a Bool.
	ce := compileErr(t, `true lt false`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("bool < bool: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
}

// TestCompiler_EmptyArrayInRejected verifies that `in` against an empty array is
// rejected — the `in` operator needs a non-empty set to make semantic sense.
func TestCompiler_EmptyArrayInRejected(t *testing.T) {
	ce := compileErr(t, `http.status in []`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("empty array: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
}

// TestCompiler_SyslogProfile exercises D9 in the other direction: a syslog-only field
// is fine in a syslog profile, and the compiler must resolve it without error.
func TestCompiler_SyslogProfile(t *testing.T) {
	p := compileOK(t, `syslog.facility eq "auth"`, syslogScheme(t))
	if _, ok := p.Root().(*opCmp); !ok {
		t.Errorf("root = %T, want *opCmp", p.Root())
	}
}

// TestCompiler_BoolLiteral covers parsing a top-level boolean literal. The compiled
// Plan should have *opLitBool as the root.
func TestCompiler_BoolLiteral(t *testing.T) {
	p := compileOK(t, `true`, wafScheme(t))
	if _, ok := p.Root().(*opLitBool); !ok {
		t.Errorf("root = %T, want *opLitBool", p.Root())
	}
}

// TestCompiler_TimestampCmp verifies that Timestamp operands can be compared
// orderably. We use a core.* timestamp field registered in wafScheme.
func TestCompiler_TimestampCmp(t *testing.T) {
	src := `core.timestamp ge ts"2026-01-01T00:00:00Z"`
	p := compileOK(t, src, wafScheme(t))
	if _, ok := p.Root().(*opCmp); !ok {
		t.Errorf("root = %T, want *opCmp", p.Root())
	}
}

// TestCompiler_TimestampTypeMismatch verifies that comparing a Timestamp to an Int
// is a compile error. Orderable is fine, but the Kinds must match.
func TestCompiler_TimestampTypeMismatch(t *testing.T) {
	ce := compileErr(t, `core.timestamp ge 42`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
}

// TestCompiler_NotStringOp verifies that the parser-accepted `not` can be applied
// to a string operator. The Plan's root is *opNot wrapping *opContains.
func TestCompiler_NotStringOp(t *testing.T) {
	p := compileOK(t, `not (http.uri contains "/admin")`, wafScheme(t))
	not, ok := p.Root().(*opNot)
	if !ok {
		t.Fatalf("root = %T, want *opNot", p.Root())
	}
	if _, ok := not.operand.(*opContains); !ok {
		t.Errorf("operand = %T, want *opContains", not.operand)
	}
}

// ========================== BitAnd operator tests (Group F1, D19) =============================
//
// The `&` bytes bitmask-test operator is end-to-end compiled and evaluated:
// lexer (TAmpersand) → parser (BitAnd) → compiler (opBitAnd, CodeTypeMismatch
// on operand-kind and literal-length mismatches) → evaluator (evalBitAnd,
// alloc-free per-byte AND test).

// TestCompiler_BitAnd_FieldAndLiteral verifies the happy path: both operands
// are KindBytes, the literal length is fixed, and a field operand is allowed.
// The Plan's root is *opBitAnd.
func TestCompiler_BitAnd_FieldAndLiteral(t *testing.T) {
	p := compileOK(t, `http.body & 0x"0f0f"`, wafScheme(t))
	root := p.Root()
	if _, ok := root.(*opBitAnd); !ok {
		t.Fatalf("root = %T, want *opBitAnd", root)
	}
}

// TestCompiler_BitAnd_LiteralAndLiteral is the all-literal happy path. The
// runtime shape mirrors the field case — *opBitAnd with two opLitBytes children.
func TestCompiler_BitAnd_LiteralAndLiteral(t *testing.T) {
	p := compileOK(t, `0x"abcd" & 0x"0f0f"`, wafScheme(t))
	root := p.Root()
	if _, ok := root.(*opBitAnd); !ok {
		t.Fatalf("root = %T, want *opBitAnd", root)
	}
}

// TestCompiler_BitAnd_LiteralLengthMismatch verifies that two byte literals of
// different lengths produce a compile error (DECISION D19 — length is statically
// determinable when both operands are literals). The runtime mismatch case
// (one side is a field) is covered by the eval-time defensive-false contract,
// not by a compile error.
func TestCompiler_BitAnd_LiteralLengthMismatch(t *testing.T) {
	ce := compileErr(t, `0x"abcd" & 0x"ff"`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("literal length mismatch: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "length") {
		t.Errorf("Message %q should mention the length mismatch", ce.Message)
	}
}

// TestCompiler_BitAnd_LeftNotBytes verifies that a non-bytes left operand
// (KindInt literal here) is rejected with CodeTypeMismatch. The error is
// anchored at the left operand's source position.
func TestCompiler_BitAnd_LeftNotBytes(t *testing.T) {
	ce := compileErr(t, `42 & 0x"ff"`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("int & bytes: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "left operand must be bytes") {
		t.Errorf("Message %q should identify the bad left operand", ce.Message)
	}
}

// TestCompiler_BitAnd_RightNotBytes mirrors the left-not-bytes case for the
// right operand. Same CodeTypeMismatch, but the error mentions the right
// operand's kind.
func TestCompiler_BitAnd_RightNotBytes(t *testing.T) {
	ce := compileErr(t, `http.body & "mask"`, wafScheme(t))
	if ce.Code != CodeTypeMismatch {
		t.Errorf("bytes & string: got Code %q, want %q", ce.Code, CodeTypeMismatch)
	}
	if !strings.Contains(ce.Message, "right operand must be bytes") {
		t.Errorf("Message %q should identify the bad right operand", ce.Message)
	}
}

// TestCompiler_BitAnd_EmptyMaskIsLegal verifies that `value & 0x""` compiles
// successfully. The empty mask is documented as a vacuously-true predicate
// (D19); a runtime-only test in eval_test.go pins the verdict.
func TestCompiler_BitAnd_EmptyMaskIsLegal(t *testing.T) {
	p := compileOK(t, `http.body & 0x""`, wafScheme(t))
	if _, ok := p.Root().(*opBitAnd); !ok {
		t.Fatalf("root = %T, want *opBitAnd", p.Root())
	}
}

// TestCompiler_BitAnd_StrictWrapsIt verifies that the `strict` modifier is
// accepted around `&` — the compiler flattens it transparently (compileStrict
// already lists *opBitAnd as a strict-eligible inner op). The root of the
// Plan is *opStrict wrapping *opBitAnd.
func TestCompiler_BitAnd_StrictWrapsIt(t *testing.T) {
	p := compileOK(t, `strict (http.body & 0x"ff")`, wafScheme(t))
	root := p.Root()
	s, ok := root.(*opStrict)
	if !ok {
		t.Fatalf("root = %T, want *opStrict", root)
	}
	if _, ok := s.inner.(*opBitAnd); !ok {
		t.Errorf("strict.inner = %T, want *opBitAnd", s.inner)
	}
}

// ========================== H3 — kindFromFieldType closed-set guard ==========================

// TestKindFromFieldType_CoversAllFieldTypes pins the contract that every
// declared pkg/plugin.FieldType constant has a non-Invalid mapping in
// kindFromFieldType (compiler.go ~line 1290). kindFromFieldType has no
// `default` case that panics — an unmapped FieldType silently returns
// KindInvalid, which is defensible at runtime but a silent capability gap
// at design time. Iterating every plugin.FieldType constant here means a new
// FieldType added to pkg/plugin/manifest.go without a corresponding case in
// kindFromFieldType fails the build rather than the runtime contract.
//
// The list mirrors pkg/plugin/manifest.go's declared constants. If pkg/plugin
// gains a new FieldType, this test must be updated in the same change.
func TestKindFromFieldType_CoversAllFieldTypes(t *testing.T) {
	all := []plugin.FieldType{
		plugin.TypeString,
		plugin.TypeInt,
		plugin.TypeFloat,
		plugin.TypeBool,
		plugin.TypeIP,
		plugin.TypeBytes,
		plugin.TypeTimestamp,
		plugin.TypeDuration,
		plugin.TypeArray,
		plugin.TypeMap,
	}
	for _, ft := range all {
		got := kindFromFieldType(ft)
		if got == rule.KindInvalid {
			t.Errorf("kindFromFieldType(%q) = KindInvalid — every declared FieldType must have a non-Invalid mapping", ft)
		}
	}
}
