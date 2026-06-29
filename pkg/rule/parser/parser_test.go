// ========================== pkg/rule/parser — tests ========================================
//   Coverage goals (from TASKS.md F3):
//     1.  Round-trip parse of every literal node type, positive cases + AST.String()
//         sanity.
//     2.  FieldRef — bare and dotted (http.uri.path → single FieldRef).
//     3.  FuncCall — no args, single arg, multiple args.
//     4.  BracketAccess — attrs["key"], chained.
//     5.  Logic ops — and, or, not, with precedence assertion:
//         `a or b and c` must parse as `a or (b and c)`, NOT `(a or b) and c`.
//     6.  All six Cmp operators (eq, ne, lt, le, gt, ge).
//     7.  String operators (contains, starts_with, ends_with, matches, wildcard).
//     8.  `in` — array membership with heterogeneous element types.
//     9.  Strict wrapper — `a eq strict b` and `strict a eq b`.
//    10.  Parenthesised — `(a or b) and c` precedence override.
//    11.  Complex: `http.status ge 400 and http.status lt 500`.
//    12.  Complex: `not (ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"])`.
//    13.  Comments ignored: `# comment\nip.src eq ip"1.2.3.4"`.
//    14.  Error cases — unknown keyword, missing punctuation, missing operand,
//         trailing tokens, malformed duration / timestamp / IP / CIDR, empty input.
//    15.  AST String() — sanity on a few representative trees.
//
//   Style note: white-box tests in `package parser` so we can compare against the
//   concrete node types without reflecting. Comparison is done via reflect.DeepEqual
//   for full structural equality, and via string-contains for the sanity String()
//   checks. Stdlib only.

package parser

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/lexer"
)

// ========================== Helpers =======================================================

// mustParse is a test helper that calls Parse and fails the test on a non-nil error.
// Returns the root node for further structural assertions.
func mustParse(t *testing.T, src string) Node {
	t.Helper()
	n, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q) returned unexpected error: %v", src, err)
	}
	if n == nil {
		t.Fatalf("Parse(%q) returned nil node with nil error", src)
	}
	return n
}

// mustFail is the mirror of mustParse — it fails the test if Parse does NOT return
// an error. The error message is logged for visibility.
func mustFail(t *testing.T, src string) error {
	t.Helper()
	n, err := Parse(src)
	if err == nil {
		t.Fatalf("Parse(%q) expected error, got node %#v", src, n)
	}
	return err
}

// parseDur parses a Go duration string via stdlib; fails the test on error so
// the literal-table cases stay readable.
func parseDur(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("parseDur(%q): %v", s, err)
	}
	return d
}

// parseTS parses an RFC3339 timestamp via stdlib.
func parseTS(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parseTS(%q): %v", s, err)
	}
	return ts
}

// parseIP parses a plain IP address via stdlib.
func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("parseIP(%q): invalid", s)
	}
	return ip
}

// parseCIDRIP extracts the IP half of a CIDR string via net.ParseCIDR. Used to
// build the Value for LitIP-CIDR cases.
func parseCIDRIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parseCIDRIP(%q): %v", s, err)
	}
	return ip
}

// ========================== 1. Literals — round-trip =====================================

func TestParse_Literals(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want Node
	}{
		{
			name: "string_basic",
			src:  `"hello"`,
			want: &LitString{Line: 1, Col: 1, Value: rule.NewString("hello")},
		},
		{
			name: "string_empty",
			src:  `""`,
			want: &LitString{Line: 1, Col: 1, Value: rule.NewString("")},
		},
		{
			name: "int_zero",
			src:  `0`,
			want: &LitInt{Line: 1, Col: 1, Value: rule.NewInt(0)},
		},
		{
			name: "int_positive",
			src:  `42`,
			want: &LitInt{Line: 1, Col: 1, Value: rule.NewInt(42)},
		},
		{
			name: "int_large",
			src:  `1000000`,
			want: &LitInt{Line: 1, Col: 1, Value: rule.NewInt(1000000)},
		},
		{
			name: "float_basic",
			src:  `3.14`,
			want: &LitFloat{Line: 1, Col: 1, Value: rule.NewFloat(3.14)},
		},
		{
			name: "float_with_exponent",
			src:  `1e10`,
			want: &LitFloat{Line: 1, Col: 1, Value: rule.NewFloat(1e10)},
		},
		{
			name: "bool_true",
			src:  `true`,
			want: &LitBool{Line: 1, Col: 1, Value: rule.NewBool(true)},
		},
		{
			name: "bool_false",
			src:  `false`,
			want: &LitBool{Line: 1, Col: 1, Value: rule.NewBool(false)},
		},
		{
			name: "duration_seconds",
			src:  `5s`,
			want: &LitDuration{Line: 1, Col: 1, Value: rule.NewDuration(parseDur(t, "5s"))},
		},
		{
			name: "duration_composite",
			src:  `1h30m`,
			want: &LitDuration{Line: 1, Col: 1, Value: rule.NewDuration(parseDur(t, "1h30m"))},
		},
		{
			name: "timestamp_basic",
			src:  `ts"2026-06-29T10:30:00Z"`,
			want: &LitTimestamp{Line: 1, Col: 1, Value: rule.NewTimestamp(parseTS(t, "2026-06-29T10:30:00Z"))},
		},
		{
			name: "ip_plain",
			src:  `ip"192.168.1.1"`,
			want: &LitIP{
				Line: 1, Col: 1,
				Raw:    "192.168.1.1",
				IsCIDR: false,
				Value:  rule.NewIP(parseIP(t, "192.168.1.1")),
			},
		},
		{
			name: "ip_cidr",
			src:  `ip"10.0.0.0/8"`,
			want: &LitIP{
				Line: 1, Col: 1,
				Raw:    "10.0.0.0/8",
				IsCIDR: true,
				Value:  rule.NewIP(parseCIDRIP(t, "10.0.0.0/8")),
			},
		},
		{
			name: "bytes_hex",
			src:  `0x"deadbeef"`,
			want: &LitBytes{Line: 1, Col: 1, Value: rule.NewBytes([]byte{0xde, 0xad, 0xbe, 0xef})},
		},
		{
			name: "bytes_empty",
			src:  `0x""`,
			want: &LitBytes{Line: 1, Col: 1, Value: rule.NewBytes([]byte{})},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse(%q):\n got  %#v\n want %#v", tc.src, got, tc.want)
			}
		})
	}
}

// ========================== 2. FieldRef ===================================================

func TestParse_FieldRef(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"bare", "http", "http"},
		{"dotted_two", "http.uri", "http.uri"},
		{"dotted_three", "http.uri.path", "http.uri.path"},
		{"namespace_stream", "core.stream", "core.stream"},
		{"namespace_only_dot", "core", "core"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.src)
			fr, ok := got.(*FieldRef)
			if !ok {
				t.Fatalf("Parse(%q): got %#v, want *FieldRef", tc.src, got)
			}
			if fr.Name != tc.want {
				t.Fatalf("Parse(%q).Name = %q, want %q", tc.src, fr.Name, tc.want)
			}
			if l, c := fr.Pos(); l != 1 || c != 1 {
				t.Fatalf("Parse(%q).Pos = (%d, %d), want (1, 1)", tc.src, l, c)
			}
		})
	}
}

// ========================== 3. FuncCall ===================================================

func TestParse_FuncCall(t *testing.T) {
	t.Run("no_args", func(t *testing.T) {
		got := mustParse(t, `now()`)
		fc, ok := got.(*FuncCall)
		if !ok {
			t.Fatalf("got %#v, want *FuncCall", got)
		}
		if fc.Name != "now" || len(fc.Args) != 0 {
			t.Fatalf("got %#v", fc)
		}
	})

	t.Run("one_arg", func(t *testing.T) {
		got := mustParse(t, `lower(http.uri.path)`)
		fc, ok := got.(*FuncCall)
		if !ok {
			t.Fatalf("got %#v, want *FuncCall", got)
		}
		if fc.Name != "lower" || len(fc.Args) != 1 {
			t.Fatalf("got %#v", fc)
		}
		fr, ok := fc.Args[0].(*FieldRef)
		if !ok || fr.Name != "http.uri.path" {
			t.Fatalf("Args[0] = %#v, want FieldRef(http.uri.path)", fc.Args[0])
		}
	})

	t.Run("three_args", func(t *testing.T) {
		got := mustParse(t, `coalesce(a, b, c)`)
		fc, ok := got.(*FuncCall)
		if !ok {
			t.Fatalf("got %#v, want *FuncCall", got)
		}
		if fc.Name != "coalesce" || len(fc.Args) != 3 {
			t.Fatalf("got %#v", fc)
		}
		for i, want := range []string{"a", "b", "c"} {
			fr, ok := fc.Args[i].(*FieldRef)
			if !ok || fr.Name != want {
				t.Fatalf("Args[%d] = %#v, want FieldRef(%s)", i, fc.Args[i], want)
			}
		}
	})

	t.Run("nested_func", func(t *testing.T) {
		got := mustParse(t, `lower(strip(http.uri.path))`)
		fc, ok := got.(*FuncCall)
		if !ok || fc.Name != "lower" {
			t.Fatalf("outer = %#v", got)
		}
		inner, ok := fc.Args[0].(*FuncCall)
		if !ok || inner.Name != "strip" {
			t.Fatalf("Args[0] = %#v, want *FuncCall(strip)", fc.Args[0])
		}
	})
}

// ========================== 4. BracketAccess ===============================================

func TestParse_BracketAccess(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		got := mustParse(t, `attrs["key"]`)
		ba, ok := got.(*BracketAccess)
		if !ok {
			t.Fatalf("got %#v, want *BracketAccess", got)
		}
		obj, ok := ba.Object.(*FieldRef)
		if !ok || obj.Name != "attrs" {
			t.Fatalf("Object = %#v, want FieldRef(attrs)", ba.Object)
		}
		key, ok := ba.Key.(*LitString)
		if !ok {
			t.Fatalf("Key = %#v, want *LitString", ba.Key)
		}
		s, _ := key.Value.AsString()
		if s != "key" {
			t.Fatalf("Key value = %q, want %q", s, "key")
		}
	})

	t.Run("chained", func(t *testing.T) {
		got := mustParse(t, `a["b"]["c"]`)
		// Outer BracketAccess: object is the inner BracketAccess(a, "b")
		outer, ok := got.(*BracketAccess)
		if !ok {
			t.Fatalf("got %#v, want *BracketAccess", got)
		}
		inner, ok := outer.Object.(*BracketAccess)
		if !ok {
			t.Fatalf("outer.Object = %#v, want *BracketAccess", outer.Object)
		}
		fr, ok := inner.Object.(*FieldRef)
		if !ok || fr.Name != "a" {
			t.Fatalf("inner.Object = %#v, want FieldRef(a)", inner.Object)
		}
	})

	t.Run("expression_as_key", func(t *testing.T) {
		// Compiler validates this — parser just builds the AST.
		got := mustParse(t, `attrs[other_field]`)
		ba, ok := got.(*BracketAccess)
		if !ok {
			t.Fatalf("got %#v, want *BracketAccess", got)
		}
		key, ok := ba.Key.(*FieldRef)
		if !ok || key.Name != "other_field" {
			t.Fatalf("Key = %#v, want FieldRef(other_field)", ba.Key)
		}
	})

	t.Run("after_parenthesised", func(t *testing.T) {
		got := mustParse(t, `(some.complex.expr)["k"]`)
		ba, ok := got.(*BracketAccess)
		if !ok {
			t.Fatalf("got %#v, want *BracketAccess", got)
		}
		// Object should be a FieldRef(some.complex.expr) since the grammar allows
		// any primary inside the parens; the parser produces a FieldRef from the
		// single TIdent inside.
		fr, ok := ba.Object.(*FieldRef)
		if !ok || fr.Name != "some.complex.expr" {
			t.Fatalf("Object = %#v, want FieldRef(some.complex.expr)", ba.Object)
		}
	})
}

// ========================== 5. Logic ops — precedence =====================================

func TestParse_LogicOps(t *testing.T) {
	t.Run("and_basic", func(t *testing.T) {
		got := mustParse(t, `a and b`)
		if _, ok := got.(*And); !ok {
			t.Fatalf("got %#v, want *And", got)
		}
	})

	t.Run("or_basic", func(t *testing.T) {
		got := mustParse(t, `a or b`)
		if _, ok := got.(*Or); !ok {
			t.Fatalf("got %#v, want *Or", got)
		}
	})

	t.Run("not_basic", func(t *testing.T) {
		got := mustParse(t, `not a`)
		if _, ok := got.(*Not); !ok {
			t.Fatalf("got %#v, want *Not", got)
		}
	})

	t.Run("or_and_precedence", func(t *testing.T) {
		// `a or b and c` MUST parse as `a or (b and c)` — `and` binds tighter.
		got := mustParse(t, `a or b and c`)
		or, ok := got.(*Or)
		if !ok {
			t.Fatalf("root = %#v, want *Or", got)
		}
		if l, ok := or.Left.(*FieldRef); !ok || l.Name != "a" {
			t.Fatalf("Or.Left = %#v, want FieldRef(a)", or.Left)
		}
		and, ok := or.Right.(*And)
		if !ok {
			t.Fatalf("Or.Right = %#v, want *And (precedence)", or.Right)
		}
		if l, ok := and.Left.(*FieldRef); !ok || l.Name != "b" {
			t.Fatalf("And.Left = %#v, want FieldRef(b)", and.Left)
		}
		if r, ok := and.Right.(*FieldRef); !ok || r.Name != "c" {
			t.Fatalf("And.Right = %#v, want FieldRef(c)", and.Right)
		}
	})

	t.Run("and_or_precedence_explicit_parens", func(t *testing.T) {
		// `(a or b) and c` overrides precedence to bind `or` first.
		got := mustParse(t, `(a or b) and c`)
		and, ok := got.(*And)
		if !ok {
			t.Fatalf("root = %#v, want *And", got)
		}
		or, ok := and.Left.(*Or)
		if !ok {
			t.Fatalf("And.Left = %#v, want *Or", and.Left)
		}
		if l, ok := or.Left.(*FieldRef); !ok || l.Name != "a" {
			t.Fatalf("Or.Left = %#v, want FieldRef(a)", or.Left)
		}
	})

	t.Run("double_not", func(t *testing.T) {
		got := mustParse(t, `not not a`)
		outer, ok := got.(*Not)
		if !ok {
			t.Fatalf("root = %#v, want *Not", got)
		}
		inner, ok := outer.Operand.(*Not)
		if !ok {
			t.Fatalf("Not.Operand = %#v, want *Not", outer.Operand)
		}
		if fr, ok := inner.Operand.(*FieldRef); !ok || fr.Name != "a" {
			t.Fatalf("inner.Operand = %#v, want FieldRef(a)", inner.Operand)
		}
	})

	t.Run("chained_and_left_associative", func(t *testing.T) {
		// `a and b and c` MUST parse as `(a and b) and c`.
		got := mustParse(t, `a and b and c`)
		outer, ok := got.(*And)
		if !ok {
			t.Fatalf("root = %#v, want *And", got)
		}
		inner, ok := outer.Left.(*And)
		if !ok {
			t.Fatalf("And.Left = %#v, want *And (left-associative)", outer.Left)
		}
		if l, ok := inner.Left.(*FieldRef); !ok || l.Name != "a" {
			t.Fatalf("inner.Left = %#v, want FieldRef(a)", inner.Left)
		}
		if r, ok := inner.Right.(*FieldRef); !ok || r.Name != "b" {
			t.Fatalf("inner.Right = %#v, want FieldRef(b)", inner.Right)
		}
	})
}

// ========================== 6. Comparison operators =======================================

func TestParse_CmpOps(t *testing.T) {
	cases := []struct {
		name string
		src  string
		op   CmpOp
	}{
		{"eq", `a eq 1`, CmpEq},
		{"ne", `a ne 1`, CmpNe},
		{"lt", `a lt 1`, CmpLt},
		{"le", `a le 1`, CmpLe},
		{"gt", `a gt 1`, CmpGt},
		{"ge", `a ge 1`, CmpGe},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.src)
			cmp, ok := got.(*Cmp)
			if !ok {
				t.Fatalf("Parse(%q): got %#v, want *Cmp", tc.src, got)
			}
			if cmp.Op != tc.op {
				t.Fatalf("Parse(%q).Op = %v, want %v", tc.src, cmp.Op, tc.op)
			}
		})
	}
}

// ========================== 7. String operators ===========================================

func TestParse_StringOps(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want func(Node) bool
	}{
		{
			name: "contains",
			src:  `http.uri.path contains "admin"`,
			want: func(n Node) bool { _, ok := n.(*Contains); return ok },
		},
		{
			name: "starts_with",
			src:  `http.uri.path starts_with "/api"`,
			want: func(n Node) bool { _, ok := n.(*StartsWith); return ok },
		},
		{
			name: "ends_with",
			src:  `http.uri.path ends_with ".php"`,
			want: func(n Node) bool { _, ok := n.(*EndsWith); return ok },
		},
		{
			name: "matches",
			src:  `http.uri.path matches "^/api/.*$"`,
			want: func(n Node) bool { _, ok := n.(*Matches); return ok },
		},
		{
			name: "wildcard",
			src:  `http.uri.path wildcard "/api/*"`,
			want: func(n Node) bool { _, ok := n.(*Wildcard); return ok },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.src)
			if !tc.want(got) {
				t.Fatalf("Parse(%q): got %#v, want matching string-op node", tc.src, got)
			}
		})
	}
}

// ========================== 8. `in` — array membership =====================================

func TestParse_In(t *testing.T) {
	t.Run("ints", func(t *testing.T) {
		got := mustParse(t, `count in [1, 2, 3]`)
		in, ok := got.(*In)
		if !ok {
			t.Fatalf("got %#v, want *In", got)
		}
		if l, ok := in.Element.(*FieldRef); !ok || l.Name != "count" {
			t.Fatalf("Element = %#v, want FieldRef(count)", in.Element)
		}
		arr, ok := in.Set.(*LitArray)
		if !ok {
			t.Fatalf("Set = %#v, want *LitArray", in.Set)
		}
		if len(arr.Elements) != 3 {
			t.Fatalf("len(Elements) = %d, want 3", len(arr.Elements))
		}
		for i, want := range []int64{1, 2, 3} {
			li, ok := arr.Elements[i].(*LitInt)
			if !ok {
				t.Fatalf("Elements[%d] = %#v, want *LitInt", i, arr.Elements[i])
			}
			gotI, _ := li.Value.AsInt()
			if gotI != want {
				t.Fatalf("Elements[%d] = %d, want %d", i, gotI, want)
			}
		}
	})

	t.Run("ips_cidr", func(t *testing.T) {
		got := mustParse(t, `ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"]`)
		in, ok := got.(*In)
		if !ok {
			t.Fatalf("got %#v, want *In", got)
		}
		arr, ok := in.Set.(*LitArray)
		if !ok || len(arr.Elements) != 2 {
			t.Fatalf("Set = %#v, want *LitArray(2)", in.Set)
		}
		for i, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12"} {
			lip, ok := arr.Elements[i].(*LitIP)
			if !ok || !lip.IsCIDR || lip.Raw != cidr {
				t.Fatalf("Elements[%d] = %#v, want CIDR %q", i, arr.Elements[i], cidr)
			}
		}
	})

	t.Run("empty_array", func(t *testing.T) {
		got := mustParse(t, `a in []`)
		in, ok := got.(*In)
		if !ok {
			t.Fatalf("got %#v, want *In", got)
		}
		arr, ok := in.Set.(*LitArray)
		if !ok || len(arr.Elements) != 0 {
			t.Fatalf("Set = %#v, want empty *LitArray", in.Set)
		}
	})

	t.Run("heterogeneous", func(t *testing.T) {
		// Parser does NOT validate element-type homogeneity — heterogeneous arrays
		// are the compiler's concern.
		got := mustParse(t, `x in [1, "a", true]`)
		in, ok := got.(*In)
		if !ok {
			t.Fatalf("got %#v, want *In", got)
		}
		arr, ok := in.Set.(*LitArray)
		if !ok || len(arr.Elements) != 3 {
			t.Fatalf("Set = %#v, want *LitArray(3)", in.Set)
		}
		if _, ok := arr.Elements[0].(*LitInt); !ok {
			t.Fatalf("Elements[0] = %#v, want *LitInt", arr.Elements[0])
		}
		if _, ok := arr.Elements[1].(*LitString); !ok {
			t.Fatalf("Elements[1] = %#v, want *LitString", arr.Elements[1])
		}
		if _, ok := arr.Elements[2].(*LitBool); !ok {
			t.Fatalf("Elements[2] = %#v, want *LitBool", arr.Elements[2])
		}
	})
}

// ========================== 9. Strict wrapper ==============================================

func TestParse_Strict(t *testing.T) {
	t.Run("after_operator", func(t *testing.T) {
		got := mustParse(t, `a eq strict b`)
		cmp, ok := got.(*Cmp)
		if !ok {
			t.Fatalf("got %#v, want *Cmp", got)
		}
		if cmp.Op != CmpEq {
			t.Fatalf("Op = %v, want CmpEq", cmp.Op)
		}
		s, ok := cmp.Right.(*Strict)
		if !ok {
			t.Fatalf("Right = %#v, want *Strict", cmp.Right)
		}
		if fr, ok := s.Inner.(*FieldRef); !ok || fr.Name != "b" {
			t.Fatalf("Strict.Inner = %#v, want FieldRef(b)", s.Inner)
		}
	})

	t.Run("before_operator", func(t *testing.T) {
		got := mustParse(t, `strict a eq b`)
		cmp, ok := got.(*Cmp)
		if !ok {
			t.Fatalf("got %#v, want *Cmp", got)
		}
		if cmp.Op != CmpEq {
			t.Fatalf("Op = %v, want CmpEq", cmp.Op)
		}
		s, ok := cmp.Left.(*Strict)
		if !ok {
			t.Fatalf("Left = %#v, want *Strict", cmp.Left)
		}
		if fr, ok := s.Inner.(*FieldRef); !ok || fr.Name != "a" {
			t.Fatalf("Strict.Inner = %#v, want FieldRef(a)", s.Inner)
		}
	})
}

// ========================== 10. Parenthesised — precedence override ========================

func TestParse_ParensPrecedence(t *testing.T) {
	got := mustParse(t, `(a or b) and c`)
	and, ok := got.(*And)
	if !ok {
		t.Fatalf("root = %#v, want *And", got)
	}
	or, ok := and.Left.(*Or)
	if !ok {
		t.Fatalf("And.Left = %#v, want *Or (parenthesised grouping)", and.Left)
	}
	if l, ok := or.Left.(*FieldRef); !ok || l.Name != "a" {
		t.Fatalf("Or.Left = %#v, want FieldRef(a)", or.Left)
	}
	if r, ok := or.Right.(*FieldRef); !ok || r.Name != "b" {
		t.Fatalf("Or.Right = %#v, want FieldRef(b)", or.Right)
	}
	if r, ok := and.Right.(*FieldRef); !ok || r.Name != "c" {
		t.Fatalf("And.Right = %#v, want FieldRef(c)", and.Right)
	}
}

// ========================== 11. Real-world complex expressions =============================

func TestParse_RealExpressions(t *testing.T) {
	t.Run("status_range", func(t *testing.T) {
		got := mustParse(t, `http.status ge 400 and http.status lt 500`)
		// Root must be And; each side must be Cmp.
		and, ok := got.(*And)
		if !ok {
			t.Fatalf("root = %#v, want *And", got)
		}
		if cmp, ok := and.Left.(*Cmp); !ok || cmp.Op != CmpGe {
			t.Fatalf("Left = %#v, want *Cmp(ge)", and.Left)
		}
		if cmp, ok := and.Right.(*Cmp); !ok || cmp.Op != CmpLt {
			t.Fatalf("Right = %#v, want *Cmp(lt)", and.Right)
		}
	})

	t.Run("ip_cidr_in_with_not", func(t *testing.T) {
		got := mustParse(t, `not (ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"])`)
		not, ok := got.(*Not)
		if !ok {
			t.Fatalf("root = %#v, want *Not", got)
		}
		in, ok := not.Operand.(*In)
		if !ok {
			t.Fatalf("Not.Operand = %#v, want *In", not.Operand)
		}
		if l, ok := in.Element.(*FieldRef); !ok || l.Name != "ip.src" {
			t.Fatalf("In.Element = %#v, want FieldRef(ip.src)", in.Element)
		}
		arr, ok := in.Set.(*LitArray)
		if !ok || len(arr.Elements) != 2 {
			t.Fatalf("In.Set = %#v, want LitArray(2)", in.Set)
		}
	})

	t.Run("contains_and_method", func(t *testing.T) {
		got := mustParse(t, `http.method eq "POST" and http.uri.path contains "/admin"`)
		if _, ok := got.(*And); !ok {
			t.Fatalf("root = %#v, want *And", got)
		}
	})

	t.Run("nested_with_func_and_in", func(t *testing.T) {
		got := mustParse(t, `lower(http.uri.path) in ["/", "/index"]`)
		in, ok := got.(*In)
		if !ok {
			t.Fatalf("root = %#v, want *In", got)
		}
		if _, ok := in.Element.(*FuncCall); !ok {
			t.Fatalf("Element = %#v, want *FuncCall", in.Element)
		}
	})
}

// ========================== 12. Comments ignored ===========================================

func TestParse_Comments(t *testing.T) {
	src := `# leading comment
ip.src eq ip"1.2.3.4"  # trailing comment
`
	got := mustParse(t, src)
	cmp, ok := got.(*Cmp)
	if !ok || cmp.Op != CmpEq {
		t.Fatalf("root = %#v, want *Cmp(eq)", got)
	}
	if l, ok := cmp.Left.(*FieldRef); !ok || l.Name != "ip.src" {
		t.Fatalf("Left = %#v, want FieldRef(ip.src)", cmp.Left)
	}
	lip, ok := cmp.Right.(*LitIP)
	if !ok || lip.Raw != "1.2.3.4" || lip.IsCIDR {
		t.Fatalf("Right = %#v, want LitIP(1.2.3.4, plain)", cmp.Right)
	}
}

func TestParse_LineCommentOnly(t *testing.T) {
	// Just a comment, no expression — empty after comment → empty expression error.
	err := mustFail(t, `# only a comment here`)
	if !strings.Contains(err.Error(), "empty expression") {
		t.Fatalf("error = %v, want 'empty expression'", err)
	}
}

// ========================== 13. Lexer integration =========================================

func TestParse_LexerIntegration(t *testing.T) {
	// End-to-end: real expression through the lexer → parser pipeline.
	src := `http.status ge 400 and http.status lt 500`
	toks := lexer.Lex(src)
	if toks[len(toks)-1].Kind != lexer.TEOF {
		t.Fatalf("last token = %v, want TEOF", toks[len(toks)-1].Kind)
	}
	got := mustParse(t, src)
	if _, ok := got.(*And); !ok {
		t.Fatalf("got %#v, want *And", got)
	}
}

// ========================== 14. Error cases ===============================================

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		wantSubstr string // substring the error message MUST contain; "" = any error
	}{
		// Structural errors.
		{"empty_input", ``, "empty expression"},
		{"whitespace_only", "   \n\t  ", "empty expression"},
		{"trailing_tokens", `a and b c`, "unexpected token after expression"},
		{"missing_rparen", `(a`, "expected"},
		{"missing_rbrack", `a["key"`, "expected"},
		{"missing_comma", `f(a b)`, "expected"},

		// Operator missing operand.
		{"eq_no_right", `a eq`, "unexpected"},
		{"and_no_right", `a and`, "unexpected"},

		// Malformed literals.
		// `5x` is TInt+TIdent → unexpected trailing after expression.
		{"trailing_int_with_ident", `5x`, "unexpected"},
		{"bad_timestamp", `ts"not-a-date"`, "invalid RFC3339"},
		{"bad_ip", `ip"999.999.999.999"`, "invalid IP"},
		{"bad_cidr", `ip"10.0.0.0/40"`, "invalid CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mustFail(t, tc.src)
			if tc.wantSubstr == "" {
				return
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("Parse(%q) error = %q, want substring %q",
					tc.src, err.Error(), tc.wantSubstr)
			}
		})
	}
}

// ========================== 15. AST String() sanity ========================================

func TestParse_StringSanity(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string // substrings that must appear in the rendered form
	}{
		{
			name: "cmp",
			src:  `http.status eq 500`,
			want: []string{"Cmp", "eq", "http.status"},
		},
		{
			name: "and",
			src:  `a eq 1 and b eq 2`,
			want: []string{"And", "eq"},
		},
		{
			name: "in",
			src:  `ip.src in [ip"10.0.0.0/8"]`,
			want: []string{"In", "LitArray", "LitIP"},
		},
		{
			name: "func",
			src:  `lower(http.uri)`,
			want: []string{"FuncCall", "lower", "http.uri"},
		},
		{
			name: "bracket",
			src:  `attrs["k"]`,
			want: []string{"BracketAccess", "attrs", "LitString"},
		},
		{
			name: "not",
			src:  `not (a eq b)`,
			want: []string{"Not", "Cmp", "eq"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.src)
			rendered := got.String()
			for _, want := range tc.want {
				if !strings.Contains(rendered, want) {
					t.Fatalf("Parse(%q).String() = %q, want substring %q",
						tc.src, rendered, want)
				}
			}
		})
	}
}

// ========================== 16. CmpOp.String() =============================================

func TestCmpOp_String(t *testing.T) {
	cases := []struct {
		op   CmpOp
		want string
	}{
		{CmpEq, "eq"},
		{CmpNe, "ne"},
		{CmpLt, "lt"},
		{CmpLe, "le"},
		{CmpGt, "gt"},
		{CmpGe, "ge"},
		{CmpOp(255), "unknown(255)"},
	}
	for _, tc := range cases {
		if got := tc.op.String(); got != tc.want {
			t.Errorf("CmpOp(%d).String() = %q, want %q", tc.op, got, tc.want)
		}
	}
}

// ========================== 17. Position tracking ==========================================

func TestParse_PositionTracking(t *testing.T) {
	t.Run("multiline", func(t *testing.T) {
		got := mustParse(t, "a and\nb")
		and, ok := got.(*And)
		if !ok {
			t.Fatalf("got %#v, want *And", got)
		}
		if l, c := and.Pos(); l != 1 || c != 3 {
			t.Fatalf("And.Pos = (%d, %d), want (1, 3)", l, c)
		}
		if fr, ok := and.Right.(*FieldRef); ok {
			if l, c := fr.Pos(); l != 2 || c != 1 {
				t.Fatalf("Right.Pos = (%d, %d), want (2, 1)", l, c)
			}
		}
	})

	t.Run("node_at_operator_keyword", func(t *testing.T) {
		// Position of `a or b` — Or.Pos() is at the `or` keyword (col 3).
		got := mustParse(t, `a or b`)
		or, ok := got.(*Or)
		if !ok {
			t.Fatalf("got %#v, want *Or", got)
		}
		if l, c := or.Pos(); l != 1 || c != 3 {
			t.Fatalf("Or.Pos = (%d, %d), want (1, 3) (at the `or` keyword)", l, c)
		}
	})
}

// ========================== 18. NewParser / (*Parser).Parse() ==============================

func TestNewParser(t *testing.T) {
	p := NewParser(`a eq 1`)
	if p == nil {
		t.Fatalf("NewParser returned nil")
	}
	if len(p.toks) == 0 {
		t.Fatalf("NewParser produced empty token stream")
	}
	got, err := p.Parse()
	if err != nil {
		t.Fatalf("(*Parser).Parse() returned error: %v", err)
	}
	if _, ok := got.(*Cmp); !ok {
		t.Fatalf("Parse() = %#v, want *Cmp", got)
	}
}
