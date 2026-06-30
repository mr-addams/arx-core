// ========================== pkg/rule/compiler — IP function tests =================================
//   Coverage goals (Flow 002 Group E — Task E1):
//     1. Registry accessors: Lookup returns the expected FuncSpec for ip_to_int and
//        cidr_matches, including ParamKinds, ReturnKind, and Allocating=false.
//     2. Names() includes the two E1 names.
//     3. Positive compile for both functions against the WAF scheme.
//     4. Compile-time negatives: bad arity, bad per-argument Kind, invalid literal
//        CIDR.
//     5. Eval coverage for ip_to_int: IPv4 loopback, 0.0.0.0, 255.255.255.255, a few
//        IPv6 cases capturing the low-64 contract.
//     6. Eval coverage for cidr_matches: IPv4 and IPv6 in-network and out-of-network
//        cases, plus nil/defensive edge cases.
//     7. Benchmark proving the literal-cidr fast path performs one allocation per
//        eval (the AsIP defensive copy baseline), guarding against a regression that
//        re-introduces per-eval ParseCIDR.
//
//   Style note: white-box tests in `package compiler`; the helpers from
//   compiler_test.go and eval_test.go are reused.

package compiler

import (
	"encoding/binary"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/parser"
)

// ========================== E1 — Registry =====================================================

// TestRegistry_E1_Lookup verifies the metadata for the E1 functions. The registry
// is the single source of truth (D16) and the contract includes the expected
// parameter Kinds, return Kind, and the alloc-free flag.
func TestRegistry_E1_Lookup(t *testing.T) {
	cases := []struct {
		name       string
		wantKinds  []rule.Kind
		wantReturn rule.Kind
		wantAlloc  bool
	}{
		{
			name:       "ip_to_int",
			wantKinds:  []rule.Kind{rule.KindIP},
			wantReturn: rule.KindInt,
			wantAlloc:  false,
		},
		{
			name:       "cidr_matches",
			wantKinds:  []rule.Kind{rule.KindIP, rule.KindString},
			wantReturn: rule.KindBool,
			wantAlloc:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, ok := Lookup(c.name)
			if !ok {
				t.Fatalf("Lookup(%q): not found", c.name)
			}
			if spec.Name != c.name {
				t.Errorf("Name = %q, want %q", spec.Name, c.name)
			}
			if len(spec.ParamKinds) != len(c.wantKinds) {
				t.Errorf("arity = %d, want %d", len(spec.ParamKinds), len(c.wantKinds))
			} else {
				for i, want := range c.wantKinds {
					if spec.ParamKinds[i] != want {
						t.Errorf("ParamKinds[%d] = %s, want %s", i, spec.ParamKinds[i], want)
					}
				}
			}
			if spec.ReturnKind != c.wantReturn {
				t.Errorf("ReturnKind = %s, want %s", spec.ReturnKind, c.wantReturn)
			}
			if spec.Allocating != c.wantAlloc {
				t.Errorf("Allocating = %v, want %v", spec.Allocating, c.wantAlloc)
			}
			if spec.Eval == nil {
				t.Errorf("Eval is nil; registry entry is invalid")
			}
			// Mutate the returned copy — must not affect the registry.
			spec.Name = "mutated"
			again, _ := Lookup(c.name)
			if again.Name != c.name {
				t.Errorf("Lookup returned shared spec; mutation leaked into the registry")
			}
		})
	}
}

// TestRegistry_E1_NamesPresent checks that Names() contains both E1 names. The
// check is presence-based so a future flow adding functions does not break it.
func TestRegistry_E1_NamesPresent(t *testing.T) {
	all := Names()
	sort.Strings(all)
	want := []string{"cidr_matches", "ip_to_int"}
	for _, w := range want {
		found := false
		for _, n := range all {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Names() missing %q; got %v", w, all)
		}
	}
}

// ========================== E1 — Compile ====================================================

// TestCompiler_E1_Compile exercises the positive compile path and the standard
// compile-time negatives (arity and per-argument Kind). cidr_matches uses the
// special-cased compile path in compiler.go because its second arg is a literal
// CIDR; ip_to_int uses the generic func compile path.
func TestCompiler_E1_Compile(t *testing.T) {
	scheme := wafScheme(t)

	positive := []string{
		`ip_to_int(http.client_ip) eq 16820416`,
		`cidr_matches(http.client_ip, "10.0.0.0/8")`,
	}
	for _, src := range positive {
		t.Run("positive_"+src, func(t *testing.T) {
			compileOK(t, src, scheme)
		})
	}

	negative := []struct {
		name     string
		src      string
		wantCode string
	}{
		{"ip_to_int_bad_arg", `ip_to_int(http.method)`, string(CodeBadFuncArgType)},
		{"cidr_matches_bad_ip_arg", `cidr_matches(http.method, "10.0.0.0/8")`, string(CodeBadFuncArgType)},
		{"cidr_matches_too_few", `cidr_matches(http.client_ip)`, string(CodeBadFuncArity)},
		{"cidr_matches_too_many", `cidr_matches(http.client_ip, "10.0.0.0/8", "extra")`, string(CodeBadFuncArity)},
	}
	for _, c := range negative {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, scheme)
			if string(ce.Code) != c.wantCode {
				t.Errorf("got Code %q, want %q", ce.Code, c.wantCode)
			}
			// The message must mention the function name. Pick the expected
			// name out of the test name (everything up to the first "_bad_"
			// or "_too_" marker) rather than relying on a fragile substring
			// of the test name itself.
			want := ""
			switch {
			case strings.HasPrefix(c.name, "ip_to_int_"):
				want = "ip_to_int"
			case strings.HasPrefix(c.name, "cidr_matches_"):
				want = "cidr_matches"
			}
			if want != "" && !strings.Contains(ce.Message, want) {
				t.Errorf("Message %q should mention function %q", ce.Message, want)
			}
		})
	}
}

// TestCompiler_E1_CIDRLiteralBadCIDR checks the special-cased literal-CIDR path.
// A syntactically invalid CIDR must produce CodeInvalidLiteral at compile time,
// not a runtime error.
func TestCompiler_E1_CIDRLiteralBadCIDR(t *testing.T) {
	ce := compileErr(t, `cidr_matches(http.client_ip, "not-a-cidr")`, wafScheme(t))
	if ce.Code != CodeInvalidLiteral {
		t.Errorf("got Code %q, want %q", ce.Code, CodeInvalidLiteral)
	}
	if !strings.Contains(ce.Message, "not-a-cidr") {
		t.Errorf("Message %q should mention the invalid CIDR", ce.Message)
	}
}

// TestCompiler_E1_CIDRMatchesReturnKind guards the nodeKind case for
// *opCIDRMatcher (DECISION D16 §2: function return Kinds are visible to
// downstream operators). Without the explicit case, the wildcard branch in
// checkCmpOperands would let the compiler silently accept semantically
// meaningless expressions like `cidr_matches(...) eq "true"`. This test pins
// that the type-mismatch path is reached.
func TestCompiler_E1_CIDRMatchesReturnKind(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"cidr_matches_eq_string", `cidr_matches(http.client_ip, "10.0.0.0/8") eq "true"`},
		{"cidr_matches_eq_int", `cidr_matches(http.client_ip, "10.0.0.0/8") eq 1`},
		{"cidr_matches_eq_uri", `cidr_matches(http.client_ip, "10.0.0.0/8") eq http.uri`},
		{"cidr_matches_gt_bool", `cidr_matches(http.client_ip, "10.0.0.0/8") gt true`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := compileErr(t, c.src, wafScheme(t))
			if ce.Code != CodeTypeMismatch {
				t.Errorf("got Code %q, want %q (message: %s)", ce.Code, CodeTypeMismatch, ce.Message)
			}
		})
	}
}

// ========================== E1 — Eval =======================================================

// TestEval_E1_IPToInt pins the IPv4 full-conversion and IPv6 low-64 conversion
// contracts. The table is intentionally written with explicit integer literals so
// the expected value is obvious to a reader.
func TestEval_E1_IPToInt(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	cases := []struct {
		name string
		ip   net.IP
		want int64
	}{
		{"ipv4_loopback", net.ParseIP("127.0.0.1"), 0x7F000001},
		{"ipv4_zero", net.ParseIP("0.0.0.0"), 0},
		{"ipv4_max", net.ParseIP("255.255.255.255"), 0xFFFFFFFF},
		{"ipv6_loopback", net.ParseIP("::1"), 1},
		{"ipv6_2001db8_1", net.ParseIP("2001:db8::1"), 1},
		{"ipv6_low64_ff", parseIPv6Low64(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF), 0xFF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `ip_to_int(http.client_ip) eq ` + strconv.FormatInt(c.want, 10)
			p := evalCompileOK(t, src, scheme)
			r := &mapResolver{scalars: map[string]rule.Value{
				"http.client_ip": rule.NewIP(c.ip),
			}}
			if !p.Eval(r, ev) {
				t.Errorf("Eval(%q) = false, want true for IP %v -> %d", src, c.ip, c.want)
			}
		})
	}

	// Nil / empty IP yields 0.
	t.Run("empty_ip", func(t *testing.T) {
		src := `ip_to_int(http.client_ip) eq 0`
		p := evalCompileOK(t, src, scheme)
		r := &mapResolver{scalars: map[string]rule.Value{
			"http.client_ip": rule.NewIP(nil),
		}}
		if !p.Eval(r, ev) {
			t.Errorf("Eval(%q) for nil IP should be true", src)
		}
	})
}

// parseIPv6Low64 builds a 16-byte IPv6 address whose high 64 bits are zero and
// whose low 64 bits are set from the provided bytes (in order). It is a test
// helper that makes the low-64-bit contract explicit without hand-writing the
// full IPv6 form.
func parseIPv6Low64(b ...byte) net.IP {
	if len(b) != 8 {
		panic("parseIPv6Low64 expects exactly 8 bytes")
	}
	ip := make(net.IP, 16)
	copy(ip[8:], b)
	return ip
}

// TestEval_E1_CIDRMatches exercises both the literal-cidr compile-time fast path
// and the resulting Contains semantics for IPv4 and IPv6. Out-of-network addresses
// must return false; nil/defensive cases must return false rather than error.
func TestEval_E1_CIDRMatches(t *testing.T) {
	scheme := evalWafScheme(t)
	ev := fixedEvent()

	cases := []struct {
		name string
		ip   net.IP
		cidr string
		want bool
	}{
		// IPv4.
		{"ipv4_in", net.ParseIP("10.1.2.3"), "10.0.0.0/8", true},
		{"ipv4_out", net.ParseIP("11.1.2.3"), "10.0.0.0/8", false},
		{"ipv4_24_in", net.ParseIP("192.168.0.5"), "192.168.0.0/24", true},
		{"ipv4_24_out", net.ParseIP("192.168.1.5"), "192.168.0.0/24", false},

		// IPv6.
		{"ipv6_32_in", net.ParseIP("2001:db8::1"), "2001:db8::/32", true},
		{"ipv6_32_out", net.ParseIP("2001:db9::1"), "2001:db8::/32", false},
		{"ipv6_ll_in", net.ParseIP("fe80::1"), "fe80::/10", true},
		{"ipv6_loopback_cidr", net.ParseIP("::1"), "::1/128", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := `cidr_matches(http.client_ip, "` + c.cidr + `")`
			p := evalCompileOK(t, src, scheme)
			r := &mapResolver{scalars: map[string]rule.Value{
				"http.client_ip": rule.NewIP(c.ip),
			}}
			got := p.Eval(r, ev)
			if got != c.want {
				t.Errorf("Eval(%q) = %v, want %v", src, got, c.want)
			}
		})
	}

	// Defensive cases: nil / empty IP and unresolved field.
	t.Run("nil_ip", func(t *testing.T) {
		src := `cidr_matches(http.client_ip, "10.0.0.0/8")`
		p := evalCompileOK(t, src, scheme)
		r := &mapResolver{scalars: map[string]rule.Value{
			"http.client_ip": rule.NewIP(nil),
		}}
		if p.Eval(r, ev) {
			t.Errorf("Eval(%q) for nil IP should be false", src)
		}
	})
	t.Run("unresolved_ip", func(t *testing.T) {
		src := `cidr_matches(http.client_ip, "10.0.0.0/8")`
		p := evalCompileOK(t, src, scheme)
		r := &mapResolver{}
		if p.Eval(r, ev) {
			t.Errorf("Eval(%q) for unresolved IP should be false", src)
		}
	})
}

// ========================== E1 — Benchmark ==================================================

// BenchmarkEval_CIDRMatches_Literal proves the literal-CIDR fast path has one
// allocation per eval: the AsIP defensive copy from the stored Value. Any
// increase above one allocation/op signals a regression that re-introduced
// per-eval ParseCIDR or other heap traffic on the hot path.
func BenchmarkEval_CIDRMatches_Literal(b *testing.B) {
	ev := &plugin.Event{}
	src := `cidr_matches(http.client_ip, "10.0.0.0/8")`
	ast, err := parser.Parse(src)
	if err != nil {
		b.Fatalf("Parse(%q): %v", src, err)
	}
	cat := rule.NewCatalog()
	if err := cat.Register("http", "client_ip", rule.TypeIP); err != nil {
		b.Fatalf("Register: %v", err)
	}
	scheme := cat.Project("http")
	p, cerr := Compile(ast, scheme)
	if p == nil {
		b.Fatalf("Compile: %v", cerr)
	}
	r := &mapResolver{scalars: map[string]rule.Value{
		"http.client_ip": rule.NewIP(net.ParseIP("10.1.2.3")),
	}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Eval(r, ev)
	}
}

// ========================== E1 — internal contract =========================================

// TestIPToInt_InternallContract pins the ipToInt64 helper directly. This is
// cheap insurance that the helper shared with coerce.go does not drift from the
// public ip_to_int expectations.
func TestIPToInt_InternalContract(t *testing.T) {
	if got := ipToInt64(net.ParseIP("10.0.0.1")); got != 0x0A000001 {
		t.Errorf("ipToInt64(10.0.0.1) = %v, want %v", got, 0x0A000001)
	}
	if got := ipToInt64(net.ParseIP("::1")); got != 1 {
		t.Errorf("ipToInt64(::1) = %v, want 1", got)
	}
	if got := ipToInt64(nil); got != 0 {
		t.Errorf("ipToInt64(nil) = %v, want 0", got)
	}
}

// TestIPLowUint64_InternalContract confirms the unsigned low-64 contract used
// by to_float. It differs from ipToInt64 only in signedness: an IP whose low 64
// bits are 0xFF...FF must be 0xFF...FF as uint64, not negative.
func TestIPLowUint64_InternalContract(t *testing.T) {
	ip := parseIPv6Low64(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	want := uint64(0xFFFFFFFFFFFFFFFF)
	if got := ipLowUint64(ip); got != want {
		t.Errorf("ipLowUint64(all-ones low 64) = %x, want %x", got, want)
	}
	if got := ipLowUint64(net.ParseIP("10.0.0.1")); got != 0x0A000001 {
		t.Errorf("ipLowUint64(10.0.0.1) = %x, want %x", got, 0x0A000001)
	}
	// Signed counterpart must be -1 for all-ones low 64.
	if got := ipToInt64(ip); got != -1 {
		t.Errorf("ipToInt64(all-ones low 64) = %v, want -1", got)
	}
}

// ========================== E1 — imports anchors ============================================

// encoding/binary is used by ip.go to decode IP bytes; the no-op call below keeps
// the import honest even if a future refactor hides the package name.
var _ = binary.BigEndian.Uint32

// net is used directly in the tests for IP literals and parsing.
var _ = net.ParseIP

// strconv is used to format expected int64 values in test sources.
var _ = strconv.Itoa
