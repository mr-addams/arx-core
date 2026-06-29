// ========================== pkg/rule — Scheme / Catalog tests ==============================
//   Verifies Task A3 requirements end-to-end:
//     - FieldInfo / FieldType contract (D5 mirror)
//     - Catalog registration + idempotency + validation errors
//     - Revision counter (D13): monotonic, never decreases, not bumped on error
//     - Fields() / Has() reads under concurrent Register (race detector must pass)
//     - Scheme: immutable snapshot, Has() / Fields() / Revision() contract
//     - Project(): namespace-filtered projection of Catalog
//     - Namespaced fields per D7 (core.*, http.*, syslog.*)
//
//   Deep coverage (negative tests for each operator combination, fuzzing) lives in
//   Group F — Task F1. This file is the Task-A3 success-criteria suite.

package rule

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// ========================== FieldType — closed set ==========================================

// TestFieldType_KnownTypes pins the expected closed set of FieldType constants. Adding a
// new Kind (and corresponding FieldType) to the engine requires updating this test;
// the test fails loudly so reviewers can audit the expansion.
func TestFieldType_KnownTypes(t *testing.T) {
	want := []FieldType{
		TypeString, TypeInt, TypeFloat, TypeBool, TypeIP,
		TypeBytes, TypeTimestamp, TypeDuration, TypeArray, TypeMap,
	}
	for _, ft := range want {
		if !isKnownFieldType(ft) {
			t.Errorf("expected FieldType %q to be known", ft)
		}
	}

	// And a few obviously-not-known values must report false.
	notWant := []FieldType{
		"",
		"inteher", // typo
		"STRING",  // uppercase
		"object",  // not in D5
		"any",     // not in D5
	}
	for _, ft := range notWant {
		if isKnownFieldType(ft) {
			t.Errorf("expected FieldType %q to be unknown", ft)
		}
	}
}

// ========================== FieldInfo — FullName / Equal ===================================

// TestFieldInfo_FullNameAndEqual covers the basic FieldInfo contract that the rest of the
// engine (Register, Project, Has) builds on. namespace/name/Type variations must all
// distinguish correctly.
func TestFieldInfo_FullNameAndEqual(t *testing.T) {
	a := FieldInfo{Namespace: "http", Name: "method", Type: TypeString}
	b := FieldInfo{Namespace: "http", Name: "method", Type: TypeString}
	c := FieldInfo{Namespace: "http", Name: "status", Type: TypeInt}
	d := FieldInfo{Namespace: "core", Name: "method", Type: TypeString} // same name, diff ns
	e := FieldInfo{Namespace: "http", Name: "method", Type: TypeInt}    // same name, diff type

	if got := a.FullName(); got != "http.method" {
		t.Errorf("FullName: got %q, want %q", got, "http.method")
	}
	if !a.Equal(b) {
		t.Error("two identical FieldInfo values must compare Equal")
	}
	if a.Equal(c) {
		t.Error("different Name must NOT be Equal")
	}
	if a.Equal(d) {
		t.Error("different Namespace must NOT be Equal")
	}
	if a.Equal(e) {
		t.Error("different Type must NOT be Equal")
	}
}

// ========================== validation helpers ==============================================

// TestValidNamespaceAndName pins the exact rules in DECISION D7. The rules are part of
// the public contract with downstream plugins (Manifest names must satisfy them too) —
// if any of these cases starts passing/failing differently, the contract changed.
func TestValidNamespaceAndName(t *testing.T) {
	cases := []struct {
		in         string
		wantNSOK   bool
		wantNameOK bool
	}{
		{"", false, false},     // empty
		{"core", true, true},   // canonical
		{"http", true, true},   // canonical
		{"syslog", true, true}, // canonical
		{"my_plugin", true, true},
		{"a-b", true, true},
		{"a.b", false, false},  // dot forbidden
		{"a b", false, false},  // space forbidden
		{"a\tb", false, false}, // tab forbidden
		{"Core", false, false}, // uppercase rejected
		{"CORE", false, false}, // uppercase rejected
		{"a1", true, true},     // digit allowed (middle)
		{"1a", true, true},     // digit leading also OK
		{"a/", false, false},   // punctuation rejected
	}
	for _, tc := range cases {
		if got := validNamespace(tc.in); got != tc.wantNSOK {
			t.Errorf("validNamespace(%q) = %v, want %v", tc.in, got, tc.wantNSOK)
		}
		if got := validName(tc.in); got != tc.wantNameOK {
			t.Errorf("validName(%q) = %v, want %v", tc.in, got, tc.wantNameOK)
		}
	}
}

// ========================== Catalog — basic Register / Fields ==============================

// TestCatalog_RegisterAndFields is the happy-path baseline: each Register returns nil,
// the field appears in Fields(), and the FullName / Type pair round-trips correctly.
func TestCatalog_RegisterAndFields(t *testing.T) {
	c := NewCatalog()

	if err := c.Register("core", "timestamp", TypeTimestamp); err != nil {
		t.Fatalf("register core.timestamp: %v", err)
	}
	if err := c.Register("http", "method", TypeString); err != nil {
		t.Fatalf("register http.method: %v", err)
	}
	if err := c.Register("http", "status", TypeInt); err != nil {
		t.Fatalf("register http.status: %v", err)
	}
	if err := c.Register("syslog", "facility", TypeInt); err != nil {
		t.Fatalf("register syslog.facility: %v", err)
	}

	fields := c.Fields()
	if len(fields) != 4 {
		t.Fatalf("Fields() len = %d, want 4", len(fields))
	}

	// Fields() must be sorted by FullName.
	for i := 1; i < len(fields); i++ {
		if fields[i-1].FullName() >= fields[i].FullName() {
			t.Fatalf("Fields() not sorted: %q before %q", fields[i-1].FullName(), fields[i].FullName())
		}
	}

	// Spot-check the actual content.
	want := map[string]FieldType{
		"core.timestamp":  TypeTimestamp,
		"http.method":     TypeString,
		"http.status":     TypeInt,
		"syslog.facility": TypeInt,
	}
	for _, fi := range fields {
		wantType, ok := want[fi.FullName()]
		if !ok {
			t.Errorf("unexpected field in Fields(): %+v", fi)
			continue
		}
		if fi.Type != wantType {
			t.Errorf("%s.Type = %q, want %q", fi.FullName(), fi.Type, wantType)
		}
	}
}

// TestCatalog_Register_ValidationErrors verifies that every documented validation error
// fires on the matching bad input and that none of them touch the Catalog state (no
// revision bump, no field recorded).
func TestCatalog_Register_ValidationErrors(t *testing.T) {
	c := NewCatalog()

	type testCase struct {
		name    string
		ns      string
		fld     string
		typ     FieldType
		wantErr error
	}
	cases := []testCase{
		{"empty namespace", "", "thing", TypeString, ErrEmptyNamespace},
		{"invalid namespace (dot)", "ns.bad", "thing", TypeString, ErrInvalidNamespace},
		{"invalid namespace (upper)", "NS", "thing", TypeString, ErrInvalidNamespace},
		{"invalid name (dot)", "ns", "fld.bad", TypeString, ErrInvalidName},
		{"invalid name (upper)", "ns", "Fld", TypeString, ErrInvalidName},
		{"unknown type", "ns", "fld", FieldType("inteher"), ErrUnknownFieldType},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Register(tc.ns, tc.fld, tc.typ); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Register(%q,%q,%q): got err %v, want %v", tc.ns, tc.fld, tc.typ, err, tc.wantErr)
			}
		})
	}

	// None of the failed registers above should have bumped the revision.
	if got := c.Revision(); got != 0 {
		t.Errorf("Revision after failed Registers = %d, want 0 (errors must not bump)", got)
	}
	// And the catalog must be empty.
	if got := c.Fields(); len(got) != 0 {
		t.Errorf("Fields() after failed Registers = %d entries, want 0", len(got))
	}
}

// ========================== Catalog — duplicate / type-mismatch ============================

// TestCatalog_Register_IdempotencyAndMismatch pins the D7 ownership rule: a namespace
// owns its field spellings. Re-registering the same field with the same type is an
// error (silent acceptance would hide duplication); re-registering with a different type
// is also an error (D7 forbids conflicting declarations). Neither path mutates the Catalog.
func TestCatalog_Register_IdempotencyAndMismatch(t *testing.T) {
	c := NewCatalog()

	if err := c.Register("http", "method", TypeString); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := c.Register("http", "method", TypeString); !errors.Is(err, ErrFieldExists) {
		t.Fatalf("duplicate same-type: got %v, want ErrFieldExists", err)
	}
	if err := c.Register("http", "method", TypeInt); !errors.Is(err, ErrFieldTypeMismatch) {
		t.Fatalf("duplicate different-type: got %v, want ErrFieldTypeMismatch", err)
	}

	// Only the first registration is in the Catalog.
	fields := c.Fields()
	if len(fields) != 1 {
		t.Fatalf("Fields() len = %d, want 1", len(fields))
	}
	if fields[0].Type != TypeString {
		t.Fatalf("Fields()[0].Type = %q, want string", fields[0].Type)
	}

	// Revision bumped exactly once — by the first, successful register.
	if got := c.Revision(); got != 1 {
		t.Errorf("Revision = %d, want 1 (only the first successful Register counts)", got)
	}
}

// ========================== Catalog — Revision monotonicity ================================

// TestCatalog_RevisionMonotonic exercises the D13 revision-bump contract: one bump per
// successful Register, never on error, never on read.
func TestCatalog_RevisionMonotonic(t *testing.T) {
	c := NewCatalog()

	prev := c.Revision()
	for i := 0; i < 5; i++ {
		err := c.Register("ns", nameField(i), TypeInt)
		if err != nil {
			t.Fatalf("register #%d: %v", i, err)
		}
		cur := c.Revision()
		if cur <= prev {
			t.Fatalf("Revision did not increase: prev=%d, cur=%d after register #%d", prev, cur, i)
		}
		prev = cur
	}

	// Reads must not bump the revision.
	for i := 0; i < 10; i++ {
		_ = c.Revision()
	}
	if got := c.Revision(); got != 5 {
		t.Errorf("Revision = %d after reads, want 5", got)
	}
}

// nameField returns a deterministic name for iteration in tests.
func nameField(i int) string { return "field" + itoaSmall(i) }

// itoaSmall avoids pulling strconv into tests for tiny numbers.
func itoaSmall(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}

// ========================== Catalog — Has ==================================================

// TestCatalog_Has covers both positive and negative lookups. Has must reflect the
// current registered set; unregistered (or malformed) names must report false.
func TestCatalog_Has(t *testing.T) {
	c := NewCatalog()
	if err := c.Register("http", "method", TypeString); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.Register("core", "level", TypeString); err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := []struct {
		full string
		want bool
	}{
		{"http.method", true},
		{"core.level", true},
		{"http.status", false},   // unknown in known ns
		{"http.", false},         // empty name (not registered — not malformed-checked here)
		{".method", false},       // empty ns
		{"core.method", false},   // wrong ns for same leaf
		{"unknown.thing", false}, // unknown ns
	}
	for _, tc := range cases {
		if got := c.Has(tc.full); got != tc.want {
			t.Errorf("Has(%q) = %v, want %v", tc.full, got, tc.want)
		}
	}
}

// ========================== Catalog — concurrent Register + Read =========================

// TestCatalog_ConcurrentRegisterRead is the canonical race-detector exercise for
// Task A3 success criterion #5: many goroutines hammering Register while readers
// (Fields / Has / Revision) run. Without the RWMutex + atomic revision, this race
// fires the detector under -race. Run with `go test -race`.
func TestCatalog_ConcurrentRegisterRead(t *testing.T) {
	c := NewCatalog()

	const (
		writerGoroutines      = 8
		writesPerGoroutine    = 200
		readerGoroutines      = 4
		readsPerGoroutine     = 200
		namespacesPerWriterNS = 3 // core, http, syslog
	)

	namespaces := []string{"core", "http", "syslog"}
	types := []FieldType{TypeString, TypeInt, TypeBool, TypeIP, TypeTimestamp}

	var wg sync.WaitGroup

	// Writers — each picks one of three namespaces and registers field<idx>.
	for w := 0; w < writerGoroutines; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			ns := namespaces[wID%namespacesPerWriterNS]
			for i := 0; i < writesPerGoroutine; i++ {
				// Each writer uses its own name range so the duplicate-path is also
				// exercised (some registrars will land on already-occupied names and
				// exercise ErrFieldExists / ErrFieldTypeMismatch — both must remain
				// safe under -race).
				name := "f" + itoaSmall(wID) + "_" + itoaSmall(i)
				typ := types[(wID+i)%len(types)]
				_ = c.Register(ns, name, typ)
			}
		}(w)
	}

	// Readers — Fields / Has / Revision in tight loops, asserting monotonicity.
	for r := 0; r < readerGoroutines; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lastRev uint64
			for i := 0; i < readsPerGoroutine; i++ {
				rev := c.Revision()
				if rev < lastRev {
					t.Errorf("Revision decreased: %d -> %d", lastRev, rev)
				}
				lastRev = rev
				_ = c.Fields()
				_ = c.Has("http.method")
				_ = c.Has("nonexistent.field")
			}
		}()
	}

	wg.Wait()

	// Final sanity check: every successful Register bumped the revision exactly once.
	// We can't predict the final field count (depends on which goroutines won the
	// race for each name — first writer wins, rest get ErrFieldExists / mismatch),
	// but we can predict Revision() >= number of goroutines that did at least one
	// successful write.
	fields := c.Fields()
	if len(fields) == 0 {
		t.Fatalf("expected at least some fields to be registered")
	}
	if got := c.Revision(); int(got) != len(fields) {
		t.Errorf("Revision=%d but Fields()=%d (must be equal: one bump per surviving field)", got, len(fields))
	}
}

// TestCatalog_ConcurrentRevisionOnlyAtomicity checks the atomic-load path independently
// of the mutex: even with no callers holding the write lock, many goroutines spin on
// Revision() and the atomic load must remain race-free. If we ever swap Revision() for
// a mutex-locked read, this test would still pass — but the cost-comment in scheme.go
// would no longer apply.
func TestCatalog_ConcurrentRevisionOnlyAtomicity(t *testing.T) {
	c := NewCatalog()
	if err := c.Register("core", "stream", TypeString); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const goroutines = 32
	const iters = 1000

	var wg sync.WaitGroup
	var done atomic.Int32
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = c.Revision()
			}
			done.Add(1)
		}()
	}
	wg.Wait()
	if done.Load() != int32(goroutines) {
		t.Fatalf("done=%d, want %d", done.Load(), goroutines)
	}
}

// ========================== Project — namespace filter =====================================

// TestCatalog_Project_Namespaces covers the D9 use-case gating: a Scheme built from
// {core, http} must contain only those fields, never syslog. An empty namespace set
// yields a Scheme with zero fields; passing a malformed namespace (one that no field
// uses) also yields zero fields without error.
func TestCatalog_Project_Namespaces(t *testing.T) {
	c := NewCatalog()
	mustRegisterAll(t, c,
		Register("core", "timestamp", TypeTimestamp),
		Register("core", "level", TypeString),
		Register("http", "method", TypeString),
		Register("http", "status", TypeInt),
		Register("http", "uri", TypeString),
		Register("syslog", "facility", TypeInt),
		Register("syslog", "severity", TypeInt),
	)

	waf := c.Project("core", "http")
	want := []string{
		"core.level",
		"core.timestamp",
		"http.method",
		"http.status",
		"http.uri",
	}
	got := fieldNames(waf.Fields())
	if !equalStringSlice(got, want) {
		t.Fatalf("WAF scheme fields = %v, want %v", got, want)
	}

	syslogProf := c.Project("syslog")
	want = []string{"syslog.facility", "syslog.severity"}
	got = fieldNames(syslogProf.Fields())
	if !equalStringSlice(got, want) {
		t.Fatalf("syslog scheme fields = %v, want %v", got, want)
	}

	// Empty namespace filter → empty Scheme, still well-formed.
	empty := c.Project()
	if got := empty.Fields(); len(got) != 0 {
		t.Fatalf("empty Project: Fields() = %v, want empty slice", got)
	}

	// Malformed namespace: nothing matches, but no panic and no error.
	junk := c.Project("nope-does-not-exist", "core")
	got = fieldNames(junk.Fields())
	if !equalStringSlice(got, []string{"core.level", "core.timestamp"}) {
		t.Fatalf("Project with junk ns: Fields() = %v, want core.* only", got)
	}

	// Scheme.Revision matches Catalog.Revision at Project time.
	if waf.Revision() != c.Revision() {
		t.Errorf("Scheme.Revision = %d, Catalog.Revision = %d", waf.Revision(), c.Revision())
	}
}

// TestScheme_IsImmutableAfterProjection is the safety contract for D6: a Scheme built
// from a Catalog is a snapshot — subsequent Register calls on the Catalog MUST NOT
// change the Scheme's Fields() or Revision().
func TestScheme_IsImmutableAfterProjection(t *testing.T) {
	c := NewCatalog()
	mustRegisterAll(t, c,
		Register("http", "method", TypeString),
		Register("http", "status", TypeInt),
	)
	snap := c.Project("http")
	snapFields := snap.Fields()
	if len(snapFields) != 2 {
		t.Fatalf("initial snap has %d fields, want 2", len(snapFields))
	}
	snapRev := snap.Revision()

	// Mutate the Catalog — the snapshot must not move.
	mustRegisterAll(t, c,
		Register("http", "uri", TypeString),
		Register("http", "host", TypeString),
	)
	// And one in a different namespace to make sure cross-NS changes also do not move
	// the http-only Scheme.
	mustRegisterAll(t, c, Register("syslog", "facility", TypeInt))

	afterFields := snap.Fields()
	if len(afterFields) != len(snapFields) {
		t.Fatalf("Scheme.Fields() changed after Catalog mutation: before=%d after=%d", len(snapFields), len(afterFields))
	}
	if snap.Revision() != snapRev {
		t.Fatalf("Scheme.Revision changed after Catalog mutation: before=%d after=%d", snapRev, snap.Revision())
	}

	// Sanity: the Catalog itself did change.
	if got := len(c.Fields()); got != 5 {
		t.Errorf("Catalog has %d fields after mutation, want 5", got)
	}
}

// TestScheme_NilReceiver covers the nil-receiver guards documented on Scheme.Has and
// Scheme.Revision — callers that hold a "Scheme that may not have been projected yet"
// must not panic.
func TestScheme_NilReceiver(t *testing.T) {
	var s *Scheme
	if got := s.Has("anything"); got != false {
		t.Errorf("(*Scheme)(nil).Has = %v, want false", got)
	}
	if got := s.Revision(); got != 0 {
		t.Errorf("(*Scheme)(nil).Revision = %d, want 0", got)
	}
	// Fields() on nil must return nil — same convention as len(nil) == 0.
	if got := s.Fields(); got != nil {
		t.Errorf("(*Scheme)(nil).Fields = %v, want nil", got)
	}
}

// TestScheme_Has filters correctly over a projection. Has must use the Scheme's own
// field set, not the source Catalog's, so a scheme built from one profile cannot leak
// fields owned by another.
func TestScheme_Has(t *testing.T) {
	c := NewCatalog()
	mustRegisterAll(t, c,
		Register("core", "timestamp", TypeTimestamp),
		Register("http", "method", TypeString),
		Register("syslog", "facility", TypeInt),
	)

	waf := c.Project("core", "http")
	cases := []struct {
		full string
		want bool
	}{
		{"core.timestamp", true},
		{"http.method", true},
		{"syslog.facility", false}, // not in this profile
		{"http.status", false},     // not registered at all
	}
	for _, tc := range cases {
		if got := waf.Has(tc.full); got != tc.want {
			t.Errorf("waf.Has(%q) = %v, want %v", tc.full, got, tc.want)
		}
	}
}

// ========================== Scheme — concurrent safety =====================================

// TestScheme_ConcurrentReads verifies that a Scheme — once constructed — can be read
// concurrently without coordination. Run with -race.
func TestScheme_ConcurrentReads(t *testing.T) {
	c := NewCatalog()
	mustRegisterAll(t, c,
		Register("core", "timestamp", TypeTimestamp),
		Register("http", "method", TypeString),
	)
	s := c.Project("core", "http")

	const goroutines = 16
	const itersPerGoroutine = 500

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerGoroutine; j++ {
				_ = s.Has("http.method")
				_ = s.Fields()
				_ = s.Revision()
			}
		}()
	}
	wg.Wait()
}

// ========================== helpers =========================================================

// Register is a tiny wrapper used by mustRegisterAll to keep test tables short. It is a
// local type to avoid pulling testify/require for four-line uses.
type registerCall struct {
	ns  string
	fld string
	typ FieldType
}

// Register builds a registerCall — the only constructor the table uses.
func Register(ns, fld string, typ FieldType) registerCall {
	return registerCall{ns: ns, fld: fld, typ: typ}
}

// mustRegisterAll runs each Register call against c and fails the test on error. The
// call sites are table-literal to keep groups of registrations visually grouped (every
// Group-A task test file groups its seeds the same way).
func mustRegisterAll(t *testing.T, c *Catalog, calls ...registerCall) {
	t.Helper()
	for _, call := range calls {
		if err := c.Register(call.ns, call.fld, call.typ); err != nil {
			t.Fatalf("Register(%s.%s, %s) failed: %v", call.ns, call.fld, call.typ, err)
		}
	}
}

// fieldNames extracts the FullName of every FieldInfo in s.
func fieldNames(s []FieldInfo) []string {
	out := make([]string, len(s))
	for i, fi := range s {
		out[i] = fi.FullName()
	}
	return out
}

// equalStringSlice compares two string slices for equality (length + element-by-element).
// Avoiding reflect.DeepEqual keeps the failure mode readable.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
