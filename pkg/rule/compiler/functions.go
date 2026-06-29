// ========================== pkg/rule/compiler — function registry ============================
//   The function registry (DECISION D16) is a closed, package-level map from function
//   name to FuncSpec. Compile-time signature checking and eval-time dispatch both go
//   through this map; the registry is the single place where a new function is added
//   in a future flow.
//
//   WHAT IS HERE:
//     - FuncSpec — the per-function declaration: parameter Kinds, return Kind, an
//       "allocating" flag, and a small eval entry point that takes already-resolved
//       Value arguments and produces a Value result.
//     - The package-level closed registry, populated at init() from the registered
//       function list.
//     - Lookup / Names accessors used by the compiler and by tests.
//
//   WHAT IS NOT HERE:
//     - The compileFuncCall rewrite — lives in compiler.go (Group B).
//     - The evalFuncCall dispatch — lives in eval.go (Group C).
//     - Functions themselves are declared in adjacent files (strings.go, etc.) per
//       family; this file is only the registry skeleton + the data shape.
//
//   DEPENDENCY RULE:
//     stdlib only (D2): strings, strconv, encoding/json, net/url, html, regexp, net.
//     Plus sibling pkg/rule (Value / Kind).
//
//   CONCURRENCY:
//     The registry is built at package init and never mutated afterwards. It is
//     safe for concurrent reads from any number of goroutines — Eval walks it
//     from many goroutines, Compile walks it from any goroutine.
//
//   CLOSED SET (D16 §5):
//     The v0.3.0 set is closed. Adding a function requires a new flow / version
//     bump — there is intentionally no public Register function.

package compiler

import (
	"sync"

	"github.com/mr-addams/arx-core/pkg/rule"
)

// ========================== FuncSpec — per-function declaration ==============================

// FuncSpec is the compile-time + eval-time descriptor of a registered function. It
// captures the function's parameter shape (ParamKinds, one per argument), its return
// Kind, whether the hot path allocates, and the eval entry point that performs the
// actual computation.
//
// The eval entry point receives the arguments as already-resolved Values (the
// compiler has already type-checked the arguments against ParamKinds; the entry
// point does not re-validate). The returned Value's Kind MUST match ReturnKind;
// callers rely on this invariant when composing expressions.
//
// The FuncSpec is value-typed and allocated where it is declared (registry init).
// A *FuncSpec is never shared across functions.
type FuncSpec struct {
	// Name is the canonical name of the function (the same string used to look it
	// up). Stored on the spec itself so callers can recover it from a value the
	// registry returned (useful in error messages and tests).
	Name string

	// ParamKinds lists the expected Kind of each argument, in order. The length
	// of the slice IS the function's arity. The compiler enforces this at
	// compile time (CodeBadFuncArity for length mismatch, CodeBadFuncArgType
	// for per-argument Kind mismatch).
	ParamKinds []rule.Kind

	// ReturnKind is the Kind of the Value the function produces. The compiler
	// reports this Kind via nodeKind(opFunc), so downstream type-checking
	// (operators, comparisons) can validate against the function's return.
	ReturnKind rule.Kind

	// Allocating records whether the eval entry point allocates per call. The
	// D4 contract is honorific: alloc-free functions must not allocate beyond
	// what the stdlib impl inherently needs; allocating functions are labelled
	// in REFERENCE.md and benchmarked. The flag is informational — the engine
	// does NOT act on it at runtime. It exists so tests can pin the contract.
	Allocating bool

	// IsVariadic marks the function as variadic: it accepts zero or more
	// arguments, and the LAST ParamKinds element is the kind of every variadic
	// argument beyond the minimum-arity prefix. The minimum arity is
	// len(ParamKinds) - 1 for a variadic function (so a variadic with one
	// ParamKind accepts zero-or-more args; a non-variadic function accepts
	// exactly len(ParamKinds) args).
	//
	// Default false: the v0.3.0 closed set has exactly one variadic entry —
	// concat(args... :string). All others are fixed-arity.
	IsVariadic bool

	// Eval is the eval entry point. It receives the function's arguments as
	// already-resolved Values (matching ParamKinds in order) and returns the
	// resulting Value. Implementations MUST be safe for concurrent use — Eval
	// is called from many goroutines on the same Plan.
	//
	// The Eval signature is intentionally narrow: it cannot reach back into
	// the resolver or the event, because every function in the v0.3.0 set is
	// pure (it operates only on its arguments). A future flow that needs
	// field-resolver access would extend the signature — that is a deliberate
	// future-flow decision, not a silent expansion here.
	Eval func(args []rule.Value) rule.Value
}

// ========================== Registry — closed, package-internal =============================

// registry is the package-level function table. It is built at init() from the
// per-family register calls below and never mutated afterwards. Lookup is
// protected by a RWMutex so a future flow that hot-loads functions does not
// race with concurrent Eval / Compile reads; for the v0.3.0 closed set, the
// mutex is held in read mode for every Lookup (the cost is negligible).
//
// The use of a mutex rather than a frozen map is forward-compatible with a
// future hot-load mechanism; for v0.3.0 it is effectively read-only.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]FuncSpec)
)

// registerFunc inserts spec into the registry. Called from init() in the
// per-family file. Duplicate names panic — that is a programmer error caught
// at process start, not a runtime failure.
func registerFunc(spec FuncSpec) {
	if spec.Name == "" {
		panic("compiler: cannot register function with empty name")
	}
	if spec.Eval == nil {
		panic("compiler: cannot register function " + spec.Name + " with nil Eval")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[spec.Name]; exists {
		panic("compiler: duplicate function registration for " + spec.Name)
	}
	registry[spec.Name] = spec
}

// Lookup returns the FuncSpec for name, plus a boolean indicating presence.
// The returned value is a copy of the registered spec — callers may not mutate
// the registry through the returned value.
//
// Lookup is safe for concurrent use.
func Lookup(name string) (FuncSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	spec, ok := registry[name]
	return spec, ok
}

// Names returns the registered function names in an unspecified order. The
// returned slice is a fresh copy — callers may sort or mutate it without
// affecting the registry. Used by tests and by the documentation builder.
//
// Names is safe for concurrent use.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}
