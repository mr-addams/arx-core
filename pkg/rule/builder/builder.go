// ========================== pkg/rule/builder — fluent RuleSet builder ===========================
//   Builder (Task E2) provides a chainable, ergonomic way to assemble a RuleSet from
//   a field schema. It hides the Catalog / Scheme / Compiler pipeline from callers,
//   while still producing the same immutable, compiled RuleSet that ruleset.New does.
//
//   WHAT IS HERE:
//     - Builder — the fluent type: New / Field / Profiles / Ruleset / CompileRules / Err.
//     - fieldDecl — lightweight registration request captured during chaining.
//
//   WHAT IS NOT HERE:
//     - Lifeycle management after the RuleSet is built — owned by ruleset.RuleSet.
//     - Evaluation / resolvers — owned by plugins and pkg/rule.
//     - FieldType definitions — owned by pkg/rule (alias to pkg/plugin).
//
//   DEPENDENCY RULE:
//     pkg/rule/builder depends only on sibling packages: pkg/rule (Catalog,
//     FieldType, Scheme), pkg/rule/compiler (Compiler), and pkg/rule/ruleset
//     (RuleSet). No non-stdlib dependencies.

package builder

import (
	"errors"

	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/compiler"
	"github.com/mr-addams/arx-core/pkg/rule/ruleset"
)

// Builder assembles a RuleSet from a field schema.
type Builder struct {
	cat           *rule.Catalog
	profile       string
	fields        []fieldDecl
	extraProfiles []string
	firstErr      error
}

type fieldDecl struct {
	namespace string
	name      string
	typ       rule.FieldType
}

// New creates a Builder for the given profile namespace (e.g. "http", "syslog").
func New(profile string) *Builder {
	cat := rule.NewCatalog()
	// The core namespace (Envelope fields) is implicitly part of every RuleSet
	// per ruleset.New; registering those fields here keeps a Builder-constructed
	// Catalog consistent with what resolvers and the compiler expect.
	_ = cat.Register("core", "timestamp", rule.TypeTimestamp)
	_ = cat.Register("core", "stream", rule.TypeString)
	_ = cat.Register("core", "source", rule.TypeString)
	_ = cat.Register("core", "source_type", rule.TypeString)
	_ = cat.Register("core", "level", rule.TypeString)
	return &Builder{
		cat:     cat,
		profile: profile,
		fields:  make([]fieldDecl, 0),
	}
}

// Field registers one field. Chainable. Stores first error (empty namespace/name).
func (b *Builder) Field(namespace, name string, typ rule.FieldType) *Builder {
	if namespace == "" || name == "" {
		if b.firstErr == nil {
			b.firstErr = errors.New("builder: namespace and name must be non-empty")
		}
		return b
	}
	b.fields = append(b.fields, fieldDecl{namespace: namespace, name: name, typ: typ})
	return b
}

// Profiles declares additional namespaces visible to the Scheme (besides profile).
// Optional — most callers only need one namespace.
func (b *Builder) Profiles(namespaces ...string) *Builder {
	b.extraProfiles = append(b.extraProfiles, namespaces...)
	return b
}

// Ruleset validates fields, builds Catalog → Scheme → Compiler → RuleSet.
// Returns first stored error if any Field() call failed.
func (b *Builder) Ruleset() (*ruleset.RuleSet, error) {
	if b.firstErr != nil {
		return nil, b.firstErr
	}

	// Register user fields in the order they were declared. The Catalog will reject
	// duplicates with a typed error; we surface the first such error immediately.
	for _, f := range b.fields {
		if err := b.cat.Register(f.namespace, f.name, f.typ); err != nil {
			return nil, err
		}
	}

	// Profiles() may reference namespaces that have no explicit fields. Register a
	// synthetic no-op field per extra namespace so the namespace is known to the
	// Catalog and can appear in the Scheme projection.
	for _, ns := range b.extraProfiles {
		// We ignore the error here because an empty/malformed namespace will simply
		// be dropped by Project below; this keeps Profiles a lightweight marker.
		_ = b.cat.Register(ns, "_", rule.TypeString)
	}

	// Project the primary profile, the implicit core namespace, and any extra
	// profiles declared via Profiles().
	nsArgs := make([]string, 0, 2+len(b.extraProfiles))
	nsArgs = append(nsArgs, b.profile, "core")
	nsArgs = append(nsArgs, b.extraProfiles...)
	scheme := b.cat.Project(nsArgs...)

	comp, cerr := compiler.NewCompiler(scheme)
	if cerr != nil {
		return nil, cerr
	}

	rs, err := ruleset.NewWithCompiler(b.cat, scheme, comp, b.profile)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// CompileRules is a convenience: Ruleset() + Add each rule. Returns first error.
func (b *Builder) CompileRules(rules map[string]string) (*ruleset.RuleSet, error) {
	rs, err := b.Ruleset()
	if err != nil {
		return nil, err
	}
	for name, expr := range rules {
		if err := rs.Add(name, expr); err != nil {
			return rs, err
		}
	}
	return rs, nil
}

// Err returns the first error stored during Field() calls (before Ruleset() is called).
func (b *Builder) Err() error {
	return b.firstErr
}
