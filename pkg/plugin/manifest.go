// ========================== pkg/plugin — Manifest declaration ==============================
//   Manifest describes a plugin's identity and data contract for the pipeline framework.
//   It is populated from the plugin's embedded metadata at registration time and validated
//   by the pipeline bootstrapper before any data flows.

package plugin

// ========================== FieldType — field contract mirror of Kind =======================

// FieldType is the stable, version-independent name of a field's value kind carried by
// FieldDecl (DECISION D8). It mirrors the Value Kind enum (DECISION D5) as a string
// constant so the field contract — what a Manifest and the rule-language type-checker
// exchange — stays textual rather than dependent on the underlying numeric Kind values.
//
// FieldType is owned by pkg/plugin (DECISION D8.1): the canonical definition lives here
// next to FieldDecl so that pkg/plugin does NOT need to import pkg/rule (which would
// create a new dep-graph edge the Core author deliberately avoided). pkg/rule re-exports
// FieldType as a type alias (rule.FieldType = plugin.FieldType) so existing callers of
// pkg/rule — the compiler, the parser, the evaluator, and tests — keep compiling
// unchanged.
//
// KindInvalid (the "absent field" sentinel) is intentionally NOT represented: it is a
// runtime sentinel, not a declared field type. A future Kind added without a corresponding
// FieldType constant will be rejected by pkg/rule.Catalog.Register with ErrUnknownFieldType.
type FieldType string

// Field type constants. The string value is part of the engine's diagnostic surface
// (rule-language type names, error messages, Manifest exports) — treat changes as
// breaking.
const (
	TypeString    FieldType = "string"
	TypeInt       FieldType = "int"
	TypeFloat     FieldType = "float"
	TypeBool      FieldType = "bool"
	TypeIP        FieldType = "ip"
	TypeBytes     FieldType = "bytes"
	TypeTimestamp FieldType = "timestamp"
	TypeDuration  FieldType = "duration"
	TypeArray     FieldType = "array"
	TypeMap       FieldType = "map"
)

// ========================== FieldDecl — single field declaration ===========================

// FieldDecl declares a single named field that a plugin either produces
// (emits in its output payloads) or consumes (requires in its input payloads).
//
// RESOLVED-Q4a (Flow 083) fixes the minimum viable shape: a Name plus a
// Required flag. The Type field was intentionally absent at first — it is added
// in Flow 001 (DECISION D8) as the forward-compatible extension point the Core
// author left in FieldDecl for exactly this purpose (a new field with a string-typed
// zero value is backward-compatible at both the Go ABI level and the API level: every
// existing FieldDecl literal keeps compiling, and plugins that have not opted into
// the rule engine continue to work via the Name/Required-only contract).
//
// A plugin that leaves Produces and Consumes nil declares "no field contract"
// — the pipeline bootstrapper treats it as compatible with any field shape.
// The field-level validator (Phase 4 of Flow 083) will check that for every
// adjacent consumer in the pipeline, producer.Produces is a superset of
// consumer.Consumes by Name (Required flag participates in the comparison).
type FieldDecl struct {
	// Name is the symbolic field identifier. Plugins agree on a Name spelling
	// when their data shapes overlap; mismatched Names are treated as
	// incompatible by the field-level validator.
	Name string

	// Required marks a field as mandatory for a consumer. A producer that
	// omits a Required field fails the field-level check at startup, surfacing
	// the mismatch before any data flows. Optional fields (Required == false)
	// are still listed in Consumes so consumers can use them when present.
	Required bool

	// Type carries the field's FieldType (DECISION D8) — the type this field holds at
	// evaluation time, mirroring the Value Kind enum (D5). The zero value (empty string)
	// means "untyped / legacy field": the field-level validator continues to work on
	// Name/Required alone, and the rule engine treats the field as invisible to Schemes
	// (a Schemes-only-aware plugin must explicitly set Type to opt into rule-engine
	// registration). This preserves back-compat with every existing FieldDecl user.
	//
	// Adding this field is the forward-compatible extension point the Core author left
	// in FieldDecl for exactly this purpose (see the original RESOLVED-Q4a / Flow 083
	// comment above).
	Type FieldType
}

// Manifest describes a plugin's identity and data contract.
// Every plugin exposes a Manifest so the pipeline framework can verify compatibility
// of roles and data types before starting data processing.
type Manifest struct {
	// PluginID is a unique identifier for the plugin within the pipeline.
	PluginID string
	// PluginVersion is the semantic version of the plugin.
	PluginVersion string
	// Role defines the plugin's position and responsibility in the pipeline.
	Role Role
	// InputType declares the DataType this plugin expects to receive.
	InputType DataType
	// OutputType declares the DataType this plugin produces after processing.
	OutputType DataType
	// Tags are free-form labels for selection and filtering in pipeline config.
	Tags []string

	// Produces declares the named fields this plugin emits in its output
	// payloads. A producer populates Produces so downstream consumers can
	// verify field-level compatibility. Leaving Produces nil preserves
	// back-compat with plugins that have not yet adopted field contracts —
	// the field-level validator treats nil as "no field contract declared".
	Produces []FieldDecl

	// Consumes declares the named fields this plugin requires (or accepts)
	// from its input payloads. A consumer that lists a field with
	// Required == true forces the field-level validator to fail-fast at
	// startup if no upstream producer emits that field. Leaving Consumes
	// nil preserves back-compat with plugins that have not yet adopted
	// field contracts.
	Consumes []FieldDecl
}
