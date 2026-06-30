# pkg/rule — REFERENCE

The rule-language reference for `pkg/rule`. This document is normative for the
v1 engine surface — every operator, function, literal form, and compile-time
error class is exactly what the lexer, parser, and compiler accept or reject
(see `pkg/rule/lexer/`, `pkg/rule/parser/`, `pkg/rule/compiler/`).

Use this document when you need the exact spelling of an operator, the
precise operand-type rules, or the limit cases (IP-in-CIDR equality, `strict`
modifier placement, the empty function table). For the high-level orientation
— what the engine is, why it is split into `Catalog`/`Scheme`/`Plan`/`RuleSet`,
how a plugin embeds it — read [`README.md`](./README.md) first.

## Audience

Two readers, two lenses:

- **Rule authors** — write config expressions. Care about literal grammar,
  operator semantics, precedence, and the cookbook recipes in
  [`cookbook/rule-engine/`](../../cookbook/rule-engine/).
- **Plugin embedders** — call the Go API. Care about the integration contract
  (`Manifest`, `FieldResolver`, `Builder.FromManifest()`/`Builder`,
  `Compile(...)`, `RuleSet.Match`). The Go-shaped view is in `README.md`; the
  rule-shaped view is here.

## Reading order

1. [Value types](#value-types) — what kinds of values flow through expressions.
2. [Literal grammar](#literal-grammar) — how every value kind is spelled in source.
3. [Identifier grammar](#identifier-grammar) — how fields are referenced.
4. [Operators](#operators) — the closed operator keyword set, with arity,
   operand-type rules, and semantics.
5. [Functions](#functions) — v1 has no user-callable functions; see note.
6. [Field references](#field-references) — dotted field refs and Map bracket access.
7. [Comments](#comments) — `#` to end of line.
8. [Precedence and associativity](#precedence-and-associativity) — operator stack.
9. [DSL examples](#dsl-examples) — example expressions for each value kind.
10. [Compile-time errors](#compile-time-errors) — exhaustive error-code list.
11. [Eval-time semantics](#eval-time-semantics) — missing field, invalid Kind, error fallback.
12. [v1 non-goals](#v1-non-goals--deferred-extensions) — what is intentionally NOT in v1.
13. [Cross-references](#cross-references) — pointers to the source-of-truth files.

---

## Value types

The engine has one universal value carrier — `rule.Value`, a tagged union
selected by `rule.Kind`. The table below lists every kind, its Go backing
type, the DSL literal forms that produce it, and the operators that accept
it on either side.

`FieldType` (the textual spelling declared in `Manifest.FieldDecl.Type`) and
`Kind` (the discriminated union tag) are mirrored one-to-one (DECISION D8.1).
Constants live in `pkg/plugin/manifest.go`; they are re-exported under the
`rule` package as `rule.TypeString`, `rule.TypeInt`, etc.

| Kind              | Go repr                | FieldType constant   | DSL literal forms                       | Comparable with            | Orderable with (`lt`/`le`/`gt`/`ge`) |
|-------------------|------------------------|----------------------|-----------------------------------------|----------------------------|--------------------------------------|
| `KindString`      | `string`               | `rule.TypeString`    | `"..."` with escapes                    | `eq`, `ne`                 | yes (lexicographic)                  |
| `KindInt`         | `int64`                | `rule.TypeInt`       | `[0-9]+` (unsigned — see [note](#about-signed-numerics)) | `eq`, `ne`                 | yes (numeric)                        |
| `KindFloat`       | `float64`              | `rule.TypeFloat`     | `[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?`      | `eq`, `ne`                 | yes (numeric)                        |
| `KindBool`        | `bool`                 | `rule.TypeBool`      | `true`, `false`                         | `eq`, `ne`                 | no                                   |
| `KindIP`          | `net.IP`               | `rule.TypeIP`        | `ip"..."` (single IP or CIDR with `/`)  | `eq`, `ne` (IP-in-CIDR if RHS is CIDR), `in` | no                  |
| `KindBytes`       | `[]byte`               | `rule.TypeBytes`     | `0x"<hex>"`                             | `eq`, `ne`                 | no                                   |
| `KindTimestamp`   | `time.Time`            | `rule.TypeTimestamp` | `ts"..."` (RFC 3339)                    | `eq`, `ne`                 | yes (time)                           |
| `KindDuration`    | `time.Duration`        | `rule.TypeDuration`  | `<int><unit>...` (Go duration grammar)  | `eq`, `ne`                 | yes (time)                           |
| `KindArray`       | `[]Value`              | `rule.TypeArray`     | `[<expr>, <expr>, ...]`                 | `eq`, `ne`                 | no                                   |
| `KindMap`         | `map[string]Value`     | `rule.TypeMap`       | *(none — see [note](#about-maps))*      | `eq`, `ne`                 | no                                   |
| `KindInvalid`     | *(zero value of `Value`)* | *(no FieldType — runtime sentinel)* | `n/a`                          | *(never equal to anything)* | n/a                                |

**Orderable kinds** (`lt`, `le`, `gt`, `ge`): `KindInt`, `KindFloat`, `KindString`,
`KindTimestamp`, `KindDuration`. Cross-Kind ordering is rejected at compile time
(DECISION D14 — no implicit coercions, e.g. `42 lt "abc"` is a type-mismatch
error).

**Equality-only kinds** (`eq`, `ne`): `KindBool`, `KindIP`, `KindBytes`,
`KindArray`, `KindMap`, `KindInvalid`. These do not have a meaningful order;
the compiler rejects ordering operators on them.

### About signed numerics

Numeric literals are unsigned in v1 (DECISION D15). The lexer emits only
unsigned `TInt` and `TFloat`; there is no `TMinus`/`TPlus` token in the closed
enum, and unary-minus on a literal (`-42`) is not supported. Extensions are
tracked in [v1 non-goals](#v1-non-goals--deferred-extensions).

### About Maps

`KindMap` has **no literal form** in the expression language (DECISION D11).
Map-typed values arise at evaluation time from `FieldResolver` (e.g. an
`attrs` Map-typed field on the plugin side). Expressions reach into them via
[field references](#field-references): `attrs["tenant_id"]`. Map keys appearing
in bracket access are NOT individually validated at compile time — that is by
design (D11), and the resolver decides what an unknown key means at
evaluation time (conventionally: returns `(Value{}, false)`, which the
compiler treats as `KindInvalid`).

### About Arrays

`KindArray` has a literal form because the `in` operator needs a set on its
right-hand side (`x in [...]`). The grammar is a comma-separated list of
expressions inside square brackets:

```text
http.status in [200, 301, 404]                # KindInt array
ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"] # KindIP array, CIDR allowed
core.level in ["error", "critical"]           # KindString array
```

All elements of an array literal must share one Kind. Mixed-Kind arrays are
a compile error (`in: array has mixed element kinds`).

---

## Literal grammar

Every literal form is recognized by the lexer (`pkg/rule/lexer/`). The lexer
is purely lexical — RFC 3339 timestamps, IP addresses, durations, and regex
patterns are validated at parser/compile time. The table below describes
what the lexer accepts; [Compile-time errors](#compile-time-errors) lists the
validation failures.

### `KindString` — `"..."`

```text
"plain string"
"with \"escapes\" \\ and \n newlines"
```

Recognised escapes: `\n \t \r \" \\` (DECISION D14). Any other backslash
form is a `TError` token. Embedded raw newlines are a `TError`.

### `KindInt` — `[0-9]+`

```text
0
42
2026
```

Unsigned. `-42` is NOT a literal in v1 (DECISION D15).

### `KindFloat` — float literal

```text
3.14
1.0e3
6.022e-23
```

Forms accepted (lexical): `[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?` and the
integer-only `[0-9]+[eE][-+]?[0-9]+`. No leading sign.

### `KindDuration` — Go duration grammar

```text
1h30m
500ms
2s
750us
```

Units: `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`. Chains compose (`1h30m`,
`2h45m30s`). Validated at parser time via stdlib `time.ParseDuration`.

### `KindTimestamp` — `ts"..."`

```text
ts"2026-06-29T10:00:00Z"
ts"2026-06-29T10:00:00+02:00"
```

The inner string is RFC 3339. Parsed via `time.Parse(time.RFC3339, ...)`.
Validation errors are surfaced as compile-time `invalid_literal`.

### `KindIP` — `ip"..."`

```text
ip"192.0.2.1"        # single IP
ip"10.0.0.0/8"       # CIDR
ip"2001:db8::/32"    # IPv6 CIDR
```

The lexer treats both forms identically; the compiler switches to
**IP-in-CIDR membership** semantics when `ip"..."` contains a `/` (DECISION
D14, `isCIDRLit`). See [Operators — `eq`/`ne`/IP special case](#special-case-ip-cidr-equality-and-membership).

### `KindBytes` — `0x"<hex>"`

```text
0x"deadbeef"
0x""              # empty bytes — allowed
```

Hex-decoded at lex time. Odd length or non-hex characters are a `TError`.

### `KindBool` — `true` / `false`

```text
true
false
```

Reserved keywords. Lex as `TBool`, not `TIdent` — a field name cannot be
`true` or `false`.

### `KindArray` — `[ <expr>, ... ]`

```text
[200, 301, 404]
[ip"10.0.0.0/8", ip"172.16.0.0/12"]
["error", "critical"]
[]
```

Empty arrays are rejected at compile time (`in: array literal must contain at
least one element` — `x in []` would always be false, an oddity an author
probably did not mean).

### `KindMap` — *(no literal form)*

See [About Maps](#about-maps). Constructed only via `FieldResolver` at
runtime; the language has no syntax for `{"a": "b"}`. The square brackets are
reserved exclusively for array literals (`[expr, expr]`).

### Regex — `KindString` (RE2) as a right operand of `matches`

```text
http.uri.path matches "[a-z]+/admin/.*"
```

There is no regex-literal token. The right operand of `matches` is a
`TString` — the parser validates the pattern and the compiler compiles it
into `*regexp.Regexp` at compile time (D4 — pre-compiled). RE2 syntax: no
backreferences, no lookahead. Invalid patterns are a `code_bad_regex`
compile error.

### Null / nil — *(no literal form)*

The engine has no null literal. A field that did not resolve at evaluation
time produces `KindInvalid`, not a `nil`-typed value. This is the
single, well-defined sentinel for "field not present"; users should not need
a separate null spelling.

---

## Identifier grammar

Field references are lowercase, dot-separated identifiers (`DECISION D7`):

```text
core.timestamp
http.uri.path
syslog.severity
my_ns.my_field
```

**Lexical shape:** `[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*` — a single `TIdent`
token when dotted. Reserved words lex as `TKeyword`, not `TIdent`, only
when they appear as bare words:

```text
http.eq          # TIdent "http.eq" — namespace-qualified, never a TKeyword collision
http.uri.path    # TIdent "http.uri.path"
eq               # TKeyword "eq"
contains         # TKeyword "contains"
```

This is why field names MUST be namespace-qualified: a bare `eq` would
shadow the comparison operator. Names without a `.` are NOT field references
in the v1 grammar — the compiler rejects them at `Scheme` lookup time.

### Reserved keyword set (TKeyword)

From `pkg/rule/lexer/token.go`:

```text
and, or, not, in,
eq, ne, lt, le, gt, ge,
contains, starts_with, ends_with, matches, wildcard,
strict
```

The lexer never emits these as `TIdent`. `true`/`false` are `TBool`, NOT
`TKeyword` (they are reserved via a different code path) — see [v1
non-goals](#v1-non-goals--deferred-extensions) for the function-name story
(function names lex as `TIdent` because the closed keyword set does not
include them — see [Functions](#functions)).

---

## Operators

The operator keyword set is CLOSED (DECISION D14). Listed by family, then
individually. Every entry shows: arity, allowed operand Kinds, result Kind,
semantics, and an example.

### Logic family

| Operator    | Arity | Operands                | Result | Semantics                                       |
|-------------|-------|-------------------------|--------|-------------------------------------------------|
| `and`       | 2     | any Bool-typed operands | `Bool` | Conjunction; short-circuit when LHS is false.   |
| `or`        | 2     | any Bool-typed operands | `Bool` | Disjunction; short-circuit when LHS is true.    |
| `not`       | 1     | any Bool-typed operand  | `Bool` | Logical negation. Chains: `not not p` is `p`.   |

Operands of `and`/`or`/`not` are the result of any other expression — field
references, comparisons, string-ops, membership tests, or nested logic. There
is no implicit conversion from non-Bool to Bool; `not 42` is a compile error.

```text
http.uri.path contains "/admin" and http.status eq 403
not http.uri.path contains "/.env" or http.uri.path contains "/wp-admin"
core.level eq "error" and (http.status eq 500 or http.status eq 503)
```

### Comparison family

| Operator    | Arity | Operands                                            | Result | Semantics                                                       |
|-------------|-------|-----------------------------------------------------|--------|-----------------------------------------------------------------|
| `eq`        | 2     | same Kind (or IP-LHS / IP-CIDR-RHS — see below)     | `Bool` | Semantic equality of two Values of the same Kind.               |
| `ne`        | 2     | same Kind (or IP-LHS / IP-CIDR-RHS — see below)     | `Bool` | Logical inverse of `eq`.                                        |
| `lt`        | 2     | same Orderable Kind                                 | `Bool` | Strict less-than.                                               |
| `le`        | 2     | same Orderable Kind                                 | `Bool` | Less-than-or-equal.                                             |
| `gt`        | 2     | same Orderable Kind                                 | `Bool` | Strict greater-than.                                            |
| `ge`        | 2     | same Orderable Kind                                 | `Bool` | Greater-than-or-equal.                                          |

`KindFloat` equality is bitwise (Go's `==` operator on `float64`). NaN is
preserved; two `NaN` floats compare equal under this definition.

`KindTimestamp` arithmetic with `KindDuration` (e.g. `core.timestamp + 1h`)
is NOT supported in v1; the only supported arithmetic-adjacent operation is
cross-Kind-failure as a compile error. Orderable cross-Kind pairs that the
compiler will accept: same-Kind only (D14 — no implicit Int↔Float
conversion, no Timestamp-vs-Duration comparison).

```text
http.status eq 200
http.status ne 404
http.status ge 400
core.timestamp ge ts"2026-06-01T00:00:00Z"
syslog.severity le 3
```

#### Special case: IP / CIDR equality and membership

`KindIP` LHS compared with a CIDR RHS on the right (`ip"10.0.0.0/8"`) is
**membership**, not literal equality:

```text
ip.src eq ip"10.0.0.0/8"     # "is ip.src a member of the 10.0.0.0/8 network?"
ip.src ne ip"172.16.0.0/12"  # "is ip.src NOT in the RFC1918 172.16/12 network?"
```

The compiler detects this at compile time via `isCIDRLit(right)` and switches
from literal `eq`/`ne` to network-membership semantics. The reverse
direction (CIDR `eq` single-IP) is a literal equality.

This special case is the only cross-Kind-on-RHS exception in the comparison
family. `ip"10.0.0.0/8" eq ip.src` is checked literally (CIDR-typed equality
of two CIDRs, including prefix length).

### String family

| Operator        | Arity | Left operand    | Right operand                | Result | Semantics                                                                  |
|-----------------|-------|-----------------|------------------------------|--------|----------------------------------------------------------------------------|
| `contains`      | 2     | `KindString`    | `KindString`                 | `Bool` | Substring test: `L contains R` ⇒ `R` appears in `L`.                       |
| `starts_with`   | 2     | `KindString`    | `KindString`                 | `Bool` | Prefix test.                                                               |
| `ends_with`     | 2     | `KindString`    | `KindString`                 | `Bool` | Suffix test.                                                               |
| `matches`       | 2     | `KindString`/`KindBytes` | `KindString` (compiled to `*regexp.Regexp`) | `Bool` | RE2 regex match. |
| `wildcard`      | 2     | `KindString`    | `KindString` (literal)       | `Bool` | Shell-glob-style match — `?` any single char, `*` any sequence.            |

`matches` accepts `KindString` or `KindBytes` on the left. The right operand
of `matches` and `wildcard` MUST be a string literal — a dynamic pattern is
not allowed (compile-time regex pattern is a security and per-call-cost
hazard).

```text
http.uri.path contains "/.env"
http.uri.path starts_with "/admin"
http.uri.path ends_with ".php"
http.uri.path matches "^/api/v[0-9]+/users/[0-9]+$"
http.uri.path wildcard "/api/*/users"
```

### Membership family

| Operator | Arity | Left operand (Element) | Right operand (Set) | Result | Semantics                                                         |
|----------|-------|------------------------|---------------------|--------|-------------------------------------------------------------------|
| `in`     | 2     | scalar (any Kind)      | array literal       | `Bool` | Element-vs-set membership; set Kinds must match Element Kind.      |

`in` requires an array literal on the right. Mixed-Kind arrays and empty
arrays are compile errors. When Element is `KindIP`, the array may include
CIDR members — the evaluator performs IP-in-CIDR membership for those
slots.

```text
http.status in [200, 301, 404]
core.level in ["error", "critical"]
ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12", ip"192.168.0.0/16"]
syslog.facility in [0, 3, 16]
```

### Bytes family

| Operator | Arity | Left operand | Right operand | Result | Semantics                                                            |
|----------|-------|--------------|---------------|--------|----------------------------------------------------------------------|
| `&`      | 2     | `KindBytes`  | `KindBytes`   | `Bool` | Bitmask test: every bit set in `mask` is also set in `value`.         |

The `&` operator (DECISION D20) answers "are all the bits in `mask`
present in `value`?". Formally, the result is true iff for every byte
position `i`, `(value[i] & mask[i]) == mask[i]`. This is the conventional
"all-bits-set" test used to match a bit pattern within a byte payload
(e.g. matching TCP flag combinations in a captured header, matching a
protocol signature in raw bytes).

**Operand rules.** Both operands must be `KindBytes`. A `KindString` is
NOT acceptable — the bytes and string operator families share no path
(the lex form `0x"..."` is hex-decoded into bytes; the lex form `"..."`
is a Go string). A non-bytes operand is a `type_mismatch` compile error.

**Length rules.** The two operands need not be the same length: the
result is true iff, within the SHORTER length, every bit set in `mask`
is also set in `value`. The remainder of the longer operand is
implicitly required to be zero in `value` (a non-zero byte at any
position outside the shorter mask's reach fails the test, because
`mask[i] == 0` for the implicit "no mask" region, so the test at those
positions is `(value[i] & 0) == 0`, which is true only when
`value[i] == 0`).

**Empty mask.** The right-hand side may be `0x""` (an empty bytes
literal). The empty mask has no bits to test — the result is true iff
the value is also empty (the "implicit zero" region covers the entire
value). This is the natural identity element of the bitmask test.

```text
# A captured TCP header where the SYN+ACK flags are set, and no others.
payload[0:1] & 0x"12" eq 0x"12"

# Any byte with the high bit set in the first byte of the signature.
payload.signature & 0x"80" eq 0x"80"

# Empty mask matches an empty value only.
raw_payload & 0x"" eq 0x""   # true iff raw_payload is empty
```

The `&` operator completes the v0.3.0 bytes operator table from Flow 001
(D5). It is documented as an operator — not a function — because it is
an infix keyword in the lexer (D14) and shares the comparison-tier
precedence level (see [Precedence and associativity](#precedence-and-associativity)).

### `strict` modifier

`strict` is a syntactic marker (DECISION D14) that wraps an operand of a
binary operator or a whole sub-expression. v1 is strict-typed by default
(no implicit coercions), so the modifier is reserved for explicit author
intent at the expression site; the compiler preserves the wrapper in the
Plan for future semantics. Accepted placements:

| Syntactic form                            | Meaning                                                |
|-------------------------------------------|--------------------------------------------------------|
| `a eq strict b`                           | Strict wrapper on the right operand.                   |
| `strict a eq b`                           | Strict wrapper on the left operand (and the Cmp node). |
| `strict <literal>` as right-operand slot  | Hoisted by the parent binary op onto the op node.      |
| `strict (a eq b)`                         | Wraps the whole sub-expression.                        |

Rejected: `strict (a or b)` (no binary-op parent to attach to), bare
`strict <expression>` at the top level when `<expression>` is a logic op
(And/Or/Not). These produce `code_bad_strict_placement` at compile time.

---

## Functions

v0.3.0 ships a closed function table of 19 entries (DECISION D16). The
table is built at package init and never mutated afterwards. A function
name lexes as `TIdent` (not `TKeyword`) because the closed reserved
keyword set does not include function names — this is how the parser
disambiguates `lower(http.host) starts_with "www"` (a function call
followed by the `starts_with` operator) from a hypothetical keyword
collision.

```text
<func_name>(<arg>, <arg>, ...)
  ^^^^^^^^^
  TIdent — the function name. snake_case, lowercase; no dots in a single
  func name (use underscore). Every name below is a literal in the table.
  ^^^^^^^^^^^
  Arguments are positional. Type-checking happens at compile time against
  the registered function signature. Wrong arity → code_bad_func_arity;
  wrong arg Kind → code_bad_func_arg_type. ParamKinds declares
  KindInvalid for "any Kind" parameters (used by the coercion functions
  and by to_string).
```

### Function reference table (v0.3.0 — 19 entries)

One row per registered function. Signature is "paramKinds → returnKind"
where `...` marks a variadic last argument. The "Alloc" column mirrors
`FuncSpec.Allocating` (`alloc-free` = no engine-side allocation beyond
what the operation inherently needs; `allocating` = produces a new
string/slice/builder per call).

| Name                  | Signature                                                  | Returns       | Alloc        | Description / edge-case behaviour |
|-----------------------|------------------------------------------------------------|---------------|--------------|-----------------------------------|
| `lower`               | `(string) → string`                                        | `KindString`  | alloc-free   | `strings.ToLower`; stdlib may copy on mixed-case input. |
| `upper`               | `(string) → string`                                        | `KindString`  | alloc-free   | `strings.ToUpper`; stdlib may copy on mixed-case input. |
| `len`                 | `(string) → int`                                           | `KindInt`     | alloc-free   | Byte length of the input. |
| `to_string`           | `(any) → string`                                           | `KindString`  | alloc-free   | `Value.String()` over the union; `KindInvalid` renders as `"<invalid>"`. |
| `substring`           | `(string, int, int) → string`                              | `KindString`  | allocating   | Bounds-clamped. `start<0`→0; `end>len(s)`→`len(s)`; `start≥end`→`""`. Never panics. |
| `concat`              | `(string...) → string` *(variadic; ≥0 args)*               | `KindString`  | allocating   | Concatenates all args in order. Empty-arg case returns `""`. Pre-sizes the buffer to the sum of arg lengths. |
| `url_decode`          | `(string) → string`                                        | `KindString`  | allocating   | `url.QueryUnescape`; malformed `%xx` → `""` (no error path on Eval signature). |
| `url_encode`          | `(string) → string`                                        | `KindString`  | allocating   | `url.QueryEscape` (RFC 3986 query-string form; `/` is percent-encoded). |
| `html_entity_decode`  | `(string) → string`                                        | `KindString`  | allocating   | `html.UnescapeString`; named and numeric entities; unknown entities pass through. |
| `remove_bytes`        | `(string, string) → string`                                | `KindString`  | allocating   | Drops every byte of `s` that appears in `set`. Byte-level filter (not rune). Empty `set` returns `s` unchanged. |
| `regex_replace`       | `(string, string, string) → string`                        | `KindString`  | allocating   | RE2 replacement. When the pattern is a string literal, the pattern is precompiled at compile time (D4) and reused per eval. Non-literal pattern compiles per call. Bad pattern → input string returned unchanged. |
| `lookup_json_string`  | `(string, string) → string`                                | `KindString`  | allocating   | Parses the first arg as a top-level JSON object; returns the string value at `key`. Misses (invalid JSON, key absent, non-string value) → `""`. Non-string JSON values render via `fmt.Sprint` (e.g. `42` → `"42"`). |
| `ip_to_int`           | `(ip) → int`                                               | `KindInt`     | alloc-free   | IPv4 → 32-bit network-byte-order int (zero-extended to int64). IPv6 → LOW 64 BITS as int64 (bit-interpreted; high bit set yields a negative int64). Nil/empty IP → 0. |
| `cidr_matches`        | `(ip, string) → bool`                                      | `KindBool`    | alloc-free   | `net.IPNet.Contains(ip)`. When the CIDR arg is a string literal, `*net.IPNet` is resolved at compile time (D17) and `Contains` is called directly per eval — zero `ParseCIDR` per call. Non-literal CIDR parses per call. Malformed CIDR or nil IP → `false`. |
| `now`                 | `() → timestamp`                                           | `KindTimestamp` | allocating | Current wall-clock time at eval; intentionally non-deterministic. |
| `unix_time`           | `(timestamp) → int`                                        | `KindInt`     | alloc-free   | `t.Unix()` seconds since 1970-01-01 UTC. |
| `format_time`         | `(timestamp, string) → string`                             | `KindString`  | allocating   | `time.Format` with the supplied layout. Empty layout → `time.RFC3339` (D20 fallback for unparameterised call sites). Bad layouts are caller error; Go returns a deterministic string for any input. |
| `to_int`              | `(any) → int`                                              | `KindInt`     | alloc-free   | Per-Kind coercion (D19): Int→identity; Float→truncate toward zero, NaN/-Inf→`math.MinInt64`, +Inf→`math.MaxInt64`; String→`strconv.ParseInt(s, 10, 64)`, parse failure→0; Bool→1/0; IP→low 64 bits (matches `ip_to_int`); Timestamp→`t.Unix()`; Duration→`int64(d)` ns. Unsupported Kinds (Bytes/Array/Map/KindInvalid) → 0. |
| `to_float`            | `(any) → float`                                            | `KindFloat`   | alloc-free   | Per-Kind coercion (D19): Float→identity; Int→`float64(i)`; String→`strconv.ParseFloat(s, 64)`, parse failure→0; Bool→1.0/0.0; IP→`float64(low 64 bits as uint64)`. Unsupported Kinds (Timestamp/Duration/Bytes/Array/Map/KindInvalid) → 0. |

### Notes on the function table

- **"Alloc-free" contract (D4 / D16).** The alloc-free flag means the
  engine itself adds no per-call bookkeeping allocation beyond what the
  stdlib operation inherently needs (e.g. `strings.ToLower` on a
  mixed-case input). It does NOT mean the function never allocates
  period. Allocating functions (`substring`, `concat`, `url_*`, etc.)
  are benchmarked and labelled.
- **Variadic only `concat`.** Every other function in v0.3.0 is
  fixed-arity. The compiler enforces arity at compile time
  (`code_bad_func_arity`).
- **No public `Register`.** The registry is closed (D16 §5). Adding a
  function in a future flow / version is a new entry in
  `pkg/rule/compiler/functions.go` and a new case in
  `compileFuncCall`'s dispatch — never a runtime `Register` call from
  embedder code.
- **`starts_with` / `ends_with` are NOT in this table** (DECISION D18).
  They are operators (D14) and the lexer keyword-tokenises them before
  the parser can see a function call. The operator form accepts a
  function-call left operand: `lower(http.host) starts_with "www"`
  compiles and evaluates as expected.
- **Cross-links.** D16 (registry design, allocation contract), D17
  (`*net.IPNet` compile-time resolution for `cidr_matches`), D18
  (`starts_with` / `ends_with` as operators, not functions), D19 (the
  per-Kind coercion semantics of `to_int` / `to_float`), D20 (`&`
  bitmask operator and the `format_time` empty-layout fallback).

---

## Field references

Field references use two syntactic forms:

### Dotted form — `<namespace>.<name>(.<sub>)?`

```text
core.timestamp
http.uri.path
syslog.severity
```

The full identifier is a single `TIdent` token (DECISION D14 — the dot is
part of the identifier grammar). The parser stores it verbatim and the
compiler resolves it against the active `Scheme`. Unknown fields are
`code_unknown_field` at compile time.

### Bracket access — `<primary>[<key>]`

```text
attrs["tenant_id"]
labels["env"]
```

The expression on the left must evaluate to a `KindMap` value at runtime;
the key on the right is typically a `KindString` literal but may be any
expression whose evaluation produces a string-suitable result. The parser
builds a `BracketAccess` AST node; the compiler validates that the LHS
field is a `KindMap`-typed field in the Scheme.

**Key validation is runtime, not compile-time** (DECISION D11). A
brackets-access key that does not resolve at evaluation time yields
`KindInvalid` for the whole expression — the rule's continue-with-default
behaviour depends on operator placement (see [Eval-time
semantics](#eval-time-semantics)).

The keys accessible from a Map-typed field are determined by the
`FieldResolver` for that field; the engine imposes no vocabulary on them.

---

## Comments

```text
# This is a comment to end of line.
http.uri.path contains "/admin"  # inline comment also OK
```

Line comments start with `#` and run to the next `\n`. The lexer consumes
them silently and never emits a token (DECISION D14 — no `TComment` token in
the closed enum). Comments are invisible to the parser.

---

## Precedence and associativity

Highest first; same row binds with the listed associativity.

| Level | Operators                                                | Associativity | Notes                                        |
|-------|----------------------------------------------------------|---------------|----------------------------------------------|
| 7     | `not`                                                    | right         | Recursive — `not not p` parses as `not(not(p))`. |
| 6     | eq, ne, lt, le, gt, ge, contains, starts_with, ends_with, matches, wildcard, in | left          | All binary comparison/membership ops share the same level. They are mutually exclusive within one expression — the parser picks the operator that matches the trailing keyword. |
| 5     | `and`                                                    | left          |                                              |
| 4     | `or`                                                     | left          | Lowest.                                      |

Parentheses `( ... )` override precedence at any level.

### Disambiguation within level 6

The parser uses 1-token lookahead to pick the right operator when multiple
binary ops could match. The choices:

- `in` is contextual: the right operand must be `[ ... ]`; if not, `in` is
  not the operator and parsing falls back to a primary. This means
  `x in [a, b]` parses as `In`, while `x in <not-array>` is a parse error.
- The remaining level-6 ops are picked by the literal keyword after the
  primary — `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `contains`,
  `starts_with`, `ends_with`, `matches`, `wildcard`.

### Examples

```text
not a eq b and c eq d           # ((not (a eq b)) and (c eq d)) — not binds tighter than and/or
a and b or c and d              # ((a and b) or (c and d)) — and binds tighter than or
a in [1, 2, 3] and b eq 0       # ((a in [1, 2, 3]) and (b eq 0))
not (a or b)                    # not(a or b) — parentheses override
```

---

## DSL examples

Example-driven reference for each Value Kind and each operator family.
These are runnable expressions — they are the same form a config author would
write.

### Per-Kind literals

```text
# KindString
core.stream eq "production"

# KindInt
http.status eq 200

# KindFloat
custom.score ge 0.95

# KindBool
custom.maintenance_enabled eq true

# KindIP — single
ip.src eq ip"203.0.113.5"

# KindIP — CIDR
ip.src eq ip"10.0.0.0/8"

# KindBytes
payload.signature eq 0x"deadbeef"

# KindTimestamp
core.timestamp ge ts"2026-06-01T00:00:00Z"

# KindDuration
syslog.window le 500ms

# KindArray (right operand of `in`)
http.status in [200, 301, 404]

# KindMap — accessed via [], never literal
attrs["tenant"] eq "acme"
```

### WAF-style rules

```text
# Probe blocking
http.uri.path contains "/.env" or http.uri.path contains "/wp-admin"

# Admin path + bad bot
http.uri.path starts_with "/admin" and not http.user_agent contains "Mozilla"

# Internal-range access to admin endpoints
http.uri.path starts_with "/admin" and ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"]

# HTTP method gate
http.method eq "DELETE" and http.uri.path starts_with "/users/"

# Regex match on user agent
http.user_agent matches "^curl/[0-9]+\\.[0-9]+"

# Wildcard on URI pattern
http.uri.path wildcard "/api/*/users"
```

### Syslog anomaly rules

```text
# Severity-gated triage
syslog.severity le 3 and core.source_type eq "syslog"

# Critical-level only
core.level eq "critical"

# Time-bounded sliding window via timestamps
core.timestamp ge ts"2026-06-29T00:00:00Z" and syslog.severity le 2

# Bytes payload inspection
syslog.message matches "(?i)panic|critical" and syslog.severity eq 0

# Map-typed labels, key not pre-declared in Scheme
syslog.labels["env"] eq "prod"
```

### Envelope + custom fields

```text
# Cross-namespace guard: stream + custom counter
core.stream eq "main" and custom.errors gt 10

# Dynamic-key lookup on a Map field
attrs["retry_count"] ge 3 and core.level eq "error"

# Heavy error burst envelope gate
core.timestamp ge ts"2026-06-29T00:00:00Z" and core.level in ["error", "critical"]
```

### Compound and parenthesised

```text
# Explicit grouping
(http.uri.path contains "/admin" or http.uri.path contains "/api")
  and ip.src in [ip"10.0.0.0/8", ip"172.16.0.0/12"]

# Negation
not (http.status in [400, 401, 403, 404, 500])

# Multi-criterion short-circuit AND
http.uri.path contains "/login" and http.method eq "POST" and http.status ne 200
```

---

## Compile-time errors

Compile errors are returned as `*compiler.CompileError` with `Code`,
`Line`, `Col`, `Message` fields. `Code` is a closed string enum from
`pkg/rule/compiler/compiler.go`:

| Code                      | Trigger                                                                                                                |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| `unknown_field`           | A `FieldRef.Name` does not exist in the active `Scheme`. Cross-namespace typos land here.                              |
| `type_mismatch`           | Operand Kind is incompatible with the operator — e.g. `42 contains "x"`, `"a" eq 42`, ordering on non-Orderable Kind. |
| `bad_regex`               | `matches` against a pattern that does not compile via `regexp.Compile`.                                                |
| `unknown_function`        | A `FuncCall.Name` is not in the v0.3.0 function table (DECISION D16). See [Functions](#functions).                       |
| `bad_func_arity`          | Function called with the wrong number of arguments (D16). The minimum arity is enforced for variadic fns (`concat` requires ≥0 args; anything else with fewer than `len(ParamKinds) - (variadic?1:0)` fails here). |
| `bad_func_arg_type`       | Per-argument Kind mismatch against `FuncSpec.ParamKinds` (D16). `KindInvalid` in ParamKinds means "any Kind" (used by `to_int` / `to_float` / `to_string`). |
| `bad_array_element`       | Array literal contains a non-literal sub-expression that the compiler cannot const-fold (forward-compat hook).         |
| `bad_strict_placement`    | `strict` modifier placed in a context without a binary-op parent — e.g. `strict (a or b)`.                            |
| `bad_bracketaccess`       | Bracket-access operator: object not Map-typed, or key not string-typed.                                                 |
| `invalid_literal`         | Lexer accepted, parser failed on semantic parse — e.g. malformed `ts"..."`, malformed duration, unparseable hex.      |
| `nil_scheme`              | `Compile` / `NewCompiler` called with nil Scheme. Programmer error — surface at startup.                                |

Errors are detected before any rule starts receiving traffic — bad config
does NOT silently compile to a permissive Plan. `Builder.CompileRules` and
`ruleset.RuleSet.Add` both return the compile error to the caller
synchronously so a misconfiguration surfaces at process startup.

---

## Eval-time semantics

A compiled `Plan` is invoked at runtime via `(*Plan).Eval(resolver, event)`
(`pkg/rule/compiler/eval.go`). The contract:

### Missing field

A `FieldResolver` that returns `(rule.Value{}, false)` for a field causes
the corresponding expression position to evaluate to `KindInvalid`. The
subsequent behaviour depends on operator context:

- **Comparison / string-ops:** `KindInvalid` on either operand yields a
  comparison result of `false` (the rule does not match). Rationale: a
  missing field is the absence of positive evidence, so `eq`/`contains`/`in`
  /etc. all evaluate to `false` rather than erroring. This matches what
  rule authors want for the common case: a WAF rule should not crash on an
  event whose Payload has no `http.uri.path`.
- **Logic ops:** `not <KindInvalid>` evaluates to `false` (no positive
  evidence ⇒ negation does not fire). `KindInvalid and <anything>` is
  `false`. `KindInvalid or p` is `p`.
- **`in` array membership:** `KindInvalid in [...]` is `false`. `[]` is
  unreachable because empty arrays are rejected at compile time.

A `FieldResolver` MUST return `(Value{}, false)` on a nil event (D3) — this
is the sentinel for "evaluation cannot proceed for this field".

### Resolver-induced allocation cost

The engine itself is allocation-free on the hot path for scalar-only plans
(DECISION D4). A resolver that allocates per call (e.g. building a `[]byte`
buffer for a hex-encoded Bytes field) undermines the contract — that cost
is the resolver author's responsibility, not the engine's. The
`EnvelopeResolver` for `core.*` is allocation-free for non-IP scalars
(`net.IP` allocation notwithstanding).

### Wildcard regex / pattern compilation

The `wildcard` operator compiles its pattern to a `*regexp.Regexp` lazily
on the first `Eval` call via `sync.Once`, then amortises the cost across
subsequent calls. The first call bears the compile; subsequent calls hit the
cached pattern.

### `matches` regex compilation

The `matches` pattern is compiled at **compile time** (D4 — pre-compiled).
The Plan stores the `*regexp.Regexp` directly. The hot path performs no
regex compilation per `Eval`.

---

## v1 non-goals & deferred extensions

The following are deliberately NOT in v1; each is a DECISION-tracked
non-feature with a sketched extension path. Adding any of them is an
architectural decision, not a code change.

### Signed numeric literals (DECISION D15)

The lexer emits only unsigned `TInt`/`TFloat`; `TMinus`/`TPlus` are not in
the closed enum. `-42` and `-3.14` are not supported. Author-facing
workaround for the rare cases that need a "negative" comparison: invert the
operator — `eq 42` becomes `ne 42`, `lt 0` becomes `gt 0`, etc.

**Extension path:** add `TMinus` to the closed `TokenKind` enum, bump B1's
grammar, add `UnaryOp{Op: Neg}` to the AST node set, handle it in B2's
parser and C1's type checker. Additive; does not break v1 plans.

### Map literal form (DECISION D11)

`KindMap` has no literal form — Map values arise only from `FieldResolver`
at evaluation time. There is intentionally no `{...}` syntax.

**Extension path:** would require (a) a Map-literal AST node, (b) a new
parser production, (c) a `KindMap` literal op node in the compiler, and
(d) re-opening the value-vs-literal kind compatibility rules. The D11
rationale (Map values come from real payload data, not expressions) argues
against ever adding it.

### Rate-limiting / windowed aggregation / stateful detectors (DECISION D10)

No `rate()`, `count_in_window()`, `since_last()`, or any stateful operator.
The engine evaluates a single event against a snapshot of rules; it does
not track traffic across events and does not produce "matches per second"
semantics.

**Extension path:** a separate `pkg/aggregation` (or similar) that sits
**alongside** `pkg/rule`, not inside it — keeping the predicate layer free
of state.

### Action keywords (DECISION D12)

No `pass`/`drop`/`tag`/`enrich`/`alert` keyword. The engine returns a
boolean and (optionally) the matched rule name; the embedding plugin
chooses the action. Cookbook entries describe the action mapping on the
plugin side (e.g. `Cookbook: custom-plugin.yaml` — generic tutorial).

### HTTP-specific fields in `pkg/rule` (DECISION D7)

`http.*` field names do NOT live in `arx-core/pkg/rule` — they belong to
the arxsentinel WAF plugin. The engine imposes no vocabulary beyond the
namespace convention.

### External (non-stdlib) dependencies (DECISION D2)

The only stdlib packages the engine pulls in are `net` (for IP/CIDR
parsing) and `regexp` (for `matches`). No third-party parser, no
third-party regex engine.

### Unary minus AST node (related to DECISION D15)

The grammar exposes `not` (the AST `Not` node) but no `neg` operator. `-x`
against a field reference is not supported. This is a consequence of D15 —
without `TMinus`, the parser has no token to bind a `neg` node to.

### Lossless source round-trip

`AST.Node.String()` produces a stable diagnostic rendering — not a
parseable source form. A formatter that re-emits an AST as `Rule`-language
source is not a v1 goal.

---

## Cross-references

- [`README.md`](./README.md) — concept overview, architecture, embedder
  guide, performance contract.
- [`cookbook/rule-engine/`](../../cookbook/rule-engine/) — runnable recipes:
  WAF-style rules, syslog anomaly, rate-profile combinations, and a
  custom-plugin wiring tutorial.
- [`.opencode/flows/001_2026-06-25_universal-rule-engine/DECISIONS.md`](../../.opencode/flows/001_2026-06-25_universal-rule-engine/DECISIONS.md)
  — the architectural decisions that govern the engine.
- [`.opencode/flows/002_2026-06-29_function-layer-and-hardening/DECISIONS.md`](../../.opencode/flows/002_2026-06-29_function-layer-and-hardening/DECISIONS.md)
  — D16 (function registry), D17 (compile-time `*net.IPNet`),
  D18 (`starts_with` / `ends_with` as operators), D19 (coercion
  semantics for `to_int` / `to_float`), D20 (`&` bitmask operator and
  `format_time` empty-layout fallback).
- [`pkg/rule/types.go`](./types.go) — `Value`/`Kind` constructors.
- [`pkg/rule/scheme.go`](./scheme.go) — `FieldType` re-export, `FieldInfo`,
  `Catalog`, `Scheme`.
- [`pkg/rule/resolver.go`](./resolver.go) — `FieldResolver` interface and
  `EnvelopeResolver` (the `core.*` impl).
- [`pkg/rule/lexer/token.go`](./lexer/token.go) — closed token enum and
  keyword set.
- [`pkg/rule/parser/ast.go`](./parser/ast.go) — every AST node shape.
- [`pkg/rule/parser/parser.go`](./parser/parser.go) — full grammar.
- [`pkg/rule/compiler/compiler.go`](./compiler/compiler.go) — type
  checker, `*Plan`, error codes.
- [`pkg/rule/compiler/eval.go`](./compiler/eval.go) — runtime evaluator.
- [`pkg/plugin/manifest.go`](../plugin/manifest.go) — `FieldType` (canonical
  here, re-exported by `pkg/rule/scheme.go`), `FieldDecl`.
