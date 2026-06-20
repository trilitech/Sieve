# Sieve IAM — Specification

**Status:** Draft for design-lock · **Author:** (rework) · **Date:** 2026-06-19
**Depends on nothing shipped; supersedes `internal/policy` composition semantics.**

---

## 1. Goals, non-goals, and constraints

### Goals

- **Coherent composition.** Adding a policy must never silently reduce access.
  The only thing that reduces access is an explicit deny.
- **One mental model, end to end.** What the operator sees in the editor, how
  policies combine, and what the audit log reports are the *same* model.
- **Granular, attribute-based decisions.** Decisions are a function of subject
  attributes, object attributes, the operation, and the request environment —
  expressible down to a single op on a single object under a specific condition.
- **Powerful, reusable filters.** The *decision* is declarative (Cedar); the
  *obligations* attached to an allow are a first-class, named, reusable **filter
  library** whose entries may be regex/declarative **or scripts** (pre-execution
  guards and post-execution response transforms). Obligations can only ever
  *narrow or transform* — never grant.
- **Explainability.** For any decision, an operator can ask "why?" and get the
  exact policies that determined it, plus a dry-run explorer for hypotheticals.
- **Reuse a policy across accounts without drift, with minimal machinery.** Build
  a complex policy for one Gmail account; reuse it on another by **adding that
  connection to the policy's resource set** — Cedar scopes are set-valued, so one
  policy applies to many connections, single-source. No template/link subsystem;
  the admin UI's "apply to connection(s)" gesture manages the set (§9.1).
- **Faithful, debt-free port.** Adopt a real, formally-specified authorization
  language (Cedar) rather than grow another bespoke evaluator — and keep the
  artifact count minimal (policy + filter library; nothing else).

### Non-goals (v1)

- Per-object resource policies for *every* connector at launch. The schema
  models object hierarchies richly; v1 extractors may emit coarse resources
  (connection / connector / owner level). Cedar's transitive `in` makes
  refinement non-breaking.
- **A template/link subsystem.** Considered and dropped: Cedar's set-valued
  `principal`/`resource` scopes already deliver "one policy, many accounts/roles"
  with single-source editing — a templates table + links table + a slot-linker
  would be strictly more machinery for the same outcome (the owner explicitly does
  not care whether reuse is "the same policy" or "a template instance," so the
  simpler mechanism wins). Presets are just **shipped example policies**, not a
  seeded second artifact. Reuse never reintroduces the binding footgun (§9.4).
- Replacing the LLM-as-policy *evaluator*. There are no production policy scripts
  to migrate; going forward, script logic lives in the **filter library** (guards
  + response filters, §7), not as a whole-policy evaluator type. LLM-as-decision
  is out; Cedar `when`/`unless` + connector-enriched context + script guards
  cover the cases.

### Constraints (invariants)

1. **`connections` table is immutable across this rework.** No migration, no
   schema change, no read path change. Credentials persist exactly.
2. **Fail closed** at every layer (§6, §7.4).
3. **Reversible** via the `iam_enabled` flag and a legacy-table overlap window.

---

## 2. The problem, stated precisely

Today (verified in `internal/policy/composite.go`, `internal/policies`,
`internal/roles`, `internal/api/router.go`):

- A **token** → a **role**. A role holds **bindings** `[{connection_id,
  policy_ids[]}]`. For a request on connection *C*, the engine builds an
  evaluator from `role.PoliciesForConnection(C)`.
- Multiple policies are wrapped in `CompositeEvaluator`, which **AND-composes**:
  it runs each sub-evaluator and **the first `deny` short-circuits**; an
  `approval_required` is sticky; only if *all* return `allow` is the result
  `allow`. Each sub-policy (a `rules` evaluator) is itself **default-deny**.
- Therefore the effective grant is the **intersection** of per-policy
  allow-sets. Attaching a Drive-only policy alongside a working Gmail policy
  makes the Gmail policy's default-deny fire on Drive ops and the Drive policy's
  default-deny fire on Gmail ops — **the intersection is empty**, and a
  previously-working integration goes dark (tezos_ops **P0**).
- `RulesConfig.Scope` exists but **no evaluator consults it** — it is decorative
  (tezos_ops P0.3, confirmed: neither `composite.go` nor `rules.go` routes by
  scope).

The diagnosis: Sieve has a **constraint/filter algebra** (intersection, like a
firewall chain) wearing a **capability UX** (a catalog you multi-select from,
with a namespace-looking `scope` field). The two are incompatible. The clean fix
is to commit to the capability algebra — which is exactly what NIST ABAC / Cedar
provide — and delete the constraint machinery.

Two more field-report items are the same shortfall at adjacent layers:

- **P2** (no curated commit/comment read ops; escape hatch is denied by
  read-only presets): an artifact of policy keying on *op names* with a binary
  read-only preset, rather than on an **action taxonomy** where "read" is a
  group an op belongs to.
- **P1** (one GitHub PAT must be registered once per org because credential
  selection requires exact owner scope): authorization-by-credential-scope
  instead of authorization-by-resource. In the target model the PAT is one
  credential and *owners are resources*, scoped in policy.

---

## 3. Conceptual model (NIST SP 800-162)

We adopt the 800-162 vocabulary verbatim and map each concept to a Sieve
artifact. Using the standard nouns is not ceremony — it makes the audit log, the
editor, and this spec describe one thing.

| 800-162 concept | Definition | Sieve realization |
|---|---|---|
| **Subject** | The entity requesting access | The Sieve **token** (`sieve_tok_…`). Cedar principal `Sieve::Token::"<id>"`. |
| **Object** | The protected resource | A connector **object** (a Gmail message, a GitHub repo, a Slack channel, a connection as a whole). Cedar resource, typed (§5.2). |
| **Operation** | The action on the object | A connector **operation** (`list_emails`, `github_create_pr`). Cedar action `Sieve::Action::"<connector>/<op>"` (§5.3). |
| **Environment** | Contextual conditions | Request **context**: HTTP method, derived attributes (recipient domains, estimated cost), time, source IP (§5.4). Cedar `context`. |
| **Attributes** | Properties of subject/object/environment used by rules | Entity attributes + context fields, referenced in `when`/`unless`. |
| **Policy / Rule** | The decision logic | A **Cedar policy** (`permit`/`forbid`). |

And the 800-162 **functional points**, mapped to existing Sieve components so the
refactor is a *re-layering*, not a rewrite of the request path:

| Point | Role | Sieve component |
|---|---|---|
| **PEP** (Enforcement) | Intercepts the request, calls the PDP, enforces the decision + obligations | `internal/api/router.go`, `internal/mcp/server.go` (the existing surfaces) |
| **PDP** (Decision) | Evaluates policies against the request, returns allow/deny + obligations | **new** `internal/iam` (wraps cedar-go) |
| **PIP** (Information) | Supplies subject/object/environment attributes | **new** entity-store + context builders; existing `tokens`, `roles`, `connections` stores |
| **PAP** (Administration) | Authoring, storage, validation, explain | **new** policy store + admin UI editor + decision explorer |

---

## 4. Why Cedar (and the cedar-go facts that shape the design)

Cedar is AWS's open-source authorization language: formally specified (machine-
checked semantics), production-proven (AWS Verified Permissions, MongoDB Atlas
resource policies), and available as an Apache-2.0 Go library. It *is* NIST ABAC
made concrete: `permit`/`forbid` over `(principal, action, resource)` with
`when`/`unless` attribute conditions and an entity hierarchy. We adopt the Cedar
language as Sieve's stored policy language and vendor cedar-go as the engine.

The following verified facts (cedar-go **v1.8.0**, 2026-06-01; semantics from
docs.cedarpolicy.com) are load-bearing and constrain the design:

### 4.1 Evaluation semantics (we inherit these — we do not implement them)

- **Default deny.** No applicable `permit` ⇒ `Deny`.
- **Forbid overrides permit.** Any satisfied `forbid` ⇒ `Deny`, regardless of
  permits.
- **Allow iff** (≥1 `permit` satisfied) **and** (0 `forbid` satisfied).
  Order-independent (existential over the policy set).
- **Errored policies are skipped** — counted as neither permit nor forbid. (We
  log them; see §6, §12.)

### 4.2 The decision surface

```go
func Authorize(policies PolicyIterator, entities types.EntityGetter, req Request) (Decision, Diagnostic)

type Request    struct { Principal EntityUID; Action EntityUID; Resource EntityUID; Context Record }
type Diagnostic struct { Reasons []DiagnosticReason; Errors []DiagnosticError }
type DiagnosticReason struct { PolicyID PolicyID; Position Position }
```

`Diagnostic.Reasons` lists the **determining policies**. On `Allow`, those are
exactly the satisfied `permit`s (no `forbid` can be satisfied on an allow), which
is what makes annotation-based obligations safe (§7). On `Deny`, they are the
satisfied `forbid`s (used for the deny message). `Diagnostic.Errors` carries
per-policy evaluation errors.

### 4.3 No native obligations → annotations

Cedar's output is *only* Allow/Deny. There is no XACML-style obligation channel.
The idiomatic mechanism is **policy annotations** — `@id("…")` and arbitrary
`@key("value")` pairs that Cedar ignores during evaluation but tools can read.
cedar-go exposes `Policy.Annotations() → map[Ident]String`. Sieve's obligations
(approval, redaction, filters) are encoded as a **registered annotation
vocabulary** and collected off the determining `permit`s (§7).

### 4.4 We do not use Cedar templates (don't need them)

Cedar *templates* (`?principal`/`?resource` slots) exist, but cedar-go does not
implement template **linking**. This is a non-issue: Sieve gets cross-account /
cross-role reuse from **set-valued scopes** (`principal in [..]`, `resource in
[..]`) on an ordinary policy (§9.1) — no slots, no linker, no second artifact.
This removes what would otherwise be the riskiest cedar-go integration (a
slot-substitution linker) from the design entirely.

### 4.5 Data types

cedar-go implements all Cedar types: `String`, `Long` (int64 — **no float**),
`Boolean`, `Set`, `Record`, `EntityUID`, and extensions `ipaddr`, `decimal`,
`datetime`, `duration`. We use `String`, `Set<String>`, `Long`, `Boolean`,
`datetime` (context.now), and `ipaddr` (context.source_ip). Costs/limits use
`Long` or `decimal` (never float).

### 4.6 Schema validation is experimental in Go

Policy *evaluation* is in cedar-go's stable, SemVer'd core. The schema
*validator* lives under `x/exp/` (explicitly **not** under SemVer). Design
consequence (§8, impl §8): the Sieve Cedar schema is generated and authoritative;
runtime validation uses `x/exp` behind a Sieve-owned interface, and the
**authoritative** validation gate runs in CI via the stable Rust `cedar` CLI.

**Pin:** `cedar-go v1.8.0`. Avoid v1.2.0 (retracted) and anything < v1.6.0
(correctness fixes). v1.8.0 changed IPv6 handling — note for `context.source_ip`
tests. Isolate all `x/exp` imports behind one adapter package.

---

## 5. The Sieve Cedar model

### 5.1 Principals

```
Sieve::Token::"<token_id>"        // the subject of every request
Sieve::Role::"<role_id>"          // principal group; tokens are `in` a role
Sieve::RoleGroup::"<group_id>"    // optional super-group; roles are `in` a group
```

- A request's principal is **always** a `Sieve::Token`.
- A token's `parents` = `[Sieve::Role::"<its role>"]`. (Tokens keep referencing
  exactly one role, as today.)
- A role's `parents` = role-groups it belongs to (zero or more). Role-groups give
  cross-role reuse: write `permit(principal in Sieve::RoleGroup::"readers", …)`
  once; add roles to the group to grant it. This replaces "attach the same policy
  to N roles."

Token attributes available to conditions: `principal.name`. (We deliberately
keep subject attributes minimal in v1; richer subject ABAC — e.g. team, owner —
is a forward extension.)

### 5.2 Resources

Every object lives in a **container hierarchy** so a single policy can target one
object, a whole connection, or an entire connector via transitive `in`:

```
Sieve::Connector::"<type>"                 // e.g. "google", "github"      (top)
  ▲ parent
Sieve::Connection::"<connection_id>"       // one credential/account
  ▲ parent
<connector-specific object type>           // e.g. Sieve::Github::Repo
```

Per-connector object types and the **extractor** that derives the resource UID
from `(connection_id, params)`. (Derived from the verified op inventory.)

| Connector (`Type`) | Object entity types | Resource UID template | Extracted from |
|---|---|---|---|
| `google` (gmail) | `Sieve::Google::{Mailbox,Message,Thread,Draft,Label,DriveFile,CalendarEvent,Contact,Spreadsheet,Document}` | `"<conn>/<objId>"`, else `"<conn>"` | `message_id`,`thread_id`,`draft_id`,`label_id`,`file_id`,`event_id`,`resource_name`,`spreadsheet_id`,`document_id` |
| `github` | `Sieve::Github::{Owner,Repo,RawRequest}` | Repo `"<conn>/<owner>/<repo>"` (parent Owner `"<conn>/<owner>"`); RawRequest `"<conn>"` | `owner`,`repo`; escape hatch → `extractOwner(path)` |
| `gitlab` | `Sieve::Gitlab::{Project,RawRequest}` | `"<conn>/<project>"` (project = numeric id or namespaced path) | `project` |
| `slack` | `Sieve::Slack::{Channel,User}` | `"<conn>/<channelId>"`, `"<conn>/<userId>"` | `channel`,`user` |
| `linear` | `Sieve::Linear::{Issue,Team,RawRequest}` | `"<conn>/<id>"` | `id`,`issue_id`,`team_id` |
| `http_proxy` | `Sieve::Httpproxy::{Path}` | `"<conn>/<path>"` (path-level control) | request `path` |
| `anthropic` | *(none)* — resource = the connection | `"<conn>"` | — |
| `mcp_proxy` | `Sieve::Mcp::Tool` | `"<conn>/<toolName>"` | upstream tool name |

Notes:
- **github Owner/Repo** is the P1 fix: one PAT = one connection holding many
  owners; policy scopes by `Sieve::Github::Owner`, not by registering the
  credential per owner.
- **mcp_proxy** has *dynamic* operations, so the **tool is the resource** and the
  action is the single `mcp_proxy/call` (§5.3). Policies target tools:
  `resource in Sieve::Mcp::Tool::"<conn>/run_query"` — no dynamic actions in the
  schema.
- **Each op declares exactly ONE resource entity type** (review M1) — never
  "finest available, sometimes coarser." The type is fixed per op; only the **id**
  varies (the object id when a natural id param is present, the parent/collection
  id when it is absent). That single type is what the op's action lists in
  `appliesTo` and what a policy author relies on. Examples:
  - `github_get_file` → always `Sieve::Github::Repo` (id `<conn>/<owner>/<repo>`).
  - `github_list_repos` → always `Sieve::Github::Owner` (id `<conn>/<owner>`; when
    the owner param is omitted, the connection-default owner). It does **not**
    sometimes emit `Owner` and sometimes `Connection`.
  - A genuinely connection-wide op (e.g. `github_search_code`, which has no
    owner/repo) declares a connection-level type (`Sieve::Github::Account`,
    id `<conn>`) — consistently, every call.

  Consequence: a policy targeting `resource in Sieve::Github::Owner` matches every
  op whose declared type is `Owner` (or a descendant), and never silently misses
  because an op down-graded to a connection resource. Refining an id later
  (collection → object) is non-breaking (transitive `in`); changing an op's
  resource *type* is a schema change, caught by the taxonomy test (impl §9).

Resource attributes available to conditions: `resource.connection_status` (so a
policy can `forbid … when { resource.connection_status == "reauth_required" }`,
folding today's pre-flight reauth check into policy — optional).

### 5.3 Actions

**One Cedar action per connector operation**, id = `"<connectorType>/<opName>"`
(mechanical, collision-free). Actions are organized into **groups** so policies
can target any altitude:

```
Sieve::Action::"read"                       // global read group
Sieve::Action::"write"                      // global write group
Sieve::Action::"<type>/read"                // per-connector, e.g. "github/read"
Sieve::Action::"<type>/write"
Sieve::Action::"google/gmail.read"          // per-subservice (google only)
Sieve::Action::"google/drive.read" … etc.
Sieve::Action::"google/list_emails"         // the leaf op
```

- **Group membership is derived mechanically** from the op's `ReadOnly` flag
  (→ `read`/`write` and `<type>/read`|`<type>/write`) and, for `google`, from the
  op-name prefix (`drive.`,`calendar.`,`sheets.`,`docs.`,`people.`, bare = gmail)
  → the per-subservice group. This is what makes tezos_ops **P0** dissolve: a
  "drive read" policy targets `google/drive.read` and is *silent* on gmail ops.
- **Escape hatches** (`github_request`, `gitlab_request`, `linear_request`,
  `proxy_request`) are **write** actions and additionally carry
  `context.http_method`, so a policy can grant *read-only raw access*:
  `permit(…, action == Sieve::Action::"github/github_request", …) when {
  context.http_method == "GET" };` — the clean answer to **P2** without losing
  per-op control. Adding curated read ops (e.g. `github_list_commits`) is then
  orthogonal: they simply join `read`.
- `mcp_proxy` contributes a single action `Sieve::Action::"mcp_proxy/call"`
  (per §5.2 the tool is the resource). It is placed in the **`write` group only**
  (not `read`): an upstream MCP tool's effects are unknown, so a `read`-only token
  must **not** reach MCP tools by default. Granting MCP access is explicit —
  `action == Sieve::Action::"mcp_proxy/call"` scoped to specific
  `Sieve::Mcp::Tool` resources.
- `search_messages` (slack) keeps its action so policies bind stably even though
  the connector returns `ErrOperationNotEnabled` (unchanged behavior).

The action map (`op → action id + groups`) is **generated** from the connector
registry (impl §3, §8) so it cannot drift from the catalog.

### 5.4 Context (environment)

Common fields shared by all actions (optional; populated by PEP + connector
**enrichers**):

| Field | Type | Source | Used for |
|---|---|---|---|
| `http_method` | `String` | escape-hatch `method` param / proxy method | read-only raw access (P2) |
| `recipient_domains` | `Set<String>` | gmail send/reply enricher (parse `to`/`cc`) | "internal-only send" |
| `estimated_cost` | `Long` | anthropic enricher (`max_cost`/token estimate) | spend caps |
| `now` | `datetime` | PEP clock | time-window comparisons (before/after a timestamp) |
| `source_ip` | `ipaddr` | PEP (request remote addr) | network conditions |
| `param` | per-action record (§ below) | scalar operation params | targeted conditions (e.g. `context.param.state == "open"`) |

**`param` is a per-action typed record, not an open one (review N2).** Cedar
schema records are **closed** — `context.param.<arbitrary>` would fail validation
against a single open type. Because the schema is **generated** from the connector
registry, and `ParamDef` already carries a `Type` (`string`/`int`/`bool`), the
generator emits a **per-action `context` shape**: each action's `appliesTo.context`
declares exactly that op's scalar params, typed (`string→String`, `int→Long`,
`bool→Boolean`; non-scalar params omitted). So `context.param.state` is
schema-valid for `gitlab_list_issues` (which has a `state` param) and a
*validation error* for an op that has no such param — typo protection for free.

Cedar can't express calendar logic (hour-of-day, weekday) on `now` — only
ordering. **Business-hours and similar belong in a `script_guard`** (§7.1), as the
§13.5 example does; `context.now` is for "before/after this instant" only.

### 5.5 Request mapping

A Sieve request `(token T on connection C, operation Op, params P, http)` becomes:

```
Request{
  Principal: Sieve::Token::"T",
  Action:    Sieve::Action::"<connectorType(C)>/Op",
  Resource:  <connector(C).extract(C, P)>,     // §5.2
  Context:   <PEP + enrichers>(P, http),        // §5.4
}
```

plus an **entity store** for this request containing: the token (→ role), the
role (→ role-groups), the resource (→ connection → connector), and the action
group memberships. (Action-group entities and connector/connection container
entities can be precomputed and cached; only the per-request token/resource
leaves are assembled per call.)

---

## 6. Evaluation

```
decision, diag := cedar.Authorize(activePolicySet, entities, request)
```

- `Deny` (default or forbid) → Sieve denies. Deny reason = annotations of the
  determining `forbid`s (`@deny_message`) if any, else "no matching permit".
- `Allow` → Sieve proceeds, then collects obligations from `diag.Reasons` (§7).
- `diag.Errors` non-empty → each errored policy is logged with its id +
  message (audit + metrics). Errors do **not** flip a deny to allow (Cedar skips
  them); a policy that *should* have permitted but errored therefore fails
  closed, which is the correct posture.

There is exactly **one** evaluation per request (matching today's single-pass
design). Post-execution filtering is an *obligation applied to the response*, not
a second decision.

---

## 7. Obligations and the filter library

Cedar decides **allow/deny**. Everything that happens *because* of an allow —
human approval, a pre-execution script guard, response redaction/exclusion, an
arbitrary script transform — is an **obligation**. Obligations are the second
half of the system and the place where Sieve's power and reusability live: the
decision is bespoke per policy, but obligations are **first-class, named,
reusable objects** that policies merely *reference*.

**The one invariant that makes this safe:** an obligation can only ever *narrow*
(deny) or *transform* (filter) — it can **never grant**. Cedar is the sole source
of "allow." Adding an obligation to a policy is therefore always safe: the worst
it can do is block or scrub. This preserves the monotonicity property from §12
even with arbitrary scripts in the loop.

### 7.1 The filter library (first-class, named, reusable, script-capable)

A **filter** is a stored object (the PAP-managed library), not inline policy
text. A policy *references* filters by name; the same filter is reused across
unrelated policies because a transform like "redact card numbers" is genuinely
identical everywhere (this is the reuse that §1 says policies should *not* have).

```
Filter {
  id, name, description
  kind:    "redact" | "exclude_items" | "script_filter" | "script_guard" | "rate_limit"
  phase:   "pre" (guard / rate_limit) | "post" (response transform)   // implied by kind
  order:   int      // post-filter application order (lower first); ties broken by id (M3)
  config:  { patterns: [...] }                                         // redact/exclude
        |  { command, path, timeout_ms }                              // script_*
        |  { limit: int, window_seconds: int, key: "token"|"token+resource"|"token+action" } // rate_limit
}
```

| kind | phase | what it does | can it deny? | can it transform? |
|---|---|---|---|---|
| `redact` | post | regex-mask matches in the response | no | yes |
| `exclude_items` | post | drop list items containing text/regex | no | yes |
| `script_filter` | post | run a script over the response JSON; stdout replaces it | no¹ | yes |
| `script_guard` | pre | run a script over the request before Execute; non-zero/`{"deny":true}` ⇒ deny | **yes** | no |
| `rate_limit` | pre | count calls keyed per `key`; over `limit`/`window_seconds` ⇒ deny | **yes** | no |

¹ A `script_filter` that errors fails closed (the un-transformed result is
withheld) — it can effectively block, but it cannot *grant* or alter the
allow decision.

**`rate_limit`** (review M4) restores the per-op rate limiting the legacy
`builtin` evaluator had. It is a pre-phase obligation backed by the existing
`internal/ratelimit` package; the counter key is `(token[, resource|action])` per
`config.key`. Like every obligation it is monotonic — over-limit denies, it never
grants. Because it is stateful, the **decision explorer (§11) does not consume
quota** (dry-run skips `rate_limit` evaluation and reports "would rate-limit:
<key>" instead).

**Post-filter ordering (review M3):** when several `post` filters apply,
redact-then-reformat ≠ reformat-then-redact, so order is significant. Filters
apply in ascending `order`, ties broken by filter `id` — **deterministic and
operator-controllable**, never "library insertion order." The built-in
`AuthValueScrubFilter` (HTTP proxy) has `order = -∞` (always first). Pre-phase
obligations (`script_guard`, `rate_limit`) are unordered: any deny denies, so
order among them can't change the outcome.

Scripts reuse the existing Python policy-script runtime (`/opt/sieve-py`,
stdin→stdout JSON, the same contract as today's `internal/policy` script
evaluator — see `docs/policy-scripts.md`). The library is the home for *all*
script logic; there is no whole-policy "script evaluator" type any more.

### 7.2 How a policy references obligations (annotations)

Obligations are attached to a `permit` via annotations. Two are intrinsic
(approval, audit label); the rest are **references into the filter library** by
name:

| Annotation | Value | Effect |
|---|---|---|
| `@approval("required")` | literal | Allow-after-approval: PEP submits + blocks (REST) / returns a ticket (MCP) before Execute. |
| `@filters("name1 name2 …")` | space-separated filter names | Apply those library filters (pre-phase guards run before Execute; post-phase transforms run on the response). |
| `@audit_label("<label>")` | label | Sets the audit decision label. |
| `@deny_message("<text>")` | text | (on `forbid`) human-readable deny reason. |

`@filters` takes a *list* (annotation values are strings, so a space-separated
list keeps the map-keyed annotation model while allowing many filters per
policy). Filter names are validated at policy save against the library; a
dangling reference is a save-time error.

### 7.3 Collection semantics

On `Allow`, walk `diag.Reasons` (all satisfied `permit`s — §4.2) and combine:

```go
for _, r := range diag.Reasons {
    anns := activePolicySet.Get(r.PolicyID).Annotations()
    // approval:   any "required"            ⇒ approval required        (logical OR)
    // @filters:   union the named filters    ⇒ resolve against library  (set union)
    // audit_label: collect                   ⇒ joined for the audit row
}
guards  := resolved.filter(phase == pre)    // script_guard, rate_limit
xforms  := resolved.filter(phase == post)   // redact/exclude/script_filter, sorted by (order,id)
```

- **Approval** OR; **filters** union, then **deduped by filter id** (two
  determining permits naming the same filter ⇒ it applies once). Post-transforms
  are sorted by `(order, id)` (§7.1) so application is deterministic and idempotent
  in the filter set.
- Obligations are read **only on Allow**; never on Deny.

### 7.4 Application points

```
Cedar Allow
  → run pre obligations: rate_limit then script_guard; any deny ⇒ DENY   [pre, fail-closed]
  → if @approval: submit + block(REST)/ticket(MCP)                       [pre]
  → conn.Execute(...)
  → apply post transforms sorted by (order,id): redact/exclude/script_filter  [post]
       (AuthValueScrubFilter at order -∞, always first, for the HTTP proxy)
  → return
```

`rate_limit` runs **before** `script_guard` and **before** approval — cheap quota
checks first, so an over-limit request neither spawns a guard process nor pages a
human.

Post-transforms run through the existing `policy.ApplyResponseFilters`
(`RedactPatterns`, `ExcludeContaining`, and `ScriptCommand`/`ScriptPath` — all
already supported by that applier), so the enforcement code is reused; only the
*source* of the filters changes (the library, resolved from annotations, instead
of `decision.Filters`).

### 7.5 Fail-closed

A `script_guard` that errors ⇒ **deny**. Any post-transform that errors ⇒ the
PEP returns an error and the un-transformed result is **never** sent to the agent
(today's behavior in `router.go`/`server.go`). Approval timeout/rejection denies.
A script can therefore fail safe in exactly one direction: toward less access.

### 7.6 Fail-closed authoring rule (Cedar gotchas)

Two Cedar properties make naïve restrictions fail **open**; both are mandatory
authoring rules enforced by the editor's linter (impl §9):

1. **Express restrictions as conditions on a `permit`, never as `forbid … unless`.**
   If a condition errors or is vacuously satisfied, a `permit`-condition yields
   "no grant" (deny), whereas a `forbid`-`unless` yields "not denied" (allow). The
   internal-send example (§13.2) is the canonical case.
2. **Guard every optional `context`/attribute access with `has`.** Accessing an
   absent attribute is an *evaluation error*; an errored `permit` is skipped
   (deny — safe) but an errored `forbid` is also skipped (allow — unsafe). Always
   write `context has x && context.x …`.

Cedar limitation to design around: there is **no set-cardinality / `isEmpty`
operator**. "Non-empty" cannot be tested directly — so enrichers signal "empty"
by **omitting** the attribute (caught by `has`), never by emitting `[]` (which
passes `containsAll` vacuously). Count-based logic belongs in a `script_guard`.

### 7.7 Guard contract and audit attribution

- **Guards must be side-effect-free** (review L2). `script_guard`/`rate_limit` run
  *pre-execution* and may be followed by approval or denial; the request may never
  execute. A guard that mutates external state would do so for requests that are
  then blocked. Guards read the request, return allow/deny; nothing else.
- **Audit distinguishes guard/rate denials** (review L3). A guard runs because a
  `permit` named it via `@filters`, so `determining_policies` would point at that
  *permit* (which allowed) — confusing on a denial. The audit therefore records a
  distinct decision value: `guard_deny` / `rate_limited` (alongside `deny`,
  `approval_*`), with the denying filter's id, so "Cedar denied" vs "an obligation
  denied" is never ambiguous.

---

## 8. The Cedar schema

The schema is **generated** from the connector registry (impl §3) and checked in
(human-readable format shown; JSON equivalent emitted too). Illustrative excerpt:

```cedar
namespace Sieve {
  entity RoleGroup;
  entity Role in [RoleGroup];
  entity Token in [Role] = { "name": String };

  entity Connector;
  entity Connection in [Connector] = { "connection_status": String };

  // resource objects (excerpt)
  entity Google::Message     in [Connection];
  entity Google::DriveFile   in [Connection];
  entity Github::Owner       in [Connection];
  entity Github::Repo        in [Github::Owner];
  entity Mcp::Tool           in [Connection];

  // action groups
  action "read";
  action "write";
  action "google/gmail.read"  in ["read"];
  action "google/drive.read"  in ["read"];

  // leaf op (generated) — PER-ACTION context: the common fields + a `param`
  // record typed from THIS op's ParamDefs (closed + validatable). The generator
  // inlines the full record per action (no reliance on a record-merge operator).
  action "google/list_emails" in ["read", "google/gmail.read"]
    appliesTo { principal: [Token], resource: [Google::Message],
      context: { "http_method"?: String, "recipient_domains"?: Set<String>,
                 "estimated_cost"?: Long, "now"?: datetime, "source_ip"?: ipaddr,
                 "param"?: { "query"?: String, "max_results"?: Long } } };

  action "github/github_request" in ["write", "github/write"]
    appliesTo { principal: [Token], resource: [Github::RawRequest],
      context: { "http_method"?: String, /* …common… */
                 "param"?: { "method"?: String, "path"?: String } } };
}
```

Each action's `param` is a **closed, typed** record generated from its ParamDefs
(not one shared open `Context`), so `context.param.<k>` validates per op. The
generator inlines the common fields into every action (a plain code-gen loop — no
dependence on a Cedar record-merge operator that may not exist). The schema is the
contract between connectors (which emit
actions + resources) and policies (which reference them). The generator guarantees
every op has an action, each action's `appliesTo` lists the **single** resource
type its extractor produces (§5.2, review M1) plus its typed `param` context, and
group membership matches the `ReadOnly` flag — drift becomes a build failure (impl
§9 taxonomy tests).

> **Schema is authoring/CI-only.** `cedar.Authorize` takes no schema (§4.2); at
> runtime, action-group membership and resource ancestry come **entirely from the
> entity store** (impl §5, review C3). The schema validates policies at save/CI;
> it does nothing at decision time.
>
> **Empirically validated (PR-B), authoritative Rust `cedar` 4.11.1.** The
> generated schema validates these properties via `cedar validate`: N2 (per-action
> typed `param`; undeclared `context.param.X` rejected), N4 (broad `action in read`
> + connection resource accepted), and connector-gating (a `google/*` action on a
> `Sieve::Github::*` resource is *rejected* — the Gmail-policy-on-GitHub invariant
> holds at the validator). Go-side `x/exp` policy validation is impractical (its
> `Policy()` wants `x/exp/ast`, which has no parser); policy validation uses the
> Rust CLI (impl §8).

---

## 9. Policy storage and runtime assembly

There are **two** authoring artifacts: the **policy** and the **filter library**
(§7). No templates, no links, no binding table — reuse falls out of Cedar's
set-valued scopes.

### 9.1 The policy (one artifact, set-valued scopes)

A named, enableable Cedar document (one or more `permit`/`forbid` statements with
annotations). The connection set a policy applies to lives in a **`when` clause**
(`resource in [A, B, …]`). That is the reuse mechanism:

```cedar
@id("assistant.gmail_read")
permit(principal in Sieve::Role::"assistant",
       action   in Sieve::Action::"google/gmail.read",
       resource)
when { resource in [ Sieve::Connection::"gmail-A",      // ← reuse: add accounts here
                     Sieve::Connection::"gmail-B" ] };
```

> **Cedar scope constraint (verified, H4 spike).** A *set* after `in` is allowed
> in the scope **only for `action`** (`action in [..]`); `principal` and
> `resource` take a **single** entity in the scope. So a multi-connection set
> goes in a `when` clause, where `resource in [..]` is a valid membership
> expression. The scope's `resource` stays unconstrained (or `resource is
> <Type>`); the action already pins the connector (a `google/*` action only
> matches Google requests). `resource in [..]` never errors (resource is always
> present), and it's a permit-condition, so it's fail-closed (§7.6).

- **Reuse across accounts (your ask):** a policy applies to every connection in
  its `when`-clause set. "Reuse my complex Gmail policy on another account" =
  **add that connection to the set.** One policy, single source — edit the logic
  once, it applies to every listed account. No clone-and-drift, no second artifact.
- **The "apply to connection(s)" affordance (PAP).** The admin UI manages the
  connection set as a **structured list**: "apply this policy to connection X"
  appends `Sieve::Connection::"X"` to the `when`-clause set of every statement (a
  structured edit, not Cedar-text munging). One gesture; whether the operator
  thinks "reuse the policy" or "add an account" is immaterial — same artifact.
- **Connector-safety — a Gmail policy can NOT be applied to a GitHub connection.**
  This is the gate the dropped template `connector_type` used to give; it is now
  enforced two ways:
  1. **Schema validation (authoritative).** A statement's actions and resources
     must be `appliesTo`-compatible: `google/gmail.read` declares its resource type
     as a Google type, so `permit(action in google/gmail.read, resource in
     Sieve::Connection::"<github-conn>")` is a **validation error** (no Google
     resource lives under a GitHub connection). The nonsensical policy is rejected
     at save (cheap connector-coherence check + x/exp + CI Rust validator), not
     left silently inert.
  2. **Connector-aware affordance.** "Apply to connection" only offers connections
     whose connector type is compatible with the policy's actions — a Gmail-action
     policy simply doesn't list GitHub connections as targets.

  The deliberately cross-connector case still works because it uses the **global**
  `read`/`write` groups, whose members legitimately apply across connectors (e.g.
  tezos_ops §13.1: `action in read, resource in [gmail, gitlab, github]` — each
  member action matches its own connector's resources). Only **connector-specific**
  actions are gated to their connector. So: cross-service-read = fine; Gmail-ops on
  GitHub = impossible.
- **Presets** are simply **shipped example policies** per connector type ("Gmail
  read-only"). Applying a preset = clone it (or "apply to connection X", which
  scopes the shipped policy to your connection — and the same connector-safety
  gate applies, so a Gmail preset can't be aimed at GitHub). No preset *system*,
  no seeding of a separate table — they're ordinary policies you instantiate.
- **One-offs / finer scope** (e.g. "…except the Sensitive label") are the same
  artifact — just statements with a narrower `resource` (a specific object) or a
  `forbid`. There is no separate "bespoke vs template" distinction; every policy
  is the same kind of thing.

Storage (`iam_policies`): `id, name, description, cedar_text, enabled,
created_at`. The resource/principal **scope sets** are structured data the editor
round-trips into the Cedar `in [...]` scope (built via the typed cedar-go API /
generated scope text — never arbitrary user text in the scope, so "apply to
connection" can't corrupt the policy).

### 9.2 Filter library (reusable obligations)

Unchanged (§7): named redact/exclude/script obligations referenced by
`@filters("…")`. The reusable *transform* layer. (Filters are the one thing that
*is* identical across unrelated policies, so they stay a named library; policy
*logic* reuses via the scope sets above.)

### 9.3 The active PolicySet (assembly)

At load (and on any policy or filter change), Sieve assembles **one**
`cedar.PolicySet`:

- Each policy contributes its statements directly (they are already concrete
  Cedar — no linker, no materialization step).
- Every statement gets a **stable, unique PolicyID** `"pol:<id>#<idx>"`. This is
  what `diag.Reasons` returns, so the explorer/audit maps a determining policy
  back to its source policy + statement and reads its annotations.
- The set is cached in memory, rebuilt on change. Evaluation never hits storage.
- **Scale via principal partitioning (review H3) — done correctly (review N1).**
  A request for role `R` evaluates only the policies whose principal scope **can be
  satisfied by R**: those scoped to `R`, to a `Sieve::RoleGroup` R belongs to
  (transitive), or with an **unconstrained `principal`**. A naive role-id key would
  drop the latter two → false denies; the partition is computed from each role's
  group-ancestor set and invalidated on membership change.

  **Partitioning is a transparent optimization and may be deferred.** It changes
  no decision (Cedar is order-independent); v1 MAY evaluate the whole set and add
  partitioning only if policy count makes latency matter. Golden/differential
  tests pin partitioned == whole-set. The N1 correctness risk exists *only if* we
  partition; the safe default carries none.

### 9.4 This is not the old binding model

Set-valued resource scopes can look like the old `{connection, policy_ids[]}`
binding, but they are the opposite. The binding model AND-composed the *set of
policies* on a connection (the intersection footgun). Here, listing connections in
one policy's resource scope just makes that **single** policy apply to each — every
policy still joins the global **union** (forbid-overrides-permit, default-deny).
There is no per-connection policy set and no composition semantics; the §1 hard
break (no AND-of-default-deny) stands.

---

## 10. Decision lifecycle (end to end)

```
agent → PEP (api/mcp)
  1. authenticate bearer → token            (unchanged: tokens.Validate)
  2. resolve connection from request        (unchanged: path/alias/tool-name)
  3. build Cedar Request + entity store      (PIP: §5.5)
       principal = Token, action = connector/op,
       resource  = connector.extract(conn, params),
       context   = enrichers(params, http)
  4. decision, diag := PDP.Decide(request)   (iam.Decide → cedar.Authorize)
  5. switch decision:
       Deny  → 403 with reason (forbid @deny_message / "no permit"); audit
       Allow → obligations := collect(diag.Reasons)      (§7.2; @filters resolved vs library)
                 run rate_limit then script_guard; any deny ⇒ 403 (fail-closed)  [pre]
                 if obligations.approval:
                    REST: submit + WaitForResolution(5m) + re-validate token
                    MCP:  submit + return ticket (non-blocking)   (unchanged shapes)
                 result := conn.Execute(ctx, op, params)
                 result  = ApplyResponseFilters(result, obligations.filters, sorted by (order,id))  [post; fail-closed]
                 audit(decision, determining_policies=diag.Reasons, label)
                 return result
```

Reused from today's PEP: steps 1–2, approval, the response-filter applier, and the
429/ticket shapes. **New:** steps 3–4 (build request + Cedar decision), the
obligation *source* (annotations → filter library), and the pre-phase
guard/rate-limit step. The guard/rate-limit step reuses the existing script
runtime + `internal/ratelimit`, so the net new surface is the engine and the
obligation wiring — small and reviewable.

---

## 11. Explainability (the decision explorer)

A first-class PAP capability, impossible in the current model (today an operator
sees only `"Policy denied: default policy"`):

- **Audit** gains `decision` (allow/deny) and `determining_policies` (the
  `diag.Reasons` ids). Every logged decision answers "which policies?".
- **Explorer endpoint** (admin-only, web port 19816): submit a hypothetical
  `(token|role, connection, operation, params)`; Sieve builds the Request and runs
  `Authorize`, returning the `Decision`, the determining policy ids + text, any
  `diag.Errors`, and the obligations that would fire. This is the "why is this
  denied / why is this allowed" tool.

---

## 12. Security properties

- **Default deny** — structural (Cedar), not a configurable `default_action`.
- **Deny is absolute** — a `forbid` cannot be overridden by any number of
  permits. The old "first deny short-circuits but ordering matters" hazard is
  gone.
- **No privilege via composition** — adding policies is monotonic in capability
  except `forbid`. The tezos_ops P0 class is impossible by construction.
- **Fail closed on error** — a policy that errors is skipped (so it can't grant);
  obligation failure blocks the response; approval timeout denies.
- **Schema-validated authoring** — typos in action/resource/attribute names are
  caught at save (x/exp) and in CI (Rust `cedar`), not at 2 a.m. in the audit
  log.
- **Two-port model preserved** — the explorer and editor are PAP (web 19816); the
  PEP stays on 19817. No new agent-callable surface.
- **Credentials untouched** — §1 invariant 1.

---

## 13. Worked examples

Each shows the legacy intent and the target Cedar. (Legacy→Cedar mechanics are in
the migration doc.)

### 13.1 tezos_ops: one token, read-only across Gmail + GitLab + GitHub (fixes P0, P2)

```cedar
@id("tezos_ops.read")
permit(
  principal in Sieve::Role::"tezos_ops",
  action in Sieve::Action::"read",
  resource
) when {
  resource in [ Sieve::Connection::"ops-gmail",
                Sieve::Connection::"ops-gitlab",
                Sieve::Connection::"ops-github" ]
};

// P2: read-only raw access for commit/comment endpoints not yet curated
@id("tezos_ops.github_get")
permit(
  principal in Sieve::Role::"tezos_ops",
  action == Sieve::Action::"github/github_request",
  resource in Sieve::Connection::"ops-github"        // single entity → scope is fine
) when { context has http_method && context.http_method == "GET" };
```

One statement replaces the entire broken multi-attach. Adding a fourth service is
adding a connection to the `when`-clause set — it can only *widen*. (The
single-connection scope on the second statement is valid as-is; only multi-element
sets must move to the `when` clause.)

### 13.2 Gmail assistant: read + draft freely, send only internal, send needs approval

```cedar
@id("asst.read_draft")
permit(
  principal in Sieve::Role::"assistant",
  action in [Sieve::Action::"google/gmail.read", Sieve::Action::"google/gmail.draft"],
  resource in Sieve::Connection::"work-gmail"
);

@id("asst.send_internal")
@approval("required")
permit(
  principal in Sieve::Role::"assistant",
  action == Sieve::Action::"google/send_email",
  resource in Sieve::Connection::"work-gmail"
) when {
  context has recipient_domains &&
  ["trilitech.com"].containsAll(context.recipient_domains)
};
```

The internal-only restriction is a **condition on the `permit`**, not a `forbid …
unless`. This is the **fail-closed authoring rule** (§7.6): if `recipient_domains`
is absent (enricher didn't run) or the recipients aren't all internal, the
condition is false → no permit → default deny. A `forbid … unless
{ containsAll(recipient_domains) }` would fail **open** instead — an absent
attribute errors the forbid (skipped → not denied), and `containsAll([])` is
vacuously true (empty recipient set → not denied). **Enricher contract:** emit
`recipient_domains` only when there is ≥1 recipient (never `[]`), since Cedar has
no set-cardinality operator to test emptiness (§7.6). An all-internal send is then
permitted *and* carries the approval obligation. (`google/gmail.draft` is the
per-subservice action group for `create_draft`/`update_draft`/`send_draft`.)

### 13.3 GitHub: one PAT, many orgs (fixes P1)

```cedar
@id("ci.github_read")
permit(
  principal in Sieve::Role::"ci",
  action in Sieve::Action::"github/read",
  resource
) when {
  resource in [ Sieve::Github::Owner::"ops-github/trilitech",
                Sieve::Github::Owner::"ops-github/tezos" ]
};
```

The credential is one connection (`ops-github`) with one PAT; authorization is by
**owner resource**, so the "register the same token per org" footgun is gone. To
allow every org the PAT can reach, scope the whole connection instead (single
entity, so it can live in the scope): `resource in Sieve::Connection::"ops-github"`.

### 13.4 Read-everything-except (deny-override the old model couldn't express)

```cedar
@id("analyst.read_all_github")
permit(principal in Sieve::Role::"analyst",
       action in Sieve::Action::"github/read",
       resource in Sieve::Connector::"github");

@id("analyst.block_secret")
@deny_message("secret-infra is off-limits")
forbid(principal in Sieve::Role::"analyst",
       action,
       resource in Sieve::Github::Repo::"ops-github/trilitech/secret-infra");
```

Read all GitHub across all connections, except one repo. Expressing this in the
old intersection model was effectively impossible.

### 13.5 Reusable filters: a script-based PII scrub + a pre-execution guard

First, two library filters (PAP objects, defined once, referenced anywhere):

```jsonc
// filter "scrub-pii"   — post-execution script transform
{ "name": "scrub-pii", "kind": "script_filter",
  "config": { "command": "python3", "path": "/opt/sieve-py/filters/scrub_pii.py", "timeout_ms": 5000 } }

// filter "biz-hours"   — pre-execution script guard (denies outside business hours)
{ "name": "biz-hours", "kind": "script_guard",
  "config": { "command": "python3", "path": "/opt/sieve-py/guards/biz_hours.py", "timeout_ms": 2000 } }
```

Then a policy references them by name:

```cedar
@id("support.read_tickets")
@filters("scrub-pii biz-hours")
permit(
  principal in Sieve::Role::"support_bot",
  action in Sieve::Action::"linear/read",
  resource in Sieve::Connection::"support-linear"
);
```

`biz-hours` runs before Execute and can deny; `scrub-pii` runs over the response.
Both are reused verbatim by any other policy that names them — editing
`scrub_pii.py` once updates every policy. Neither can grant access; the `permit`
is the only thing that allows, and the script invariant (§7) guarantees the
guard/filter can only subtract. This is the granular + script-based control from
the design review, with reuse living where it's actually well-defined.

### 13.6 Reuse a complex Gmail policy across accounts (§9.1)

A "complex" policy is several statements — read + draft, internal-only send,
scrub PII. Written once, it applies to **both** accounts because each statement's
connection set lives in a `when` clause (`resource in [..]`):

```cedar
@id("assistant.gmail.read_draft")
permit(principal in Sieve::Role::"assistant",
       action in [Sieve::Action::"google/gmail.read", Sieve::Action::"google/gmail.draft"],
       resource)
  when { resource in [ Sieve::Connection::"work-gmail",          // ← both accounts
                       Sieve::Connection::"ops-gmail" ] };

@id("assistant.gmail.send_internal") @approval("required")
permit(principal in Sieve::Role::"assistant",
       action == Sieve::Action::"google/send_email",
       resource)
  when { resource in [ Sieve::Connection::"work-gmail", Sieve::Connection::"ops-gmail" ]
         && context has recipient_domains                        // fail-closed (§7.6)
         && ["trilitech.com"].containsAll(context.recipient_domains) };

@id("assistant.gmail.scrub") @filters("scrub-pii")
permit(principal in Sieve::Role::"assistant",
       action in Sieve::Action::"google/gmail.read",
       resource)
  when { resource in [ Sieve::Connection::"work-gmail", Sieve::Connection::"ops-gmail" ] };
```

**Reuse on a third account** = add `Sieve::Connection::"third-gmail"` to the
`when`-clause sets — the admin UI's "apply to connection" does this in one gesture
across all statements. One policy, single source: edit the logic once and every
listed account follows. No template, no link, no linker. A **preset** ("Gmail
read-only") is just a shipped one-statement policy you apply to your connection
the same way. (`action in [..]` *is* valid in the scope — only `principal`/
`resource` sets must move to the `when` clause.)

---

## 14. Concept diff: what this kills, what it adds

| Old | New |
|---|---|
| `policy_type` ∈ {rules,builtin,llm,chain,script} + `policy_config` | Cedar text (`permit`/`forbid` + annotations) |
| `CompositeEvaluator` AND-intersection, first-deny-shortcircuit | Cedar union, forbid-overrides-permit, default-deny |
| `RulesConfig.Scope` (decorative) | Real action groups + resource hierarchy |
| Role `bindings [{connection_id, policy_ids[]}]` (AND-composed set) | Policy carries its own set-valued `principal`/`resource` scopes; **no binding table, no AND-composition** (§9.4) |
| "empty policy_ids = DENY ALL" special case | Default deny (no special case) |
| `default_action: allow|deny` per policy | `permit`/`forbid` statements; default is always deny |
| Reuse by multi-attach (the footgun) | **Set-valued scopes** — one policy lists many connections/roles, single-source (§9.1); **filter library** for obligations; role-groups for principals. No templates/links. |
| `script` policy type / `action:script` rules | `script_guard` (pre) + `script_filter` (post) in the filter library |
| `decision.Filters` from the evaluator | Obligations: `@approval` + `@filters("…")` resolved from the library, read off determining `permit`s |
| `"Policy denied: default policy"` | Determining-policy ids in audit + decision explorer |
| Two guards (`connectionAllowed` + empty-policies) | One decision (no permit ⇒ deny) |

Unchanged: tokens (`sieve_tok_…`, role reference), the role *concept* (now a
principal group), connections + credentials, the approval queue, the response-
filter applier, the two-port topology, the connector `Execute` contract.

---

## 15. Open questions / future work

- **Per-object extractors for every connector** (v1 may ship coarse). Non-
  breaking to refine.
- **Richer filter kinds** — e.g. a `transform`/rewrite kind, or WASM filters as a
  sandboxed alternative to process scripts. The library schema (`kind` + `config`)
  is designed to extend without touching the policy language.
- **Templates/links** — explicitly *not* built (§1, §4.4): set-valued scopes cover
  reuse with less machinery. Could revisit only if a future need wants a reusable
  shape that varies by something *other* than connection/role (the only axes
  set-scopes handle).
- **Subject ABAC** (token attributes like team/owner) for attribute-driven, not
  role-driven, grants.
- **Partial evaluation** (`x/exp/batch`) for a fast explorer over many
  hypotheticals. Experimental; not v1.
- **Connector credential selection by resource** (the connector-side half of P1):
  once owners are resources, `pickCredential` can match on the resolved resource
  rather than requiring exact per-owner registration. Separate connector PR.
