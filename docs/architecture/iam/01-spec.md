# Sieve IAM — Specification

**Status:** Implemented (rev 2 — RBAC composition + grant/guardrail obligations) · **Date:** 2026-06-22
**Shipped on `feat/iam-rbac-impl`; the legacy `internal/policy` composition engine is removed (cutover, §1).**

> **Rev 2 (RBAC).** The model is now explicit RBAC on the subject side: a **token
> is assigned a set of roles**, a **role is a reusable bundle of rules**,
> composition is the **union** of a token's roles (deny overrides, §3.1). This
> replaces rev 1's "token → one role + role-groups," which could not express
> "compose an email bundle and an LLM bundle onto one token." See §3.1, §5.1, §9.5,
> §13.1.

---

## 1. Goals, non-goals, and constraints

### Goals

- **Composable, reusable roles (RBAC) — the headline goal.** A **role** is a
  named bundle of rules, authored once, **assigned to many tokens** (reuse); a
  **token** is **assigned many roles** (composition). "Email access" and "LLM
  access" are separate roles; a token that needs both is simply issued both, and
  gets the union of their capabilities. No cramming unrelated permissions into one
  role, no copying rules between roles, no per-token throwaway roles.
- **Coherent composition.** Adding a role (or a rule) must never silently reduce
  access. The only thing that reduces access is an explicit `deny`, which then
  applies everywhere (§3.1 composition law).
- **One mental model, end to end.** What the operator sees in the editor, how
  rules and guardrails combine, and what the audit log reports are the *same* model.
- **Granular, attribute-based decisions.** Decisions are a function of subject
  attributes, object attributes, the operation, and the request environment —
  expressible down to a single op on a single object under a specific condition.
- **Powerful, reusable filters.** The *decision* is declarative (Cedar); the
  *obligations* attached to an allow are a first-class, named, reusable **filter
  library** whose entries may be regex/declarative **or scripts** (pre-execution
  guards and post-execution response transforms). Obligations can only ever
  *narrow or transform* — never grant.
- **Explainability.** For any decision, an operator can ask "why?" and get the
  exact rules that determined it, plus a dry-run explorer for hypotheticals.
- **Reuse without drift, with minimal machinery.** Reuse a **role** across tokens
  by assigning it (§13.1); reuse a **rule's** resource set across connections by
  **adding a connection to its `resource in [..]` set** — Cedar scopes are
  set-valued, so one rule applies to many connections, single-source. No
  template/link subsystem; the admin UI's "apply to connection(s)" gesture manages
  the set (§9.1).
- **Faithful, debt-free port.** Adopt a real, formally-specified authorization
  language (Cedar) rather than grow another bespoke evaluator — and keep the
  concept count minimal: **rule, role, token, guardrail, filter** (§3.1) — nothing
  else.

### Non-goals (v1)

- Per-object resource policies for *every* connector at launch. The schema
  models object hierarchies richly; v1 extractors may emit coarse resources
  (connection / connector / owner level). Cedar's transitive `in` makes
  refinement non-breaking.
- **A template/link subsystem.** Considered and dropped: Cedar's set-valued
  `resource` scopes already deliver "one rule, many connections" (and RBAC delivers
  "one role, many tokens") with single-source editing — a templates table + links table + a slot-linker
  would be strictly more machinery for the same outcome (the owner explicitly does
  not care whether reuse is "the same role" or "a template instance," so the
  simpler mechanism wins). Presets are just **shipped example roles**, not a
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
3. **Legacy cutover is complete (commit `0fb9d68`).** IAM is the **sole**
   authorization engine — no enable/disable toggle, no legacy fallback; the
   `internal/policy` composition evaluator is removed. (During development this was
   gated by an `iam_enabled` flag for reversibility; that flag and the legacy
   evaluator no longer exist. Invariant 1 — `connections` untouched — still holds.)

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

The legacy model's *intent* was, however, partly right and must be **preserved**:
a principal draws on **multiple reusable permission bundles** (a role bound to
several policies; a policy reusable across bindings). That composition + reuse is
exactly what operators need — *only its intersection semantics are broken*. The
target keeps composition and reuse (RBAC: a token assigned a set of roles; a role
a reusable bundle of rules) and makes composition **monotonic** (union, with deny
overriding — §3.1). Losing composability while fixing the algebra (e.g. "one role
per token") would trade one defect for another.

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
| **Rule** | The decision logic | One Cedar statement (`permit`/`forbid`) — see §3.1. |

And the 800-162 **functional points**, mapped to existing Sieve components so the
refactor is a *re-layering*, not a rewrite of the request path:

| Point | Role | Sieve component |
|---|---|---|
| **PEP** (Enforcement) | Intercepts the request, calls the PDP, enforces the decision + obligations | `internal/api/router.go`, `internal/mcp/server.go` (the existing surfaces) |
| **PDP** (Decision) | Evaluates policies against the request, returns allow/deny + obligations | **new** `internal/iam` (wraps cedar-go) |
| **PIP** (Information) | Supplies subject/object/environment attributes | **new** entity-store + context builders; the **new** role/rule + guardrail store; existing `tokens`, `connections` stores |
| **PAP** (Administration) | Authoring, storage, validation, explain | **new** role/rule + guardrail store + admin UI editor + decision explorer |

### 3.1 The concepts, in two layers (and their composition laws)

The system has **two layers** — *grants* (what is allowed) and *guardrails*
(constraints that always apply) — plus a small transform library. We use these
nouns consistently in the editor, storage, audit log, and this spec.

**Grants layer (RBAC):**

| Concept | What it is | RBAC analogue |
|---|---|---|
| **Rule** | One **grant**: `allow` or `deny`, over **operations**, scoped to **connections/objects**, with optional **conditions**, and — on an allow — optional **obligations** (approval / response filters) that apply when the grant is used. Compiles to exactly one Cedar `permit`/`forbid` carrying its obligations as annotations. | A permission (richer: deny, scope, conditions, obligations) |
| **Role** | A **reusable, named bundle of rules** — the rules that target it. Author once, reuse. | A role |
| **Token** | The agent credential, **assigned a *set* of roles**. | A user + its role assignments |

**Guardrails layer (constraints that survive composition):**

| Concept | What it is |
|---|---|
| **Guardrail** | A **global constraint** — the *role-agnostic* variant of an obligation. For any request the grants layer *allows* that matches the guardrail's scope (operations/resources) + condition, it **requires approval and/or applies named filters**, **regardless of which rule granted the request**. A guardrail never grants; it only adds an obligation. Use it for an invariant a grant-author must not be able to omit (a rule's own obligation, by contrast, applies only when *that* rule grants). |
| **Filter** | A named, reusable **transform/guard definition** (redact / exclude / script) that rules and guardrails reference by name. The reuse unit for obligations. |

**Why two layers.** RBAC governs *who gets which bundles* (token↔role, role↔rule —
both many-to-many); Cedar governs *what each rule says* (deny, scope, attribute
conditions). Obligations (approval/filters) may be attached to a **grant** — they
apply when that grant is used — or to a **guardrail** — they apply to *every*
allowed request in scope, no matter which rule granted it. **Both are safe under
composition** because obligations are collected as the **union** of those carried
by every *matching* grant and every matching guardrail: a narrow rule's obligation
still applies whenever that rule matches, so a broader obligation-free rule in
another role cannot strip it (adding a role only ever *adds* obligations — the
monotonicity invariant, §7.0). Reach for a **grant** obligation when it is
intrinsic to that grant ("this read is redacted"); reach for a **guardrail** when
it is a global invariant a grant-author must not be able to omit ("every Gmail
read is redacted, whoever granted it").

**Two composition laws.**

1. **Grants compose by union, deny overrides:** a token's allowed set is

   > (union of every `permit` from every rule of every assigned role) − (any
   > `forbid` from any of them), default-deny.

   Additive grants, global denies. Adding a role can only *widen* capability
   (except a deny it brings); a deny anywhere wins everywhere.

2. **Obligations compose by "any match applies":** for an allowed request, the
   obligations are the union of those carried by **every matching grant** *and*
   **every matching guardrail** — approval required if *any* of them requires it;
   filters = the union of all. Adding a role can only add matching obligations,
   never remove them. Obligations are monotonic *upward* (more roles can add
   constraints, never subtract them).

Capability is monotonic in roles; **constraint is monotonic too** — but in the
other direction (you cannot compose *away* a guardrail). This is the property the
permit-annotation model failed (§7.0).

---

## 4. Cedar — the verified facts we build on

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

`Diagnostic.Reasons` lists the **determining statements**. On `Allow`, those are
exactly the satisfied `permit`s (no `forbid` can be satisfied on an allow); on the
separate guardrail pass (§7.3) these are the matched guardrails whose obligations
Sieve collects. On `Deny`, they are the satisfied `forbid`s (used for the deny
message). `Diagnostic.Errors` carries per-policy evaluation errors.

### 4.3 No native obligations → annotations

Cedar's output is *only* Allow/Deny. There is no XACML-style obligation channel.
The idiomatic mechanism is **policy annotations** — `@id("…")` and arbitrary
`@key("value")` pairs that Cedar ignores during evaluation but tools can read.
cedar-go exposes `Policy.Annotations() → map[Ident]String`. Sieve's obligations
(approval, redaction, filters) are encoded as a **registered annotation
vocabulary** carried by **permit** statements — on grants and on guardrails alike
— and collected off **every matching permit** (`Reasons`), so composition can only
add an obligation, never strip one (§7.0).

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
consequence (§8, impl §8): the Sieve Cedar schema is generated and checked in;
save-time validation uses `x/exp` behind a Sieve-owned interface, and the
**authoritative *schema* validation gate** (action/resource/attribute names, types,
`appliesTo` shapes) runs in CI via the stable Rust `cedar` CLI. Note this gate does
**not** cover connector-safety for connection-scoped rules — that is a separate
PAP-time check in Sieve code (§8, §9.1).

**Pin:** `cedar-go v1.8.0`. Avoid v1.2.0 (retracted) and anything < v1.6.0
(correctness fixes). v1.8.0 changed IPv6 handling — note for `context.source_ip`
tests. Isolate all `x/exp` imports behind one adapter package.

---

## 5. The Sieve Cedar model

### 5.1 Principals — RBAC: a token is assigned a *set* of roles

```
Sieve::Token::"<token_id>"        // the subject of every request
Sieve::Role::"<role_id>"          // a reusable BUNDLE of rules; tokens are `in` their roles
```

This is textbook **RBAC on the subject side**, with Cedar-expressive rules on the
object side (§3.1):

- A request's principal is **always** a `Sieve::Token`.
- **A token's `parents` = the *set* of roles assigned to it** — `Token.parents =
  [Sieve::Role::"A", Sieve::Role::"B", …]`. This is the composition primitive: a
  token issued with `[email-access, llm-access]` is `in` both roles, so every rule
  targeting *either* role applies. The agent's capability is the **union** of its
  roles' permits, with any role's `forbid` overriding (§6). (Contrast the old
  binding model, whose AND-of-default-deny made the union *shrink* — §2, §9.4.)
- **A role is a reusable, named bundle of rules** — the rules that target it via
  `principal in Sieve::Role::"<role>"`. Author it once ("email-access"); **assign
  it to any number of tokens** (reuse) and **compose several roles on one token**
  (composition). A role holds zero or more rules; tokens are assigned zero or more
  roles. Both edges are many-to-many — the RBAC user→role and role→permission
  assignments.
- **No role-groups in v1.** Multi-role tokens subsume the cross-cutting reuse that
  role-groups were introduced for; *role hierarchy* (a base role inherited by
  others) is a forward extension (§15), not a launch concept. One fewer noun.

Token attributes available to conditions: `principal.name`. (Subject ABAC — team,
owner — is a forward extension, §15.)

### 5.2 Resources

Every object lives in a **container hierarchy** so a single rule can target one
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
| `mcp_proxy` | *(v1: none)* — resource = the connection; per-tool `Sieve::Mcp::Tool` is **deferred** (§5.3, §15) | `"<conn>"` | — |

Notes:
- **github Owner/Repo** is the P1 fix: one PAT = one connection holding many
  owners; a rule scopes by `Sieve::Github::Owner`, not by registering the
  credential per owner.
- **mcp_proxy** has *dynamic* operations, so there are no per-tool actions; the
  action is the single `mcp_proxy/call` (§5.3). **v1 scopes at connection grain**
  (`resource in Sieve::Connection::"<conn>"`). Per-**tool** resource scoping
  (`Sieve::Mcp::Tool::"<conn>/run_query"`) is a forward extension (§15): the schema
  reserves the type, but v1 extractors emit the connection, so a token granted
  `mcp_proxy/call` on a connection reaches every tool on it.
- **Each op declares exactly ONE resource entity type** (review M1) — never
  "finest available, sometimes coarser." The type is fixed per op; only the **id**
  varies (the object id when a natural id param is present, the parent/collection
  id when it is absent). That single type is what the op's action lists in
  `appliesTo` and what a rule author relies on. Examples:
  - `github_get_file` → always `Sieve::Github::Repo` (id `<conn>/<owner>/<repo>`).
  - `github_list_repos` → always `Sieve::Github::Owner` (id `<conn>/<owner>`; when
    the owner param is omitted, the connection-default owner). It does **not**
    sometimes emit `Owner` and sometimes `Connection`.
  - A genuinely connection-wide op (e.g. `github_search_code`, which has no
    owner/repo) declares the connection-level type `Sieve::Connection`
    (id `<conn>`) — consistently, every call. There is **no** per-connector
    "Account" type; the connection entity *is* the connection-grain resource (used
    uniformly by `anthropic`, `mcp_proxy`, and connection-wide ops everywhere).

  Consequence: a rule targeting `resource in Sieve::Github::Owner` matches every
  op whose declared type is `Owner` (or a descendant), and never silently misses
  because an op down-graded to a connection resource. Refining an id later
  (collection → object) is non-breaking (transitive `in`); changing an op's
  resource *type* is a schema change, caught by the taxonomy test (impl §9).

Resource attributes available to conditions: `resource.connection_status` (so a
rule can `forbid … when { resource.connection_status == "reauth_required" }`,
folding today's pre-flight reauth check into a rule — optional).

### 5.3 Actions

**One Cedar action per connector operation**, id = `"<connectorType>/<opName>"`
(mechanical, collision-free). Actions are organized into **groups** so rules
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
  "drive read" rule targets `google/drive.read` and is *silent* on gmail ops.
- **Escape hatches** (`github_request`, `gitlab_request`, `linear_request`,
  `proxy_request`) are **write** actions and additionally carry
  `context.http_method`, so a rule can grant *read-only raw access*:
  `permit(…, action == Sieve::Action::"github/github_request", …) when {
  context.http_method == "GET" };` — the clean answer to **P2** without losing
  per-op control. Adding curated read ops (e.g. `github_list_commits`) is then
  orthogonal: they simply join `read`.
- `mcp_proxy` contributes a single action `Sieve::Action::"mcp_proxy/call"`
  (per §5.2, v1 scopes it at connection grain). It is placed in the **`write` group
  only** (not `read`): an upstream MCP tool's effects are unknown, so a `read`-only
  token must **not** reach MCP tools by default. Granting MCP access is explicit —
  `action == Sieve::Action::"mcp_proxy/call"` scoped to a `Sieve::Connection`
  (per-**tool** scoping is deferred, §15).
- `search_messages` (slack) keeps its action so rules bind stably even though
  the connector returns `ErrOperationNotEnabled`; the builder's operation picker
  **marks it not-available** (a connector can flag an op as not-enabled so it isn't
  offered as a freely-grantable leaf op).

The action map (`op → action id + groups`) is **generated** from the connector
registry (impl §3, §8) so it cannot drift from the catalog. **Generation invariant:
every shipped action group is non-empty** (a group with zero member ops is a
generation-time error). This matters for validation: a group-targeted rule
(`action in Sieve::Action::"read"`) over a constrained resource is never flagged as
an *impossible policy* by `cedar validate`, because the group always has at least
one member action whose `appliesTo` the resource can satisfy.

### 5.4 Context (environment)

Common fields shared by all actions (optional; populated by PEP + connector
**enrichers**):

| Field | Type | Source | Used for |
|---|---|---|---|
| `http_method` | `String` | escape-hatch `method` param / proxy method | read-only raw access (P2) |
| `recipient_domains` | `Set<String>` | gmail send/reply enricher (parse `to`/`cc`) | "internal-only send" |
| `estimated_cost` | `decimal` | anthropic enricher (`max_cost`/token estimate) | spend caps (fractional dollars) |
| `now` | `datetime` | PEP clock | time-window comparisons (before/after a timestamp) |
| `source_ip` | `ipaddr` | PEP (request remote addr) | network conditions |
| `param` | per-action record (§ below) | scalar operation params | targeted conditions (e.g. `context.param.state == "open"`) |

**`param` is a per-action typed record, not an open one (review N2).** Cedar
schema records are **closed** — `context.param.<arbitrary>` would fail validation
against a single open type. Because the schema is **generated** from the connector
registry, and `ParamDef` already carries a `Type` (`string`/`int`/`float`/`bool`),
the generator emits a **per-action `context` shape**: each action's
`appliesTo.context` declares exactly that op's scalar params, typed
(`string→String`, `int→Long`, `float→decimal`, `bool→Boolean`; non-scalar params
omitted — Cedar has no float, so a fractional param like `temperature` is a
`decimal`, compared with `.lessThanOrEqual(decimal("0.7"))`). So
`context.param.state` is
schema-valid for `gitlab_list_issues` (which has a `state` param) and a
*validation error* for an op that has no such param — typo protection for free.

Cedar can't express calendar logic (hour-of-day, weekday) on `now` — only
ordering. **Business-hours and similar belong in a `script_guard`** (§7.1), as the
§13.6 example does; `context.now` is for "before/after this instant" only.

**Condition attributes are advertised, not hardcoded (review Compl-S6).** The
structured condition editor (§9.5) is not a fixed menu; each connector declares
which attribute paths a given op exposes and their types, via a named interface:

```go
// what the editor reads to build the (attribute · operator · value) picker
func ConditionAttributes(connType string, op string) []AttrDef
type AttrDef struct {
    Path      string   // "context.param.max_tokens", "context.recipient_domains",
                       //   "resource.connection_status", "context.estimated_cost"
    Type      string   // "String" | "Long" | "decimal" | "Boolean" | "Set<String>" | "datetime" | "ipaddr"
    Operators []string // the type's Cedar operators: ==, <, <=, in, contains, containsAll, like, …
}
```

This is the same source the schema generator uses for the per-action `param`
record, so the editor and the validator never disagree: any attribute the editor
offers is schema-valid for that op, and its operator list is exactly the Cedar
operators its type supports.

**Shipped vs planned (reconciliation).** What ships today is the connector-declared
form, not the fully general `ConditionAttributes` above: each connector advertises a
**curated** `ConnectorMeta.RuleConditions` list (the specific attributes it chooses
to expose — e.g. anthropic `model` and `max_tokens`), and the builder offers exactly
those. Condition **kinds** are `number`, `string`, `domain_allowlist`, and `one_of`
(a scalar constrained to an allowlist — the form anthropic `model` uses). The fully
general, op-param-**derived** editor above (every typed `param` auto-exposed) is the
planned generalization (§15); until then a connector must declare a condition for it
to appear in the builder.

**Decision-time context is request-time only — response/body content is NOT
available.** Cedar `context` is built *before* `Execute` (§5.5), so a `when`/`unless`
condition can see the request (params, recipients, cost estimate, method, ip,
time) but **never the response body**. The legacy `RuleMatch` response-content
predicates (`From`/`To`/`Subject`/`ContentContains`/`Labels` matched against the
*returned* message) therefore cannot be decision conditions. They move to the
**post** phase: an `exclude_items`/`script_filter` that inspects the response, or a
`script_guard` when the decision genuinely needs request-derived content. A
condition that references response data is a save-time error (the attribute is not
in `ConditionAttributes`). The full legacy-`RuleMatch`→new-home mapping is the
capability-parity map (§13.8).

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

plus an **entity store** for this request containing: the token (→ its **set of
roles**), the resource (→ connection → connector), and the action group
memberships. (Action-group entities and connector/connection container entities
can be precomputed and cached; only the per-request token/resource leaves — and
the token's role-set edges — are assembled per call.)

---

## 6. Evaluation

```
decision, gdiag := grantsPDP.Authorize(grantsSet, entities, request)   // pass 1: the decision
```

- `Deny` (default or forbid) → Sieve denies. Deny reason = annotations of the
  determining `forbid`s (`@deny_message`) if any, else "no matching permit".
- `Allow` → Sieve collects obligations as the **union** of the matching grant
  permits (`gdiag.Reasons`, pass 1) and **pass 2** over the *guardrail* set
  (§7.3), then proceeds.
- `gdiag.Errors` non-empty → each errored statement is logged with its id +
  message (audit + metrics). Errors do **not** flip a deny to allow (Cedar skips
  them); a rule that *should* have permitted but errored therefore fails closed,
  which is the correct posture.

There are **two `Authorize` passes** per request: pass 1 over the **grants** set is
the allow/deny decision *and* the source of grant-scoped obligations (off its
`Reasons`); pass 2 over the **guardrails** set (only on allow) adds the
role-agnostic obligations. Pass 2 is obligation *collection*, not a second
decision — it can never turn allow into deny, only add approval/filters (§7.3).
Collecting from every matching permit (not one) is the load-bearing correction in
§7.0.

---

## 7. Guardrails and the filter library

The grants layer (§5–§6) decides **allow/deny**. Everything that happens
*because* of an allow — human approval, a pre-execution script guard, response
redaction/exclusion, a script transform, a rate limit — is an **obligation**.
Obligations may be carried by a **grant** (they apply when that grant is used) or
by a **guardrail** (they apply to every allowed request in scope, role-agnostically).
The engine collects the **union** of both (§7.3).

**The invariant that makes this safe:** an obligation can only ever *narrow*
(deny / require approval) or *transform* (filter) — it can **never grant**; and
obligations are **unioned across every matching permit**, so composition can only
*add* an obligation, never strip one.

### 7.0 Obligation soundness: union across all matching permits

This is the design's load-bearing rule (rev-1 got it wrong). The rev-1 mistake was
reading obligations off *the* determining permit — but a request is allowed if
*any* permit matches, so an obligation-free sibling permit could be the one read,
silently dropping the obligation:

> Role `email` has `@approval permit(send_email)`. Role `ops` (same token) has a
> plain `permit(send_email)`. If the engine reads obligations off a single
> satisfying permit and happens to pick `ops`'s, the approval is lost.

The fix is to collect obligations from **every** matching permit (Cedar's
`Reasons`), not one: `email`'s permit still matches, so its `@approval` is still
collected — `ops`'s plain grant cannot strip it. Union is monotonic — composition
only ever *adds*.

With union, an obligation is safe **on a grant**, and it is **grant-scoped**: it
applies exactly when that grant fires, *its conditions included*. That precision is
the point of grant obligations:

> Role `email`: `@approval permit(send_email) when { recipient internal }`. An
> *external* send doesn't match that permit, so its approval isn't collected —
> correct: the operator scoped approval to internal sends. If a sibling `ops` role
> grants external sends, those go unapproved **by design**.

When you instead want an invariant that holds **regardless of any grant's
conditions or which role granted** — "every external send needs approval, no
matter what" — express it as a **guardrail**: it matches the *allowed request* by
its own scope+condition and is collected in the same union (§7.3). Grant
obligations and guardrails are the *same mechanism* — annotated permits, unioned —
differing only in reach: a guardrail is the role-agnostic one no grant-author can
omit.

### 7.1 The filter library (named, reusable, script-capable transform/guard defs)

A **filter** is a stored definition in the PAP-managed library; **rules and
guardrails** reference filters by name (a transform like "redact card numbers" is
identical everywhere — the genuine reuse unit for obligations).

```
Filter {
  id, name, description
  kind:    "redact" | "exclude_items" | "script_filter" | "script_guard" | "rate_limit"
  phase:   "pre" (guard / rate_limit) | "post" (response transform)   // implied by kind
  order:   int      // post-filter application order (lower first); ties broken by id (M3)
  config:  { patterns: [...], match: "contains"|"regex", fields?: [...] }  // redact/exclude
        |  { command, path, timeout_ms }                              // script_* (command = python3 | node)
        |  { limit, window_seconds, key: "token"|"token+resource"|"token+action"|"token+action_group" } // rate_limit (deferred §15)
}
```

| kind | phase | what it does | can it deny? | can it transform? |
|---|---|---|---|---|
| `redact` | post | mask pattern matches in the response (within content fields) | no | yes |
| `exclude_items` | post | drop list items whose content fields match a pattern | no | yes |
| `script_filter` | post | run a script over the response JSON; stdout replaces it | no¹ | yes |
| `script_guard` | pre | run a script over the request before Execute; `{"action":"deny",…}` ⇒ deny | **yes** | no |
| `rate_limit` | pre | count calls keyed per `key`; over `limit`/`window_seconds` ⇒ deny | **yes** | no |

¹ A `script_filter` that errors fails closed (the un-transformed result is
withheld) — it can effectively block, but it cannot *grant* or alter the
allow decision.

**Field-aware matching (redact / exclude).** A filter is a connector-**agnostic**
transform — `patterns` + a `match` mode: `"contains"` (case-insensitive literal
substring, the default) or `"regex"`. The two are equally powerful — no
exclude-literal/redact-regex asymmetry. Matching applies **only within a connector's
declared content fields** (`ConnectorMeta.ContentFields` — e.g. gmail
`subject`/`body`/`snippet`, never ids, labels, base64 attachment data, or raw
headers), so a 16-digit run inside an attachment or a metadata id is never touched.
The field set comes from the **connector of the rule or guardrail the filter is
attached to** (a filter carries no connector of its own); the default is *all* of
that connector's content fields, optionally narrowed via `config.fields`. A
connector that declares no content fields (e.g. anthropic) filters the whole
response.

**Script command + path allowlist (security boundary).** A `script_*` filter
references its script by **path** (`config.path`) and runs it under an allowlisted
interpreter (`config.command`). Both are validated **at save time and at execution
time**: the command MUST pass `ValidateCommand(CurrentCommandAllowlist())` — default
runtimes **`python3` and `node`** (a guard/filter may be written in Python *or*
JavaScript; identical stdin-JSON→stdout-JSON contract) — and the path MUST pass
`ValidateScriptPath` (absolute, no `..`, symlink-resolved, under an allowlisted
scripts directory, default `/opt/sieve-py`). A non-allowlisted command or an
out-of-tree path is a save-time rejection. Without this boundary a PAP user who can
author a filter could exec an arbitrary host binary or script.

**`rate_limit`** restores the legacy `builtin` per-op-class limiting. To match
legacy buckets ("100 reads/hr AND 10 sends/day"), `key` includes
**`token+action_group`** (aggregates across all ops in a group, e.g. all reads),
not only single actions. **v1 status:** `rate_limit` execution is **deferred**; a
guardrail that references a `rate_limit` filter is rejected at save until the
counter is wired (no silent no-op — see §15). `script_guard`, `redact`,
`exclude_items`, `script_filter` execute in v1.

**Post-filter ordering (M3):** post filters apply in ascending `order`, ties by
`id` — deterministic, operator-controllable. The built-in `AuthValueScrubFilter`
(HTTP proxy) has `order = -∞` (always first). Pre-phase guards are unordered (any
deny denies).

Scripts reuse the existing policy-script runtime (`/opt/sieve-py`, stdin→stdout
JSON; Python *or* JavaScript; `docs/policy-scripts.md`). The library is the home for
*all* script logic; there is no whole-policy "script evaluator" type.

### 7.2 Guardrails (the global obligation layer)

A **guardrail** is a stored overlay: a **scope** (operations + resources, and
optionally a principal/role) + an optional **condition** → an **obligation**
(require approval and/or apply named filters). It is authored like a rule but it
**does not grant**; it binds any *allowed* request that matches.

```
Guardrail {
  id, name, enabled
  scope:      { principal? (role), action(s)/group, resource(s) }   // who/what it covers
  condition:  <Cedar when-expr, optional>                            // e.g. recipients external
  obligation: { approval: bool, filters: [name…] }                  // references the library
}
```

Stored as a Cedar `permit` (the scope+condition) carrying `@approval` /
`@filters` annotations, kept in a **separate policy set** from the grants
(§7.3).

**Invariant — the guardrail set is permit-only.** The two-pass soundness (§7.3)
depends on it: on `Allow`, Cedar returns the satisfied *permits* as the determining
policies, so "which guardrails matched" = `Reasons` *only if* the set has no
`forbid`. Save-time validation therefore **rejects any `forbid` in the guardrail
set, and any annotation other than `@approval`/`@filters`/`@deny_message`** — even
via the raw-Cedar escape hatch (§9.5). A guardrail never denies and never grants;
it only adds an obligation to an already-allowed request.

**Authoring polarity — a guardrail imposes by default and *exempts* by condition**
(the mirror of §7.6, which restricts a grant by condition). Write the *exemption*
as an `unless` clause, `has`-guarded, so a missing/uncertain attribute leaves the
obligation **in force** (fail-safe). Examples:

- *Every send needs approval unless provably all-internal* (a missing
  `recipient_domains` ⇒ not provably internal ⇒ approval still required):
  `@approval("required") permit(principal, action == "google/send_email", resource)
   unless { context has recipient_domains && ["trilitech.com"].containsAll(context.recipient_domains) };`
- *Every Gmail read is PII-scrubbed* (unconditional — the safest guardrail shape):
  `@filters("scrub-pii") permit(principal, action in "google/gmail.read", resource);`
- *Sends by anything in the `finance` role need approval* (role-scoped, still
  composition-safe — it matches on the token's role membership, not on the granting
  rule): `@approval("required") permit(principal in Sieve::Role::"finance",
  action == "google/send_email", resource);`

Because a guardrail matches on the request (principal's role-set, action,
resource, context) and not on which grant fired, no sibling grant can route around
it (§7.0); and because it imposes-unless-exempt, no *absent attribute* can route
around it either (§7.6).

### 7.3 Evaluation — two passes (grants, then guardrails)

```go
// pass 1 — grants: the allow/deny decision AND grant-scoped obligations
dec, gdiag := grantsPDP.Authorize(req)        // grant rules only
if dec != Allow { return Deny(reason from gdiag) }
grantPermits := gdiag.Reasons                  // Reasons ONLY → a condition-erroring permit is fail-closed (skipped)

// pass 2 — guardrails: the role-agnostic obligations
_, hdiag := guardrailsPDP.Authorize(req)       // guardrail set (permit-only, §7.2)
guardPermits := hdiag.Reasons ∪ hdiag.Errors   // ERRORED guardrail fails SAFE → treat as matched

for _, r := range grantPermits ∪ guardPermits {  // union: every matching grant + guardrail permit
    anns := r.set.Get(r.PolicyID).Annotations()
    approval = approval || (anns["approval"] == "required")   // OR
    filters  = filters ∪ split(anns["filters"])               // union
}
filters = dedupeByID(resolve(filters, library))
```

- Obligations are the **union** of two sources: the **matching grant permits**
  (`gdiag.Reasons` from pass 1 — *grant-scoped*, so they apply exactly when the
  grant fires) and the **matching guardrails** (a second `Authorize` over the
  permit-only guardrail set — *role-agnostic*). Because the guardrail set has no
  `forbid` (§7.2 invariant), `hdiag.Reasons` on `Allow` is exactly the matched
  guardrails. Unioning across **all** matching permits (never just one) is what
  makes an obligation impossible to strip by composition (§7.0).
- **Fail-safe selection (the §7.6 polarity, engine half).** An errored guardrail
  condition appears in `hdiag.Errors`, not `hdiag.Reasons`. For a *grant* an errored
  permit is skipped (fail-closed — deny). For a *guardrail* skipping would **drop**
  the obligation (fail-open), so the engine takes `Reasons ∪ Errors`: an errored
  guardrail is treated as **matched** and its obligation **applies**. Combined with
  the `unless`-exemption authoring form (§7.2), neither an absent attribute nor an
  evaluation error can bypass a guardrail.
- **Approval** = OR over matched guardrails; **filters** = union, deduped by id;
  post-filters sorted by `(order, id)`. Obligations are computed **only when pass 1
  allowed**.
- `@approval` + post-`@filters` on the same matched guardrail **both** apply: the
  post-filters run on the response *after* approval resolves (fixes the rev-1
  "approval drops filters" gap — review item; the approval branch must run
  post-filters).

### 7.4 Application points

The obligations collected in pass 2 (§7.3) are applied around `Execute`:

```
Grants Allow → collect guardrail obligations (§7.3)
  → run pre guards: script_guard (rate_limit deferred, §7.1); any deny ⇒ DENY   [pre, fail-closed]
  → if approval required: submit + block(REST)/ticket(MCP)                       [pre]
  → conn.Execute(...)
  → apply post filters sorted by (order,id): redact/exclude/script_filter         [post]
       (AuthValueScrubFilter at order -∞, always first, for the HTTP proxy)
  → return
```

When `rate_limit` ships (§15) it runs **before** `script_guard` and **before**
approval — cheap quota checks first, so an over-limit request neither spawns a
guard process nor pages a human.

Post-filters run through the existing `policy.ApplyResponseFilters`
(`RedactPatterns`, `ExcludeContaining`, and `ScriptCommand`/`ScriptPath` — all
already supported by that applier), so the enforcement code is reused; only the
*source* of the filters changes (the guardrail obligations of §7.3, instead of
`decision.Filters`).

### 7.5 Fail-closed

A `script_guard` that errors ⇒ **deny**. Any post-transform that errors ⇒ the
PEP returns an error and the un-transformed result is **never** sent to the agent
(today's behavior in `router.go`/`server.go`). Approval timeout/rejection denies.
A script can therefore fail safe in exactly one direction: toward less access.

### 7.6 Fail-safe authoring rules (grants and guardrails have OPPOSITE polarity)

Cedar skips any statement whose condition errors, and `containsAll([])` is
vacuously true. Naïvely, both make a restriction fail **open**. The safe direction
is **opposite for the two layers**, and the editor's linter (impl §9) enforces each:

**For grants — restrict by `when`; absence ⇒ no grant (deny):**

1. **Express restrictions as conditions on a `permit`, never as `forbid … unless`.**
   If the condition errors or is vacuously satisfied, a `permit`-condition yields
   "no grant" (deny — safe); a `forbid`-`unless` yields "not denied" (allow —
   unsafe). The internal-send grant (§13.3) is the canonical case.
2. **Guard every optional `context`/attribute access with `has`.** An errored
   `permit` is skipped (deny — safe). Always write `context has x && context.x …`.

**For guardrails — exempt by `unless`; absence ⇒ obligation still applies** (§7.2,
§7.3). The polarity inverts because for a guardrail *matching* is what imposes the
constraint, so "skip on error" would fail **open**:

3. **Express the exemption as `unless`, `has`-guarded, never the imposition as
   `when`.** Write `@approval permit(…) unless { has x && <provably-exempt> }`, not
   `when { <provably-sensitive> }`. An absent attribute then leaves the obligation
   in force. Prefer an **unconditional** guardrail whenever the whole scope should
   be covered (e.g. "scrub every Gmail read").
4. **The engine backs this:** an errored guardrail is treated as **matched**
   (`Reasons ∪ Errors`, §7.3), so even a generator bug or raw-Cedar typo fails
   toward *more* constraint, not less.

Cedar set handling to design around: **`.isEmpty()` exists in the Cedar language
(v4.3.0), but cedar-go v1.8.0 support is unverified — do not rely on it.** This
doesn't matter, because the safe pattern needs no cardinality operator: an enricher
signals "empty" by **omitting** the attribute (caught by `has` → fail-closed),
never by emitting `[]`. The real footgun is `containsAll([])`, which is **vacuously
true** — an emitted empty set would satisfy an all-internal check and fail *open*.
So the enricher contract ("emit only when non-empty"; §13.3) is the guard, not an
operator. Count-based logic still belongs in a `script_guard`.

### 7.7 Guard contract and audit attribution

- **Guards must be side-effect-free** (review L2). `script_guard`/`rate_limit` run
  *pre-execution* and may be followed by approval or denial; the request may never
  execute. A guard that mutates external state would do so for requests that are
  then blocked. Guards read the request, return allow/deny; nothing else.
- **Audit distinguishes guard/rate denials** (review L3). A guard runs because a
  **guardrail** named it via `@filters`, so `determining_rules` would point at the
  *grant rule* that allowed (the guardrail itself only adds the obligation) —
  confusing on a denial. The audit therefore records a distinct decision value:
  `guard_deny` / `rate_limited` (alongside `deny`, `approval_*`), with the denying
  filter's id and the matched guardrail's id, so "grants denied" vs "an obligation
  denied" is never ambiguous.

---

## 8. The Cedar schema

The schema is **generated** from the connector registry (impl §3) and checked in
(human-readable format shown; JSON equivalent emitted too). Illustrative excerpt:

```cedar
// Per-connector object types each live in their OWN namespace: an entity short
// name cannot contain "::", so `Sieve::Github::Repo` MUST be declared inside a
// `namespace Sieve::Github` block. (A flat `entity Github::Repo` is invalid Cedar.)
namespace Sieve::Google {
  entity Message   in [Sieve::Connection];
  entity DriveFile in [Sieve::Connection];
  // … Thread, Draft, Label, CalendarEvent, Contact, Spreadsheet, Document
}
namespace Sieve::Github {
  entity Owner      in [Sieve::Connection];
  entity Repo       in [Sieve::Github::Owner];   // Repo's parent is Owner, Owner's is Connection
  entity RawRequest in [Sieve::Connection];      // escape-hatch resource (github_request)
}
namespace Sieve::Mcp {
  entity Tool in [Sieve::Connection];            // reserved; v1 scopes mcp at the Connection (§5.2)
}

// Sieve core: principals, the connection container, and all actions.
namespace Sieve {
  entity Role;                                    // a reusable bundle of rules
  entity Token in [Role] = { "name": String };    // `in [Role]` permits MANY role parents
                                                  //   → a token composes a SET of roles (§5.1)
  entity Connector;
  entity Connection in [Connector] = { "connection_status": String };

  // action groups
  action "read";
  action "write";
  action "google/gmail.read"  in ["read"];
  action "google/drive.read"  in ["read"];

  // leaf op (generated) — PER-ACTION context: the common fields + a `param`
  // record typed from THIS op's ParamDefs (closed + validatable). The generator
  // inlines the full record per action (no reliance on a record-merge operator).
  action "google/list_emails" in ["read", "google/gmail.read"]
    appliesTo { principal: [Token], resource: [Sieve::Google::Message],
      context: { "http_method"?: String, "recipient_domains"?: Set<String>,
                 "estimated_cost"?: decimal, "now"?: datetime, "source_ip"?: ipaddr,
                 "param"?: { "query"?: String, "max_results"?: Long } } };

  action "github/github_request" in ["write", "github/write"]
    appliesTo { principal: [Token], resource: [Sieve::Github::RawRequest],
      context: { "http_method"?: String, /* …common… */
                 "param"?: { "method"?: String, "path"?: String } } };

  // anthropic has no object types — the resource IS the Connection (§5.2);
  // floats (max spend, temperature) are Cedar `decimal`, never Long (§5.4).
  action "anthropic/messages" in ["write", "anthropic/write"]
    appliesTo { principal: [Token], resource: [Sieve::Connection],
      context: { "estimated_cost"?: decimal, /* …common… */
                 "param"?: { "max_tokens"?: Long, "temperature"?: decimal } } };
}
```

Each action's `param` is a **closed, typed** record generated from its ParamDefs
(not one shared open `Context`), so `context.param.<k>` validates per op. The
generator inlines the common fields into every action (a plain code-gen loop — no
dependence on a Cedar record-merge operator that may not exist). The schema is the
contract between connectors (which emit
actions + resources) and rules + guardrails (which reference them). The generator guarantees
every op has an action, each action's `appliesTo` lists the **single** resource
type its extractor produces (§5.2, review M1) plus its typed `param` context, and
group membership matches the `ReadOnly` flag — drift becomes a build failure (impl
§9 taxonomy tests).

> **Schema is authoring/CI-only.** `cedar.Authorize` takes no schema (§4.2); at
> runtime, action-group membership and resource ancestry come **entirely from the
> entity store** (impl §5, review C3) — the entity store is the decision-time trust
> boundary. The schema validates rules at save/CI; it does **nothing** at decision
> time.
>
> **Empirically validated (PR-B), Rust `cedar` 4.11.1.** The generated schema
> validates these properties via `cedar validate`: N2 (per-action typed `param`;
> undeclared `context.param.X` rejected), N4 (broad `action in read` + connection
> resource accepted). Go-side `x/exp` policy validation is impractical (its
> `Policy()` wants `x/exp/ast`, which has no parser); policy validation uses the
> Rust CLI (impl §8).
>
> **Connector-safety is NOT a validator property (correction).** The validator
> *does* reject a `google/*` action aimed at a github **object** type
> (`resource is Sieve::Github::Repo`) — no Google object lives under a GitHub
> owner. But it **accepts** `permit(action == "google/list_emails", resource in
> Sieve::Connection::"<a-github-connection>")` clean, because a `Connection` can
> have descendants of *every* connector type, so a Google object *could*
> hypothetically live under any connection (verified). Connection-scoped rules are
> the common case, so the validator is **not** the authoritative connector-safety
> gate. Authoritative gates are: (1) a **PAP-time check in Sieve code** —
> `connector(connection)` must be compatible with every action in a rule whose
> resource set names that connection (§9.1); and (2) **runtime entity-store
> correctness** — the store only ever places a connection under its real connector
> and an object under its real connection, so a `google/*` action can never match a
> GitHub connection's resource at decision time regardless of what validated.

---

## 9. Rule/role storage and runtime assembly

The authoring artifacts are the **role** (a named bundle of **rules**), the
**guardrail** set, and the **filter library** (§7); a **token** references roles by
assignment. No templates, no links, no binding table — reuse falls out of RBAC
(roles across tokens) and Cedar's set-valued scopes (connections within a rule).

### 9.1 Rules and roles (set-valued scopes)

A **role** is a named, enableable bundle of **rules**; each rule is one
`permit`/`forbid` statement scoped to that role
(`principal in Sieve::Role::"<role>"`) with optional annotations. The connection
set a rule applies to lives in a **`when` clause** (`resource in [A, B, …]`). That
is the within-rule reuse mechanism:

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

- **Reuse across accounts (your ask):** a rule applies to every connection in its
  `when`-clause set. "Reuse my complex Gmail rule on another account" = **add that
  connection to the set.** One rule, single source — edit the logic once, it
  applies to every listed account. No clone-and-drift, no second artifact. (Reuse
  across *tokens* is the other axis: assign the role, §13.1.)
- **The "apply to connection(s)" affordance (PAP).** The admin UI manages the
  connection set as a **structured list**: "apply this rule to connection X"
  appends `Sieve::Connection::"X"` to the rule's `when`-clause set (a structured
  edit, not Cedar-text munging). One gesture; whether the operator thinks "reuse
  the rule" or "add an account" is immaterial — same rule.
- **Connector-safety — a Gmail rule can NOT be applied to a GitHub connection.**
  This is the gate the dropped template `connector_type` used to give. The
  **authoritative gate is a PAP-time check in Sieve code**, *not* schema validation
  (§8): when a rule's resource set names connection `X`, `connector(X)` must be
  compatible with every action in the rule. `cedar validate` does **not** catch
  `permit(action in google/gmail.read, resource in Sieve::Connection::"<github-conn>")`
  — a `Connection` can host objects of any connector, so the validator accepts it
  (§8). So the rule is rejected at save by:
  1. **PAP connector-coherence check (authoritative).** For each connection in the
     rule's resource set, Sieve verifies its connector type is compatible with the
     rule's actions; a Gmail action on a GitHub connection is a save-time error.
     (Schema validation still catches the narrower case of a Gmail action aimed at a
     GitHub **object** type, but the connection-scoped case — the common one — is
     covered only by this PAP check.)
  2. **Connector-aware affordance.** "Apply to connection" only offers connections
     whose connector type is compatible with the rule's actions — a Gmail-action
     rule simply doesn't list GitHub connections as targets.

  The deliberately cross-connector case still works because it uses the **global**
  `read`/`write` groups, whose members legitimately apply across connectors (e.g.
  tezos_ops §13.2: `action in read, resource in [gmail, gitlab, github]` — each
  member action matches its own connector's resources). Only **connector-specific**
  actions are gated to their connector. So: cross-service-read = fine; Gmail-ops on
  GitHub = impossible.
- **Presets** are simply **shipped example roles** per connector type ("Gmail
  read-only"). You don't clone a preset — you **assign** it to a token and **scope
  it to your connection** via "apply to connection X" (the same connector-safety
  gate applies, so a Gmail preset can't be aimed at GitHub). This matches §9.5's
  "no clone-and-save": reuse is assignment, not copying. No preset *system*, no
  seeding of a separate table — presets are ordinary roles.
- **One-offs / finer scope** (e.g. "…except the Sensitive label") are the same kind
  of rule — just a narrower `resource` (a specific object) or a `forbid`. There is
  no separate "bespoke vs template" distinction; every rule is the same kind of
  thing.

**Storage** (as shipped):
- `iam_roles`: `id, name, description, created_at`.
- `iam_policies`: `id, role_id, name, cedar_text, spec_json, description, enabled,
  created_at` — one row per **rule** (one Cedar `permit`/`forbid` targeting its
  role). `spec_json` is the builder form-state, round-tripped for edit-in-place and
  the plain-English summary (raw-Cedar rules carry none). (The table keeps the
  historical name `iam_policies`; a "rule" *is* a stored policy row.)
- `iam_guardrails`: `id, name, description, cedar_text, spec_json, enabled,
  created_at` — the guardrail overlay set (§7.2), assembled into a **separate**
  policy set from the rules.
- `iam_filters`: the filter library (§9.2).
- **token→role-set assignment** is a `role_ids` JSON column on the existing `tokens`
  table (a legacy single `role_id` is kept consistent for rollback), **not** a
  separate join table — the many-to-many composition primitive (§5.1) stored inline
  on the token.

The resource/principal **scope sets** in each rule are structured data the editor
round-trips into the Cedar `in [...]` scope (built via the typed cedar-go API /
generated scope text — never arbitrary user text in the scope, so "apply to
connection" can't corrupt a rule).

### 9.2 Filter library (reusable obligations)

Unchanged (§7): named redact/exclude/script obligations referenced by **rules and
guardrails** via `@filters("…")`. The reusable *transform* layer. (Filters are the one thing
that *is* identical across unrelated guardrails, so they stay a named library; rule
*logic* reuses via the scope sets above, roles reuse via assignment.) Stored in
`iam_filters (id, name, description, kind, phase, order, config_json)` — the fifth
concept's table, alongside `iam_roles`/`iam_policies`/`iam_guardrails` (§9.1; the
token→role-set is a `role_ids` column on `tokens`, not a join table).

### 9.3 The active policy sets (assembly)

At load (and on any rule, guardrail, or filter change), Sieve assembles **two**
`cedar.PolicySet`s — the **grants** set (every enabled rule) and the **guardrails**
set (every enabled guardrail). Pass 1 evaluates grants; pass 2 evaluates guardrails
(§6, §7.3).

- Each rule / guardrail contributes its statement directly (already concrete Cedar
  — no linker, no materialization step).
- Every statement gets a **stable, unique PolicyID** of the form
  `"<prefix>:<source_id>#<idx>"` — the grants set uses the legacy prefix `pol`
  (`"pol:<rule_id>#<n>"`, kept for audit/explorer back-compat), the guardrails set
  uses `guard` (`"guard:<guardrail_id>#<n>"`); `#<n>` disambiguates multiple
  statements compiled from one source. This is what `gdiag.Reasons` / `hdiag.Reasons`
  return, so the explorer/audit maps a determining statement back to its source rule
  (or guardrail) and reads its annotations.
- Both sets are cached in memory, rebuilt on change. Evaluation never hits storage.
- **Scale via principal partitioning (review H3) — done correctly (review N1).**
  A request from a token assigned roles `{R1,…,Rn}` evaluates only the rules whose
  principal scope **can be satisfied by that token**: those scoped to any of its
  roles, or with an **unconstrained `principal`**. A naive single-role key would
  drop the unconstrained ones (and, pre-RBAC, additional roles) → false denies; the
  partition is the union over the token's role set, invalidated on assignment
  change. (The guardrails set partitions the same way — a role-scoped guardrail
  only applies to tokens in that role.)

  **Partitioning is a transparent optimization and may be deferred.** It changes
  no decision (Cedar is order-independent); v1 MAY evaluate the whole set and add
  partitioning only if rule count makes latency matter. Golden/differential tests
  pin partitioned == whole-set. The N1 correctness risk exists *only if* we
  partition; the safe default carries none.

### 9.4 This is not the old binding model

Set-valued resource scopes can look like the old `{connection, policy_ids[]}`
binding, but they are the opposite. The binding model AND-composed the *set of
policies* on a connection (the intersection footgun). Here, listing connections in
one rule's resource scope just makes that **single** rule apply to each — every
rule still joins the global **union** (forbid-overrides-permit, default-deny).
There is no per-connection rule set and no composition semantics; the §1 hard
break (no AND-of-default-deny) stands.

**Assigning many roles to a token is also not the binding model.** The old
binding *intersected* the policies sharing a connection. RBAC assignment is the
opposite: a token's roles **union** their rules (§3.1 law) — each role's permits
add capability; a deny in any role subtracts globally. Composition can only widen
(modulo deny), never shrink. So both reuse axes — roles across tokens, and
connections within a rule's resource set — are unions with single sources, never
the AND-footgun.

### 9.5 Authoring model (PAP) — what the operator actually does

The editor surfaces the five concepts (§3.1) directly; **no Cedar is required for
the common case**, and the structured editor reaches Cedar's real `when`
expressiveness rather than a hardcoded menu.

- **Role = the authoring unit.** You open a role and see/edit **its list of
  rules** (the bundle). Reuse is *not* "edit a rule to copy it elsewhere" — it is
  assigning the role to another token. (There is no clone-and-save; that was a v0
  mistake and is removed — reuse is assignment, §9.1.)
- **Token = assign a set of roles.** The token create/edit form is a **multi-select
  of roles**. This is the composition gesture (§13.1). Capability = the union
  (§3.1).
- **Rule editor.** A rule is: **effect** (allow / deny) · **operations** (an action
  group — read/write/per-subservice — or specific ops) · **resource scope** ·
  **conditions** · and, on an allow, optional **obligations** ("Response filters &
  guards": require approval and/or apply named library filters). The obligations
  apply whenever this grant is used — *grant-scoped* — and are safe under
  composition (obligations union across matching rules, §7.0).
- **Guardrail editor (the global obligation layer).** Same obligation controls,
  but role-agnostic: a guardrail is **scope** (optional principal/role · operations
  · resources) · an optional **exemption** condition (authored as `unless`, §7.6) →
  **obligation**. Use it for an invariant that must hold regardless of which rule
  granted (the thing a grant-author can't omit). Authored as a global overlay, not
  inside a role (§7.2); the editor enforces permit-only + obligation-only
  annotations and defaults the condition to the fail-safe `unless` form.
- **Filter library editor.** Named, reusable **redact / exclude / script_filter /
  script_guard** definitions (§7.1), referenced by **rules or guardrails** by name.
  redact/exclude take patterns + a match mode and are field-aware (§7.1); a
  `script_*` filter takes a script **path** + interpreter (`python3`/`node`), checked
  against the allowlist at save. (`rate_limit` is specified but **not offered** in the
  UI — deferred, §15.)
- **Full lifecycle — every artifact is editable in place.** Roles, rules,
  guardrails, filters, and a token's role set are all editable from the admin UI
  (not delete-and-recreate); rules, guardrails, and roles are deletable. A token edit
  **never regenerates the secret** — it changes only the role set. **Deleting a role
  cascades:** it strips the role from every token's set, deletes the role's rules and
  any guardrails scoped to it, then removes the role — so access is *truly* revoked
  (a token cannot retain capability through a dangling role id the engine would still
  synthesize as a parent, §5.1).
- **Resource scope = set-valued, structured.** "Apply to connection(s)" edits a
  structured list that becomes the rule's `resource in [..]` set (§9.1); for
  connectors with object types, scope to an owner/repo/channel/etc. The editor only
  offers connector-compatible targets (the connector-safety gate, §9.1).
- **Conditions = (attribute · operator · value), from the connector's declared set.**
  Each connector advertises the attributes it exposes for conditions
  (`ConnectorMeta.RuleConditions`, §5.4) — e.g. anthropic `model` (an `one_of`
  allowlist) and `max_tokens` (a numeric cap) — and the builder offers exactly those,
  with the operators the kind supports (`number`, `string`, `domain_allowlist`,
  `one_of`). The builder compiles these to fail-closed `when` terms (§7.6: conditions
  live on permits). A fully general, op-param-derived condition editor (every typed
  param auto-exposed) is the planned generalization (§5.4, §15).
- **Raw Cedar is the escape hatch, not the only door.** Anything the structured
  editor can't express (novel attribute logic, intricate `unless`) is authorable as
  raw Cedar in the same role. Round-tripped into the structured view where it maps
  cleanly; shown read-only as Cedar where it doesn't.
- **Everything is validated at save** — schema (action/resource/attribute names,
  connector-coherence) + parse — so a malformed or nonsensical rule is rejected
  with a specific message, never stored inert or surfaced as a raw engine error.

---

## 10. Decision lifecycle (end to end)

```
agent → PEP (api/mcp)
  1. authenticate bearer → token            (unchanged: tokens.Validate)
  2. resolve connection from request        (unchanged: path/alias/tool-name)
  3. build Cedar Request + entity store      (PIP: §5.5)
       principal = Token, with Token.parents = the token's role SET (RBAC, §5.1)
       action    = connector/op,
       resource  = connector.extract(conn, params),
       context   = enrichers(params, http)
       // No separate connection allow-list pre-check: a token may reach a
       // connection iff some rule of one of its roles permits it. The gate is
       // the rules, not a binding (this replaces legacy connectionAllowed).
  4. decision, gdiag := PDP.DecideGrants(request)   (grants set → cedar.Authorize)
  5. switch decision:
       Deny  → 403 with reason (forbid @deny_message / "no permit"); audit
       Allow → obligations := collectGuardrails(request)  (§7.3: 2nd Authorize over the
                 guardrail set; union obligations from every matched guardrail)
                 run rate_limit (deferred, §15) then script_guard; any deny ⇒ 403  [pre, fail-closed]
                 if obligations.approval:
                    REST: submit + WaitForResolution(5m) + re-validate token
                    MCP:  submit + return ticket (non-blocking)   (unchanged shapes)
                 result := conn.Execute(ctx, op, params)
                 result  = ApplyResponseFilters(result, obligations.filters, sorted by (order,id))  [post; fail-closed]
                 audit(decision, determining_rules=gdiag.Reasons, guardrails=hdiag.Reasons, label)
                 return result
```

Reused from today's PEP: steps 1–2, approval, the response-filter applier, and the
429/ticket shapes. **New:** steps 3–4 (build request + two-pass Cedar decision),
the obligation *source* (the guardrail pass → filter library, §7.3), and the
pre-phase script-guard step. That step reuses the existing script runtime (and
`internal/ratelimit` once `rate_limit` ships, §15), so the net new surface is the
engine and the obligation wiring — small and reviewable.

---

## 11. Explainability (the decision explorer)

A first-class PAP capability, impossible in the current model (today an operator
sees only `"Policy denied: default policy"`):

- **Audit** gains `decision` (allow / deny / guard_deny / …) and
  `determining_rules` (the `gdiag.Reasons` rule ids) plus the matched `guardrails`.
  Every logged **allow** answers "which rules, which guardrails?".
- **Deny explainability is asymmetric — be honest about it.** On an *allow*,
  `gdiag.Reasons` names the satisfied rules. On a **default deny there are NO
  determining rules** — `gdiag.Reasons` is *empty* (nothing matched), so "which rule
  denied you?" has no answer; only an explicit `forbid` deny names a rule (its
  `@deny_message`). For the empty-deny case the explorer offers **near-miss
  diagnostics** instead: rules that matched the action but not the resource (or vice
  versa), and rules whose `when` errored (`gdiag.Errors`) — "you were one condition
  away," rather than inventing a determining rule that does not exist.
- **Explorer endpoint** (admin-only, web port 19816): submit a hypothetical
  `(token|role, connection, operation, params)`; Sieve builds the Request, runs both
  passes (§7.3), and returns the `Decision`, the determining rule ids + text (or the
  near-miss set on a default deny), any `Errors`, and the obligations that would
  fire. This is the "why is this denied / why is this allowed" tool.

---

## 12. Security properties

- **Default deny** — structural (Cedar), not a configurable `default_action`.
- **Deny is absolute** — a `forbid` cannot be overridden by any number of
  permits. The old "first deny short-circuits but ordering matters" hazard is
  gone.
- **Composition is monotonic in both directions** — adding a role only *widens*
  capability (except a `forbid` it brings, which denies globally), **and** it can
  only *add* guardrail matches, never remove them: you **cannot compose away a
  guardrail** (§3.1 law 2, §7.0). So the tezos_ops P0 (silent shrink) is impossible
  by construction, and so is the rev-1 obligation-bypass (composing a sibling grant
  to strip an approval — §7.0).
- **Fail safe on error, at every stage** — (a) *grant selection:* an errored grant
  rule is skipped, so it can't grant (deny — §7.6); (b) *obligation selection:* an
  errored guardrail is treated as **matched**, so it can't drop its obligation
  (`Reasons ∪ Errors` — §7.3); (c) *obligation execution:* a failing guard/filter
  blocks the response; (d) approval timeout denies. Each stage fails toward *less*
  access / *more* constraint.
- **Schema-validated authoring** — typos in action/resource/attribute names are
  caught at save (x/exp) and in CI (Rust `cedar`), not at 2 a.m. in the audit log.
  (Connector-safety is a separate PAP-time check, not a validator property — §8,
  §9.1.)
- **Container scopes reach future connections (F3 — a real behavioral change).**
  With the legacy `connectionAllowed` pre-check gone (§10), the gate is purely the
  rules: a rule scoped to a **connector** (`resource in Sieve::Connector::"github"`)
  or with an unconstrained resource grants **every current *and future*** connection
  of that connector — adding a connection later silently *widens* every token whose
  roles carry such a rule. That is intended for "all my GitHub orgs," but it is
  least-privilege only when you mean it. Guidance: prefer **connection-scoped**
  resource sets (`resource in [Sieve::Connection::…]`); the decision explorer
  surfaces a rule's **per-connection reach** so the blast radius is visible before a
  new connection joins.
- **Two-port model preserved** — the explorer and editor are PAP (web 19816); the
  PEP stays on 19817. No new agent-callable surface.
- **Credentials untouched** — §1 invariant 1.

---

## 13. Worked examples

Each shows the legacy intent and the target Cedar. (Legacy→Cedar mechanics are in
the migration doc.)

### 13.1 Composition (the headline): one token = two reusable roles

Build **role `email-access`** once — read, draft, and send (the send-approval is a
*guardrail*, below, not part of the grant):

```cedar
@id("email-access.read_draft")
permit(principal in Sieve::Role::"email-access",
       action in [Sieve::Action::"google/gmail.read", Sieve::Action::"google/gmail.draft"],
       resource in Sieve::Connection::"work-gmail");

@id("email-access.send")                        // the GRANT — just allows the send
permit(principal in Sieve::Role::"email-access",
       action == Sieve::Action::"google/send_email",
       resource in Sieve::Connection::"work-gmail");
```

The "sends need approval" requirement is expressed here as a **guardrail** in the
separate guardrail set (§7.2) so it binds **every** allowed send regardless of which
role granted it — the role-agnostic, can't-be-omitted form. (It could instead be a
`@approval` annotation on the send grant when you want it scoped to *that* grant;
both are composition-safe — a sibling plain-send grant can't route around either,
because obligations union across every matching permit, §7.0.):

```cedar
// guardrail set (global overlay)
@id("guard.gmail_send_approval") @approval("required")
permit(principal, action == Sieve::Action::"google/send_email", resource);
```

Build **role `llm-access`** once — call the model, cap the spend:

```cedar
@id("llm-access.complete")
permit(principal in Sieve::Role::"llm-access",
       action in Sieve::Action::"anthropic/write",
       resource in Sieve::Connection::"claude")
  when { context has param && context.param has max_tokens
         && context.param.max_tokens <= 4096 };
```

Now issue a token **assigned both roles** — nothing is rewritten or copied:

```
token "agent-x":  roles = [ email-access, llm-access ]
// entity store: Sieve::Token::"agent-x".parents
//                 = [ Sieve::Role::"email-access", Sieve::Role::"llm-access" ]
```

The agent can now do email **and** LLM work — the union of both roles (§3.1 law).
**Reuse:** assign `email-access` to another token too — one source of truth, edit
it once. **Recompose:** a read-only agent is the token `[ email-access ]`; an
LLM-only batch job is `[ llm-access ]`. No throwaway per-token role, no rule
duplicated across roles. This is the composition the old binding model and the
"one role per token" v0 could not express.

### 13.2 tezos_ops: one token, read-only across Gmail + GitLab + GitHub (fixes P0, P2)

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
sets must move to the `when` clause.) The broad `action in read` validates even
though `read` spans connectors: the resource is bounded to three named connections
in the `when` clause and the group is non-empty (§5.3), so `cedar validate` accepts
it — not an "impossible policy" (N4, §8).

### 13.3 Gmail assistant: read + draft freely, send only internal, send needs approval

```cedar
@id("asst.read_draft")
permit(
  principal in Sieve::Role::"assistant",
  action in [Sieve::Action::"google/gmail.read", Sieve::Action::"google/gmail.draft"],
  resource in Sieve::Connection::"work-gmail"
);

// GRANT: send allowed ONLY to internal recipients — the internal-only test
// RESTRICTS what is granted, so it is a condition on the grant (not a guardrail)
@id("asst.send_internal")
permit(
  principal in Sieve::Role::"assistant",
  action == Sieve::Action::"google/send_email",
  resource in Sieve::Connection::"work-gmail"
) when {
  context has recipient_domains &&
  ["trilitech.com"].containsAll(context.recipient_domains)
};
```

```cedar
// GUARDRAIL set: any allowed send needs approval, regardless of the granting role (§7.0)
@id("guard.send_approval") @approval("required")
permit(principal, action == Sieve::Action::"google/send_email", resource);
```

**Grant condition vs. obligation — the load-bearing distinction.** The internal-only
test *narrows the grant* (it changes allow→deny), so it is a **condition on the
`permit`**. The approval *adds an obligation to an already-allowed send*; it is
authored as a **guardrail** here because the invariant is global — every send needs
approval, whoever granted it. (It could equally ride on the grant rule when you want
it scoped to *that* grant; both are composition-safe — obligations union across every
matching permit, §7.0. The guardrail form is the right choice when no grant-author
should be able to omit it.)

The internal-only condition follows the **fail-closed authoring rule** (§7.6): a
condition on a `permit`, never a `forbid … unless`. If `recipient_domains` is absent
(enricher didn't run) or the recipients aren't all internal, the condition is false
→ no permit → default deny. A `forbid … unless { containsAll(recipient_domains) }`
would fail **open** instead — an absent attribute errors the forbid (skipped → not
denied), and `containsAll([])` is vacuously true (empty recipient set → not denied).
**Enricher contract:** emit `recipient_domains` only when there is ≥1 recipient
(never `[]`), so the all-internal test can't pass vacuously through `containsAll([])`
(§7.6 — don't lean on `.isEmpty()`). An all-internal send is then permitted *and*,
via the guardrail, requires approval. (`google/gmail.draft` is the per-subservice
action group for `create_draft`/`update_draft`/`send_draft`.)

### 13.4 GitHub: one PAT, many orgs (fixes P1)

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

### 13.5 Read-everything-except (deny-override the old model couldn't express)

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

### 13.6 Reusable filters: a script-based PII scrub + a pre-execution guard

First, two library filters (PAP objects, defined once, referenced anywhere):

```jsonc
// filter "scrub-pii"   — post-execution script transform
// command MUST be allowlist-resolved absolute path (§7.1): /opt/sieve-py/bin/python3
{ "name": "scrub-pii", "kind": "script_filter",
  "config": { "command": "/opt/sieve-py/bin/python3", "path": "/opt/sieve-py/filters/scrub_pii.py", "timeout_ms": 5000 } }

// filter "biz-hours"   — pre-execution script guard (denies outside business hours)
{ "name": "biz-hours", "kind": "script_guard",
  "config": { "command": "/opt/sieve-py/bin/python3", "path": "/opt/sieve-py/guards/biz_hours.py", "timeout_ms": 2000 } }
```

Then a **rule** grants the access and a **guardrail** attaches the filters (here a
guardrail, so the scrub binds support_bot's Linear reads regardless of which rule
granted them; the same filters could instead ride on the grant rule when you want
them scoped to that grant — both are composition-safe, §7.0):

```cedar
// GRANT (rule): allow the read
@id("support.read_tickets")
permit(
  principal in Sieve::Role::"support_bot",
  action in Sieve::Action::"linear/read",
  resource in Sieve::Connection::"support-linear"
);
```

```cedar
// GUARDRAIL set: scrub + business-hours on support_bot's Linear reads
@id("guard.support_linear_reads")
@filters("scrub-pii biz-hours")
permit(
  principal in Sieve::Role::"support_bot",
  action in Sieve::Action::"linear/read",
  resource in Sieve::Connection::"support-linear"
);
```

`biz-hours` runs before Execute and can deny; `scrub-pii` runs over the response.
Both are reused verbatim by any other guardrail that names them — editing
`scrub_pii.py` once updates every guardrail. Neither can grant access; the rule is
the only thing that allows, and the script invariant (§7) guarantees the
guard/filter can only subtract. The guardrail binds whenever support_bot's Linear
read is allowed, no matter which role granted it (§7.0). This is the granular +
script-based control from the design review, with reuse living where it's actually
well-defined.

### 13.7 Reuse a complex Gmail role across accounts (§9.1)

A "complex" role is several rules — read + draft, internal-only send — plus
guardrails (approval, scrub PII). Written once, each rule applies to **both**
accounts because its connection set lives in a `when` clause (`resource in [..]`):

```cedar
// RULES (role: assistant) — the grants
@id("assistant.gmail.read_draft")
permit(principal in Sieve::Role::"assistant",
       action in [Sieve::Action::"google/gmail.read", Sieve::Action::"google/gmail.draft"],
       resource)
  when { resource in [ Sieve::Connection::"work-gmail",          // ← both accounts
                       Sieve::Connection::"ops-gmail" ] };

// send allowed only to internal recipients (grant condition, §7.6) — NO @approval here
@id("assistant.gmail.send_internal")
permit(principal in Sieve::Role::"assistant",
       action == Sieve::Action::"google/send_email",
       resource)
  when { resource in [ Sieve::Connection::"work-gmail", Sieve::Connection::"ops-gmail" ]
         && context has recipient_domains                        // fail-closed (§7.6)
         && ["trilitech.com"].containsAll(context.recipient_domains) };
```

```cedar
// GUARDRAIL set — obligations that bind regardless of which role granted (§7.0)
@id("guard.assistant.send_approval") @approval("required")
permit(principal in Sieve::Role::"assistant",
       action == Sieve::Action::"google/send_email", resource);

@id("guard.assistant.scrub") @filters("scrub-pii")
permit(principal in Sieve::Role::"assistant",
       action in Sieve::Action::"google/gmail.read", resource);
```

The scrub and the send-approval are **guardrails**, not extra grant rules: the
read is already granted by `read_draft`, so the obligation only *adds* a transform /
an approval to an allowed request (§7.0). **Reuse on a third account** = add
`Sieve::Connection::"third-gmail"` to the `when`-clause sets of the rules — the
admin UI's "apply to connection" does this in one gesture across all of a role's
rules. One rule per grant, single source: edit the logic once and every listed
account follows. No template, no link, no linker. A **preset** ("Gmail read-only")
is just a shipped one-rule role you assign and scope to your connection the same
way. (`action in [..]` *is* valid in the scope — only `principal`/`resource` sets
must move to the `when` clause.)

### 13.8 Capability-parity map (legacy `RuleMatch` → new home)

Nothing in the legacy `RuleMatch` is silently dropped; each capability class has an
explicit home in the new model:

| Legacy `RuleMatch` capability | New home |
|---|---|
| `Operations` (op-name match) | **Rules** — `action` scope (a leaf op, or an action group, §5.3) |
| Response content: `From`/`To`/`Subject`/`ContentContains`/`Labels` (matched on the *returned* message) | **Post-phase** `exclude_items` / `script_filter` (or, when the decision needs request-derived content, a **pre-phase** `script_guard`) — never a decision condition (the response is not in `context`, §5.4) |
| Glob/list matches: `From []string`, `Model []string` with `*` | Cedar `like` for simple globs; an **enricher**-derived `context` field + condition, or a `script_guard`, for list/regex semantics |
| Float caps: `MaxCost`, `MaxTemperature` | **`decimal`** context conditions (`context.estimated_cost`, `context.param.temperature`; §4.5, §5.4) |
| Network: CIDR-negation, `Ports` | `context.source_ip` (`ipaddr`/CIDR) condition; port logic in a `script_guard` |
| `RequireApproval` | **Guardrail** `@approval("required")` (§7.2) |
| `Filters` (redact / exclude) | **Guardrail** `@filters("…")` → filter library (§7.1) |
| Rate limits (`builtin` evaluator) | **`rate_limit` filter** (§7.1) — execution **deferred** (§15) |
| Whole-policy `script` / `llm` evaluators | **Filter library** scripts (`script_guard` pre / `script_filter` post) under the command allowlist (§7.1); LLM-as-decision dropped (§1) |

**Migration safety — a dropped `deny` is a hard `--apply` blocker.** Omitting a
legacy `deny`/forbid during migration *widens* access (it removes a restriction) —
the P0 class. The migration tool MUST refuse `--apply` if any legacy deny has no
corresponding `forbid` (or guardrail) in the generated output: a fail-closed error,
never a silent "narrowing." (Dropping a *permit* only narrows access — that is
reported, not blocked.)

---

## 14. Concept diff: what this kills, what it adds

| Old | New |
|---|---|
| `policy_type` ∈ {rules,builtin,llm,chain,script} + `policy_config` | Cedar text (`permit`/`forbid` + annotations) |
| `CompositeEvaluator` AND-intersection, first-deny-shortcircuit | Cedar union, forbid-overrides-permit, default-deny |
| `RulesConfig.Scope` (decorative) | Real action groups + resource hierarchy |
| Role `bindings [{connection_id, policy_ids[]}]` (AND-composed set) | **RBAC**: a role is a reusable bundle of rules; a token is assigned a **set** of roles; rules carry set-valued `resource` scopes. **No binding table, no AND-composition** (§9.4) |
| Token → **one** role | Token → **a set of roles** (composition; union of capabilities, §3.1) |
| "empty policy_ids = DENY ALL" special case | Default deny (no special case) |
| `default_action: allow|deny` per policy | `permit`/`forbid` statements; default is always deny |
| Reuse by multi-attach (the footgun) | **RBAC composition**: reuse a role across tokens, compose roles per token (§3.1, §13.1); **set-valued `resource` scopes** for connection reuse within a rule (§9.1); **filter library** for obligations. No role-groups, no templates/links. |
| `script` policy type / `action:script` rules | `script_guard` (pre) + `script_filter` (post) in the filter library |
| `decision.Filters` from the evaluator | Obligations: `@approval` + `@filters("…")` on **guardrails** (separate set), collected in the guardrail pass and resolved from the library (§7.3) |
| `"Policy denied: default policy"` | Determining-**rule** ids (+ matched guardrails) in audit + decision explorer |
| Two guards (`connectionAllowed` + empty-policies) | One decision (no permit ⇒ deny) |

Changed at the principal layer: a token now references a **set** of roles (was
one); a role is a **reusable rule bundle** (was a bare principal group). Otherwise
unchanged: the token artifact (`sieve_tok_…`), connections + credentials, the
approval queue, the response-filter applier, the two-port topology, the connector
`Execute` contract.

---

## 15. Open questions / future work

- **`rate_limit` execution (deferred).** The `rate_limit` filter kind is specified
  (§7.1) but **not executed in v1** and **not offered in the filter-library UI**: a
  rule or guardrail that references a `rate_limit` filter is **rejected at save**
  until the counter (`internal/ratelimit`) is wired — no silent no-op.
  `script_guard`/`redact`/`exclude_items`/`script_filter` execute in v1.
- **MCP per-tool resource scoping (deferred).** v1 scopes `mcp_proxy/call` at
  **connection grain** (§5.2/§5.3); the `Sieve::Mcp::Tool` resource type is reserved
  in the schema but extractors emit the connection, so a token granted MCP on a
  connection reaches every tool on it. Per-tool scoping is non-breaking to add
  (transitive `in`).
- **Per-object extractors for every connector** (v1 may ship coarse). Non-
  breaking to refine.
- **Richer filter kinds** — e.g. a `transform`/rewrite kind, or WASM filters as a
  sandboxed alternative to process scripts. The library schema (`kind` + `config`)
  is designed to extend without touching the policy language.
- **Templates/links** — explicitly *not* built (§1, §4.4): set-valued scopes cover
  reuse with less machinery. Could revisit only if a future need wants a reusable
  shape that varies by something *other* than connection/role (the only axes
  set-scopes handle).
- **Role hierarchy** — a role that inherits another role's rules (a `base-read`
  role included by `support` and `analyst`). The Cedar primitive (`Role in
  [Role]`) is trivial; v1 leaves it out because multi-role tokens already cover the
  common "share a bundle" case (compose the shared role directly on each token). Add
  only if hierarchy earns its complexity.
- **Managed sub-policies** — an AWS-IAM-style layer where a named policy (a set of
  rules) attaches to many roles, giving reuse *below* the role. v1 keeps one bundle
  level (the role) for simplicity; revisit if rule-level reuse across roles becomes
  common (today: make the shared rules their own small role and compose it).
- **Subject ABAC** (token attributes like team/owner) for attribute-driven, not
  role-driven, grants.
- **Partial evaluation** (`x/exp/batch`) for a fast explorer over many
  hypotheticals. Experimental; not v1.
- **Connector credential selection by resource** (the connector-side half of P1):
  once owners are resources, `pickCredential` can match on the resolved resource
  rather than requiring exact per-owner registration. Separate connector PR.
