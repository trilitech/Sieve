# Sieve IAM — Implementation Plan

Companion to [`01-spec.md`](01-spec.md). This is the build: dependency decision,
package layout, the connector-taxonomy wiring, the PEP refactor, schema
generation/validation, testing, feature-flagging, and the PR sequence with
acceptance criteria.

> **Superseded on one point (see [`01-spec.md`](01-spec.md) §3.2/§5.4).** Where this
> plan calls `script_guard` a *filter-library kind* or a *pre-phase guard obligation*,
> the current model differs: a script returning allow/deny/approval is the **script mode
> of a rule's condition** (authored on the rule, run **per-grant** — a deny vetoes only
> that grant), **not** a filter. The filter library holds content transforms only
> (redact / exclude_items / script_filter). The lines below predate that and are kept as
> build history.

---

## 0. Implementation status (built + validated)

PR-A through PR-E are **implemented, tested, and validated end to end**; the
production default now runs on IAM (PR-F "flip default"). What shipped:

- **PR-A** `internal/iam` — engine, obligation resolution, golden corpus (cedar-go
  v1.8.0; H4 round-trip verified by the spike).
- **PR-B** connector taxonomy + `internal/iam/schema.go` → checked-in
  `schema.cedar` (108 actions, 8 entity types); the **full schema validates under
  the Rust `cedar` 4.11.1 CLI** (N2/N4/connector-gating proven).
- **PR-C** `internal/iampolicies` storage (policies/filters/role-groups + cached
  engine) + `internal/iammigrate` (rules→Cedar + `MigrateAll` + true differential
  vs the legacy evaluator).
- **PR-D** live wiring on **both** surfaces (`api` generic/gmail/proxy + `mcp`)
  via "swap the decision source": `iampolicies.Decide` returns a
  `*policy.PolicyDecision`, so all downstream control flow (execute/approval/
  filters/audit) is unchanged. Startup auto-migration. Proven by
  `TestIAMWiring_*`, `TestPEP_Integration`, `TestMigrateAll_GovernsAgentPath`.
- **PR-E** admin IAM page (`internal/web/iam.go` + `iam.html`): policy CRUD,
  enable toggle, decision explorer; `web.Server.SetIAM`.
- **PR-F (flip)** production defaults to IAM (`iam_enabled` unset ⇒ "true" + first-
  start migration in `cmd/sieve`). **Legacy removal is deferred** (overlap window;
  see §11 PR-F) — it requires migrating the legacy test suite and is the staged
  final phase.
- **Playwright** `e2e/iam.spec.ts` (run the harness on IAM via `SIEVE_IAM=1`):
  **5/5 green** — agent API governed by the migrated policy, unauthorized-
  connection deny, IAM admin page, decision explorer allow+deny. The testserver
  now wires operator auth (`SetAuth` + `loginOperator` helper), closing a
  pre-existing admin-UI e2e gap.

### Live-wiring findings (validate-via-implementation)

- **Decision-source swap** kept the PEP edit tiny and exact — the legacy
  allow/deny/approval/filter machinery is reused verbatim; only the producer
  changed.
- **Guard execution is deferred**: `script_guard`/`rate_limit` obligations are
  resolved but not yet *executed* in the live PEP, so a determining permit that
  carries a guard **fails closed (denies)** rather than allowing past an
  unenforced guard (`toPolicyDecision`). Wiring the guard runner (reusing
  `/opt/sieve-py`) is the follow-up; the fail-closed default is safe meanwhile.
- **`@approval` + `@filters` on the same permit**: the legacy approval branch
  doesn't apply response filters post-approval, so that combination applies
  approval but not the filters (matches legacy behavior). A v1 limitation;
  documented.
- **mcp_proxy** maps any tool to the synthetic `mcp_proxy/call` action at
  connection grain in the live PIP (tool-level resource scoping deferred).

---

## 1. Dependency decision: vendor cedar-go

**Decision: take `github.com/cedar-policy/cedar-go` as a runtime dependency,
pinned to `v1.8.0`.** Rationale (from research):

- The four things we need — policy-text parse/store, evaluation **with
  diagnostics** (determining policies), annotation reads, and an entity store —
  are all in the **stable, SemVer'd, Apache-2.0 core**.
- Re-implementing a Cedar subset means re-deriving `(principal,action,resource)` +
  `when`/`unless` evaluation, forbid-overrides-permit, transitive `in` over an
  entity DAG, and four extension types — large surface, real correctness risk
  (even the official impls shipped eval bugs: cedar-go v1.6.0). Not worth it.

**Guardrails:**

- Pin `v1.8.0`. Forbidden: `v1.2.0` (retracted), `< v1.6.0` (correctness fixes).
  Note `v1.8.0` changed IPv6 handling — cover `context.source_ip` in tests.
- **Isolate `x/exp`.** The schema validator (`x/exp/schema/validate`) and any
  batch/partial-eval are *not* under SemVer. All `x/exp` imports live behind one
  Sieve adapter package (`internal/iam/cedarx`) so churn is contained and the
  rest of the codebase imports only stable cedar-go.
- A single `internal/iam/cedarengine` wrapper owns the cedar-go surface
  (`Authorize`, `PolicySet`, `Policy`, `ast`); nothing else imports cedar-go
  directly. If we ever swap engines, this is the seam.

---

## 2. Package layout

```
internal/iam/
  iam.go            // PDP entrypoint: Decide(ctx, Request) (Decision, error)
  request.go        // Sieve Request type; the (token,conn,op,params,http) → cedar.Request build
  entities.go       // PIP: per-request entity store (token→role→group, resource→conn→connector)
  resource.go       // Resource UID types + ResourceMapper interface (connector-supplied)
  actions.go        // generated: op→action id + group membership (from registry)
  context.go        // context Record builder + ContextEnricher dispatch
  obligations.go    // annotation vocabulary; collect(diag.Reasons) → Obligations
  policyset.go      // load enabled policies → cached cedar.PolicySet; stable PolicyIDs; invalidation
  explain.go        // decision explorer (dry-run Authorize + Diagnostic projection)
  schema.go         // embeds generated schema; exposes it for validation/tests
  schema.cedar      // generated (go:embed); human-readable schema
  schema.json       // generated; JSON schema (for Rust cedar CLI in CI)
  cedarengine/      // the ONLY importer of cedar-go core (Authorize/PolicySet/ast)
  cedarx/           // the ONLY importer of cedar-go x/exp (schema validate); behind an interface

internal/connector/
  connector.go      // OperationDef gains Action + Resource (ResourceMapper) + ContextEnricher (opt)

internal/iampolicies/ // storage for iam_policies, iam_roles, iam_role_groups (NOT bindings)

cmd/sieve/
  iam_schema_gen.go // go:generate target: registry → schema.cedar/.json + actions.go
  iam_migrate.go    // the `sieve iam-migrate` subcommand (migration doc)
```

The PEP edits are confined to `internal/api/router.go` and
`internal/mcp/server.go`.

---

## 3. Connector taxonomy wiring

### 3.1 Interface additions (`internal/connector`)

```go
// OperationDef gains the IAM taxonomy. Existing fields unchanged.
type OperationDef struct {
    Name        string
    Description string
    Params      map[string]ParamDef
    ReadOnly    bool

    // Action is the Cedar action leaf id, e.g. "google/list_emails".
    // If empty, generated as "<connectorType>/<Name>" (the default).
    Action string

    // Resource maps a request to its Cedar resource UID. If nil, the
    // resource defaults to the connection container (Sieve::Connection::"<conn>").
    Resource ResourceMapper
}

// ResourceMapper derives a resource entity from the connection id + params.
// It returns the entity type, the id suffix, and the parent chain so the
// engine can build the entity store and the schema generator can record
// appliesTo. Pure; no I/O.
type ResourceMapper func(connID string, params map[string]any) ResourceRef

type ResourceRef struct {
    Type   string   // e.g. "Sieve::Github::Repo"
    ID     string   // full UID id, e.g. "ops-github/trilitech/sieve"
    Parent string   // parent UID, e.g. "Sieve::Github::Owner::\"ops-github/trilitech\""
}

// ContextEnricher optionally adds derived context attributes (recipient
// domains, estimated cost, http method). Connector-specific; pure.
type ContextEnricher interface {
    EnrichContext(op string, params map[string]any) map[string]any
}
```

`ConnectorMeta` gains a declaration of its resource entity types (so the schema
generator knows them without executing extractors):

```go
type ConnectorMeta struct {
    // …existing…
    ResourceTypes []ResourceType // e.g. {Name:"Sieve::Github::Repo", Parent:"Sieve::Github::Owner"}
}
```

### 3.2 Per-connector wiring (from the verified inventory)

Each connector annotates its ops. Examples (full set is mechanical):

- **google**: ops carry sub-service-aware actions. `list_emails` →
  `Action:"google/list_emails"` (groups `read`,`google/gmail.read`),
  `Resource` → `Google::Message`. `drive.list_files` →
  `Action:"google/drive.list_files"` (`read`,`google/drive.read`),
  `Resource` → `Google::DriveFile`. A `ContextEnricher` on send/reply parses
  `to`/`cc` into `recipient_domains`.
- **github**: `Resource` for `owner`+`repo` ops → `Github::Repo` (parent
  `Github::Owner`); `github_request` → `Github::RawRequest` + a `ContextEnricher`
  that sets `http_method` from `method`. (Owner extraction reuses the existing
  `extractOwner`.)
- **gitlab/slack/linear**: `Resource` from `project`/`channel`/`id` per §5.2.
  Escape hatches set `http_method`.
- **anthropic/http_proxy**: no `Resource` (defaults to connection);
  http_proxy may map `path` → `Httpproxy::Path`; anthropic enriches
  `estimated_cost`.
- **mcp_proxy**: single action `mcp_proxy/call`; `Resource` → `Mcp::Tool` from
  the (dynamic) tool name.

### 3.3 Generation, not hand-maintenance

`go generate ./cmd/sieve` walks the registry and emits:

1. `internal/iam/actions.go` — the `op → (actionID, groups)` map + the set of all
   action entities and their group memberships.
2. `internal/iam/schema.cedar` + `schema.json` — entity types (from
   `ResourceTypes` + containers), actions with `appliesTo`, the `Context` type.

A CI check fails if generated files are stale (`go generate` + `git diff
--exit-code`). This is what makes "edit shows different fields than create"-style
drift (the bug class from the prior PR #31 work) **impossible** for the
action/resource taxonomy too: the catalog is the single source.

---

## 4. PDP engine (`internal/iam`)

```go
func (e *Engine) Decide(ctx context.Context, r Request) (Decision, error) {
    req, entities := e.build(r)              // §5.5 of spec: principal/action/resource/context + store
    dec, diag := e.cedar.Authorize(e.activeSet(), entities, req)
    e.recordErrors(diag.Errors)              // audit + metrics; do not alter outcome
    if dec != cedar.Allow {
        return Decision{Allow: false, Reason: e.denyReason(diag)}, nil
    }
    obl := e.collectObligations(diag.Reasons) // §7.2
    return Decision{Allow: true, Determining: ids(diag.Reasons), Obligations: obl}, nil
}
```

`Decision` is the Sieve-facing result (allow bool, reason, determining policy ids,
obligations). The PEP consumes only this — it never sees cedar-go types.
`collectObligations` reads `@approval`/`@filters`/`@audit_label` off the
determining permits and **resolves** the `@filters` names against the filter
library (§7), returning `Obligations{Approval, Guards[], Filters[], AuditLabel}`
ready for the PEP — `Guards` (pre, `script_guard`) and `Filters` (post, as
`policy.ResponseFilter`). Unknown filter names can't occur at runtime (validated
at policy save), but a missing library entry fails closed (deny).

`activeSet()` returns the cached `*cedar.PolicySet`, rebuilt on policy change
(§9.3 of spec). Build assigns stable ids `"<policyID>#<idx>"`. The engine also
holds the cached filter library, invalidated on filter change.

---

## 5. PIP: entities and context

**Runtime correctness depends entirely on the entity store, not the schema**
(review C3): `cedar.Authorize` takes no schema, so *all* hierarchy — action-group
membership and resource ancestry — must be present in `entities` or `in` matches
nothing. The store builder therefore must be exhaustive:

- **Action entities** — every leaf action with its full group-parent set
  (`google/list_emails` → parents `read`, `google/gmail.read`). Static; built once
  from the generated `actions.go` and cached. *Without this, `action in
  Action::"read"` matches nothing → mass deny.* A dedicated test asserts a leaf
  matches its group.
- **Container entities** (connectors, connections) — derived from the registry +
  connections store and **cached**; rebuilt on connection add/remove. Connection
  entities carry `connection_status` (keyring-free `connections.Get` — no
  decryption, per the Slack-era contract).
- **Per-request leaves**: the token (parent = its role), the role (parents =
  role-groups), and the resource **with its full ancestor chain** (Repo → Owner →
  Connection → Connector). The per-request `EntityGetter` overlays these leaves on
  the cached base.
- **Build EntityUIDs via the typed cedar-go API, never by concatenating Cedar
  text** (review L1): connection/owner/repo/project ids are user-influenced and may
  contain quotes/slashes; `types.NewEntityUID(type, id)` treats the id as data, so
  there is no entity-id injection surface. (String-building Cedar text would
  reintroduce one — forbidden.)
- **Context** is assembled by `context.go` from PEP-supplied http/time/ip plus
  the connector's `ContextEnricher`. Scalar params projected into `context.param`;
  enrichers **omit** absent/empty values rather than emitting nulls/`[]` (spec
  §7.6).

No PIP call performs credential decryption; the connections table is read for
status/metadata only (invariant 1).

---

## 6. PEP refactor (api + mcp)

The change is surgical — replace the evaluator build + `Evaluate` with
`iam.Decide`, and source obligations from the decision:

**Before** (`router.go`, paraphrased):
```go
evaluator, err := rt.getEvaluator(role, connID)        // policy set for (role,conn)
decision, err := evaluator.Evaluate(ctx, policyReq)    // composite AND
switch decision.Action { case "deny": …; case "approval_required": …; default: … }
// allow: conn.Execute; ApplyResponseFilters(decision.Filters)
```

**After:**
```go
dec, err := rt.iam.Decide(ctx, iam.Request{
    Token: tok, Connection: connID, Operation: operation, Params: params, HTTP: httpMeta,
})
if !dec.Allow { writeError(403, dec.Reason); audit(deny, dec.Determining); return }

// pre-execution obligations (can only DENY, never grant):
if err := rt.iam.RunGuards(ctx, dec.Obligations.Guards, guardInput); err != nil {
    writeError(403, "guard denied: "+err.Error()); audit(guard_deny, dec.Determining); return  // fail-closed
}
if dec.Obligations.Approval { /* REST: submit + WaitForResolution(5m) + re-validate; MCP: ticket */ }

result, err := conn.Execute(ctx, operation, params)

// post-execution obligations (response transforms; script_filter included):
result = policy.ApplyResponseFilters(result, dec.Obligations.Filters)   // fail-closed (unchanged)
audit(allow, dec.Determining, dec.Obligations.AuditLabel)
```

- `getEvaluator`, `connectionAllowed`, and the empty-policies deny-all check are
  **removed** — all subsumed by "no permit ⇒ deny". A cheap connection-existence
  check may remain only to distinguish 404 from 403.
- `dec.Obligations` is already **resolved** by the engine: the `@filters("…")`
  names from the determining permits are looked up in the filter library and split
  into `Guards` (pre, `script_guard`) and `Filters` (post — `redact`,
  `exclude_items`, `script_filter`, expressed as `policy.ResponseFilter` so the
  existing applier is reused verbatim, including its `ScriptCommand` path).
- Approval, token re-validation after wait, the 429 path for Gmail/proxy, and the
  `AuthValueScrubFilter` prepend are **unchanged**.
- **Monotonicity preserved with scripts in the loop:** guards and filters can only
  deny or transform; the `permit` is the only grant. Adding any obligation is
  always safe.

Both surfaces call the same `iam.Engine`. MCP keeps its non-blocking approval
shape; REST keeps its blocking shape.

---

## 7. Storage (`internal/iampolicies`)

New tables (DDL in migration doc), all additive — legacy `policies`/`roles`
remain during overlap:

- `iam_policies(id, name, description, cedar_text, enabled, created_at)` — the
  policy (spec §9.1). The connection set lives in a `when`-clause `resource in [..]`
  (H4 spike: sets are invalid in the `principal`/`resource` scope); the editor
  round-trips it as a structured list so "apply to connection" is a structured
  edit, not text munging.
- `iam_filters(id, name, description, kind, order, config, created_at)` — the
  **filter library** (spec §7). `kind ∈ {redact, exclude_items, script_filter,
  script_guard, rate_limit}`; `order` (int) sets post-filter application order
  (spec §7.1, review M3); `config` is JSON (patterns, `{command, path,
  timeout_ms}`, or `{limit, window_seconds, key}` for rate_limit).
- `iam_roles(id, name, created_at)` — pure principal groups (no bindings column)
- `iam_role_groups(id, name, created_at)` + `iam_role_group_members(group_id,
  role_id)`
- tokens keep `role_id` (unchanged table).

**No `iam_templates` / `iam_template_links` and no linker** — reuse is set-valued
scopes (spec §9.1), so there is nothing to materialize. This removes the design's
riskiest cedar-go dependency (slot substitution); the only remaining cedar-go
spike is the PolicyID/`diag.Reasons` round-trip (below).

Validation on write: `cedar_text` parses (§8); every `@filters("…")` name resolves
against `iam_filters`. Writes to any table bump a version counter that invalidates
the engine's cached PolicySet + filter library. Script filters/guards reuse the
existing policy-script runtime (`/opt/sieve-py`, stdin/stdout JSON) — no new
sandbox.

**Assembly** (spec §9.3): each policy contributes its statements directly (already
concrete Cedar — no materialization). Each statement gets PolicyID `pol:<id>#<idx>`
so `diag.Reasons` maps back to its source policy for audit/explain. The set is
**partitioned by principal** (spec §9.3, optional/deferrable) — a role's slice =
policies scoped to that role, to any **role-group it belongs to** (transitive),
**plus unconstrained-principal** policies (review N1; a naive role-id key drops the
latter two → false deny). Computed from role→group membership, invalidated on
membership change.

---

## 8. Schema generation + validation

> **Empirically validated (PR-B).** `internal/iam.GenerateSchema` produces the
> Cedar schema from the registry; it parses+resolves under cedar-go x/exp AND
> validates under the authoritative **Rust `cedar` 4.11.1** CLI. Confirmed by
> `cedar validate` against the generated schema:
> - **N2** — per-action typed `param` context works; an undeclared
>   `context.param.X` is rejected ("attribute param.X … not found").
> - **N4** — broad `action in Sieve::Action::"read"` + connection-scoped resource
>   validates (no per-connector-group fallback needed).
> - **Connector-gating** — a `google/*` action on a `Sieve::Github::*` resource is
>   rejected ("unable to find an applicable action given the policy scope
>   constraints"). The Gmail-policy-on-GitHub invariant holds at the validator.
>
> **x/exp finding:** the Go `x/exp/schema/validate` validator's `Policy()` takes
> `x/exp/ast.Policy`, but the stable parser yields `cedar-go/ast.Policy` and x/exp
> exposes no parser — so **Go-side *policy* validation is impractical**. Policy
> validation therefore uses the **Rust CLI** (a Go test shells out, skips if
> absent). The Go x/exp validator remains usable for *entity*/*request* validation
> (stable types). Net: the always-on Go check is the M5 name+coherence pass below;
> the Rust CLI is the authoritative policy validator (CI + opportunistic local).

- **Generation**: `internal/iam.GenerateSchema(registry metas)` → `schema.cedar`
  (+ `schema.json` via cedar-go marshaling); the action map is **computed at
  runtime** from the registry (no generated `actions.go` — equally drift-proof,
  simpler). Staleness test compares the checked-in `schema.cedar` to fresh output.
- **Cheap name + connector-coherence check (always on, review M5 + connector
  gating):** independent of the Cedar validator, a lightweight save-time pass parses
  the policy, extracts every referenced `Sieve::Action::"…"` id and entity *type*,
  and checks (a) they exist in the **generated** taxonomy (`actions.go` + entity
  types), and (b) each statement's **connector-specific** actions are compatible
  with its resource scope's connector — i.e. a `google/*` action with a GitHub
  connection/resource is rejected (the "Gmail policy on GitHub" case the dropped
  template gate used to prevent). Global-group actions (`read`/`write`) are exempt
  — they legitimately span connectors. A typo or a cross-connector-nonsense combo —
  which at runtime would silently never match (wrong decision, no error, since
  there's no runtime schema, review C3) — is rejected at save. This is the belt to
  the x/exp suspenders.
- **Save-time validation**: `internal/iam/cedarx` wraps `x/exp/schema/validate`
  behind a Sieve interface (`Validator.Validate(cedarText) error`). Used by the
  policy store and the editor for richer feedback (attribute types, `appliesTo`).
  Because it's experimental, failures block-save *only when the validator is
  enabled*; the flag lets us disable if x/exp breaks — the M5 name check still runs.
- **Authoritative validation (CI)**: a CI job runs the **Rust `cedar` CLI**
  (stable validator) against the generated `schema.cedar` + the example policies
  and the migration outputs. This is the gate that must pass. A Go test
  (`schema_cli_test.go`) already shells out to it (skips if absent) and asserts
  good-policies-pass / bad-policies-fail. **N4 confirmed (PR-B):** a broad
  `action in Sieve::Action::"read"` + connection-scoped-resource policy validates
  — the feared per-connector-group fallback is unnecessary.
- **Runtime**: rely on evaluation (errored policies skipped + logged). A policy
  that fails to parse at load is excluded from the active set and surfaced in the
  admin UI as broken (never silently dropped).

---

## 9. Testing strategy

- **Engine unit tests** (`internal/iam`): every algebraic property as an explicit
  test — default-deny; forbid-overrides-permit; permit-union (the P0
  regression: two single-service permits compose to their union, not empty);
  action-group membership (`action in read` matches a leaf); transitive resource
  `in` (connector-scoped permit matches a deep object); `when`/`unless` AND;
  obligation collection (approval OR, filter union+dedupe, post-order by
  `(order,id)`); errored-policy-skipped fails closed.
- **Entity-store completeness (review C3):** an explicit test that builds the store
  the way the PIP does and asserts `action in <group>` and connector-scoped
  `resource in` actually match — i.e. that the store (not the absent runtime
  schema) carries action-group + resource ancestry. This is the test that would
  catch the "mass deny because the store omitted action parents" failure.
- **Partition correctness (review N1):** a role in a role-group, plus an
  unconstrained-principal policy, plus a role-group-scoped policy — assert the
  role's partition includes all three; assert a naive role-id partition would miss
  two (regression guard).
- **Obligation tests**: `@filters` name resolution against the library; pre-guard
  denies short-circuit before Execute; `rate_limit` denies over quota and the
  explorer dry-run does **not** consume quota; post `script_filter` transforms the
  response; post-filters apply in `(order,id)` order; **a guard/filter can never
  flip a deny to allow** (monotonicity); guard error ⇒ deny; post-filter error ⇒
  response withheld (fail-closed). Script kinds tested against the `/opt/sieve-py`
  stdin/stdout contract with a stub script.
- **Golden decision corpus**: a table of `(policies, filters, request) →
  (decision, determining ids, obligations)` checked into the repo; the spec's
  worked examples (incl. the script-filter/guard 13.5) are golden cases.
- **Per-connector taxonomy tests**: for every op in every connector, assert
  (a) it has an action the schema declares, (b) the action's `appliesTo` includes
  the resource type the extractor produces, (c) `ReadOnly` matches the read/write
  group. Mirrors the existing `TestOperations_CatalogShape` pattern; this is the
  drift guard.
- **Connector-gating tests**: a policy with a `google/*` action and a GitHub
  connection in its resource scope **fails** the save-time coherence check and Cedar
  validation; a cross-connector `action in read` policy over [gmail, github]
  connections **passes**; at runtime, that Gmail-action-on-GitHub policy (if forced
  in) never matches a GitHub request. Encodes "a Gmail policy can't be applied to
  GitHub."
- **Schema CI**: Rust `cedar validate` over schema + example policies + migration
  output.
- **Differential tests** (overlap window, migration doc §): replay a corpus of
  requests through the **old** evaluator and the **new** PDP; assert identical
  allow/deny on the cases meant to match, and assert the *intended divergences*
  (the P0 cases the new engine fixes) with explicit expectations + comments.
- **PEP integration**: existing api/mcp tests run against the new engine behind
  the flag; the Playwright e2e suite covers the editor + explorer.

---

## 10. Feature flag + observability

- `iam_enabled` (settings, default off until PR-F). When on, the PEP routes to
  `iam.Decide`; when off, the legacy path. Both compiled in during overlap.
- **Audit**: add `decision` and `determining_policies` columns (migration doc).
  Keep `policy_result` (now sourced from `@audit_label` / decision).
- **Metrics**: deny-by-default vs deny-by-forbid counts; policy evaluation errors
  (by policy id); obligation firings (approval/redaction); explorer usage.

---

## 11. PR sequence (with acceptance criteria)

Each PR is independently reviewable and leaves the tree green.

**PR-A — `internal/iam` core (pure addition, no integration). Preceded by the H4
spike** (cedar-go PolicyID/`diag.Reasons` round-trip: parse a multi-statement
policy, add to a set with stable ids, confirm `Authorize` reports them in
`diag.Reasons` and `Get(id).Annotations()` reads back). Cedar engine wrapper,
Request/entity/context/resource/obligation types, PolicySet assembly (+ optional
per-role partitioning), the obligation engine (annotation parse → `@filters`
resolution against a `FilterLibrary` interface → `Guards`/`Filters`; guard runner
+ script contract; monotonicity enforced), the embedded schema (hand-written
initially), engine unit tests + golden corpus. Filter library is an interface here
(in-memory impl for tests); persistence lands in PR-C. *Accept:*
`go test ./internal/iam/...` covers every algebraic + obligation property (incl.
guard-can't-grant, fail-closed, set-valued-scope reuse, partitioned==whole-set);
the worked examples (incl. 13.5 script filter/guard and 13.6 set-scope reuse) pass
as golden cases; nothing else in the tree imports cedar-go.

**PR-B — connector taxonomy + schema generation.**
`OperationDef.Action/Resource`, `ConnectorMeta.ResourceTypes`, per-connector
wiring, `go generate` for `actions.go`/`schema.{cedar,json}`, taxonomy tests,
schema-staleness CI, Rust-cedar validation CI. IAM engine still not on the request
path. *Accept:* every op maps to a schema-valid action+resource; generated files
are fresh; `cedar validate` passes.

**PR-C — IAM storage + filter library + migration tool.**
`internal/iampolicies` + DDL (additive, incl. `iam_filters`), persistent
`FilterLibrary` store, save-time validation (`@filters` resolution), **shipped
example/preset policies** (per connector type — ordinary `iam_policies` rows, not a
separate artifact), `sieve iam-migrate` (dry-run/diff/apply),
differential-verification harness. Legacy tables untouched; `connections`
untouched (asserted by a test). *Accept:* migrate produces a Cedar policy set +
filter entries from current data (legacy `ResponseFilter`/`ScriptCommand` →
library entries referenced via `@filters`); example policies validate;
differential report shows expected matches + documented divergences; a test
asserts no migration statement references `connections`.

**PR-D — evaluator switchover behind `iam_enabled`.**
PEP (api+mcp) routes to `iam.Decide` when the flag is on; obligations → approval +
filters; audit columns. Old path intact when off. Both tested. *Accept:* full e2e
suite passes with the flag on and off; approval (REST block / MCP ticket) and
fail-closed filtering verified on the new path.

**PR-E — admin UI (PAP).**
Cedar policy editor (with x/exp validation feedback + `@filters` autocomplete
against the library), the **"apply to connection(s)" affordance** that manages a
policy's resource scope set (and instantiates a shipped preset onto a connection),
the **filter library editor** (redact/exclude/script_guard/script_filter/rate_limit
entries), role + role-group management, the **decision explorer**, audit shows
determining policies. Behind the flag. *Accept:* operator can author/validate a
policy, define a filter and reference it, apply a Gmail preset to a connection and
reuse one policy across two accounts via "apply to connection," and explain a
decision; Playwright covers it.

**PR-F — flip default + remove legacy.**
After one overlap release: `iam_enabled` default on; then delete
`internal/policy/composite.go` (+ chain/rules/builtin/llm/script evaluators if
fully unused), drop legacy `policies`/`roles.bindings`, remove the flag. tokens +
connections unchanged throughout. *Accept:* legacy code/tables gone; `connections`
diff is empty across the entire series.

---

## 12. Risks and mitigations

| Risk | Mitigation |
|---|---|
| `x/exp` schema validator breaks on a cedar-go bump | Behind `internal/iam/cedarx` interface + flag; CI authoritative validation is the Rust CLI, independent of x/exp |
| cedar-go semantics differ subtly from expectation | Golden corpus + differential testing against the old engine; pin v1.8.0; engine wrapper is the single seam |
| ~~H4: PolicyID/`diag.Reasons` round-trip unverified~~ **RESOLVED by spike** (`internal/iam/cedar_spike_test.go`) | Verified on cedar-go v1.8.0: stable `pol:<id>#<idx>` ids round-trip through `diag.Reasons` → `Get(id).Annotations()`; hierarchy resolves from the entity store with no runtime schema; forbid-overrides + default-deny hold. **Spike finding:** `resource in [set]` is invalid in the *scope* (only `action` takes a set there) → connection sets live in a `when` clause (spec §9.1, examples corrected). §7.6 fail-open trap confirmed real. |
| **No runtime schema** (Authorize takes none) → hierarchy must be in the entity store | The generated schema is **authoring/CI only**; the store builder includes every action entity with its group parents + each resource's full ancestor chain; a test asserts `action in <group>` matches a leaf and a connector-scoped resource matches a deep object |
| Context `param` projection too lossy for some declarative condition | Scalar projection for `when`/`unless`; anything richer is a `script_guard` in the filter library (full request JSON on stdin) — the documented escape hatch |
| Operators find Cedar unfamiliar | Example policies in docs, the editor with live validation + `@filters` autocomplete, and the decision explorer |
| Script guards/filters are a code-execution surface | Reuses the existing audited `/opt/sieve-py` runtime + timeouts; monotonic (can only deny/transform, never grant); fail-closed on error; library entries are PAP-managed (web 19816), never agent-reachable |
| PolicySet rebuild cost on change | In-memory cache, rebuild only on policy mutation; evaluation never hits storage |
| mcp_proxy dynamic ops vs static schema | Tool-as-resource + single `mcp_proxy/call` action — no dynamic actions in the schema |
