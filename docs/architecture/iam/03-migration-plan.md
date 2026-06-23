# Sieve IAM — Migration Plan

Companion to [`01-spec.md`](01-spec.md) and [`02-implementation-plan.md`](02-implementation-plan.md).
How we move every existing policy/role/binding to Cedar **without touching
credentials and without a flag day**.

> **Superseded on one point (see [`01-spec.md`](01-spec.md) §3.2/§5.4).** Rows below that
> migrate `action: script` to a `script_guard` **library entry** are stale: a script
> returning allow/deny/approval is now the **script mode of a rule's condition**, not a
> filter-library entry (the owner confirmed no production scripts exist, so the migrated
> count is 0 regardless). Kept as migration history.

---

## 1. Current-state inventory (verified from source)

The migration reads exactly these (and writes only new `iam_*` tables):

**`policies`** (`internal/policies`, `database.go`)
```sql
CREATE TABLE policies (
  id TEXT PRIMARY KEY, name TEXT UNIQUE, policy_type TEXT NOT NULL,
  policy_config TEXT NOT NULL,                 -- JSON of evaluator params
  lint_ack TEXT NOT NULL DEFAULT '{}', created_at DATETIME
);
```
`policy_type ∈ {rules, builtin, llm, chain, script}`. The `rules` evaluator is the
common case: an ordered `Rules[]` with `Match`, `Action ∈
{allow,filter,deny,approval_required,script}`, optional `ResponseFilter`
(+ legacy `FilterExclude`/`RedactPatterns`), and `DefaultAction` (default `deny`).
`builtin` is an op-level allow/deny/approval map + filters/redacts/rate-limits.

**`roles`** (`internal/roles`)
```sql
CREATE TABLE roles ( id TEXT PRIMARY KEY, name TEXT UNIQUE,
  bindings TEXT NOT NULL,                       -- JSON [{connection_id, policy_ids[]}]
  created_at DATETIME );
```
"connection absent" or "policy_ids empty" ⇒ DENY ALL (enforced in code, not data).

**`tokens`** (`internal/tokens`) — `role_id` references a role; SHA-256 hash of
`sieve_tok_…`. **Unchanged by this migration** (keeps `role_id`).

**`connections`** — **READ-ONLY reference only.** Never modified. A migration test
asserts no emitted statement and no DDL touches this table.

---

## 2. Invariants

1. **`connections` untouched** — no DDL, no writes, no read beyond id/type/status.
2. **Fail closed** — anything the tool can't translate becomes *absence of
   permit* (deny), never a broad allow. Untranslatable policies are reported, not
   silently dropped or approximated upward.
3. **Reversible** — `iam_enabled=off` restores the legacy engine; legacy tables
   persist until PR-F; `iam-migrate` is idempotent and re-runnable.
4. **Verified equivalence** — differential harness proves new==old on cases meant
   to match, and documents the intended P0 divergences.

---

## 3. Mapping rules (legacy → Cedar)

The unit of migration is a **(role, binding)** pair. For role *R* with binding
`{connection C, policy_ids [P1..Pn]}`, each referenced policy is translated into
Cedar statements scoped to `principal in Sieve::Role::"R"` and (by default)
`resource in Sieve::Connection::"C"`. The legacy AND-of-policies *intersection*
is **not** reproduced — that is the bug being removed; the new statements union,
which is the corrected intent. (Differential reporting flags every case where this
changes the outcome; see §5.)

### 3.1 `rules` policy → statements

For each rule, in order:

| Rule | Cedar |
|---|---|
| `Action: allow`/`filter`, `Match` on op(s) | `permit(principal in Role::"R", action in <ops→action ids/groups>, resource in Connection::"C") [when <match→condition>]` |
| `Action: deny` **(conditional / op-scoped)** | `forbid(principal in Role::"R", action in <ops>, resource in Connection::"C") [when <match>]` `@deny_message(<reason>)` |
| `Action: deny` **(unconditional catch-all, esp. trailing — `Match` empty)** | **emit nothing** — this is the legacy "default deny", which Cedar gives for free. Translating it to a catch-all `forbid` would override **all** permits (forbid-wins) and deny everything. **Must be detected, not translated.** |
| `Action: approval_required` | the matching `permit` above + `@approval("required")` |
| `Action: script` | a `script_guard` library entry (from the rule's script command/path) + `@filters("<entry>")` on the matching `permit` (owner: no production scripts exist, so expected count 0) |
| `ResponseFilter` / `FilterExclude` / `RedactPatterns` / `ScriptCommand` on an allow rule | a **filter-library entry** per distinct filter (`redact`/`exclude_items`/`script_filter`) + `@filters("<name…>")` on that `permit`. Identical legacy filters dedupe to one library entry. |
| `DefaultAction: deny` (typical) | nothing (Cedar default) |
| `DefaultAction: allow` | a broad `permit(principal in Role::"R", action, resource in Connection::"C")` appended last |
| `Scope: <service>` (was decorative) | **now meaningful**: narrows `resource`/`action` via a fixed **scope→taxonomy map** the migrator carries (e.g. `gmail→google` + `google/gmail.*` groups, `drive→google/drive.*`, `gitlab→gitlab`, …). Unknown scope → manual-port item, never a guess. |

Match translation: op-name matches → action ids or the appropriate group
(`read`/`write`/`<type>/<subservice>.<rw>`); param matches → `when {
context.param.<k> == <v> }` — valid only if the op declares that param (per-action
context, spec §5.4); otherwise a manual-port item. Matches the engine can't
express become a reported manual item (fail-closed: the rule is omitted, narrowing
access, never widening).

**Order-dependence caveat.** Legacy rules are first-match-wins (ordered); Cedar is
order-independent with forbid-overrides-permit. Most chains translate cleanly, but
a chain where an earlier `deny` *shadows* a later `allow` (or vice-versa) has no
faithful order-independent form. The migrator detects shadowing (a later rule
whose action/resource set intersects an earlier opposite-effect rule) and
**flags it for manual review** rather than emitting a wrong translation.

### 3.2 `builtin` policy → statements

The op-level map translates directly: each `allow` op → a `permit` for that
action; each `deny` → a `forbid`; each `approval` → `permit` + `@approval`;
filters/redacts → filter-library entries referenced via `@filters("…")`;
rate-limits → `@audit_label` (or a future rate-limit obligation — v1 records them
as labels and reports them).

### 3.3 Binding-level rules

- **Connection absent from role / `policy_ids` empty** ⇒ emit nothing ⇒ default
  deny. The special case disappears.
- **Multiple policies on one binding** ⇒ all their statements are emitted; they
  union (the fix). The tool emits a per-binding note when this changes the
  effective grant vs. the old intersection.

### 3.4 Roles, role-groups, tokens

- Each legacy role → `iam_roles(id,name)`.
- Tokens keep their `role_id` (no change).
- Role-groups are **not** auto-created; the tool can *suggest* a group when it
  detects identical statement sets across roles (a reuse opportunity), but
  defaults to per-role statements for a faithful 1:1 migration.

### 3.5 `llm`/`chain`

`chain` is flattened (its sub-evaluators migrate individually, unioned). `llm`
(LLM-as-decision) is **not** translatable to Cedar and is reported as a
**manual-port** item with its config dumped — the tool never approximates it into
a permit (fail-closed). Per the owner there are no production scripts and
LLM-as-policy is out of scope, so the expected manual-port count is 0; any rule
with `action: script` migrates to a `script_guard` library entry (§3.1), not a
manual item.

### 3.6 Presets and consolidation

Migration emits **one policy per (role, connection) binding**, faithful and 1:1,
to keep the diff legible. Separately:

- **Presets** are shipped **example policies** (per connector type) installed by
  normal seeding, independent of migration data — ordinary `iam_policies` rows, not
  a separate artifact.
- **Consolidation is an optional, operator-driven post-step.** When `iam-migrate`
  detects the *same* statement shape across multiple connections of one connector
  type (e.g. read-only on three Gmail accounts), it **suggests** collapsing them
  into **one policy whose resource scope lists all three connections** (set-valued,
  single-source). It defaults to the faithful per-connection policies; the operator
  opts in from the UI — never automatic, so migration never changes structure
  behind their back.

---

## 4. Worked migrations

### 4.1 The tezos_ops P0 case (the one that broke)

**Legacy:** role `tezos_ops`, binding on connection `ops-gmail` with policies
`[read-only, drafter]` (both `rules`, `default_action: deny`), plus later-added
`[read-all-drive, read-all-sheets, read-all-docs]` — which AND-composed to an
empty intersection (everything denied).

**Migrated Cedar** (union; the intersection bug gone):
```cedar
@id("mig:tezos_ops:ops-gmail:read")
permit(principal in Sieve::Role::"tezos_ops",
       action in [Sieve::Action::"google/gmail.read",
                  Sieve::Action::"google/drive.read",
                  Sieve::Action::"google/sheets.read",
                  Sieve::Action::"google/docs.read"],
       resource in Sieve::Connection::"ops-gmail");

@id("mig:tezos_ops:ops-gmail:draft")
permit(principal in Sieve::Role::"tezos_ops",
       action in Sieve::Action::"google/gmail.draft",
       resource in Sieve::Connection::"ops-gmail");
```
Differential report: **old=DENY, new=ALLOW** for `list_emails`, `drive.list_files`,
etc. — flagged as an **intended P0 fix** (the whole point).

### 4.2 read-only `rules` policy with a redaction filter

**Legacy** (`rules`): allow `read`-ish ops, `ResponseFilter{RedactPatterns:
["\\b\\d{16}\\b"]}`, `default_action: deny`.

**Migrated** — one library entry + a policy that references it:
```jsonc
// iam_filters
{ "name": "redact-card-16", "kind": "redact", "config": { "patterns": ["\\b\\d{16}\\b"] } }
```
```cedar
@id("mig:R:C:read")
@filters("redact-card-16")
permit(principal in Sieve::Role::"R",
       action in Sieve::Action::"<type>/read",
       resource in Sieve::Connection::"C");
```
Differential: identical allow/deny; the resolved filter reproduces the redaction.
If the same pattern appears in several legacy policies, all of them reference the
single `redact-card-16` entry (the reuse that now lives in the library).

### 4.3 deny rule (blocklist)

**Legacy** rule `Action: deny, Match: op=send_email`.

**Migrated:**
```cedar
@id("mig:R:C:deny-send")
@deny_message("denied by rule")
forbid(principal in Sieve::Role::"R",
       action == Sieve::Action::"google/send_email",
       resource in Sieve::Connection::"C");
```
forbid-overrides-permit makes this strictly correct even alongside permits.

### 4.4 deny-all binding

**Legacy:** role has connection `C` with `policy_ids: []` (deny all).
**Migrated:** nothing emitted. Default deny covers it. (Differential: old=DENY,
new=DENY for all ops on `C`.)

---

## 5. Tooling: `sieve iam-migrate`

A subcommand (admin CLI; runs against the live DB read-only by default).

```
sieve iam-migrate                 # dry-run: print Cedar + a per-binding diff + differential report
sieve iam-migrate --out dir/      # write Cedar policy files for review (no DB writes)
sieve iam-migrate --apply         # write iam_* tables; idempotent; prints summary
sieve iam-migrate --verify        # run differential harness only (old vs new), no writes
```

Output of a dry-run:
1. The generated Cedar policy set (annotated with `@id("mig:<role>:<conn>:…")`).
2. A **per-binding diff**: legacy intent vs. emitted statements.
3. A **differential report** (§6): for a generated request corpus, old vs new
   decision, with every divergence classified **intended-P0-fix** /
   **review-required** / **unexpected**.
4. A **manual-port list**: `llm`/`chain` policies, order-dependent/shadowing rule
   chains (§3.1), and any untranslatable matches, with their config.

**Widening requires explicit sign-off (review H2).** Every multi-policy binding
flips from intersection (often deny-all) to union — frequently a *large,
unreviewed* capability grant. These are **not** auto-accepted as "intended-P0-fix":
each multi-policy-binding widening is listed individually under
**review-required**, and `--apply` **refuses** to proceed until each is
acknowledged (an `--accept-widening <binding-id…>` allowlist, or interactive
sign-off). Single-policy bindings that match exactly auto-pass. "Fix the footgun"
must not mean "silently grant whatever the union happens to be."

`--apply` is idempotent (re-running reconciles to the same `iam_*` state) and
never writes `connections`.

---

## 6. Differential verification harness

The safety net that proves the migration.

> **Built + validated (PR-C core).** `internal/iammigrate` translates legacy
> `rules` policies → Cedar, and `internal/iammigrate/migrate_test.go` runs the
> **true differential** — the old `internal/policy` rules evaluator vs the new
> `iam.Engine` on a request corpus — asserting identical decisions. Confirmed:
> the common Operations-based case is decision-equivalent; **H1** (a catch-all
> `deny` rule migrates to default-deny, NOT a catch-all `forbid` — the
> differential would catch a mis-translation because the allowed op would flip to
> deny); rich-match rules (non-`Operations` fields) become manual-port items
> (fail-closed); `ResponseFilter`→filter-library + `@filters`; `DefaultAction:
> allow`→trailing broad permit. The migration *mapping* spec (§3) is thus
> empirically validated; the remaining PR-C work (the `iam_*` storage tables and
> the `sieve iam-migrate` CLI wrapper around this mapping) is mechanical.

- **Request corpus** = (a) every `(role, connection, op)` triple derivable from
  the roles/connections tables, plus (b) representative param sets, plus (c)
  replayed shapes from the **audit log** (real historical `(token→role,
  connection, operation, params)` requests).
- For each request, run the **old** evaluator (`getEvaluator` + `Evaluate`) and
  the **new** `iam.Decide`; compare allow/deny (and, where applicable, the
  obligation set vs. `decision.Filters`).
- Classify each difference:
  - **intended-P0-fix**: a *single-policy* binding where old denied due to
    decorative-scope/phase quirks; new allows the same op set. Auto-pass.
  - **review-required**: a *multi-policy* binding whose union widens access vs the
    old intersection — listed per binding, needs explicit sign-off (§5).
  - **unexpected**: anything else (incl. new *denies* a legit old allow) → blocks
    apply; investigate.
- Runs in CI (against a fixture DB) and as `iam-migrate --verify` against prod
  data before cutover.

---

## 7. Rollout

| Phase | State | Gate to advance |
|---|---|---|
| 0. Land PR-A/B/C | engine + taxonomy + tooling exist; `iam_enabled=off`; legacy live | unit + taxonomy + schema CI green |
| 1. Migrate (shadow) | run `iam-migrate --apply` to populate `iam_*`; engine still off | zero **unexpected** diffs **and** every **review-required** widening signed off |
| 2. Enable (canary) | `iam_enabled=on` for a test token/role; both engines present | explorer + audit show correct determining policies; approval + fail-closed verified |
| 3. Enable (default) | PR-F: flag default on | one release of clean operation; no deny-regression reports |
| 4. Deprecate | remove legacy evaluators (`composite.go` et al.), drop `policies` + `roles.bindings` | legacy unused for a release; `connections` diff empty |

Rollback at any phase ≤3: set `iam_enabled=off`. Legacy tables and code remain
until phase 4.

---

## 8. Data-model deltas

**Added** (all `IF NOT EXISTS`, additive):
```sql
CREATE TABLE iam_policies (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
  cedar_text TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP );

CREATE TABLE iam_filters (                       -- the filter library (§7 spec)
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,                            -- redact | exclude_items | script_guard | script_filter
  config TEXT NOT NULL,                          -- JSON: {patterns:[…]} or {command,path,timeout_ms}
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP );

CREATE TABLE iam_roles (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP );

CREATE TABLE iam_role_groups (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP );
CREATE TABLE iam_role_group_members ( group_id TEXT NOT NULL, role_id TEXT NOT NULL,
  PRIMARY KEY (group_id, role_id) );
```

**Audit** (additive columns):
```sql
ALTER TABLE audit_log ADD COLUMN decision TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN determining_policies TEXT NOT NULL DEFAULT '[]';
```

**Unchanged:** `tokens` (keeps `role_id`), `connections` (untouched — invariant),
`approval`, all connector/secrets tables.

**Removed at phase 4 only:** `policies`, the `roles.bindings` column (the `roles`
table itself is reused as `iam_roles` or migrated 1:1), and `internal/policy`
composition evaluators.

---

## 9. Cutover checklist

- [ ] PR-A/B/C merged; engine unit + taxonomy + schema(Rust-cedar) CI green.
- [ ] `iam-migrate --verify` against prod data: **zero unexpected** diffs;
      intended-P0-fix diffs reviewed + signed off.
- [ ] Manual-port list empty (or each item hand-authored as Cedar + added to the
      corpus).
- [ ] `iam-migrate --apply`; spot-check generated policies in the explorer.
- [ ] Canary token on `iam_enabled=on`: read/write/approval/redaction behave;
      audit shows determining policies.
- [ ] Flag default on (PR-F); one clean release.
- [ ] `connections` table diff empty across the entire series (automated check).
- [ ] Legacy tables + evaluators removed.
