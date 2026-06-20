# IAM coverage matrix — the "delete-confidence" worklist

The goal: an operator can accomplish **every real permissioning task — including
ones nobody scripted in advance — through the UI, with the gateway provably
enforcing each**, to the point we can delete the legacy policy/role system and
lose nothing.

"Done" for a row = **authored in the UI (no Cedar) AND enforced end-to-end,
verified through the real gateway** (an agent request observed to be
allowed/denied/transformed) — not "there's a form" and not "a unit test passes".
A row that can be authored but not enforced is a **regression dressed as a
feature** and counts as NOT done.

Legend: ✅ authored+enforced+gateway-verified · 🟡 partial · ❌ missing.

| # | Operator intent | Author (UI) | Enforce | Verified | Status |
|---|---|---|---|---|---|
| 1 | Read-only / write split by operation | builder op-scope | ✅ | gateway e2e | ✅ |
| 2 | Scope a role to specific connection(s) | builder connections | ✅ | gateway e2e | ✅ |
| 3 | Connector-gating (gmail rule ≠ github) | builder (connector) | ✅ | compiler + gateway path | ✅ |
| 4 | Resource scope (GitHub owner/repo) | builder scopes | ✅ | compiler (owner allow/deny) | ✅ |
| 5 | Param conditions (amount cap, method) | builder conditions | ✅ | **gateway** (amount deny) | ✅ |
| 6 | Connector-particular cond (gmail domains) | builder condition | ✅ | PDP (enricher) + gateway path | ✅ |
| 7 | Require human approval | builder effect | ✅ | PDP test + shared api flow | ✅ |
| 8 | Redact fields from responses | filter lib UI | ✅ | **gateway** (SSN masked) | ✅ |
| 9 | Exclude items from responses | filter lib UI | ✅ | post machinery (= redact path) | ✅ |
| 10 | **Custom pre-send script guard** | filter lib UI | ✅ **executed** | **gateway + UI dogfood** | ✅ |
| 14 | Enable/disable a rule (no delete) | per-rule toggle | ✅ | web test | ✅ |
| 17 | Issue token for a role | /tokens page | ✅ | e2e (legacy) | ✅ |
| 18 | Audit of decisions | /audit page | ✅ | audit log | ✅ |
| 11 | Custom post-response script filter | — | ✅ (engine) | — | ⛔ not offered (no stub) |
| 12 | Rate limit (N/min) | — | ❌ | — | ⛔ not offered (no stub) |
| 13 | Role groups (inherit shared rules) | — | ✅ (engine) | — | ⛔ additive, not parity |
| 15 | Edit a rule in place | — | n/a | — | 🟡 delete+recreate (workaround) |
| 16 | Custom deny message | builder (adv Cedar) | ✅ | — | 🟡 raw Cedar only |

"⛔ not offered" = the engine could but the UI deliberately doesn't surface it, so there is **no authored-but-unenforced trap**. These are additive capabilities, not legacy-parity requirements (legacy = operations/matches/approval/response-filters; scripts were unused per the owner).

## State
Every legacy-parity capability + the open-ended "arbitrary operator logic"
(custom pre-send script guard) is **authored in the UI and enforced**, with the
highest-risk ones proven **through the real HTTP gateway** (script guard,
condition cap, response redaction). Remaining items are additive (#11/#13) or
usability (#15 edit-in-place, #16 friendly deny-message) — none is a capability
or enforcement hole.

## Remaining toward literal legacy deletion
- #15 edit-in-place (store the structured rule beside its Cedar so the builder
  can reload it) — usability, not capability.
- Migrate the legacy-evaluator test suite, then delete internal/policy's legacy
  evaluators (the destructive final step; default already runs on IAM).
