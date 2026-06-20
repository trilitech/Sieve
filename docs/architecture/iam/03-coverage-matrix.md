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

| # | Operator intent | Author (UI) | Enforce (engine) | Gateway-verified | Status |
|---|---|---|---|---|---|
| 1 | Read-only / write split by operation | builder op-scope | ✅ | e2e/iam.spec | ✅ |
| 2 | Scope a role to specific connection(s) | builder connections | ✅ | e2e (unauth-conn deny) | ✅ |
| 3 | Connector-gating (gmail rule ≠ github) | builder (connector) | ✅ | compiler test | 🟡 need gateway |
| 4 | Resource scope (GitHub owner/repo) | builder scopes | ✅ | compiler test | 🟡 need gateway |
| 5 | Param conditions (amount ≤ N, method) | builder conditions | ✅ | compiler test | 🟡 need gateway |
| 6 | Connector-particular cond (gmail domains) | builder condition | ✅ | PDP test | 🟡 need gateway |
| 7 | Require human approval | builder effect | ✅ (api flow) | — | 🟡 need test |
| 8 | Redact fields from responses | **filter lib UI** | ✅ (post machinery) | — | ❌ no UI |
| 9 | Exclude items from responses | **filter lib UI** | ✅ (post machinery) | — | ❌ no UI |
| 10 | **Custom pre-send script guard** (block emails matching X) | **filter lib UI** | ❌ **fail-closed** | — | ❌ THE GAP |
| 11 | Custom post-response script filter | **filter lib UI** | ✅ (post machinery) | — | ❌ no UI |
| 12 | Rate limit (N/min) | — | ❌ fail-closed | — | ❌ implement or hide |
| 13 | Role groups (inherit shared rules) | **UI** | ✅ (engine) | — | ❌ no UI |
| 14 | Enable/disable a rule without deleting | **UI** | ✅ (SetPolicyEnabled) | — | 🟡 no toggle |
| 15 | Edit an existing rule | **UI** | n/a | — | 🟡 delete+recreate only |
| 16 | Custom deny message | builder (adv) | ✅ (@deny_message) | — | 🟡 raw only |
| 17 | Issue token for a role | /tokens page | ✅ | e2e (legacy) | ✅ |
| 18 | Audit of decisions | /audit page | ✅ | — | ✅ |

## Execution order (highest leverage first)
1. **#10 + filter library UI (#8/#9/#11)** — script guards EXECUTE; author redact/exclude/script filters. The open-ended one (#10) is the "arbitrary logic" proof.
2. **Gateway verification sweep (#3/#4/#5/#6/#7)** — prove authored⇒enforced over HTTP, not just unit.
3. **#13 role groups UI**, **#14 enable/disable**, **#15 edit**.
4. **#12 rate-limit**: implement a real limiter or REMOVE it from offerable kinds (no silent stub).
5. **Legacy parity audit** → remove the legacy evaluator (the actual finish line).

Update this file as rows flip to ✅.
