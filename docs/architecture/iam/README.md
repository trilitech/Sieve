# Sieve IAM rework

This directory specifies the replacement of Sieve's policy/role authorization
layer with an **ABAC engine built on [Cedar](https://www.cedarpolicy.com/)**,
grounded in **NIST SP 800-162** (Attribute-Based Access Control).

It exists because the current model — a global policy catalog, multi-attach
bindings, AND-of-default-deny composition, and a decorative `scope` field — is a
half-built IAM whose pieces are individually defensible but combine into a
footgun. The downstream field report in `FEEDBACK_from_tezos_ops.md` (P0) is the
proximate trigger: attaching a policy to *add* capability silently *removed* it.

## The three documents

| Doc | Audience | What it answers |
|---|---|---|
| [`01-spec.md`](01-spec.md) | designers, reviewers | What the system *is*: the conceptual model, the Cedar mapping, evaluation + obligation semantics, the schema, worked examples. Design-locked before code. |
| [`02-implementation-plan.md`](02-implementation-plan.md) | implementers | How we build it: package layout, the cedar-go dependency decision, connector taxonomy wiring, the PEP refactor, testing, feature-flagging, PR sequence. |
| [`03-migration-plan.md`](03-migration-plan.md) | operators, implementers | How we move without breaking: current-state inventory, mapping rules, the `sieve iam-migrate` tool, differential verification, rollout/rollback. |

## Hard invariants (carried through every document)

1. **Credentials are never touched.** The `connections` table — and every PAT,
   OAuth token, and bot token in it — survives the refactor byte-for-byte. This
   rework is wholly upstream of credential storage. (User constraint: "getting
   PAT and api keys is a pain in the ass.")
2. **Fail closed.** Default deny; evaluation errors deny; obligation failures
   deny the *response* (an un-redacted result never reaches the agent).
3. **Reversible.** A feature flag selects engine; legacy tables persist through
   an overlap window; rollback is one setting.

## One-paragraph summary of the target

A request is `(token, operation, params)` on a connection. Sieve resolves it to
a Cedar **Request** `(principal=Token, action=Operation, resource=Object,
context=enriched-environment)`, evaluates it against the union of all enabled
Cedar policies (deny-overrides-permit, default-deny), and reads **obligations**
off the annotations of the policies that determined an *allow*. Roles are Cedar
principal groups; the connection is a resource container; per-connector object
types descend from it so one policy can target a single object, a whole
connection, or an entire connector. The incoherent multi-attach intersection is
gone: more policies can only ever *add* capability, except explicit `forbid`,
which always wins.

Three deliberate choices make the model opinionated:

- **Reuse via set-valued scopes — one artifact.** Cedar `principal`/`resource`
  scopes are sets, so one policy can list many connections/roles. "Reuse my complex
  Gmail policy on another account" = add that connection to the policy's resource
  set (the admin UI's "apply to connection" gesture); single-source, no drift. No
  templates, no links, no linker. **Connector-safety:** schema validation +
  a connector-aware "apply to connection" guard make it impossible to apply a
  Gmail-action policy to a GitHub connection (the actions don't apply to that
  connector's resources). Presets are shipped example policies you apply the same
  way.
- **Filters are the reusable obligation library.** Named, first-class
  redaction/exclusion *or* scripts (pre-execution **guards** and post-execution
  **response transforms**), referenced by name from any policy.
- **Obligations can only subtract.** Cedar is the sole source of *allow*; an
  approval, a guard, or a filter can only deny or transform, never grant. So
  adding any obligation — even an arbitrary script — is always safe.
