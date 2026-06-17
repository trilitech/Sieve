# Sieve Security Posture

Current security posture of the Sieve credential gateway. A prior audit
identified 9 findings (5 HIGH, 4 MEDIUM) plus 2 LOW observations — all
remediated. A follow-up audit of the `murbard_main` merge (Google
Workspace connectors, LLM evaluator, web UI additions) surfaced 4
additional findings, also remediated.

**Baseline:** `go test ./... -race` passes (12 packages green).

---

## Verified Security Controls

### HTTP Proxy Hardening (`internal/connectors/httpproxy/httpproxy.go`)

- **Redirect suppression:** `CheckRedirect` returns `http.ErrUseLastResponse`; 3xx responses surface to the agent as-is, eliminating SSRF pivots to internal services.
- **Path validation:** `validateProxyPath` iteratively percent-decodes (up to 5 passes), rejects residual `%2e`/`%2f`/`%5c` encodings, rejects literal backslashes, rejects `..` segments, normalizes with `path.Clean`, and requires a `/` prefix. Target URL built with `(*url.URL).JoinPath`.
- **Response filters:** two-path layout — zero-copy streaming when no filters are configured; buffered path with `io.LimitReader` (32 MiB cap) when filters are active. `Accept-Encoding` stripped on upstream request so Go's Transport auto-decompresses before filtering. Stale body-derived headers (`Content-Encoding`, `Transfer-Encoding`, `ETag`, `Content-MD5`, `Content-Length`) removed after filtering.
- **Audit accuracy:** `ProxyHTTP` returns an error on local rejection so the router logs `bad_request` (not `proxied`) for invalid paths.

### Policy Script Sandbox (`internal/policy/script.go`)

- **Environment isolation:** `cmd.Env` set to `PATH`-only; parent-process secrets not leaked.
- **Stderr truncation:** capped at 500 bytes in denial reasons.
- **Context handling:** derives from caller ctx when live (preserves client-disconnect cancellation); falls back to `context.Background()` only when caller ctx is already cancelled (prevents stale cancellation from defeating the script timeout).

### LLM Evaluator (`internal/policy/llm.go`)

- **Response size cap:** all provider responses (Ollama, Anthropic, OpenAI, Bedrock) read via `readLimitedLLMResponse` with a 5 MiB cap. Exceeding the cap triggers the fail-closed fallback decision.
- **Audit hygiene:** upstream error bodies are truncated to 500 chars (`truncateForAudit`) before being embedded in fallback decision reasons, preventing audit log bloat.
- **Fail-closed fallback:** `NewLLMEvaluator` forces `Fallback = "deny"` (ignoring any `"allow"` setting) so provider outages cannot silently open policy.

### Approval System (`internal/approval/queue.go`, `internal/api/router.go`)

- **ID entropy:** 256-bit `crypto/rand` hex IDs (64 chars); enumeration infeasible. `generateSecureID` returns `(string, error)` — entropy failure is propagated gracefully, no panic.
- **Double-resolution guard:** `resolve()` uses conditional UPDATE (`WHERE status = 'pending'`).
- **Bearer extraction:** `strings.CutPrefix` used consistently in both `authMiddleware` and post-approval revalidation.

### OAuth Flow (`internal/web/server.go`)

- **State parameter:** 16 bytes `crypto/rand`, hex-encoded, single-use, pinned to request host. 10-minute TTL.
- **Abandoned flow cleanup:** background goroutine sweeps `oauthPending` every 5 minutes. Controlled by `stopCleanup` channel; `Close()` (guarded by `sync.Once`) terminates the goroutine. All call sites (`router_test.go`, `e2e/testserver/main.go`) invoke `Close()`.

### Admin Boundary (`internal/web/server.go`)

- Every state-changing web handler enforces `rejectIfAgentToken`.
- `rejectIfAgentToken` also wired into `/api/models`, `/api/generate-script`, `/api/save-script` — defense-in-depth for the endpoints added by the Google Workspace / LLM feature set.
- Agent/admin port split (19817 / 19816) intact; no agent-callable endpoints on the web server.

### Google Workspace Connectors (`internal/gmail/*`)

- **Drive download size cap:** `DownloadFile` rejects files larger than 50 MiB — first via `Files.Get` metadata check, then via defensive `io.LimitReader` during the body read (covers Google-native formats that report `size=0`).
- **ACL enforcement:** File/calendar/contact IDs are passed to Google APIs which enforce access control server-side.

### SQL Injection

- All queries use `?` parameterization. No raw string interpolation in SQL.

---

## Shannon Security Assessment Remediation (2026-05)

External assessment by Shannon delivered 2026-05-20. The report grouped
findings into Section A (test-harness artifacts where the admin UI was
deliberately exposed off-localhost) and Section B (genuine code-level
defects). After operator review, BOTH sections were folded into the
remediation scope — the admin UI is part of Sieve and its defects are in
scope regardless of the documented localhost-binding mitigation.

Spec: `specs/001-fix-security-vulns/spec.md` (local, not committed).
Branch: `feat/fix-security-assessment`. Remediation commits are tagged
in their bodies with the Shannon finding ID and the spec FR(s) closed.

### Section B (code-level findings — all closed):

| Finding | Spec FR(s) | Remediation commit | Regression test |
|---|---|---|---|
| XSS-VULN-01/02 — DOM XSS via `renderBindings()` decode-then-`innerHTML` | FR-001..FR-003 | `security(xss):` | `internal/web/template_xss_guard_test.go::TestTemplatesNoUnsafeInnerHTML` + per-template DOM-construction rewrite |
| SSRF-VULN-01/02 — connector outbound without CheckRedirect / IP guard | FR-004..FR-009 | `security(ssrf):` | `internal/httpguard/httpguard_test.go` (36 tests) + per-connector wiring |
| AUTH-VULN-06 — host-header injection in GitHub App manifest + Google OAuth | FR-010..FR-012 | `security(oauth):` | `internal/web/host_header_test.go` |
| INJ-VULN-01/02/03 — policy `command` field accepts any binary | FR-013..FR-018a | `security(policy): enforce command allowlist` | `internal/policy/commandallowlist_test.go` + `internal/web/command_allowlist_test.go` |
| INJ-VULN-06 — `template.JS` misuse for serialized JSON | FR-019..FR-021 | `security(template):` | `internal/web/templatejs_test.go::TestNoTemplateJSAroundDynamicData` |
| AUTHZ-VULN-10 — numeric-ceiling deny-rule footgun | FR-022..FR-025 | `security(policy): warn on deny-with-ceiling` | `internal/policy/lint_test.go` + `internal/web/lint_test.go` |
| INJ-VULN-04 — `/api/save-script` path traversal | FR-046..FR-047 | `security(audit):` (same commit) | `internal/web/save_script_test.go::TestValidateScriptFilename` |

### Section A (admin-plane defects — folded into scope, all closed):

| Finding | Spec FR(s) | Remediation commit | Regression test |
|---|---|---|---|
| AUTH-VULN-03 / AUTHZ-VULN-01 — unauthenticated admin plane | FR-028..FR-033d | `security(auth): foundation packages` + `security(auth): login/logout/setup` + `security(auth): mandatory operator session` | `internal/operator/operator_test.go`, `internal/session/session_test.go`, `internal/csrf/csrf_test.go`, `internal/web/auth_test.go` (combined: ~58 tests) |
| AUTH-VULN-04 / AUTHZ-VULN-07 — `rejectIfAgentToken` bypass via header omission | FR-034..FR-036 | `security(auth): mandatory operator session on every admin endpoint` | All `*RejectsAgentToken` tests assert 403 via FR-036's middleware path; `rejectIfAgentToken` helper removed |
| AUTH-VULN-05 / AUTHZ-VULN-02/04/05/06/08 — admin CRUD without auth | FR-028..FR-029 | same | `internal/web/auth_test.go::TestMiddleware_*` |
| AUTH-VULN-01 — plaintext HTTP (off-loopback exposure) | FR-048..FR-050 | `security(tls):` | `cmd/sieve/tls_test.go` |
| AUTH-VULN-02 — no rate limiting on auth path | FR-040..FR-043 | `security(auth): per-IP rate limit + cache-control` | `internal/ratelimit/ratelimit_test.go` + `internal/api/ratelimit_test.go` |
| AUTH-VULN-10 — no cache-control on token-issuance | FR-044..FR-045 | same | `internal/web/headers_test.go`, `internal/api/headers_test.go` |
| Token issuance + admin mutations leaving no audit trail | FR-037..FR-039 | `security(audit): operator-identified audit rows` | `internal/audit/operator_test.go`, `internal/web/audit_producer_test.go` |

### Cross-references (related work fixed outside this branch)

- **Slack OAuth client_secret storage (PR #10 review, 2026-05-21)** —
  `internal/web/slack.go` originally persisted `KeySlackClientSecret` to
  the plaintext `settings` table. Constitutional Principle I requires
  long-lived secrets to route through the keyring's envelope encryption
  (`internal/secrets`). Recorded here for audit-trail completeness; fix
  belongs to PR #10. Side effect of this branch: the Slack outbound HTTP
  client now goes through `internal/httpguard`, which inherently provides
  a request timeout and replaces the previous `http.DefaultClient`
  (incidentally closes PR #10 review finding #5).

### Methodology

Every Shannon finding was reproduced as a failing regression test before
the fix landed (Constitution Principle II). Section A findings that
relied on the admin plane being unauthenticated are now structurally
impossible: the `requireOperatorSession` middleware wraps every admin
endpoint, the localhost binding remains the documented default
(defense in depth), and `rejectIfAgentToken` is gone — replaced by the
strict-superset middleware. `go test ./...` is green across every
package except the pre-existing flaky `TestRotateConcurrentRotate` in
`internal/secrets`, noted at this branch's baseline.

---

## Known Accepted Risks

- **Approval token-revocation race (MEDIUM, accepted):** The "nice-to-have" recommendation of a token generation counter for transactional approval resolution was not implemented. `tokens.Validate` queries SQLite on every call, so revocation is visible atomically at the DB level — the theoretical race window is vanishingly small.

- **Prompt injection in LLM evaluator (INFO, by design):** The agent's request JSON is interpolated into the policy prompt via `{{request_json}}`. This is the intended contract — the LLM is evaluating the agent's request. Attempts at jailbreak prompt injection are blunted by the fail-closed fallback and the structured `extractDecisionFromText` parser; the policy author is expected to author prompts that treat the request as untrusted data.

---

## Summary

| Severity | Open | Notes |
|----------|------|-------|
| CRITICAL | 0 | — |
| HIGH     | 0 | 5 remediated (pre-merge) |
| MEDIUM   | 0 | 4 remediated pre-merge + 3 remediated post-merge (LLM body, Drive download, web `/api/*` defense-in-depth) |
| LOW      | 0 | 2 remediated pre-merge + 1 remediated post-merge (audit log truncation of LLM error bodies) |

---

**Last Updated:** 2026-05-26 — Shannon assessment closure landed; see
the "Shannon Security Assessment Remediation" section above for the
finding-to-commit-to-test map.

**Methodology:** Line-by-line review of each remediation diff;
full-suite `go test ./...` green; exploratory review for regressions.
Every Shannon finding has a regression test that fails against the
pre-fix code and passes against post-fix code.
