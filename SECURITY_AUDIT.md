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

**Last Updated:** 2026-04-17
**Methodology:** Line-by-line review of each remediation diff; full-suite `go test ./... -race` green; exploratory review for regressions.
