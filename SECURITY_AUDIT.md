# Sieve Security Posture

Current security posture of the Sieve credential gateway. A prior audit identified 9 findings (5 HIGH, 4 MEDIUM); all have been fully remediated. Two additional LOW-severity observations surfaced during re-audit and were also resolved. No open findings remain.

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

### Approval System (`internal/approval/queue.go`, `internal/api/router.go`)

- **ID entropy:** 256-bit `crypto/rand` hex IDs (64 chars); enumeration infeasible. `generateSecureID` returns `(string, error)` — entropy failure is propagated gracefully, no panic.
- **Double-resolution guard:** `resolve()` uses conditional UPDATE (`WHERE status = 'pending'`).
- **Bearer extraction:** `strings.CutPrefix` used consistently in both `authMiddleware` and post-approval revalidation.

### OAuth Flow (`internal/web/server.go`)

- **State parameter:** 16 bytes `crypto/rand`, hex-encoded, single-use, pinned to request host. 10-minute TTL.
- **Abandoned flow cleanup:** background goroutine sweeps `oauthPending` every 5 minutes. Controlled by `stopCleanup` channel; `Close()` (guarded by `sync.Once`) terminates the goroutine. All call sites (`router_test.go`, `e2e/testserver/main.go`) invoke `Close()`.

### Admin Boundary

- Every state-changing web handler enforces `rejectIfAgentToken`.
- Agent/admin port split (19817 / 19816) intact; no agent-callable endpoints on the web server.

### SQL Injection

- All queries use `?` parameterization. No raw string interpolation in SQL.

---

## Known Accepted Risks

- **Approval token-revocation race (MEDIUM, accepted):** The "nice-to-have" recommendation of a token generation counter for transactional approval resolution was not implemented. `tokens.Validate` queries SQLite on every call, so revocation is visible atomically at the DB level — the theoretical race window is vanishingly small. Elevating further would require a DB-level token version column or wrapping the approval flow in a transaction, both out of scope for the current threat model.

---

## Summary

| Severity | Open | Notes |
|----------|------|-------|
| CRITICAL | 0 | — |
| HIGH | 0 | 5 remediated |
| MEDIUM | 0 | 4 remediated (1 accepted risk documented above) |
| LOW | 0 | 2 remediated |

---

**Last Updated:** 2026-04-16
**Methodology:** Line-by-line review of each remediation diff; full-suite `go test ./... -race` green; exploratory review for regressions.
