// Package ratelimit is a per-key constant-refill token-bucket limiter
// used by Sieve's authentication paths.
//
// Default parameters (configurable via settings):
//   - capacity = 10 tokens (max consecutive failures before refusal)
//   - refill   = 1 token per 6 seconds (10 failures per 60-second window)
//
// Successful authentications refund the consumed token via Refund(key) so
// legitimate high-throughput agents are not penalized for transient
// auth-failure bursts. An LRU bound (default 10000 keys) prevents memory
// exhaustion from spray attacks.
//
// Used by:
//   - internal/api authMiddleware (bearer token validation on port 19817).
//   - internal/web login handler (operator credential verification on 19816).
package ratelimit
