// Package httpguard returns *http.Client values that enforce Sieve's
// outbound SSRF policy for every connector that talks HTTP.
// Guards:
// - AbsoluteDeny: cloud-metadata IPs (169.254.169.254, fd00:ec2::254).
// No allowlist can override these.
// - DefaultDeny: loopback, RFC1918, link-local, multicast, unspecified
// IPv4/IPv6 ranges. Overridable per-connection via ClientOptions.Allowlist.
// - Scheme: only http/https. file://, gopher://, data:, etc. refused.
// - Redirect chain depth: capped (default 5). Each redirect re-validates.
// - DNS rebinding: the dialer re-resolves immediately before connect and
// pins the dial to the validated IP.
// - Cross-origin credential strip: Authorization and Cookie headers are
// stripped when a redirect moves the request to a different origin.
// Used by Sieve's outbound-HTTP connectors. Coverage is connector-by-
// connector: gmail, github, slack, mcpproxy, httpproxy, and anthropic
// build their clients through httpguard.Client; any new connector that
// dials an operator-overridable URL should do the same.
// Connection.Validate calls ValidateURL on registration; the *http.Client
// applies the same checks on every request.
package httpguard
