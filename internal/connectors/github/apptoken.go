package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// appTokenCacheEntry holds a cached installation access token.
type appTokenCacheEntry struct {
	token   string
	expires time.Time
}

// appTokenKey identifies a cache entry. Including AppID guards against a
// (vanishingly unlikely) installation ID collision across two different Apps
// configured in the same connection.
type appTokenKey struct {
	appID          int64
	installationID int64
}

// appTokenCache stores installation tokens and refreshes them lazily when
// nearing expiry. Safe for concurrent use.
type appTokenCache struct {
	mu      sync.Mutex
	entries map[appTokenKey]appTokenCacheEntry
	now     func() time.Time // override in tests
	apiBase string           // override in tests; defaults to https://api.github.com
	doer    httpDoer         // shares the connector's hardened http.Client
}

func newAppTokenCache(doer httpDoer) *appTokenCache {
	return &appTokenCache{
		entries: make(map[appTokenKey]appTokenCacheEntry),
		now:     time.Now,
		apiBase: defaultAPIBase,
		doer:    doer,
	}
}

// installationToken returns a valid installation access token for the given
// credential, minting (or refreshing) one if no cached token has at least
// `refreshSlack` left before expiry. The mutex is held only for cache reads
// and writes; the JWT signing and network exchange happen outside the lock so
// concurrent requests for different installations are not serialized.
func (c *appTokenCache) installationToken(ctx context.Context, cred *Credential) (string, error) {
	const refreshSlack = 5 * time.Minute

	key := appTokenKey{appID: cred.AppID, installationID: cred.InstallationID}

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Add(refreshSlack).Before(e.expires) {
		c.mu.Unlock()
		return e.token, nil
	}
	c.mu.Unlock()

	// Sign the JWT and exchange for an installation token outside the lock.
	// Two concurrent callers may both reach this point for the same key; the
	// result is at most one redundant mint (the second write wins in the cache).
	jwt, err := signAppJWT(cred.AppID, cred.PrivateKeyPEM, c.now())
	if err != nil {
		return "", err
	}

	tok, exp, err := exchangeJWT(ctx, c.doer, c.apiBase, cred.InstallationID, jwt)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.entries[key] = appTokenCacheEntry{token: tok, expires: exp}
	c.mu.Unlock()
	return tok, nil
}

// SignAppJWT is the exported entry point for callers outside this package
// (e.g. the web UI's installation-scope lookup) that need to sign a GitHub
// App JWT without constructing a full Connector.
func SignAppJWT(appID int64, pemKey string, now time.Time) (string, error) {
	return signAppJWT(appID, pemKey, now)
}

// signAppJWT builds an RS256-signed JWT suitable for GitHub App authentication.
// iat is set 60s in the past to tolerate clock skew, per GitHub's recommendation.
func signAppJWT(appID int64, pemKey string, now time.Time) (string, error) {
	priv, err := parseRSAPrivateKey(pemKey)
	if err != nil {
		return "", err
	}

	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(), // GitHub max is 10min
		"iss": strconv.FormatInt(appID, 10),
	}

	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)

	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("github: invalid PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: parse private key: %w", err)
	}
	rsaKey, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("github: private key is %T, want *rsa.PrivateKey", k8)
	}
	return rsaKey, nil
}

// exchangeJWT calls POST /app/installations/{id}/access_tokens to mint a
// short-lived installation access token.
func exchangeJWT(ctx context.Context, doer httpDoer, apiBase string, installationID int64, jwt string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBase, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Sieve-GitHub-Connector")

	resp, err := doer.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", time.Time{}, fmt.Errorf("mint installation token: status %d: %s", resp.StatusCode, truncate(string(body), 500))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode installation token: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("installation token response missing token")
	}
	return out.Token, out.ExpiresAt, nil
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Truncate caps a string for safe inclusion in error messages and audit logs.
// Mirrors the LLM evaluator pattern from the post-merge security audit.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func truncate(s string, n int) string { return Truncate(s, n) }
