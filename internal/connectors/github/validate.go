package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ValidatePAT calls GitHub with the given token and confirms the declared
// scope is reachable. For user scope it calls /user and checks the login.
// For org scope it calls /orgs/{name} and checks that the request succeeds.
// Called from the web UI before persisting a new PAT credential.
func ValidatePAT(ctx context.Context, client *http.Client, apiBase, token, scopeType, scopeName string) error {
	if client == nil {
		client = http.DefaultClient
	}
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	var probe string
	switch scopeType {
	case ScopeUser:
		probe = "/user"
	case ScopeOrg:
		probe = "/orgs/" + scopeName
	default:
		return fmt.Errorf("github: unknown scope type %q", scopeType)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+probe, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Sieve-GitHub-Connector")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github: probe failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("github: token rejected (401)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("github: token lacks permissions for %s (403)", scopeName)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github: probe %s returned %d: %s", probe, resp.StatusCode, truncate(string(body), 300))
	}

	if scopeType == ScopeUser {
		var u struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(body, &u); err != nil {
			return fmt.Errorf("github: decode user profile: %w", err)
		}
		if !strings.EqualFold(u.Login, scopeName) {
			return fmt.Errorf("github: token belongs to %q, not %q", u.Login, scopeName)
		}
	}
	return nil
}
