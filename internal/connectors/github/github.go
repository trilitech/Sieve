// Package github implements a Sieve connector for the GitHub REST API.
//
// A single GitHub connection holds one or more credentials (fine-grained PATs
// and/or App installation entries), each scoped to a user or org. Each request
// is routed through extractOwner -> pickCredential to select the appropriate
// bearer; ownerless endpoints (/user, /search/*, /graphql, /notifications)
// fall back to a configured default credential. The escape-hatch
// `github_request` operation surfaces any path/method combination through the
// same auth pipeline so agents can reach uncovered APIs without waiting for
// new curated operations.
package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/murbard/Sieve/internal/connector"
)

// ConnectorType is the type string used in the registry.
const ConnectorType = "github"

// Connector implements connector.Connector for GitHub.
type Connector struct {
	config     *Config
	apiBase    string
	httpClient *http.Client
	appTokens  *appTokenCache
}

// Factory returns a connector.Factory bound to api.github.com.
func Factory() connector.Factory {
	return func(raw map[string]any) (connector.Connector, error) {
		cfg, err := parseConfig(raw)
		if err != nil {
			return nil, err
		}
		hc := newHTTPClient()
		return &Connector{
			config:     cfg,
			apiBase:    defaultAPIBase,
			httpClient: hc,
			appTokens:  newAppTokenCache(hc),
		}, nil
	}
}

// Meta returns connector metadata for registration.
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "GitHub",
		Description: "Read and write GitHub repos, issues, PRs, and more via PAT or GitHub App.",
		Category:    "Developer",
	}
}

func (g *Connector) Type() string                   { return ConnectorType }
func (g *Connector) Operations() []connector.OperationDef { return operations }

// Validate hits /user (or /app for App-only setups) to confirm the first
// credential is live. Avoids hammering GitHub on every call.
func (g *Connector) Validate(ctx context.Context) error {
	if len(g.config.Credentials) == 0 {
		return errors.New("github: no credentials")
	}
	cred := &g.config.Credentials[0]
	probe := "/user"
	if cred.Kind == KindAppInstallation {
		probe = "/installation/repositories"
	}
	resp, err := g.doRequest(ctx, http.MethodGet, probe, nil, nil)
	if err != nil {
		return err
	}
	if resp.Status/100 != 2 {
		return fmt.Errorf("github: validate %s returned %d", probe, resp.Status)
	}
	return nil
}

// Execute dispatches a Sieve operation name to the appropriate handler.
func (g *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "github_request":
		return g.opRequest(ctx, params)
	case "github_list_repos":
		return g.opListRepos(ctx, params)
	case "github_get_file":
		return g.opGetFile(ctx, params)
	case "github_put_file":
		return g.opPutFile(ctx, params)
	case "github_list_issues":
		return g.opListIssues(ctx, params)
	case "github_create_issue":
		return g.opCreateIssue(ctx, params)
	case "github_comment_issue":
		return g.opCommentIssue(ctx, params)
	case "github_list_prs":
		return g.opListPRs(ctx, params)
	case "github_get_pr":
		return g.opGetPR(ctx, params)
	case "github_create_pr":
		return g.opCreatePR(ctx, params)
	case "github_search_code":
		return g.opSearchCode(ctx, params)
	default:
		return nil, fmt.Errorf("github: unknown operation %q", op)
	}
}

// --- helpers for param extraction (mirrors gmail's pattern) ---

func getString(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func requireString(p map[string]any, key string) (string, error) {
	s := getString(p, key)
	if s == "" {
		return "", fmt.Errorf("github: param %q required", key)
	}
	return s, nil
}

func getInt(p map[string]any, key string) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func qFromInt(q url.Values, key string, v int) {
	if v > 0 {
		q.Set(key, fmt.Sprintf("%d", v))
	}
}

func qFromString(q url.Values, key, v string) {
	if v != "" {
		q.Set(key, v)
	}
}
