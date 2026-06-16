// Package gitlab implements a Sieve connector for the GitLab REST API
// (https://docs.gitlab.com/ee/api/).
//
// A single GitLab connection holds one personal access token (or OAuth
// token) and an optional base URL for self-hosted instances. The token
// is attached to every outbound call via the PRIVATE-TOKEN header.
//
// The escape-hatch `gitlab_request` operation surfaces any /api/v4
// path/method combination through the same auth pipeline so agents can
// reach uncovered endpoints without waiting for new curated operations.
//
// Project identifiers in GitLab can be either a numeric ID (string of
// digits) or a URL-encoded namespaced path ("group/subgroup/project").
// All curated ops accept either form in the `project` param; the
// helpers in ops.go percent-encode the literal slashes when forwarding.
package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trilitech/Sieve/internal/connector"
)

// ConnectorType is the type string used in the registry.
const ConnectorType = "gitlab"

// Connector implements connector.Connector for GitLab.
type Connector struct {
	config     *Config
	httpClient *http.Client
}

// Factory returns a connector.Factory.
func Factory() connector.Factory {
	return func(raw map[string]any) (connector.Connector, error) {
		cfg, err := parseConfig(raw)
		if err != nil {
			return nil, err
		}
		return &Connector{
			config:     cfg,
			httpClient: newHTTPClient(),
		}, nil
	}
}

// Meta returns connector metadata for registration.
//
// SetupFields drive the generic data-driven create + edit forms. The
// `token` field is Secret (never echoed back on edit) and Required at
// create; `base_url` is optional and defaults to https://gitlab.com.
func Meta() connector.ConnectorMeta {
	return connector.ConnectorMeta{
		Type:        ConnectorType,
		Name:        "GitLab",
		Description: "Read and write GitLab projects, files, issues, and merge requests via personal access token.",
		Category:    "Developer",
		SetupFields: []connector.Field{
			{
				Name:        "token",
				Label:       "Personal Access Token",
				Type:        "password",
				Required:    true,
				Editable:    true,
				Secret:      true,
				Placeholder: "glpat-...",
				HelpText:    "GitLab PAT. Needs the api scope for full functionality, or read_api for read-only. Leave blank on edit to keep the stored value.",
			},
			{
				Name:        "base_url",
				Label:       "Base URL",
				Type:        "text",
				Required:    false,
				Editable:    true,
				Placeholder: defaultBaseURL,
				HelpText:    "Override for self-hosted GitLab instances (e.g. https://gitlab.example.com). Leave blank for gitlab.com.",
			},
		},
	}
}

func (g *Connector) Type() string                         { return ConnectorType }
func (g *Connector) Operations() []connector.OperationDef { return operations }

// Validate confirms the token works by calling /user, the cheapest
// authenticated endpoint that doesn't require knowing a project ID.
//
// Semantics match the anthropic connector (post-#19 review):
// Validate returns ErrNeedsReauth ONLY when the token is rejected
// (401/403). Any other outcome — 5xx, transient network errors,
// unexpected shapes — leaves Validate succeeding so a transient outage
// doesn't block saving the connection. The error will repeat on first
// agent call and surface in the audit log there.
func (g *Connector) Validate(ctx context.Context) error {
	resp, err := g.doRequest(ctx, http.MethodGet, "/user", nil, nil)
	if err != nil {
		// Transport error: don't refuse the save. Surface on first
		// agent call.
		return nil
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return fmt.Errorf("gitlab: token rejected by %s (status %d): %w",
			g.config.BaseURL, resp.Status, connector.ErrNeedsReauth)
	}
	return nil
}

// Execute dispatches a Sieve operation name to the appropriate handler.
func (g *Connector) Execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "gitlab_request":
		return g.opRequest(ctx, params)
	case "gitlab_list_projects":
		return g.opListProjects(ctx, params)
	case "gitlab_get_file":
		return g.opGetFile(ctx, params)
	case "gitlab_put_file":
		return g.opPutFile(ctx, params)
	case "gitlab_list_issues":
		return g.opListIssues(ctx, params)
	case "gitlab_create_issue":
		return g.opCreateIssue(ctx, params)
	case "gitlab_comment_issue":
		return g.opCommentIssue(ctx, params)
	case "gitlab_list_mrs":
		return g.opListMRs(ctx, params)
	case "gitlab_get_mr":
		return g.opGetMR(ctx, params)
	case "gitlab_create_mr":
		return g.opCreateMR(ctx, params)
	case "gitlab_search_blobs":
		return g.opSearchBlobs(ctx, params)
	default:
		return nil, fmt.Errorf("gitlab: unknown operation %q", op)
	}
}

// --- param-extraction helpers (mirror github connector pattern) ---

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
		return "", fmt.Errorf("gitlab: param %q required", key)
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
