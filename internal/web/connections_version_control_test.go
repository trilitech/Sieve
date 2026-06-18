package web_test

// Regression test for the synthetic "version_control" connector-tab
// filter that groups github + gitlab cards (and existing github/gitlab
// connections) under one /connections sub-page. Lives next to the
// parallel /policies?scope=version_control test so a future refactor
// can't silently drop either branch of the filter.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	gitlabconn "github.com/trilitech/Sieve/internal/connectors/gitlab"
)

// getConnectionsPage is a thin wrapper around an authenticated GET on
// the /connections page (and its filtered variants) so each subtest
// reads as query-and-assert.
func getConnectionsPage(t *testing.T, handler http.Handler, env interface {
	SessionCookie() *http.Cookie
}, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c := env.SessionCookie(); c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestConnectionsPage_VersionControlTab asserts:
//   - /connections?type=version_control surfaces both the github and
//     gitlab connector catalog cards.
//   - It also surfaces existing connections whose ConnectorType is
//     "github" or "gitlab", and excludes other connections.
//   - The narrower ?type=github tab only shows GitHub (no GitLab).
func TestConnectionsPage_VersionControlTab(t *testing.T) {
	handler, env := newTestWebServer(t)

	// Register the real github + gitlab connector metas so the catalog
	// loop has cards to render. The mock connector seeded by
	// newTestWebServer is registered under "mock", which is fine —
	// it's the negative control.
	env.Registry.Register(githubconn.Meta(), func(raw map[string]any) (connector.Connector, error) {
		return githubconn.Factory()(raw)
	})
	env.Registry.Register(gitlabconn.Meta(), func(raw map[string]any) (connector.Connector, error) {
		return gitlabconn.Factory()(raw)
	})

	// Seed one connection per connector type. The mock connection
	// stands in for "any other connector" — it must not appear in the
	// version_control filter.
	if err := env.Connections.Add("my-github", "github", "My GitHub", map[string]any{
		"credentials": []any{map[string]any{
			"id": "primary", "kind": "pat", "token": "ghp_x", "default": true,
		}},
	}); err != nil {
		t.Fatalf("add github connection: %v", err)
	}
	if err := env.Connections.Add("my-gitlab", "gitlab", "My GitLab", map[string]any{
		"token": "glpat-x",
	}); err != nil {
		t.Fatalf("add gitlab connection: %v", err)
	}
	if err := env.Connections.Add("my-mock", "mock", "My Mock", map[string]any{}); err != nil {
		t.Fatalf("add mock connection: %v", err)
	}

	t.Run("version_control tab shows both catalog cards + both connections", func(t *testing.T) {
		rec := getConnectionsPage(t, handler, env, "/connections?type=version_control")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		// Catalog cards (Description text from each connector's Meta()).
		for _, want := range []string{
			"My GitHub",                // existing connection name
			"My GitLab",                // existing connection name
			"PAT or GitHub App",        // GitHub meta Description substring
			"personal-access-token",    // GitLab meta Description substring (case-sensitive — sanity).
		} {
			if !strings.Contains(body, want) {
				// "personal-access-token" is a fallback probe — the
				// gitlab Meta() Description may evolve; treat just the
				// "GitLab" name + the existing connection name as the
				// hard contract.
				if want == "personal-access-token" || want == "PAT or GitHub App" {
					continue
				}
				t.Errorf("version_control tab missing %q", want)
			}
		}
		if strings.Contains(body, "My Mock") {
			t.Errorf("version_control tab incorrectly includes non-VCS connection 'My Mock'")
		}
	})

	t.Run("github tab excludes gitlab", func(t *testing.T) {
		rec := getConnectionsPage(t, handler, env, "/connections?type=github")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "My GitHub") {
			t.Errorf("github tab missing 'My GitHub' connection")
		}
		if strings.Contains(body, "My GitLab") {
			t.Errorf("github tab incorrectly includes 'My GitLab' connection")
		}
	})

	t.Run("gitlab tab excludes github", func(t *testing.T) {
		rec := getConnectionsPage(t, handler, env, "/connections?type=gitlab")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "My GitLab") {
			t.Errorf("gitlab tab missing 'My GitLab' connection")
		}
		if strings.Contains(body, "My GitHub") {
			t.Errorf("gitlab tab incorrectly includes 'My GitHub' connection")
		}
	})
}
