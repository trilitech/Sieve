package web_test

// Regression test for the synthetic "version_control" connector-tab
// filter that groups github + gitlab cards (and existing github/gitlab
// connections) under one /connections sub-page. Lives next to the
// parallel /policies?scope=version_control test so a future refactor
// can't silently drop either branch of the filter.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	gitlabconn "github.com/trilitech/Sieve/internal/connectors/gitlab"
)

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

	// Seed one connection per connector type. Config payloads are
	// intentionally empty: the filter under test keys off
	// ConnectorType + display name, not the connector's typed config
	// schema, and a too-specific seed would tie the test to a
	// schema that may evolve.
	if err := env.Connections.Add("my-github", "github", "My GitHub", map[string]any{}); err != nil {
		t.Fatalf("add github connection: %v", err)
	}
	if err := env.Connections.Add("my-gitlab", "gitlab", "My GitLab", map[string]any{}); err != nil {
		t.Fatalf("add gitlab connection: %v", err)
	}
	if err := env.Connections.Add("my-mock", "mock", "My Mock", map[string]any{}); err != nil {
		t.Fatalf("add mock connection: %v", err)
	}
	// Negative control: an http_proxy whose config.category is set to
	// "github" must NOT appear under ?type=version_control. The filter
	// keys off ConnectorType (immutable) rather than the per-connection
	// category override, so this stays excluded.
	if err := env.Connections.Add("fake-vcs-proxy", "http_proxy", "Fake VCS Proxy", map[string]any{
		"target_url": "https://example.com",
		"category":   "github",
	}); err != nil {
		t.Fatalf("add fake-vcs proxy: %v", err)
	}

	t.Run("version_control tab shows both catalog cards + both connections", func(t *testing.T) {
		rec := getRequest(handler, env, "/connections?type=version_control")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		// Catalog cards: the page renders each connector card by
		// emitting both the connector's Meta().Name (in an h4) and its
		// Meta().Description (in a sibling p). Pin both Name strings —
		// the Name is the load-bearing label and is stable text.
		// "GitLab" alone is too soft a probe (it also appears in the
		// connection-row display name), so we also pin a Description
		// substring per connector so a regression that removed the
		// catalog cards while leaving the connection list intact would
		// fail.
		for _, want := range []string{
			"My GitHub",         // existing connection display name
			"My GitLab",         // existing connection display name
			"PAT or GitHub App", // GitHub Meta() Description substring
			"merge requests",    // GitLab Meta() Description substring
		} {
			if !strings.Contains(body, want) {
				t.Errorf("version_control tab missing %q", want)
			}
		}
		if strings.Contains(body, "My Mock") {
			t.Errorf("version_control tab incorrectly includes non-VCS connection 'My Mock'")
		}
		// An http_proxy with config.category="github" must NOT slip
		// into the version_control tab — the filter keys off the
		// immutable ConnectorType, not the per-connection override.
		if strings.Contains(body, "Fake VCS Proxy") {
			t.Errorf("version_control tab incorrectly includes an http_proxy whose config.category is forged to 'github'")
		}
	})

	t.Run("github tab excludes gitlab", func(t *testing.T) {
		rec := getRequest(handler, env, "/connections?type=github")
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
		rec := getRequest(handler, env, "/connections?type=gitlab")
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
