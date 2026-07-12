package main

// Architecture invariant: every key a connector persists in its config MUST
// be declared as a SetupField on its ConnectorMeta. This is the test that
// makes "edit shows different fields than create" mechanically impossible —
// if a bespoke create flow (Google OAuth, GitHub PAT/App, Slack OAuth) writes
// a key that's not declared, this test fails and the connector author must
// either add the SetupField (typically Editable=false + EditOnly=true if the
// generic forms shouldn't render it) or stop writing the key.
//
// History: PR #21 ("data-drive connection forms from connector.SetupFields")
// unified the generic create/edit path but explicitly carved out bespoke
// flows. The carve-out reopened the drift class for GitHub, Slack, and
// Google. This test closes the loophole by enforcing the invariant at the
// registry level — no per-connector opt-out is possible.
//
// Mechanism: EVERY connector — typed-Config or map-based — must implement
// connector.ConfigSchemaProvider on its main type and return the literal
// set of keys it reads from its persisted config map. The test walks the
// registry, calls Factory on each, type-asserts the provider, and compares
// ConfigSchemaKeys() against Meta().SetupFields names.
//
// An earlier draft of this test let map-based connectors (httpproxy,
// mcpproxy) skip the provider check on the theory that "their persisted
// keys come from SetupFields-driven form parsing by construction." Codex
// caught the flaw: both factories ALSO consume outbound_allowlist (read
// directly from the config map, not from a SetupFields-rendered form
// input) for the httpguard CIDR opt-in. The vacuous-skip path let that
// drift through. Every connector implements the provider now; there is no
// opt-out.

import (
	"sort"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	anthropicconn "github.com/trilitech/Sieve/internal/connectors/anthropic"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	gitlabconn "github.com/trilitech/Sieve/internal/connectors/gitlab"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/connectors/mcpproxy"
	notionconn "github.com/trilitech/Sieve/internal/connectors/notion"
	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
)

// connectorRegistration mirrors one Register() call in main.go's
// production wiring, plus a synthetic factory-input config that the test
// can hand to the connector's Factory to obtain an instance. The input
// config is intentionally minimal — just enough to pass parseConfig's
// validate gates so we can call ConfigSchemaKeys() on the result.
type connectorRegistration struct {
	meta connector.ConnectorMeta
	fac  connector.Factory
	// sampleConfig is fed to the factory to obtain a concrete instance.
	// Must include every Required field on Meta().SetupFields with a
	// validation-passing value; non-required keys are optional. If the
	// factory itself doesn't need a non-empty value (e.g. anthropic
	// rejects malformed api_key), include it here.
	sampleConfig map[string]any
}

// allConnectors returns every connector that ships with sieve. Adding a new
// connector requires appending here AND adding it to main.go's registry.go
// wiring — keep them in sync. The duplication is intentional: this test
// would be useless if it shared its registration list with production
// (it'd be unable to detect a connector that was added to one but not
// the other).
func allConnectors(t *testing.T) []connectorRegistration {
	t.Helper()
	return []connectorRegistration{
		{
			meta: gmail.Meta,
			fac:  gmail.Factory,
			sampleConfig: map[string]any{
				"email": "test@example.com",
				"oauth_token": map[string]any{
					"access_token":  "ya29.test",
					"refresh_token": "1//test",
					"token_type":    "Bearer",
					"expiry":        "2099-01-01T00:00:00Z",
				},
				"client_id":     "test-client-id.apps.googleusercontent.com",
				"client_secret": "test-secret",
			},
		},
		{
			meta: httpproxy.Meta,
			fac:  httpproxy.Factory,
			sampleConfig: map[string]any{
				"target_url":  "https://api.example.com",
				"auth_header": "Authorization",
				"auth_value":  "Bearer test",
			},
		},
		{
			meta: mcpproxy.Meta,
			fac:  mcpproxy.Factory,
			sampleConfig: map[string]any{
				"url":  "https://mcp.example.com",
				"name": "test",
			},
		},
		{
			meta: githubconn.Meta(),
			fac:  githubconn.Factory(),
			sampleConfig: map[string]any{
				"credentials": []any{
					map[string]any{
						"kind":  "fpat",
						"scope": map[string]any{"type": "user", "name": "testuser"},
						"token": "github_pat_test",
					},
				},
			},
		},
		{
			meta: slackconn.Meta(),
			fac:  slackconn.Factory(),
			sampleConfig: map[string]any{
				"auth_kind": "token",
				"bot_token": "xoxb-test-token",
			},
		},
		{
			meta: anthropicconn.Meta(),
			fac:  anthropicconn.Factory(),
			sampleConfig: map[string]any{
				"api_key": "sk-ant-test-key",
			},
		},
		{
			meta: gitlabconn.Meta(),
			fac:  gitlabconn.Factory(),
			sampleConfig: map[string]any{
				"token": "glpat-test",
			},
		},
		{
			meta: notionconn.Meta(),
			fac:  notionconn.Factory(),
			sampleConfig: map[string]any{
				"api_key": "ntn_test",
			},
		},
	}
}

// TestConnectorConfigCoveredBySetupFields enforces the architectural
// invariant. For every connector that implements
// connector.ConfigSchemaProvider, every key in ConfigSchemaKeys() must
// also appear as a SetupField name on the same connector's Meta().
//
// Failure modes this catches:
//   - A bespoke create flow writes a new config key without adding the
//     corresponding SetupField (the exact drift PR #21 was meant to
//     prevent and that GitHub re-introduced by being exempted).
//   - A typed Config struct grows a new JSON-tagged field without the
//     Meta being updated.
//   - A connector forgot to implement ConfigSchemaProvider but persists
//     keys outside its SetupFields.
func TestConnectorConfigCoveredBySetupFields(t *testing.T) {
	for _, reg := range allConnectors(t) {
		t.Run(reg.meta.Type, func(t *testing.T) {
			c, err := reg.fac(reg.sampleConfig)
			if err != nil {
				t.Fatalf("factory(sampleConfig) failed: %v — fix the sampleConfig in registry_arch_test.go", err)
			}
			provider, ok := c.(connector.ConfigSchemaProvider)
			if !ok {
				t.Fatalf("%s does not implement ConfigSchemaProvider — every connector must, including map-based ones. See the test file's header comment for rationale.", reg.meta.Type)
			}

			declared := make(map[string]bool, len(reg.meta.SetupFields))
			for _, f := range reg.meta.SetupFields {
				declared[f.Name] = true
			}

			persistedKeys := provider.ConfigSchemaKeys()
			sort.Strings(persistedKeys)

			missing := make([]string, 0)
			for _, k := range persistedKeys {
				if !declared[k] {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				t.Errorf(
					"%s persists keys not declared as SetupFields: %s\n"+
						"\nEvery key the connector writes to its persisted Config MUST be declared\n"+
						"on Meta().SetupFields, even when set by a bespoke flow. Mark fields with\n"+
						"Editable=false + EditOnly=true if the generic forms shouldn't render them.\n"+
						"\nDeclared SetupFields: %s\n"+
						"ConfigSchemaKeys():   %s\n",
					reg.meta.Type,
					strings.Join(missing, ", "),
					sortedKeys(declared),
					strings.Join(persistedKeys, ", "),
				)
			}
		})
	}
}

// sortedKeys returns the keys of a set as a sorted comma-separated string,
// used only for failure messages.
func sortedKeys(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
