package main

import (
	"github.com/trilitech/Sieve/internal/connector"
	anthropicconn "github.com/trilitech/Sieve/internal/connectors/anthropic"
	asanaconn "github.com/trilitech/Sieve/internal/connectors/asana"
	githubconn "github.com/trilitech/Sieve/internal/connectors/github"
	gitlabconn "github.com/trilitech/Sieve/internal/connectors/gitlab"
	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	linearconn "github.com/trilitech/Sieve/internal/connectors/linear"
	"github.com/trilitech/Sieve/internal/connectors/mcpproxy"
	notionconn "github.com/trilitech/Sieve/internal/connectors/notion"
	slackconn "github.com/trilitech/Sieve/internal/connectors/slack"
)

// buildConnectorRegistry registers every production connector. Extracted from
// main() so tests (the IAM schema/taxonomy guard) can build the identical
// registry without standing up the full server.
func buildConnectorRegistry() *connector.Registry {
	registry := connector.NewRegistry()
	registry.Register(gmail.Meta, gmail.Factory)
	registry.Register(httpproxy.Meta, httpproxy.Factory)
	registry.Register(mcpproxy.Meta, mcpproxy.Factory)
	registry.Register(githubconn.Meta(), githubconn.Factory())
	registry.Register(slackconn.Meta(), slackconn.Factory())
	registry.Register(anthropicconn.Meta(), anthropicconn.Factory())
	registry.Register(gitlabconn.Meta(), gitlabconn.Factory())
	registry.Register(linearconn.Meta(), linearconn.Factory())
	registry.Register(notionconn.Meta(), notionconn.Factory())
	registry.Register(asanaconn.Meta(), asanaconn.Factory())
	return registry
}
