package github

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoCredential is returned when no credential covers the request's owner
// and no default credential is configured.
var ErrNoCredential = errors.New("github: no credential matches request scope")

// extractOwner returns the GitHub owner (user or org login) referenced by an
// API path, or "" if the path has no obvious owner segment (in which case the
// caller falls back to the connection's default credential).
//
// Recognized prefixes:
//   - /repos/{owner}/{repo}/...
//   - /orgs/{org}/...
//   - /users/{user}/...
//
// All other paths (/user, /search/*, /graphql, /notifications, /gists/...) are
// treated as owner-less.
func extractOwner(path string) string {
	if path == "" || path[0] != '/' {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	switch parts[0] {
	case "repos", "orgs", "users":
		return parts[1]
	}
	return ""
}

// pickCredential returns the credential to use for a request targeting the
// given owner. When owner is non-empty the credential list must contain an
// exact scope match — falling back to the default for a mismatched owner
// would send a doomed request (wrong token) and burn rate limit. An empty
// owner (ownerless endpoints like /user, /search/*, /graphql) falls back to
// the configured default. Returns ErrNoCredential if no candidate exists.
func (c *Config) pickCredential(owner string) (*Credential, error) {
	if owner != "" {
		for i := range c.Credentials {
			if c.Credentials[i].Scope.matches(owner) {
				return &c.Credentials[i], nil
			}
		}
		return nil, fmt.Errorf("%w: owner=%q", ErrNoCredential, owner)
	}
	if c.DefaultIndex != nil {
		return &c.Credentials[*c.DefaultIndex], nil
	}
	return nil, fmt.Errorf("%w: ownerless request and no default_credential_index set", ErrNoCredential)
}
