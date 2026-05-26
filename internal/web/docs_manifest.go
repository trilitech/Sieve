package web

import (
	"fmt"
	"sort"
	"strings"
)

// DocCategory groups related documentation pages into a named bucket.
type DocCategory struct {
	ID          string
	Title       string
	Description string
	Order       int
	Slugs       []string
}

// DocManifest is the full IA configuration for the docs UI. Edited in source,
// no I/O at runtime.
type DocManifest struct {
	Categories    []DocCategory
	Descriptions  map[string]string
	Hidden        map[string]bool
	FallbackID    string
	FallbackTitle string
	FallbackOrder int
}

// DocPage is a single rendered article. Body is filled only when the operator
// is on /docs/{slug}; for index/category views Body is empty.
type DocPage struct {
	Slug        string
	Title       string
	Description string
	CategoryID  string
	Hidden      bool
	Body        string
	Headings    []DocHeading
}

// DocHeading is an H2 or H3 inside a page body, with a slugified anchor that
// matches the rule the client-side script applies on render.
type DocHeading struct {
	Level  int
	Text   string
	Anchor string
	Body   string
}

// DocCategoryView pairs a category with the visible (non-hidden) pages it
// contains, in display order.
type DocCategoryView struct {
	Category DocCategory
	Pages    []DocPage
}

// Breadcrumb is one link in the breadcrumb trail above the docs content.
type Breadcrumb struct {
	Label string
	Href  string // empty for the trailing breadcrumb (no link)
}

// DocNavIndex is the composite structure handed to the docs template on every
// docs request. Built fresh per-request from manifest + filesystem state.
type DocNavIndex struct {
	Categories      []DocCategoryView
	Current         *DocPage
	CurrentCategory *DocCategory // category landing flag — non-nil when rendering /docs/category/{id}
	Breadcrumbs     []Breadcrumb
	SearchIndexJSON string // pre-marshalled JSON corpus, embedded into a <script type="application/json"> block and consumed via JSON.parse(textContent). Plain string per spec 001-fix-security-vulns US5 (FR-019) — template.JS was the wrong type for serialized data.
}

// Manifest returns the live category mapping. Pure; no I/O. Edit this function
// to change the IA — every other piece of the docs UI consumes its output.
func Manifest() DocManifest {
	return DocManifest{
		Categories: []DocCategory{
			{
				ID:          "getting-started",
				Title:       "Getting Started",
				Description: "Core concepts and what Sieve is for.",
				Order:       10,
				Slugs:       []string{"concepts", "user-stories"},
			},
			{
				ID:          "connectors",
				Title:       "Connectors",
				Description: "Hooking up Gmail, GitHub, and other services.",
				Order:       20,
				Slugs: []string{
					"connections-guide",
					"gmail-api",
					"github-connector",
					"google-oauth-setup",
				},
			},
			{
				ID:          "policies",
				Title:       "Policies & Approvals",
				Description: "Authoring rules and scripts that gate every agent request.",
				Order:       30,
				Slugs: []string{
					"policy-rules-reference",
					"policy-scripts",
				},
			},
			{
				ID:          "integrations",
				Title:       "Integrations",
				Description: "Embedding Sieve into agent runtimes.",
				Order:       40,
				Slugs:       []string{"mcp-integration"},
			},
			{
				ID:          "security",
				Title:       "Security",
				Description: "How Sieve stores and protects credentials.",
				Order:       50,
				Slugs:       []string{"credential-encryption"},
			},
		},
		Descriptions: map[string]string{
			"concepts":               "What Sieve is, the problem it solves, and the core building blocks.",
			"user-stories":           "End-to-end scenarios showing how operators and agents interact with Sieve.",
			"connections-guide":      "Adding, configuring, and removing service connections.",
			"gmail-api":              "Drop-in REST surface for existing Gmail clients.",
			"github-connector":       "PAT and GitHub App setup for repo and org access.",
			"google-oauth-setup":     "One-time OAuth client setup for Gmail / Drive / Calendar.",
			"policy-rules-reference": "Field-by-field syntax for the rules-style policy evaluator.",
			"policy-scripts":         "Authoring custom Python (or any-language) policies.",
			"mcp-integration":        "Wiring Sieve as an MCP server for Claude Desktop and other clients.",
			"credential-encryption":  "Envelope encryption, key derivation, and passphrase handling.",
			"cli-reference":          "Command-line invocations and runtime flags.",
		},
		Hidden:        map[string]bool{},
		FallbackID:    "reference",
		FallbackTitle: "Reference",
		FallbackOrder: 90,
	}
}

// Validate returns an error describing every invariant violation in m. Pure;
// safe to call at startup or from tests.
func (m DocManifest) Validate(knownSlugs []string) error {
	known := make(map[string]bool, len(knownSlugs))
	for _, s := range knownSlugs {
		known[s] = true
	}

	var problems []string

	// Category-level invariants.
	idSeen := make(map[string]bool)
	orderSeen := make(map[int]bool)
	slugOwner := make(map[string]string) // slug -> category ID owning it

	for _, c := range m.Categories {
		if c.ID == "" {
			problems = append(problems, "category has empty ID")
			continue
		}
		if idSeen[c.ID] {
			problems = append(problems, fmt.Sprintf("category ID %q is duplicated", c.ID))
		}
		idSeen[c.ID] = true

		if orderSeen[c.Order] {
			problems = append(problems, fmt.Sprintf("category %q reuses Order %d", c.ID, c.Order))
		}
		orderSeen[c.Order] = true

		for _, slug := range c.Slugs {
			if owner, ok := slugOwner[slug]; ok {
				problems = append(problems, fmt.Sprintf("slug %q listed in both %q and %q", slug, owner, c.ID))
			}
			slugOwner[slug] = c.ID
			if len(known) > 0 && !known[slug] {
				problems = append(problems, fmt.Sprintf("category %q references unknown slug %q", c.ID, slug))
			}
		}
	}

	// Fallback invariants.
	if m.FallbackID == "" {
		problems = append(problems, "fallback ID is empty")
	} else if idSeen[m.FallbackID] {
		problems = append(problems, fmt.Sprintf("fallback ID %q collides with a real category", m.FallbackID))
	}
	if orderSeen[m.FallbackOrder] {
		problems = append(problems, fmt.Sprintf("fallback Order %d collides with a real category", m.FallbackOrder))
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("docs manifest invalid:\n  - %s", strings.Join(problems, "\n  - "))
}

// BuildIndex composes the live filesystem state with the manifest into a
// renderable navigation index. Pure; no I/O.
//
//   - fsSlugs: the set of slugs present on disk (filenames under docs/ minus
//     the .md extension), in any order.
//   - fileTitle: callback returning the title for a given slug. Allowed to be
//     nil; in that case the slug itself is used as the title.
func BuildIndex(m DocManifest, fsSlugs []string, fileTitle func(slug string) string) DocNavIndex {
	if fileTitle == nil {
		fileTitle = func(s string) string { return s }
	}

	// Build a quick lookup for which category claims a given slug.
	owner := make(map[string]string, 0)
	for _, c := range m.Categories {
		for _, s := range c.Slugs {
			owner[s] = c.ID
		}
	}

	// Bucket every real slug into its owning category, the fallback bucket, or
	// the hidden set.
	bucketed := make(map[string][]string)
	var unmapped []string
	for _, slug := range fsSlugs {
		if m.Hidden[slug] {
			continue
		}
		if cat, ok := owner[slug]; ok {
			bucketed[cat] = append(bucketed[cat], slug)
		} else {
			unmapped = append(unmapped, slug)
		}
	}

	// Determine the display order of slugs within each category.
	out := make([]DocCategoryView, 0, len(m.Categories)+1)
	for _, c := range m.Categories {
		view := DocCategoryView{Category: c}
		// Walk the manifest's declared slug order, including only ones present
		// on disk and not hidden.
		seen := make(map[string]bool)
		for _, slug := range c.Slugs {
			if m.Hidden[slug] {
				continue
			}
			// Slug must also exist on disk (skip dangling references).
			present := false
			for _, fs := range fsSlugs {
				if fs == slug {
					present = true
					break
				}
			}
			if !present {
				continue
			}
			view.Pages = append(view.Pages, makePage(slug, m, fileTitle))
			seen[slug] = true
		}
		// Append any bucketed slugs not declared in c.Slugs in alphabetical
		// order — defensive; should not happen if manifest is consistent.
		for _, slug := range bucketed[c.ID] {
			if !seen[slug] {
				view.Pages = append(view.Pages, makePage(slug, m, fileTitle))
			}
		}
		out = append(out, view)
	}

	// Fallback bucket — alphabetical by title.
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		fallback := DocCategoryView{
			Category: DocCategory{
				ID:          m.FallbackID,
				Title:       m.FallbackTitle,
				Description: "Pages not yet placed in a category.",
				Order:       m.FallbackOrder,
			},
		}
		pages := make([]DocPage, 0, len(unmapped))
		for _, slug := range unmapped {
			pages = append(pages, makePage(slug, m, fileTitle))
		}
		sort.SliceStable(pages, func(i, j int) bool {
			return strings.ToLower(pages[i].Title) < strings.ToLower(pages[j].Title)
		})
		fallback.Pages = pages
		out = append(out, fallback)
	}

	// Sort categories by Order ascending.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Category.Order < out[j].Category.Order
	})

	// Drop empty categories from the rendered index — a category with zero
	// visible pages is noise, not signal.
	pruned := out[:0]
	for _, view := range out {
		if len(view.Pages) > 0 {
			pruned = append(pruned, view)
		}
	}

	return DocNavIndex{Categories: pruned}
}

func makePage(slug string, m DocManifest, fileTitle func(string) string) DocPage {
	title := fileTitle(slug)
	if title == "" {
		title = slug
	}
	return DocPage{
		Slug:        slug,
		Title:       title,
		Description: m.Descriptions[slug],
		CategoryID:  categoryFor(slug, m),
		Hidden:      m.Hidden[slug],
	}
}

// categoryFor returns the category ID that owns slug, or the fallback ID if
// the slug is unmapped.
func categoryFor(slug string, m DocManifest) string {
	for _, c := range m.Categories {
		for _, s := range c.Slugs {
			if s == slug {
				return c.ID
			}
		}
	}
	return m.FallbackID
}

// findCategory looks up a category by ID inside an index. Returns nil if the
// ID is not present.
func (idx DocNavIndex) findCategory(id string) *DocCategoryView {
	for i := range idx.Categories {
		if idx.Categories[i].Category.ID == id {
			return &idx.Categories[i]
		}
	}
	return nil
}
