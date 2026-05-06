package web

import (
	"reflect"
	"strings"
	"testing"
)

// realSlugs is the set of doc slugs that exist on disk in docs/ at the time
// this feature was authored. The manifest must remain consistent with this
// list; the test fails loudly if a doc is renamed/removed without a manifest
// update.
var realSlugs = []string{
	"cli-reference",
	"concepts",
	"connections-guide",
	"credential-encryption",
	"github-connector",
	"gmail-api",
	"google-oauth-setup",
	"mcp-integration",
	"policy-rules-reference",
	"policy-scripts",
	"user-stories",
}

func TestManifest_ValidateAgainstRealSlugs(t *testing.T) {
	if err := Manifest().Validate(realSlugs); err != nil {
		t.Fatalf("live manifest does not validate against on-disk doc slugs:\n%v", err)
	}
}

func TestManifest_DetectsDuplicateSlug(t *testing.T) {
	m := Manifest()
	// Force a duplicate.
	m.Categories = append([]DocCategory{}, m.Categories...)
	m.Categories[0].Slugs = append(m.Categories[0].Slugs, m.Categories[1].Slugs[0])
	err := m.Validate(realSlugs)
	if err == nil || !strings.Contains(err.Error(), "listed in both") {
		t.Fatalf("expected duplicate-slug error, got %v", err)
	}
}

func TestManifest_DetectsDuplicateCategoryID(t *testing.T) {
	m := DocManifest{
		Categories: []DocCategory{
			{ID: "x", Title: "X", Order: 1},
			{ID: "x", Title: "X2", Order: 2},
		},
		FallbackID:    "ref",
		FallbackOrder: 99,
	}
	if err := m.Validate(nil); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate-ID error, got %v", err)
	}
}

func TestManifest_DetectsDuplicateOrder(t *testing.T) {
	m := DocManifest{
		Categories: []DocCategory{
			{ID: "a", Title: "A", Order: 5},
			{ID: "b", Title: "B", Order: 5},
		},
		FallbackID:    "ref",
		FallbackOrder: 99,
	}
	if err := m.Validate(nil); err == nil || !strings.Contains(err.Error(), "Order") {
		t.Fatalf("expected duplicate-Order error, got %v", err)
	}
}

func TestManifest_DetectsDanglingSlug(t *testing.T) {
	m := Manifest()
	m.Categories = append([]DocCategory{}, m.Categories...)
	m.Categories[0].Slugs = append(append([]string{}, m.Categories[0].Slugs...), "totally-fake-slug")
	if err := m.Validate(realSlugs); err == nil || !strings.Contains(err.Error(), "totally-fake-slug") {
		t.Fatalf("expected dangling-slug error, got %v", err)
	}
}

func TestBuildIndex_AllRealSlugsLandSomewhere(t *testing.T) {
	m := Manifest()
	idx := BuildIndex(m, realSlugs, fakeTitle)

	seen := make(map[string]bool)
	for _, view := range idx.Categories {
		for _, p := range view.Pages {
			if seen[p.Slug] {
				t.Errorf("slug %q appears in more than one rendered category", p.Slug)
			}
			seen[p.Slug] = true
		}
	}
	for _, slug := range realSlugs {
		if !seen[slug] {
			t.Errorf("slug %q absent from BuildIndex output (should land in a category or fallback)", slug)
		}
	}
}

func TestBuildIndex_UnmappedSlugFallsToFallback(t *testing.T) {
	m := Manifest()
	slugs := append(append([]string{}, realSlugs...), "scratch-doc")
	idx := BuildIndex(m, slugs, fakeTitle)

	var fallbackView *DocCategoryView
	for i := range idx.Categories {
		if idx.Categories[i].Category.ID == m.FallbackID {
			fallbackView = &idx.Categories[i]
			break
		}
	}
	if fallbackView == nil {
		t.Fatalf("fallback category missing from index")
	}
	found := false
	for _, p := range fallbackView.Pages {
		if p.Slug == "scratch-doc" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unmapped slug 'scratch-doc' did not land in fallback category; got %v", fallbackView.Pages)
	}
}

func TestBuildIndex_HiddenSlugsExcluded(t *testing.T) {
	m := Manifest()
	m.Hidden = map[string]bool{"concepts": true}
	idx := BuildIndex(m, realSlugs, fakeTitle)

	for _, view := range idx.Categories {
		for _, p := range view.Pages {
			if p.Slug == "concepts" {
				t.Fatalf("hidden slug 'concepts' rendered in category %q", view.Category.ID)
			}
		}
	}
}

func TestBuildIndex_Deterministic(t *testing.T) {
	m := Manifest()
	a := BuildIndex(m, realSlugs, fakeTitle)
	b := BuildIndex(m, realSlugs, fakeTitle)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("BuildIndex is not deterministic for identical inputs")
	}
}

func TestBuildIndex_EmptyCategoriesPruned(t *testing.T) {
	m := Manifest()
	// Build with NO real slugs — every category should be pruned, fallback empty too.
	idx := BuildIndex(m, nil, fakeTitle)
	if len(idx.Categories) != 0 {
		t.Fatalf("expected zero categories with no slugs, got %d", len(idx.Categories))
	}
}

func TestBuildIndex_RespectsManifestSlugOrder(t *testing.T) {
	m := Manifest()
	idx := BuildIndex(m, realSlugs, fakeTitle)

	// "Connectors" category should list connections-guide first per Manifest().
	var connectors *DocCategoryView
	for i := range idx.Categories {
		if idx.Categories[i].Category.ID == "connectors" {
			connectors = &idx.Categories[i]
			break
		}
	}
	if connectors == nil {
		t.Fatalf("connectors category missing")
	}
	if len(connectors.Pages) == 0 || connectors.Pages[0].Slug != "connections-guide" {
		t.Errorf("connectors[0] = %q; want connections-guide", first(connectors.Pages).Slug)
	}
}

func fakeTitle(slug string) string {
	// Title-Case the slug so order assertions on title still work.
	parts := strings.Split(slug, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func first(pages []DocPage) DocPage {
	if len(pages) == 0 {
		return DocPage{}
	}
	return pages[0]
}
