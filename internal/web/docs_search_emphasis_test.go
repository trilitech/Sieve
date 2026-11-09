package web

import "testing"

// Operation names are snake_case, so the docs search index must not treat the
// underscore inside one as an emphasis delimiter. It used to: the `_` of one
// identifier paired with the `_` of the next on the same line and both were
// deleted, so the index held "calendar.updateevent" and a search for the real
// name found nothing. That mangled index was read as evidence that Sieve
// registered the operation under two different names.
func TestSearchPlainText_KeepsSnakeCaseIdentifiers(t *testing.T) {
	cases := map[string]string{
		"calendar.update_event and calendar.create_event are write ops":         "calendar.update_event and calendar.create_event are write ops",
		"Ops: calendar.list_events, calendar.get_event, calendar.delete_event.": "Ops: calendar.list_events, calendar.get_event, calendar.delete_event.",
		"Only one: calendar.list_events":                                        "Only one: calendar.list_events",
		"send_email, reply, forward_draft, update_draft":                        "send_email, reply, forward_draft, update_draft",
		// Bold around a snake_case name: the marker goes, the name survives.
		// The old pattern required the content to be free of underscores, so
		// this did not match at all and the ** markers stayed in the index.
		"**update_event** replaces the event": "update_event replaces the event",
	}
	for in, want := range cases {
		if got := SearchPlainText(in); got != want {
			t.Errorf("SearchPlainText(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Genuine emphasis must still be stripped, including two runs separated by a
// single space — the pattern consumes the boundary character on each side, so
// that case only works because the strip loops.
func TestSearchPlainText_StillStripsRealEmphasis(t *testing.T) {
	cases := map[string]string{
		"*italic* text":        "italic text",
		"**bold** text":        "bold text",
		"_italic_ text":        "italic text",
		"__bold__ text":        "bold text",
		"_a_ _b_ _c_":          "a b c",
		"an _emphasised_ word": "an emphasised word",
		"trailing _emphasis_":  "trailing emphasis",
	}
	for in, want := range cases {
		if got := SearchPlainText(in); got != want {
			t.Errorf("SearchPlainText(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// A stray unpaired underscore after a space must not reach forward into a
// snake_case identifier and eat its underscore too.
func TestSearchPlainText_StrayUnderscoreLeavesIdentifiersAlone(t *testing.T) {
	in := "Set flag _debug and call update_event"
	if got := SearchPlainText(in); got != in {
		t.Errorf("SearchPlainText(%q)\n got %q\nwant it unchanged", in, got)
	}
}
