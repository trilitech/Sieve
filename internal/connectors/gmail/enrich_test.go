package gmail

import (
	"reflect"
	"sort"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// The Gmail connector must satisfy connector.ContextEnricher so the PEP/PIP
// can pull recipient_domains off send/draft/reply requests.
var _ connector.ContextEnricher = (*GoogleConnector)(nil)

// sortedDomains pulls recipient_domains out of an EnrichContext result and
// sorts it, so assertions don't depend on iteration/insertion order beyond
// the dedup contract.
func sortedDomains(t *testing.T, out map[string]any) []string {
	t.Helper()
	if out == nil {
		return nil
	}
	raw, ok := out["recipient_domains"]
	if !ok {
		t.Fatalf("result missing recipient_domains key: %#v", out)
	}
	vals, ok := raw.([]string)
	if !ok {
		t.Fatalf("recipient_domains is %T, want []string", raw)
	}
	cp := append([]string(nil), vals...)
	sort.Strings(cp)
	return cp
}

func TestEnrichContext_CollectsAndDedupesDomains(t *testing.T) {
	g := &GoogleConnector{}
	out := g.EnrichContext("send_email", map[string]any{
		// []string and []any (JSON-decoded) both supported; mixed case and a
		// duplicate domain across to/cc must collapse to one entry.
		"to": []string{"Alice@Example.com", "bob@example.com"},
		"cc": []any{"carol@Other.ORG"},
	})
	got := sortedDomains(t, out)
	want := []string{"example.com", "other.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
}

func TestEnrichContext_SingleStringRecipient(t *testing.T) {
	g := &GoogleConnector{}
	out := g.EnrichContext("create_draft", map[string]any{
		"to": "solo@single.example",
	})
	got := sortedDomains(t, out)
	want := []string{"single.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
}

func TestEnrichContext_IgnoresReplyToMessageID(t *testing.T) {
	g := &GoogleConnector{}
	// reply_to is a Gmail message ID, not an address — it must not contribute
	// a domain. With no to/cc present, the result is nil.
	out := g.EnrichContext("reply", map[string]any{
		"reply_to": "18f2c0a1b2c3d4e5",
		"body":     "thanks",
	})
	if out != nil {
		t.Fatalf("expected nil for reply with only reply_to, got %#v", out)
	}
}

func TestEnrichContext_NilForNonRecipientOps(t *testing.T) {
	g := &GoogleConnector{}
	for _, op := range []string{"list_emails", "read_email", "send_draft", "add_label", "drive.list_files"} {
		if out := g.EnrichContext(op, map[string]any{"message_id": "x"}); out != nil {
			t.Errorf("op %q: expected nil, got %#v", op, out)
		}
	}
}

func TestEnrichContext_SkipsMalformedAddresses(t *testing.T) {
	g := &GoogleConnector{}
	out := g.EnrichContext("send_email", map[string]any{
		// no '@' and a trailing '@' with empty domain are both dropped; the
		// one valid address survives.
		"to": []string{"not-an-address", "missingdomain@", "ok@valid.test"},
	})
	got := sortedDomains(t, out)
	want := []string{"valid.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
}
