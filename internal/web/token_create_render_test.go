package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/tokens"
)

// TestTokenCreate_RendersWithExistingToken proves the token-create success page
// renders fully when a token already exists. tokens.html evaluates
// `index $.Caps .ID` per listed token; the create-success handler previously did
// not populate Caps (only handleTokens did), so with ≥1 token the template
// errored "index of untyped nil" mid-render — a 200 with a truncated body. A
// full render (contains the new plaintext token and the closing </html>, no
// "render error:") proves Caps is now supplied on this path too.
func TestTokenCreate_RendersWithExistingToken(t *testing.T) {
	ts, env := newAuditTestServer(t)
	role, err := env.Roles.Create("r1", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-existing token, so the create-success render iterates a non-empty list
	// and hits `index $.Caps .ID`.
	if _, err := env.Tokens.Create(&tokens.CreateRequest{Name: "existing", RoleID: role.ID}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("name", "second")
	form.Set("role_id", role.ID)
	req, _ := http.NewRequest("POST", ts.URL+"/tokens/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.AdminClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "render error:") {
		t.Errorf("create-success page failed to render (index $.Caps nil?): %s", body)
	}
	if !strings.Contains(body, "sieve_tok_") {
		t.Errorf("new plaintext token not shown on success page")
	}
	if !strings.Contains(body, "</html>") {
		t.Errorf("page truncated (render aborted mid-template): %s", body)
	}
}
