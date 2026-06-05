package slack

// The Slack client's GET path MUST propagate io.ReadAll errors instead
// of swallowing them and surfacing a downstream JSON decode failure.
// Regression test injects a body reader that errors mid-read and asserts
// the wrapped I/O cause shows up in the returned error.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// faultyReader returns one chunk of bytes, then a custom error on the
// next Read call — mirroring a real TLS reset / truncated-body scenario.
type faultyReader struct {
	first  []byte
	served bool
	err    error
}

func (r *faultyReader) Read(p []byte) (int, error) {
	if !r.served {
		r.served = true
		n := copy(p, r.first)
		return n, nil
	}
	return 0, r.err
}

func (r *faultyReader) Close() error { return nil }

// faultyServer is an httptest.Server whose handler hijacks the
// connection and writes a partial body before forcing a read error on
// the client side via Content-Length lying about the available bytes.
// Realistically modeling the failure inside httptest is awkward, so the
// test here goes one level deeper: we construct the slack client and
// override its httpClient.Transport to return a *http.Response whose
// Body is our faultyReader.

// transportFunc lets us inject a synthetic Response.
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestClient_Get_PropagatesIOReadError injects a body reader that errors
// after a partial read and asserts the wrapped I/O cause surfaces from
// client.get(). The legacy code dropped the error via `body, _ :=
// io.ReadAll(...)` and then handed the partial body to json.Unmarshal,
// producing a confusing "invalid character" decode error instead of the
// real network failure.
func TestClient_Get_PropagatesIOReadError(t *testing.T) {
	wantCause := errors.New("simulated network drop mid-body")

	c := &client{
		httpClient: &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: &faultyReader{
					first: []byte(`{"ok": true,`),
					err:   wantCause,
				},
				Request: req,
			}, nil
		})},
		baseURL:     "http://example.invalid",
		tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "xoxb-test"}),
	}

	_, err := c.get(context.Background(), "auth.test", nil)
	if err == nil {
		t.Fatal("expected error from get(), got nil")
	}
	if !errors.Is(err, wantCause) {
		t.Fatalf("error does not wrap the I/O cause: got %v, want wrapping %v", err, wantCause)
	}
	if !strings.Contains(err.Error(), "read auth.test response") {
		t.Fatalf("error message does not mention read failure: got %q", err.Error())
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("error surfaces as JSON decode failure instead of I/O: got %q", err.Error())
	}
}

// suppress unused warnings if test helpers are not all referenced
var _ = httptest.NewServer
var _ = io.EOF
