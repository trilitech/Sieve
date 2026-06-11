package gmail

import (
	"errors"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
	"golang.org/x/oauth2"
)

// fakeTokenSource lets a test inject any error from base.Token so we can
// exercise the wrapping logic in persistingTokenSource without standing up a
// real OAuth endpoint.
type fakeTokenSource struct {
	err error
	tok *oauth2.Token
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	return f.tok, f.err
}

// TestPersistingTokenSource_TranslatesInvalidGrant: when the base source
// returns oauth2.RetrieveError{ErrorCode: "invalid_grant"}, our wrapper
// must (a) call onRefreshFailure with the code+description, and (b) wrap
// the error so callers can detect it via errors.Is(err, ErrNeedsReauth).
func TestPersistingTokenSource_TranslatesInvalidGrant(t *testing.T) {
	upstream := &oauth2.RetrieveError{
		ErrorCode:        "invalid_grant",
		ErrorDescription: "Token has been expired or revoked.",
	}

	var capturedReason string
	pts := &persistingTokenSource{
		base: &fakeTokenSource{err: upstream},
		onRefreshFailure: func(reason string) {
			capturedReason = reason
		},
	}

	_, err := pts.Token()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, connector.ErrNeedsReauth) {
		t.Errorf("expected errors.Is(err, ErrNeedsReauth) to be true, got: %v", err)
	}
	if capturedReason == "" {
		t.Error("onRefreshFailure was not invoked")
	}
	if capturedReason != "invalid_grant: Token has been expired or revoked." {
		t.Errorf("captured reason = %q, want full code+description", capturedReason)
	}
}

// TestPersistingTokenSource_PassesThroughTransient: a transient upstream
// error (network, 500, anything that isn't a documented "your refresh
// token is dead" code) must NOT flip the flag. Otherwise an upstream
// hiccup would page a human to re-authenticate for nothing.
func TestPersistingTokenSource_PassesThroughTransient(t *testing.T) {
	upstream := errors.New("connection reset by peer")
	called := false
	pts := &persistingTokenSource{
		base:             &fakeTokenSource{err: upstream},
		onRefreshFailure: func(string) { called = true },
	}

	_, err := pts.Token()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, connector.ErrNeedsReauth) {
		t.Error("transient error should NOT translate to ErrNeedsReauth")
	}
	if called {
		t.Error("onRefreshFailure should NOT fire on a transient error")
	}
}

// TestPersistingTokenSource_NonReauthOAuthCode: an OAuth RetrieveError
// with a non-"reauth-needed" code (e.g., temporarily_unavailable) must
// also not flip the flag.
func TestPersistingTokenSource_NonReauthOAuthCode(t *testing.T) {
	upstream := &oauth2.RetrieveError{ErrorCode: "temporarily_unavailable"}
	called := false
	pts := &persistingTokenSource{
		base:             &fakeTokenSource{err: upstream},
		onRefreshFailure: func(string) { called = true },
	}

	_, err := pts.Token()
	if errors.Is(err, connector.ErrNeedsReauth) {
		t.Error("temporarily_unavailable should NOT translate to ErrNeedsReauth")
	}
	if called {
		t.Error("onRefreshFailure should NOT fire on temporarily_unavailable")
	}
}
