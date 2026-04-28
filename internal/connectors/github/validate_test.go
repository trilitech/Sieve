package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePAT_UserScopeLoginMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authz=%q", r.Header.Get("Authorization"))
		}
		fmt.Fprintln(w, `{"login": "murbard"}`)
	}))
	defer srv.Close()

	if err := ValidatePAT(context.Background(), srv.Client(), srv.URL, "tok", ScopeUser, "murbard"); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePAT_UserScopeLoginMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"login": "someoneelse"}`)
	}))
	defer srv.Close()

	err := ValidatePAT(context.Background(), srv.Client(), srv.URL, "tok", ScopeUser, "murbard")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "someoneelse") {
		t.Errorf("expected mismatch detail in error, got: %v", err)
	}
}

func TestValidatePAT_OrgScopeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/trilitech" {
			t.Errorf("path=%q", r.URL.Path)
		}
		fmt.Fprintln(w, `{"login": "trilitech"}`)
	}))
	defer srv.Close()

	if err := ValidatePAT(context.Background(), srv.Client(), srv.URL, "tok", ScopeOrg, "trilitech"); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePAT_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := ValidatePAT(context.Background(), srv.Client(), srv.URL, "bad", ScopeUser, "x")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
}

func TestValidatePAT_UnknownScope(t *testing.T) {
	err := ValidatePAT(context.Background(), nil, "http://unused", "tok", "team", "x")
	if err == nil {
		t.Fatal("expected unknown-scope error")
	}
}
