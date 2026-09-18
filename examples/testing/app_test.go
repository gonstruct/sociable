package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonstruct/sociable"
)

// The two tests from Socialite's documentation. Each test has a manager of
// its own, so nothing is configured, nothing talks to GitHub, and they run
// in parallel.

func TestUserIsRedirectedToGitHub(t *testing.T) {
	t.Parallel()

	social := sociable.New()
	social.Fake("github")

	recorder := httptest.NewRecorder()
	App(social).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/github", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirect", recorder.Code)
	}
}

func TestUserCanLoginWithGitHub(t *testing.T) {
	t.Parallel()

	social := sociable.New()
	social.Fake("github", &sociable.User{
		ID:    "github-123",
		Name:  "Jason Beggs",
		Email: "jason@example.com",
	})

	recorder := httptest.NewRecorder()
	App(social).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil))

	if location := recorder.Header().Get("Location"); location != "/dashboard" {
		t.Fatalf("landed on %q, want /dashboard", location)
	}
}
