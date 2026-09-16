//nolint:testpackage // the fallback reads an unexported endpoint field to point at the test server
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonstruct/social"
	"golang.org/x/oauth2"
)

func TestGitHubProviderDefaults(t *testing.T) {
	provider := New(Options{ClientID: "id", ClientSecret: "secret", RedirectURL: "http://app/cb"}).(*provider)

	if provider.Name() != "github" || !provider.Configured() || len(provider.Scopes) != 2 {
		t.Fatalf("basics: %+v", provider.OAuth2)
	}
}

func TestGitHubProfileAndEmailFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42.0, "login": "octo", "name": "Octo Cat", "avatar_url": "https://a"})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "old@example.com", "primary": false, "verified": true},
				{"email": "octo@example.com", "primary": true, "verified": true},
			})
		}
	}))
	t.Cleanup(server.Close)

	provider := New(Options{ClientID: "id"}).(*provider)
	provider.ProfileURL = server.URL + "/user"
	provider.emailsURL = server.URL + "/user/emails"

	grant := social.Grant{Client: (&oauth2.Config{}).Client(context.Background(), &oauth2.Token{AccessToken: "tok"})}
	user, err := provider.User(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "42" || user.Nickname != "octo" || user.Name != "Octo Cat" || user.Avatar != "https://a" {
		t.Fatalf("profile: %+v", user)
	}
	if user.Email != "octo@example.com" || !user.EmailVerified {
		t.Fatalf("the primary verified address should be used: %+v", user)
	}

	public := Profile(map[string]any{"id": 1.0, "login": "x", "email": "x@example.com"})
	if public.Email != "x@example.com" || !public.EmailVerified {
		t.Fatalf("a public address is a verified one: %+v", public)
	}
}
