package social_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonstruct/social"
	"golang.org/x/oauth2"
)

func TestOAuth2ProviderFromEndpoints(t *testing.T) {
	provider := &social.OAuth2{
		Driver: "acme", ClientID: "id", ClientSecret: "secret", RedirectURL: "http://app/cb",
		AuthURL: "https://acme/authorize", TokenURL: "https://acme/token",
		Scopes: []string{"a"}, Extra: map[string]string{"prompt": "consent"}, IssuerURL: "https://acme",
	}

	if provider.Name() != "acme" || !provider.Configured() || !provider.UsesPKCE() || provider.Issuer() != "https://acme" {
		t.Fatalf("basics: %+v", provider)
	}
	config := provider.Config()
	if config.ClientID != "id" || config.Endpoint.AuthURL != "https://acme/authorize" || config.Scopes[0] != "a" {
		t.Fatalf("config: %+v", config)
	}
	if len(provider.Parameters()) != 1 {
		t.Fatalf("extra parameters: %v", provider.Parameters())
	}

	provider.WithoutPKCE = true
	if provider.UsesPKCE() {
		t.Error("WithoutPKCE ignored")
	}
	if (&social.OAuth2{Driver: "x", AuthURL: "a", TokenURL: "t"}).Configured() {
		t.Error("a provider without a client id is not configured")
	}
}

func TestOAuth2ProviderReadsTheProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "7", "handle": "person"})
	}))
	t.Cleanup(server.Close)

	provider := &social.OAuth2{ProfileURL: server.URL + "/me", Profile: func(raw map[string]any) social.User {
		return social.User{ID: social.String(raw, "id"), Nickname: social.String(raw, "handle")}
	}}
	grant := social.Grant{Token: &oauth2.Token{AccessToken: "tok"}, Client: (&oauth2.Config{}).Client(t.Context(), &oauth2.Token{AccessToken: "tok"})}

	user, err := provider.User(t.Context(), grant)
	if err != nil || user.ID != "7" || user.Nickname != "person" {
		t.Fatalf("user: %+v %v", user, err)
	}
	if raw, ok := user.Raw.(map[string]any); !ok || raw["id"] != "7" {
		t.Error("Raw should keep the decoded profile")
	}

	// Without a Profile function the raw document is all there is.
	bare := &social.OAuth2{ProfileURL: server.URL + "/me"}
	user, err = bare.User(t.Context(), grant)
	if err != nil || user.ID != "" || user.Raw == nil {
		t.Fatalf("bare: %+v %v", user, err)
	}

	// A refused or broken profile endpoint is an error, not a user.
	unauthorised := social.Grant{Client: (&oauth2.Config{}).Client(t.Context(), &oauth2.Token{AccessToken: "wrong"})}
	if _, err := provider.User(t.Context(), unauthorised); err == nil {
		t.Error("a 401 from the profile endpoint should be an error")
	}
}
