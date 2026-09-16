package google_test

import (
	"testing"

	"github.com/gonstruct/vouch"
	"github.com/gonstruct/vouch/google"
)

func TestGoogleProvider(t *testing.T) {
	provider := google.New(google.Options{ClientID: "id", ClientSecret: "secret", RedirectURL: "http://app/cb", Offline: true})().(*vouch.OAuth2)

	if provider.Name() != "google" || !provider.Configured() || provider.Issuer() != "https://accounts.google.com" {
		t.Fatalf("basics: %+v", provider)
	}
	if len(provider.Scopes) != 3 || provider.Extra["access_type"] != "offline" || provider.Extra["prompt"] != "consent" {
		t.Fatalf("defaults: scopes %v extra %v", provider.Scopes, provider.Extra)
	}

	user := google.Profile(map[string]any{
		"sub": "1", "email": "p@example.com", "email_verified": true, "name": "P", "given_name": "Pe", "picture": "https://p",
	})
	if user.ID != "1" || user.Email != "p@example.com" || !user.EmailVerified || user.Name != "P" || user.Nickname != "Pe" || user.Avatar != "https://p" {
		t.Fatalf("profile: %+v", user)
	}
	if google.Profile(map[string]any{"sub": "1"}).EmailVerified {
		t.Error("an address Google did not verify must not read as verified")
	}
}
