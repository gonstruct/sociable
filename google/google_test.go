package google_test

import (
	"testing"

	"github.com/gonstruct/social"
	"github.com/gonstruct/social/google"
)

func TestGoogleIsOpenIDConnectThroughDiscovery(t *testing.T) {
	provider := google.New(google.Options{ClientID: "id", ClientSecret: "secret", RedirectURL: "http://app/cb", Offline: true}).(*social.OpenIDConnect)

	if provider.Name() != "google" || provider.IssuerURL != "https://accounts.google.com" || provider.ClientID != "id" {
		t.Fatalf("basics: %+v", provider)
	}
	if provider.Extra["access_type"] != "offline" || provider.Extra["prompt"] != "consent" {
		t.Fatalf("offline: %v", provider.Extra)
	}
	if len(google.New(google.Options{}).(*social.OpenIDConnect).Extra) != 0 {
		t.Error("online sign-in should send no extra parameters")
	}
}
