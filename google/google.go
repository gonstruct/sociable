// Package google signs people in with Google through OpenID Connect.
package google

import (
	"net/http"

	"github.com/gonstruct/social"
)

// Name is what the provider is registered and routed under.
const Name = "google"

// Options are the application's credentials. Offline asks for a refresh
// token, which Google only issues with access_type=offline and prompt=consent.
type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Offline      bool

	// Client fetches Google's discovery document and signing keys.
	Client *http.Client
}

// New is a provider for a social.Drivers entry. Endpoints and keys come from
// Google's discovery document, and the identity from a verified ID token.
func New(options Options) social.Provider {
	extra := map[string]string{}
	if options.Offline {
		extra["access_type"] = "offline"
		extra["prompt"] = "consent"
	}

	return &social.OpenIDConnect{
		Driver:       Name,
		IssuerURL:    "https://accounts.google.com",
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  options.RedirectURL,
		Scopes:       options.Scopes,
		Extra:        extra,
		Client:       options.Client,
	}
}
