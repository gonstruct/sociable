// Package google signs people in with Google through OpenID Connect.
package google

import (
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
}

// New is a constructor for a social.Drivers entry. The issuer is checked, the
// profile comes from the OpenID Connect userinfo endpoint, and the default
// scopes are openid, email and profile.
func New(options Options) func() social.Provider {
	return func() social.Provider {
		scopes := options.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "email", "profile"}
		}

		extra := map[string]string{}
		if options.Offline {
			extra["access_type"] = "offline"
			extra["prompt"] = "consent"
		}

		return &social.OAuth2{
			Driver:       Name,
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			RedirectURL:  options.RedirectURL,
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			ProfileURL:   "https://openidconnect.googleapis.com/v1/userinfo",
			IssuerURL:    "https://accounts.google.com",
			Scopes:       scopes,
			Extra:        extra,
			Profile:      Profile,
		}
	}
}

// Profile maps the userinfo document. sub is the stable identifier; email
// is verified only when Google says so.
func Profile(raw map[string]any) social.User {
	return social.User{
		ID:            social.String(raw, "sub"),
		Nickname:      social.String(raw, "given_name"),
		Name:          social.String(raw, "name"),
		Email:         social.String(raw, "email"),
		EmailVerified: social.Bool(raw, "email_verified"),
		Avatar:        social.String(raw, "picture"),
	}
}
