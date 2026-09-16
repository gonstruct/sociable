package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// OAuth2 is a provider described by its endpoints, for the many providers that
// need no code of their own: an authorization URL, a token URL, a profile URL
// and a function that reads the profile. It is what the google and github
// packages are built on, and what an application uses for a provider this
// module does not ship.
type OAuth2 struct {
	// Driver is the name the provider is registered and routed under.
	Driver string

	ClientID     string
	ClientSecret string
	RedirectURL  string

	AuthURL    string
	TokenURL   string
	ProfileURL string

	// Scopes are asked for unless the call site changes them.
	Scopes []string

	// Extra parameters sent on every authorization request, such as
	// access_type=offline for a Google refresh token.
	Extra map[string]string

	// IssuerURL, when set, makes the iss parameter of RFC 9207 required on
	// the callback. Only set it for a provider that sends the parameter.
	IssuerURL string

	// WithoutPKCE opts out for a provider that rejects the challenge.
	WithoutPKCE bool

	// Profile turns the decoded profile into a User. Raw is filled in by the
	// provider; a Profile that leaves it empty keeps the decoded map.
	Profile func(raw map[string]any) User
}

func (self *OAuth2) Name() string { return self.Driver }

func (self *OAuth2) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     self.ClientID,
		ClientSecret: self.ClientSecret,
		RedirectURL:  self.RedirectURL,
		Scopes:       self.Scopes,
		Endpoint:     oauth2.Endpoint{AuthURL: self.AuthURL, TokenURL: self.TokenURL},
	}
}

func (self *OAuth2) Configured() bool {
	return self.ClientID != "" && self.AuthURL != "" && self.TokenURL != ""
}

func (self *OAuth2) Parameters() []oauth2.AuthCodeOption {
	options := make([]oauth2.AuthCodeOption, 0, len(self.Extra))
	for key, value := range self.Extra {
		options = append(options, oauth2.SetAuthURLParam(key, value))
	}

	return options
}

func (self *OAuth2) UsesPKCE() bool { return !self.WithoutPKCE }

// Issuer is only consulted when IssuerURL is set; see Issued.
func (self *OAuth2) Issuer() string { return self.IssuerURL }

// User fetches ProfileURL with the grant and hands the decoded JSON to Profile.
func (self *OAuth2) User(_ context.Context, grant Grant) (*User, error) {
	raw, err := FetchJSON(grant, self.ProfileURL)
	if err != nil {
		return nil, err
	}

	if self.Profile == nil {
		return &User{Raw: raw}, nil
	}

	user := self.Profile(raw)
	if user.Raw == nil {
		user.Raw = raw
	}

	return &user, nil
}

// FetchJSON reads a JSON document from the provider with the grant's client.
// Providers written by hand use it for their profile endpoints.
func FetchJSON(grant Grant, url string) (map[string]any, error) {
	response, err := grant.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, response.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}

	return raw, nil
}

// String reads a string field of a decoded profile, "" when absent.
func String(raw map[string]any, key string) string {
	value, _ := raw[key].(string)

	return value
}

// Bool reads a boolean field of a decoded profile, false when absent.
func Bool(raw map[string]any, key string) bool {
	value, _ := raw[key].(bool)

	return value
}
