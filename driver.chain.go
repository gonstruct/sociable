package sociable

import (
	"maps"
	"slices"
)

// The chain shapes one redirect. Every method returns a changed copy, so
// nothing leaks into the next request.

// Scopes adds to the provider's scopes. Socialite's scopes().
func (self driver) Scopes(scopes ...string) DriverContract {
	self.scopes = append(self.scoped(), scopes...)
	return self
}

// SetScopes replaces the provider's scopes. Socialite's setScopes().
func (self driver) SetScopes(scopes ...string) DriverContract {
	self.scopes = scopes
	return self
}

// With adds query parameters to the auth URL: access_type, prompt,
// login_hint, whatever the provider understands. Socialite's with(). What is
// given here wins over what the flow would send.
func (self driver) With(params map[string]string) DriverContract {
	merged := maps.Clone(self.params)
	if merged == nil {
		merged = map[string]string{}
	}

	maps.Copy(merged, params)

	self.params = merged
	return self
}

// RedirectURL overrides the callback URL for this request. Socialite's
// redirectUrl().
func (self driver) RedirectURL(url string) DriverContract {
	self.redirect = url
	return self
}

// Stateless skips the handshake, for a callback this server did not start.
// Socialite's stateless(). Nothing is kept between the two steps, so PKCE is
// off and the state is not checked.
func (self driver) Stateless() DriverContract {
	self.stateless = true
	return self
}

// scoped is the scopes in effect: the chain's, or the provider's.
func (self driver) scoped() []string {
	if self.scopes != nil || self.provider == nil {
		return slices.Clone(self.scopes)
	}

	return slices.Clone(self.provider.Scoping().Scopes)
}
