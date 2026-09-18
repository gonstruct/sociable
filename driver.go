package sociable

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type driver struct {
	manager     *Manager
	name        string
	provider    Provider
	credentials Credentials

	// Set by the chain, for one request.
	scopes   []string          // nil means the provider's
	params   map[string]string // extra auth URL parameters
	redirect string            // "" means the credentials'

	// stateless skips the session: nothing is kept between the redirect and
	// the callback, so no state check and no PKCE. Socialite's stateless().
	stateless bool
}

type DriverContract interface {
	Scopes(scopes ...string) DriverContract
	SetScopes(scopes ...string) DriverContract
	With(params map[string]string) DriverContract
	RedirectURL(url string) DriverContract
	Stateless() DriverContract

	Redirect(w http.ResponseWriter, r *http.Request) error
	User(w http.ResponseWriter, r *http.Request) (*User, error)
	Callback(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error)
	UserFromToken(ctx context.Context, token *oauth2.Token) (*User, error)
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

// session is the configured one, or a cookie under Key.
func (self driver) session() (Session, error) {
	self.manager.mutex.RLock()
	defer self.manager.mutex.RUnlock()

	if self.manager.config.Session != nil {
		return self.manager.config.Session, nil
	}

	return newCookieSession(self.manager.config.Key, self.secure())
}

// secure is whether the application is served over TLS: this request is, or
// APIURL says so, for a proxy that terminates it.
func (self driver) secure() bool {
	return strings.HasPrefix(self.manager.config.APIURL, "https://")
}

func (self driver) config() *oauth2.Config {
	redirect := self.redirect
	if redirect == "" {
		redirect = self.credentials.RedirectURL
	}

	// A path is resolved against the application's URL, Socialite's
	// formatRedirectUrl.
	if strings.HasPrefix(redirect, "/") {
		redirect = strings.TrimSuffix(self.manager.config.APIURL, "/") + redirect
	}

	return &oauth2.Config{
		ClientID:     self.credentials.ClientID,
		ClientSecret: self.credentials.ClientSecret,
		RedirectURL:  redirect,
		Endpoint:     self.provider.Endpoint(self.credentials),
		Scopes:       self.scoped(),
	}
}
