package sociable

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
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

// DriverContract is what Driver hands back: Socialite's provider surface, the
// chain that shapes a redirect and the calls that run the flow. A fake
// implements it too.
type DriverContract interface { //nolint:interfacebloat // Socialite's surface, all of it.
	Scopes(scopes ...string) DriverContract
	SetScopes(scopes ...string) DriverContract
	With(params map[string]string) DriverContract
	RedirectURL(url string) DriverContract
	Stateless() DriverContract

	Redirect(w http.ResponseWriter, r *http.Request) error
	AuthURL(w http.ResponseWriter, r *http.Request) (string, error)
	User(w http.ResponseWriter, r *http.Request) (*User, error)
	Callback(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error)
	UserFromToken(ctx context.Context, token *oauth2.Token) (*User, error)
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

// configured is whether the driver can talk to its provider at all. A
// deployment without credentials, a preview or a test, should refuse the
// route rather than redirect somewhere half-built.
func (self driver) configured() error {
	config := self.config()

	if config.ClientID == "" || config.Endpoint.AuthURL == "" || config.Endpoint.TokenURL == "" || config.RedirectURL == "" {
		return fmt.Errorf("%w: %s", ErrDriverNotConfigured, self.name)
	}

	return nil
}

// outbound is the context every call to the provider is made with: it
// carries the configured client to x/oauth2 and to go-oidc.
func (self driver) outbound(ctx context.Context) context.Context {
	self.manager.mutex.RLock()
	client := self.manager.config.Client
	self.manager.mutex.RUnlock()

	if client == nil {
		return ctx
	}

	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, client), client)
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
