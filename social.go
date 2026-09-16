// Package social signs people in with somebody else's account: the OAuth 2.0
// authorization code flow with PKCE, and OpenID Connect on top of it, on
// plain net/http, for any provider.
//
// A handler does two things:
//
//	err := auth.Redirect(w, r, "google", social.To("/dashboard"))
//	result, err := auth.Callback(w, r, "google")
//
// and shapes the request with options when it needs to:
//
//	auth.Redirect(w, r, "google",
//		social.Scopes("https://www.googleapis.com/auth/drive.readonly"),
//		social.With(map[string]string{"login_hint": address}),
//		social.To("/settings/integrations"))
//
// What it does that most clients do not:
//
//   - PKCE (RFC 7636) is on unless a provider says it cannot, rather than off
//     unless somebody remembers. OAuth 2.1 requires it of every client.
//   - A provider that refuses in the redirect (RFC 6749 section 4.1.2.1) is an
//     AuthorizationError, so a cancelled sign-in is not reported as a broken
//     one.
//   - ID tokens are verified: signature against the provider's keys, issuer,
//     audience, expiry, and the nonce this package issued.
//   - The iss parameter (RFC 9207) is checked for a provider that asks for it,
//     which is what defeats a mix-up between two authorization servers.
//   - State is compared in constant time, the handshake carries its own
//     expiry, and is spent by any callback whether it succeeds or not.
//   - Granted scopes come back on the User, because RFC 6749 section 5.1 lets
//     them differ from the ones requested.
//
// It deliberately stops at the identity. What an application does with the
// resolved user, sign them in, attach them to a workspace, refuse them, is the
// application's.
package social

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Drivers maps a name to a provider. The name is what routes and logs use.
type Drivers map[string]Provider

// Configuration is what the application sets up once: how to seal a
// handshake, what the cookie looks like, which providers exist, and the HTTP
// client used to talk to them.
type Configuration struct {
	// Sealer encrypts the handshake for the browser to hold. Required; see
	// AESSealer for one that needs nothing but a key.
	Sealer Sealer

	// Cookie is how the handshake travels between the redirect and the
	// callback. Name defaults to "social_handshake", Path to "/", SameSite
	// to Lax, and Lifetime to ten minutes.
	Cookie CookieOptions

	Drivers Drivers

	// Client sends the token exchange, refresh, discovery, key and profile
	// requests. Give it a traced transport to see them; nil is
	// http.DefaultClient.
	Client *http.Client
}

// Social is a set of providers bound to one configuration. Build it once at
// boot and keep it.
type Social struct {
	mutex         sync.RWMutex
	configuration Configuration
}

// Result is what a finished callback gives back: who signed in, and where
// they asked to land afterwards.
type Result struct {
	User       *User
	RedirectTo string
}

// ErrNoSealer is returned by New when the configuration cannot seal a
// handshake, which would leave every flow stateless.
var ErrNoSealer = errors.New("social: a Sealer is required")

// New validates the configuration and applies the cookie defaults.
func New(configuration Configuration) (*Social, error) {
	if configuration.Sealer == nil {
		return nil, ErrNoSealer
	}

	configuration.Cookie = configuration.Cookie.withDefaults()
	configuration.Drivers = maps.Clone(configuration.Drivers)
	if configuration.Drivers == nil {
		configuration.Drivers = Drivers{}
	}
	if configuration.Client == nil {
		configuration.Client = http.DefaultClient
	}

	return &Social{configuration: configuration}, nil
}

// Extend adds one driver, for a provider that is not part of the
// application's own configuration.
func (self *Social) Extend(name string, provider Provider) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.configuration.Drivers[name] = provider
}

// Redirect sends the browser to the provider, remembering the state, verifier
// and nonce on the way out. The error is ErrUnknownDriver or ErrNotConfigured
// when nothing was sent, so a handler can answer those itself.
func (self *Social) Redirect(writer http.ResponseWriter, request *http.Request, name string, options ...Option) error {
	url, err := self.AuthorizationURL(writer, request, name, options...)
	if err != nil {
		return err
	}

	http.Redirect(writer, request, url, http.StatusFound)

	return nil
}

// AuthorizationURL is Redirect without the redirecting, for a handler that
// sends the browser itself. It still writes the handshake cookie, so
// whatever follows the URL must be the browser this was called for.
func (self *Social) AuthorizationURL(writer http.ResponseWriter, request *http.Request, name string, options ...Option) (string, error) {
	flow, err := self.flow(writer, request, name, options)
	if err != nil {
		return "", err
	}

	return flow.authorizationURL()
}

// Callback finishes the flow and returns the identity the provider vouches
// for, with the path the sign-in asked to land on.
//
// The code, state, issuer and any refusal are read from the request rather
// than passed in, because they are the provider's half of a conversation
// this package started: the caller has nothing to add to them.
func (self *Social) Callback(writer http.ResponseWriter, request *http.Request, name string, options ...Option) (*Result, error) {
	flow, err := self.flow(writer, request, name, options)
	if err != nil {
		return nil, err
	}

	return flow.callback()
}

// UserFromToken skips the flow and asks the provider about a token the caller
// already holds: one a native app obtained itself, or one stored earlier.
func (self *Social) UserFromToken(ctx context.Context, name string, token *oauth2.Token, options ...Option) (*User, error) {
	flow, err := self.flow(nil, (&http.Request{}).WithContext(ctx), name, options)
	if err != nil {
		return nil, err
	}

	return flow.userFromToken(token)
}

// Refresh trades a refresh token for a live one. Nothing is stored: what comes
// back may carry a new refresh token, and RFC 6749 section 6 lets the provider
// retire the old one, so the caller persists the result.
func (self *Social) Refresh(ctx context.Context, name, refreshToken string, options ...Option) (*oauth2.Token, error) {
	flow, err := self.flow(nil, (&http.Request{}).WithContext(ctx), name, options)
	if err != nil {
		return nil, err
	}

	return flow.refresh(refreshToken)
}

func (self *Social) flow(writer http.ResponseWriter, request *http.Request, name string, options []Option) (*flow, error) {
	self.mutex.RLock()
	provider, ok := self.configuration.Drivers[name]
	self.mutex.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDriver, name)
	}

	bound := &flow{
		writer:   writer,
		request:  request,
		name:     name,
		provider: provider,
		sealer:   self.configuration.Sealer,
		cookie:   self.configuration.Cookie,
		client:   self.configuration.Client,
	}
	for _, option := range options {
		option(bound)
	}

	return bound, nil
}
