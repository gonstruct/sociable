// Package vouch signs people in with somebody else's account: the OAuth 2.0
// authorization code flow with PKCE, on plain net/http, for any provider.
//
// A handler does two things:
//
//	err := auth.Driver(w, r, "google").Redirect("/after")
//	user, err := auth.Driver(w, r, "google").User()
//
// and shapes the request in between when it needs to:
//
//	auth.Driver(w, r, "google").
//		Scopes("https://www.googleapis.com/auth/drive.readonly").
//		With(map[string]string{"login_hint": address}).
//		Redirect("/settings/integrations")
//
// What it does that most clients do not:
//
//   - PKCE (RFC 7636) is on unless a provider says it cannot, rather than off
//     unless somebody remembers. OAuth 2.1 requires it of every client.
//   - A provider that refuses in the redirect (RFC 6749 section 4.1.2.1) is an
//     AuthorizationError, so a cancelled sign-in is not reported as a broken
//     one.
//   - The iss parameter (RFC 9207) is checked for a provider that sends it,
//     which is what defeats a mix-up between two authorization servers.
//   - State is compared in constant time, the handshake carries its own
//     expiry, and a nonce is issued whenever the openid scope is asked for.
//   - Granted scopes come back on the User, because RFC 6749 section 5.1 lets
//     them differ from the ones requested.
//
// It deliberately stops at the identity. What an application does with the
// resolved user, sign them in, attach them to a workspace, refuse them, is the
// application's.
package vouch

import (
	"errors"
	"maps"
	"net/http"
	"sync"
)

// Drivers maps a name to a provider constructor. It holds constructors rather
// than instances so each request reads the configuration as it is now: a
// provider built once at boot would keep whatever credentials existed then,
// which is wrong the moment anything reloads them, and untestable besides.
type Drivers map[string]func() Provider

// Configuration is what the application sets up once: how to seal a
// handshake, what the cookie looks like, which providers exist, and the HTTP
// client used to talk to them.
type Configuration struct {
	// Sealer encrypts the handshake for the browser to hold. Required; see
	// AESSealer for one that needs nothing but a key.
	Sealer Sealer

	// Cookie is how the handshake travels between the redirect and the
	// callback. Name defaults to "vouch_handshake", Path to "/", SameSite to
	// Lax, and Lifetime to ten minutes.
	Cookie CookieOptions

	Drivers Drivers

	// Client sends the token exchange, refresh and profile requests. Give it
	// a traced transport to see them; nil is http.DefaultClient.
	Client *http.Client
}

// Vouch is a set of providers bound to one configuration. Build it once at
// boot and keep it; Driver binds a provider to a request.
type Vouch struct {
	mutex         sync.RWMutex
	configuration Configuration
}

// ErrNoSealer is returned by New when the configuration cannot seal a
// handshake, which would leave every flow stateless.
var ErrNoSealer = errors.New("vouch: a Sealer is required")

// New validates the configuration and applies the cookie defaults.
func New(configuration Configuration) (*Vouch, error) {
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

	return &Vouch{configuration: configuration}, nil
}

// Extend adds one driver, for a provider that is not part of the
// application's own configuration.
func (self *Vouch) Extend(name string, construct func() Provider) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.configuration.Drivers[name] = construct
}

// Driver binds a provider to this request. An unknown name is not a panic: it
// surfaces as ErrUnknownDriver from Redirect or User, so a typo in a route
// fails as a response rather than as a crash.
func (self *Vouch) Driver(writer http.ResponseWriter, request *http.Request, name string) *Flow {
	self.mutex.RLock()
	defer self.mutex.RUnlock()

	flow := &Flow{
		writer:  writer,
		request: request,
		name:    name,
		sealer:  self.configuration.Sealer,
		cookie:  self.configuration.Cookie,
		client:  self.configuration.Client,
	}

	if construct, ok := self.configuration.Drivers[name]; ok {
		flow.provider = construct()
	}

	return flow
}
