package social

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// Provider is what a driver must supply: where to send the browser, and how to
// turn a grant into a user. Everything else about the flow is this package's,
// and everything a provider may change about it is an interface below.
type Provider interface {
	// Name identifies the driver in routes and logs.
	Name() string

	// Config carries the endpoints, credentials and default scopes. The flow
	// copies it before changing anything, so returning the same pointer on
	// every call is safe.
	Config() *oauth2.Config

	// Configured reports whether the credentials are present.
	Configured() bool

	// User reads the provider's profile and normalises it.
	User(context context.Context, grant Grant) (*User, error)
}

// Grant is what the flow obtained, handed to the provider so it can read the
// profile and check anything the token carries.
//
// Client already presents the token, so a provider reads its profile with a
// plain Get. Nonce is the value that was sent on the authorization request
// when the provider was asked for the openid scope. A provider that reads an
// ID token must check the nonce claim against it: OpenID Connect Core section
// 3.1.3.7 makes that the client's job, and it is what stops a token issued for
// one sign-in being replayed into another.
type Grant struct {
	Token  *oauth2.Token
	Nonce  string
	Client *http.Client
}

// Parameterised is implemented by a provider that needs more on the
// authorization URL than the flow itself puts there: access_type and prompt for
// a Google refresh token, audience for an API-scoped token, a provider's own
// invention. A provider that stays silent sends none.
type Parameterised interface {
	Parameters() []oauth2.AuthCodeOption
}

// Unprotected is implemented by a provider that cannot do PKCE. Some older
// providers reject the challenge outright, and a confidential client with a
// secret is not defenceless without it.
//
// PKCE is on for every provider that stays silent. OAuth 2.1 makes it mandatory
// for all clients, so opting out should be a decision somebody wrote down.
type Unprotected interface {
	UsesPKCE() bool
}

// Issued is implemented by a provider whose authorization responses carry the
// iss parameter from RFC 9207. Implementing it makes the parameter required:
// the point of the extension is that a client which expects an issuer rejects a
// response without one, which is what defeats a mix-up attack between two
// authorization servers the same client talks to.
type Issued interface {
	Issuer() string
}
