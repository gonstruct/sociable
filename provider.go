package sociable

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

// Provider is what a driver is made of, Socialite's four abstract methods:
// where to send the browser, what to ask for, how to read the raw document
// behind a token, and how to map it. The provider is a zero value, so what
// it needs to know comes in through the credentials.
type Provider interface {
	Endpoint(credentials Credentials) oauth2.Endpoint
	Scoping() Scoping

	// GetUserByToken fetches the provider's document for the person. The
	// client already presents the token, the way Socialite's getHttpClient
	// does. Socialite's getUserByToken.
	GetUserByToken(ctx context.Context, client *http.Client, token *oauth2.Token, credentials Credentials) (*fastjson.Value, error)

	// MapUserToStruct turns that document into a User. The driver calls it,
	// and fills in the token afterwards. Socialite's mapUserToObject.
	MapUserToStruct(json *fastjson.Value) (*User, error)
}

type Scoping struct {
	Scopes    []string
	Separator string
}

// User is who the provider vouches for.
type User struct {
	// ID is the provider's stable identifier for this person. Store this,
	// not the email, which can change.
	ID string

	Nickname      string
	Name          string
	Email         string
	EmailVerified bool
	Avatar        string

	// Token carries the access token, the refresh token when the provider
	// issued one, and the expiry.
	Token *oauth2.Token

	// ApprovedScopes are the scopes the provider granted, which need not be
	// the ones that were asked for.
	ApprovedScopes []string
}

// unprotectedProvider is a provider that cannot do PKCE. Every provider that
// stays silent does it.
type unprotectedProvider interface {
	UsesPKCE() bool
}

// openIDProvider is an OpenID Connect issuer. The ID token it returns with
// the access token is verified for signature, issuer, audience, expiry and
// nonce before the person is trusted.
type openIDProvider interface {
	Issuer() string
}

// fetch is a provider's GET of a JSON document, with the client that presents
// the token. Socialite's getHttpClient()->get() and json_decode in one.
func fetch(ctx context.Context, client *http.Client, url string, headers map[string]string) (*fastjson.Value, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	return fastjson.ParseBytes(body)
}
