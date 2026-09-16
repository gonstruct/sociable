package social_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gonstruct/social"
	"golang.org/x/oauth2"
)

// plainSealer stands in for the application's encryption. The flow only
// needs the round trip, so most tests do not depend on a cipher.
type plainSealer struct{}

func (plainSealer) Seal(plain []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(plain), nil
}

func (plainSealer) Open(sealed string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(sealed)
}

type fakeProvider struct{ configured bool }

func (fakeProvider) Name() string              { return "fake" }
func (provider fakeProvider) Configured() bool { return provider.configured }

func (fakeProvider) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    "client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.test/authorize",
			TokenURL: "https://provider.test/token",
		},
	}
}

func (fakeProvider) User(_ context.Context, grant social.Grant) (*social.User, error) {
	return &social.User{
		ID:            "1",
		Email:         "person@provider.test",
		EmailVerified: true,
		Raw:           grant,
	}, nil
}

// parameterisedProvider wants a Google-shaped refresh token, which only comes
// back when these two ride along on the authorization URL.
type parameterisedProvider struct{ fakeProvider }

func (parameterisedProvider) Configured() bool { return true }

func (parameterisedProvider) Parameters() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	}
}

// unprotectedProvider stands for the older providers that reject a challenge.
type unprotectedProvider struct{ fakeProvider }

func (unprotectedProvider) Configured() bool { return true }
func (unprotectedProvider) UsesPKCE() bool   { return false }

// issuedProvider names itself, which is what makes RFC 9207's iss parameter
// required rather than merely checked.
type issuedProvider struct{ fakeProvider }

func (issuedProvider) Configured() bool { return true }
func (issuedProvider) Issuer() string   { return "https://provider.test" }

// scopedProvider asks for one scope of its own, so the tests can tell adding
// from replacing.
type scopedProvider struct{ fakeProvider }

func (scopedProvider) Configured() bool { return true }

func (scopedProvider) Config() *oauth2.Config {
	config := fakeProvider{}.Config()
	config.Scopes = []string{"profile"}

	return config
}

// exchangingProvider talks to a token endpoint that answers, for the tests
// that need to get past the exchange.
type exchangingProvider struct {
	fakeProvider

	tokenURL string
}

func (exchangingProvider) Configured() bool { return true }

func (provider exchangingProvider) Config() *oauth2.Config {
	config := fakeProvider{}.Config()
	config.Endpoint.TokenURL = provider.tokenURL

	return config
}

// setup builds a registry with one provider under "fake".
func setup(t *testing.T, construct func() social.Provider) *social.Social {
	t.Helper()

	auth, err := social.New(social.Configuration{
		Sealer:  plainSealer{},
		Drivers: social.Drivers{"fake": construct},
	})
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

func fake(configured bool) func() social.Provider {
	return func() social.Provider { return fakeProvider{configured: configured} }
}

// redirect runs Redirect through a handler and returns what the browser
// would have received: the Location and the handshake cookie.
func redirect(t *testing.T, auth *social.Social, redirectTo string, shape ...func(*social.Flow) *social.Flow) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)

	flow := auth.Driver(recorder, request, "fake")
	for _, apply := range shape {
		flow = apply(flow)
	}
	if err := flow.Redirect(redirectTo); err != nil {
		t.Fatalf("redirect: %v", err)
	}

	return recorder
}

// callback runs User for a callback request, carrying the cookies a previous
// response set. It returns the recorder too, because the handshake cookie
// must be cleared by it.
func callback(
	t *testing.T,
	auth *social.Social,
	target string,
	from *httptest.ResponseRecorder,
	shape ...func(*social.Flow) *social.Flow,
) (*social.User, error, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if from != nil {
		for _, cookie := range from.Result().Cookies() {
			request.AddCookie(cookie)
		}
	}

	flow := auth.Driver(recorder, request, "fake")
	for _, apply := range shape {
		flow = apply(flow)
	}
	user, err := flow.User()

	return user, err, recorder
}

// issuedQuery is the authorization URL the driver sent the browser to, taken
// apart.
func issuedQuery(t *testing.T, recorder *httptest.ResponseRecorder) url.Values {
	t.Helper()

	parsed, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	return parsed.Query()
}

func issuedState(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	return issuedQuery(t, recorder).Get("state")
}

// tokenEndpoint answers an exchange with the smallest token RFC 6749 section
// 5.1 allows, so a test can reach what happens after one.
func tokenEndpoint(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"granted","token_type":"Bearer"}`))
	}))
	t.Cleanup(server.Close)

	return server.URL
}

func expired() social.CookieOptions {
	return social.CookieOptions{Lifetime: -time.Second}
}
