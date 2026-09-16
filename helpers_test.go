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

type fakeProvider struct {
	configured bool
	scopes     []string
	tokenURL   string
}

func (fakeProvider) Name() string              { return "fake" }
func (provider fakeProvider) Configured() bool { return provider.configured }

func (provider fakeProvider) Config() *oauth2.Config {
	tokenURL := provider.tokenURL
	if tokenURL == "" {
		tokenURL = "https://provider.test/token"
	}

	return &oauth2.Config{
		ClientID:    "client",
		RedirectURL: "http://localhost/callback",
		Scopes:      provider.scopes,
		Endpoint:    oauth2.Endpoint{AuthURL: "https://provider.test/authorize", TokenURL: tokenURL},
	}
}

func (fakeProvider) User(_ context.Context, grant social.Grant) (*social.User, error) {
	return &social.User{ID: "1", Email: "person@provider.test", EmailVerified: true, Raw: grant}, nil
}

// parameterisedProvider wants a Google-shaped refresh token, which only comes
// back when these two ride along on the authorization URL.
type parameterisedProvider struct{ fakeProvider }

func (parameterisedProvider) Parameters() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent")}
}

// unprotectedProvider stands for the older providers that reject a challenge.
type unprotectedProvider struct{ fakeProvider }

func (unprotectedProvider) UsesPKCE() bool { return false }

// issuedProvider names itself, which is what makes RFC 9207's iss parameter
// required rather than merely checked.
type issuedProvider struct{ fakeProvider }

func (issuedProvider) Issuer() string { return "https://provider.test" }

func configured() fakeProvider { return fakeProvider{configured: true} }

// setup builds a registry with one provider under "fake".
func setup(t *testing.T, provider social.Provider) *social.Social {
	t.Helper()

	auth, err := social.New(social.Configuration{Sealer: plainSealer{}, Drivers: social.Drivers{"fake": provider}})
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

// redirect runs Redirect through a handler and returns what the browser
// would have received: the Location and the handshake cookie.
func redirect(t *testing.T, auth *social.Social, options ...social.Option) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	if err := auth.Redirect(recorder, httptest.NewRequest(http.MethodGet, "/login", nil), "fake", options...); err != nil {
		t.Fatalf("redirect: %v", err)
	}

	return recorder
}

// callback runs Callback for a request, carrying the cookies a previous
// response set, and returns the recorder too because the handshake cookie
// must be cleared by it.
func callback(
	t *testing.T,
	auth *social.Social,
	target string,
	from *httptest.ResponseRecorder,
	options ...social.Option,
) (*social.Result, error, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if from != nil {
		for _, cookie := range from.Result().Cookies() {
			request.AddCookie(cookie)
		}
	}

	result, err := auth.Callback(recorder, request, "fake", options...)

	return result, err, recorder
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
