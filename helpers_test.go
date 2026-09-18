package sociable

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

// stub is a provider whose endpoints and profile live at Credentials.BaseURL,
// so every test points it at a server of its own.
type stub struct{}

func (stub) Endpoint(c Credentials) oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: c.BaseURL + "/auth", TokenURL: c.BaseURL + "/token"}
}

func (stub) Scoping() Scoping { return Scoping{Scopes: []string{"a", "b"}, Separator: " "} }

func (stub) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, c Credentials) (*fastjson.Value, error) {
	return fetch(ctx, client, c.BaseURL+"/user", nil)
}

func (stub) MapUserToStruct(json *fastjson.Value) (*User, error) {
	return &User{ID: string(json.GetStringBytes("id")), Name: string(json.GetStringBytes("name"))}, nil
}

// commaStub separates scopes with a comma.
type commaStub struct{ stub }

func (commaStub) Scoping() Scoping { return Scoping{Scopes: []string{"a", "b"}, Separator: ","} }

// noPKCEStub cannot do PKCE.
type noPKCEStub struct{ stub }

func (noPKCEStub) UsesPKCE() bool { return false }

// openidStub asks for openid and names the issuer the OIDC tests serve.
type openidStub struct{ stub }

func (openidStub) Scoping() Scoping { return Scoping{Scopes: []string{"openid", "a"}, Separator: " "} }
func (openidStub) Issuer() string   { return oidcIssuer }

// oidcIssuer is set by the one test group that serves an issuer. Those tests
// do not run in parallel.
var oidcIssuer string

// badMapStub cannot map.
type badMapStub struct{ stub }

func (badMapStub) MapUserToStruct(*fastjson.Value) (*User, error) { return nil, errors.New("no map") }

// providerServer answers the token and profile calls a driver makes.
type providerServer struct {
	*httptest.Server

	token   map[string]any // the token response; nil answers 400
	profile map[string]any // the profile document; nil answers 500
	form    url.Values     // what the last token request posted
	auth    string         // the Authorization header on the last profile call
}

func newProviderServer(t *testing.T) *providerServer {
	t.Helper()

	server := &providerServer{
		token:   map[string]any{"access_token": "at", "token_type": "bearer", "scope": "a b"},
		profile: map[string]any{"id": "42", "name": "Test User"},
	}

	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			server.form = r.PostForm

			if server.token == nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}

			_ = json.NewEncoder(w).Encode(server.token)
		case "/user":
			server.auth = r.Header.Get("Authorization")

			if server.profile == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			_ = json.NewEncoder(w).Encode(server.profile)
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(server.Close)

	return server
}

// manager is a Manager with one driver, "stub", pointed at the server.
func manager[T Provider](server *providerServer, options ...option) *Manager {
	return New(append([]option{
		WithKey("test-key"),
		WithAPIURL("https://app.example"),
		WithDriver[T]("stub", Credentials{ClientID: "id", ClientSecret: "secret", BaseURL: server.URL, RedirectURL: "/cb"}),
	}, options...)...)
}

// redirected runs Redirect and hands back the auth URL's query and the
// cookies that were set.
func redirected(t *testing.T, d DriverContract) (url.Values, []*http.Cookie) {
	t.Helper()

	recorder := httptest.NewRecorder()
	if err := d.Redirect(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil)); err != nil {
		t.Fatalf("redirect: %v", err)
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("redirect status %d", recorder.Code)
	}

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	return location.Query(), recorder.Result().Cookies()
}

// callback is the request the provider sends the browser back with, carrying
// the cookies from the redirect.
func callback(query string, cookies []*http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/cb?"+query, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	return request
}

// signIn runs the whole flow against the driver and returns what User gave.
func signIn(t *testing.T, d DriverContract) (*User, error) {
	t.Helper()

	query, cookies := redirected(t, d)

	return d.User(httptest.NewRecorder(), callback("code=c&state="+query.Get("state"), cookies))
}

// rewriting sends every request to the test server, whatever host the
// provider hard-coded, keeping the path.
type rewriting struct{ to *url.URL }

func (self rewriting) RoundTrip(request *http.Request) (*http.Response, error) {
	request.URL.Scheme = self.to.Scheme
	request.URL.Host = self.to.Host

	return http.DefaultTransport.RoundTrip(request)
}

// rewritingClient is a client that talks to the given handler regardless of
// URL, and records the last request it saw.
func rewritingClient(t *testing.T, handler http.HandlerFunc) (*http.Client, *http.Request) {
	t.Helper()

	var last http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = *r
		last.Header = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	to, _ := url.Parse(server.URL)

	return &http.Client{Transport: rewriting{to: to}}, &last
}

func encode(document any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(document) }
}

// issuer is a fake OpenID Connect issuer: discovery, a key set, and ID tokens
// signed with its key.
type issuer struct {
	*httptest.Server

	key *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	self := &issuer{key: key}

	self.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                self.URL,
				"authorization_endpoint":                self.URL + "/auth",
				"token_endpoint":                        self.URL + "/token",
				"jwks_uri":                              self.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
				"kty": "RSA", "kid": "k", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(self.Close)

	return self
}

// idToken is a signed ID token for the audience with the nonce. Signed with
// another key, it does not verify.
func (self *issuer) idToken(t *testing.T, audience, nonce string, key *rsa.PrivateKey) string {
	t.Helper()

	if key == nil {
		key = self.key
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k"})
	claims, _ := json.Marshal(map[string]any{
		"iss": self.URL, "aud": audience, "sub": "sub-1", "nonce": nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})

	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// handshakeFrom opens the handshake the redirect stored in the cookies.
func handshakeFrom(t *testing.T, cookies []*http.Cookie) handshake {
	t.Helper()

	session, err := newCookieSession("test-key", false)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := session.Pull(httptest.NewRecorder(), callback("", cookies), sessionKey)
	if err != nil {
		t.Fatal(err)
	}

	var issued handshake
	if err := json.Unmarshal([]byte(payload), &issued); err != nil {
		t.Fatal(err)
	}

	return issued
}

// memorySession is a Session of the application's own.
type memorySession struct {
	values map[string]string
	putErr error
}

func (self *memorySession) Put(_ http.ResponseWriter, _ *http.Request, key, value string) error {
	if self.putErr != nil {
		return self.putErr
	}

	self.values[key] = value

	return nil
}

func (self *memorySession) Pull(_ http.ResponseWriter, _ *http.Request, key string) (string, error) {
	value := self.values[key]
	delete(self.values, key)

	return value, nil
}
