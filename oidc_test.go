package social_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gonstruct/social"
)

// openIDProvider is an OpenID Connect provider that behaves: discovery, keys,
// an authorization endpoint that redirects back, and a token endpoint that
// signs an ID token with the nonce it was given.
type openIDProvider struct {
	*httptest.Server

	key      *rsa.PrivateKey
	nonce    string
	audience string
	issuer   string // what goes in the token; the real issuer unless a test lies
	expired  bool
	noIDTok  bool
}

func newOpenIDProvider(t *testing.T) *openIDProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &openIDProvider{key: key, audience: "app-id"}
	mux := http.NewServeMux()
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	op.issuer = op.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                op.URL,
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        op.URL + "/token",
			"jwks_uri":                              op.URL + "/keys",
			"userinfo_endpoint":                     op.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		op.nonce = query.Get("nonce")
		back, _ := url.Parse(query.Get("redirect_uri"))
		back.RawQuery = url.Values{"state": {query.Get("state")}, "code": {"the-code"}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := map[string]any{"access_token": "the-token", "token_type": "Bearer", "expires_in": 3600}
		if !op.noIDTok {
			token["id_token"] = op.idToken(t)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(token)
	})

	return op
}

func (op *openIDProvider) idToken(t *testing.T) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: op.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	expiry := now.Add(time.Hour)
	if op.expired {
		expiry = now.Add(-time.Hour)
	}
	claims := map[string]any{
		"iss": op.issuer, "sub": "person-1", "aud": op.audience, "nonce": op.nonce,
		"iat": now.Unix(), "exp": expiry.Unix(),
		"email": "person@example.com", "email_verified": true, "name": "A Person", "given_name": "A", "picture": "https://cdn/p.png",
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func openIDConnectProvider(op *openIDProvider) func(app *application) social.Provider {
	return func(app *application) social.Provider {
		return &social.OpenIDConnect{
			Driver: "acme", IssuerURL: op.URL, ClientID: "app-id", ClientSecret: "app-secret", RedirectURL: app.URL + "/callback",
		}
	}
}

func TestOpenIDConnectSignsInFromAVerifiedIDToken(t *testing.T) {
	op := newOpenIDProvider(t)
	app := newApplication(t, openIDConnectProvider(op))

	result, response := signIn(t, browser(t), app, "/login?to=/home")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if result.ID != "person-1" || result.Email != "person@example.com" || !result.Verified || result.Name != "A Person" || result.RedirectTo != "/home" {
		t.Fatalf("wrong user: %+v", result)
	}
	if op.nonce == "" {
		t.Fatal("an openid request should carry a nonce")
	}
}

func TestOpenIDConnectRefusesAnIDTokenForAnotherAudience(t *testing.T) {
	op := newOpenIDProvider(t)
	op.audience = "someone-else"
	app := newApplication(t, openIDConnectProvider(op))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode == http.StatusOK {
		t.Fatal("a token for another client must not sign anyone in")
	}
}

func TestOpenIDConnectRefusesAnExpiredIDToken(t *testing.T) {
	op := newOpenIDProvider(t)
	op.expired = true
	app := newApplication(t, openIDConnectProvider(op))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode == http.StatusOK {
		t.Fatal("an expired token must not sign anyone in")
	}
}

func TestOpenIDConnectRefusesAnIDTokenFromAnotherIssuer(t *testing.T) {
	op := newOpenIDProvider(t)
	op.issuer = "https://attacker.test"
	app := newApplication(t, openIDConnectProvider(op))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode == http.StatusOK {
		t.Fatal("a token from another issuer must not sign anyone in")
	}
}

func TestOpenIDConnectRefusesTheWrongNonce(t *testing.T) {
	op := newOpenIDProvider(t)
	app := newApplication(t, openIDConnectProvider(op))
	client := browser(t)

	// Start once so a handshake exists, then make the provider sign a token
	// for a nonce nobody issued.
	redirect := &http.Client{Jar: client.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	first, err := redirect.Get(app.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	location, _ := url.Parse(first.Header.Get("Location"))
	op.nonce = "not-the-one"

	callback := app.URL + "/callback?code=the-code&state=" + url.QueryEscape(location.Query().Get("state"))
	response, err := client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("a token with another nonce must not sign anyone in")
	}
}

func TestOpenIDConnectNeedsAnIDToken(t *testing.T) {
	op := newOpenIDProvider(t)
	op.noIDTok = true
	app := newApplication(t, openIDConnectProvider(op))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode == http.StatusOK {
		t.Fatal("a token response without an id_token must not sign anyone in")
	}
}

func TestOpenIDConnectDiscoveryFailureIsNotConfigured(t *testing.T) {
	provider := &social.OpenIDConnect{Driver: "acme", IssuerURL: "http://127.0.0.1:1", ClientID: "id"}
	if provider.Configured() {
		t.Fatal("a provider that cannot be discovered is not configured")
	}
}

func TestClaimsMapping(t *testing.T) {
	user := social.Claims(map[string]any{
		"sub": "1", "email": "p@example.com", "email_verified": true, "name": "P", "preferred_username": "pee", "picture": "https://p",
	})
	if user.ID != "1" || user.Email != "p@example.com" || !user.EmailVerified || user.Name != "P" || user.Nickname != "pee" || user.Avatar != "https://p" {
		t.Fatalf("claims: %+v", user)
	}
	if social.Claims(map[string]any{"sub": "1", "given_name": "G"}).Nickname != "G" {
		t.Error("given_name should be the fallback nickname")
	}
}
