package sociable_test

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
	"github.com/gonstruct/sociable"
)

// issuer is a fake OpenID Connect provider: discovery, a key set, an
// authorization endpoint that echoes the nonce, and a token endpoint that
// signs an ID token with it.
type issuer struct {
	*httptest.Server

	key      *rsa.PrivateKey
	audience string
	nonce    string
	claims   map[string]any
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	op := &issuer{key: key, audience: "client"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                op.URL,
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        op.URL + "/token",
			"jwks_uri":                              op.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		op.nonce = r.URL.Query().Get("nonce")
		back, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		back.RawQuery = url.Values{"code": {"c0de"}, "state": {r.URL.Query().Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t0ken", "token_type": "bearer", "id_token": op.idToken(t)})
	})

	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)

	return op
}

func (op *issuer) idToken(t *testing.T) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: op.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{
		"iss": op.URL, "aud": op.audience, "sub": "google-123", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"nonce": op.nonce, "email": "arjen@example.test", "email_verified": true, "name": "Arjen", "picture": "https://example.test/a.png",
	}
	for key, value := range op.claims {
		claims[key] = value
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func (op *issuer) factory() sociable.Factory {
	return func(credentials sociable.Credentials) sociable.Provider { return sociable.OpenID(credentials, op.URL) }
}

func TestOpenIDSignsInFromAVerifiedIDToken(t *testing.T) {
	op := newIssuer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", op.factory()) })

	result := signIn(t, browser(t), app, "acme")

	if result.Error != "" {
		t.Fatalf("sign in failed: %s", result.Error)
	}
	if result.User.ID != "google-123" || result.User.Email != "arjen@example.test" || !result.User.EmailVerified || result.User.Name != "Arjen" {
		t.Errorf("user = %+v", result.User)
	}
	if op.nonce == "" {
		t.Error("no nonce was sent")
	}
}

func TestOpenIDRefusesAnIDTokenForAnotherAudience(t *testing.T) {
	op := newIssuer(t)
	op.audience = "somebody-else"
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", op.factory()) })

	if result := signIn(t, browser(t), app, "acme"); result.Error != "idtoken" {
		t.Errorf("error = %q, want idtoken", result.Error)
	}
}

func TestOpenIDRefusesAnIDTokenWithAnotherNonce(t *testing.T) {
	op := newIssuer(t)
	op.claims = map[string]any{"nonce": "replayed"}
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", op.factory()) })

	if result := signIn(t, browser(t), app, "acme"); result.Error != "idtoken" {
		t.Errorf("error = %q, want idtoken", result.Error)
	}
}
