package social_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonstruct/social"
)

// authorizationServer is a provider that behaves: it redirects back with a
// code, exchanges it only for the right verifier and client secret, and
// describes the user for the right bearer token.
type authorizationServer struct {
	*httptest.Server

	deny      bool
	challenge string
	scope     string
	tokenSeen url.Values
}

func newAuthorizationServer(t *testing.T) *authorizationServer {
	t.Helper()

	as := &authorizationServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		as.challenge = query.Get("code_challenge")
		as.scope = query.Get("scope")

		back, _ := url.Parse(query.Get("redirect_uri"))
		values := url.Values{"state": {query.Get("state")}, "iss": {as.URL}}
		if as.deny {
			values.Set("error", "access_denied")
			values.Set("error_description", "The user declined")
		} else {
			values.Set("code", "the-code")
		}
		back.RawQuery = values.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		as.tokenSeen = r.PostForm

		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		verifier := base64.RawURLEncoding.EncodeToString(sum[:])

		switch {
		case id != "app-id" || secret != "app-secret":
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		case r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != "the-code":
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		case verifier != as.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"verifier"}`, http.StatusBadRequest)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "the-token", "token_type": "Bearer", "expires_in": 3600, "scope": "profile email",
			})
		}
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer the-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "person-1", "email": "person@example.com", "email_verified": true, "name": "A Person", "picture": "https://cdn/p.png",
		})
	})

	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)

	return as
}

// application is the site signing people in: two handlers on social.
type application struct {
	*httptest.Server

	auth *social.Social
}

func newApplication(t *testing.T, provider func(app *application) social.Provider) *application {
	t.Helper()

	app := &application{}
	mux := http.NewServeMux()
	app.Server = httptest.NewServer(mux)
	t.Cleanup(app.Close)

	sealer, err := social.AESSealer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	app.auth, err = social.New(social.Configuration{Sealer: sealer, Drivers: social.Drivers{"acme": provider(app)}})
	if err != nil {
		t.Fatal(err)
	}

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := app.auth.Redirect(w, r, "acme", social.To(r.URL.Query().Get("to"))); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		result, err := app.auth.Callback(w, r, "acme")
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, social.ErrAccessDenied) {
				status = http.StatusForbidden
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": result.User.ID, "email": result.User.Email, "verified": result.User.EmailVerified, "name": result.User.Name,
			"scopes": result.User.ApprovedScopes, "redirectTo": result.RedirectTo, "token": result.User.Token.AccessToken,
		})
	})

	return app
}

func oauth2Provider(as *authorizationServer, secret string) func(app *application) social.Provider {
	return func(app *application) social.Provider {
		return &social.OAuth2{
			Driver: "acme", ClientID: "app-id", ClientSecret: secret, RedirectURL: app.URL + "/callback",
			AuthURL: as.URL + "/authorize", TokenURL: as.URL + "/token", ProfileURL: as.URL + "/userinfo",
			IssuerURL: as.URL, Scopes: []string{"profile", "email"},
			Profile: func(raw map[string]any) social.User {
				return social.User{
					ID: social.String(raw, "sub"), Email: social.String(raw, "email"),
					EmailVerified: social.Bool(raw, "email_verified"), Name: social.String(raw, "name"),
				}
			},
		}
	}
}

// browser follows redirects and keeps cookies, like the real thing.
func browser(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{Jar: jar}
}

type signedIn struct {
	ID, Email, Name, RedirectTo, Token string
	Verified                           bool
	Scopes                             []string
}

func signIn(t *testing.T, client *http.Client, app *application, path string) (signedIn, *http.Response) {
	t.Helper()

	response, err := client.Get(app.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var result signedIn
	if response.StatusCode == http.StatusOK {
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
	}

	return result, response
}

func TestEndToEndSignIn(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, oauth2Provider(as, "app-secret"))
	client := browser(t)

	result, response := signIn(t, client, app, "/login?to=/dashboard")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected the callback to answer 200, got %d", response.StatusCode)
	}
	if result.ID != "person-1" || result.Email != "person@example.com" || !result.Verified || result.Name != "A Person" {
		t.Errorf("wrong user: %+v", result)
	}
	if result.RedirectTo != "/dashboard" || result.Token != "the-token" || strings.Join(result.Scopes, " ") != "profile email" {
		t.Errorf("result: %+v", result)
	}

	// What the provider saw: PKCE with the matching verifier, the redirect
	// URI and the scopes.
	if as.tokenSeen.Get("code_verifier") == "" || as.tokenSeen.Get("redirect_uri") != app.URL+"/callback" || as.scope != "profile email" {
		t.Errorf("token request: %v, scope %q", as.tokenSeen, as.scope)
	}

	// The handshake is spent: the browser no longer holds the cookie.
	appURL, _ := url.Parse(app.URL)
	for _, cookie := range client.Jar.Cookies(appURL) {
		if cookie.Name == "social_handshake" {
			t.Error("the handshake cookie survived the callback")
		}
	}
}

func TestEndToEndDenial(t *testing.T) {
	as := newAuthorizationServer(t)
	as.deny = true
	app := newApplication(t, oauth2Provider(as, "app-secret"))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode != http.StatusForbidden {
		t.Fatalf("a denial should reach the app as a denial, got %d", response.StatusCode)
	}
	if as.tokenSeen != nil {
		t.Error("a denial must never be exchanged")
	}
}

func TestEndToEndReplayedCallbackIsRefused(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, oauth2Provider(as, "app-secret"))
	client := browser(t)

	_, first := signIn(t, client, app, "/login")
	replayed, err := client.Get(first.Request.URL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Body.Close()

	if replayed.StatusCode == http.StatusOK {
		t.Fatal("a callback without a live handshake must not sign anyone in")
	}
}

func TestEndToEndWrongSecretFailsTheExchange(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, oauth2Provider(as, "wrong"))

	if _, response := signIn(t, browser(t), app, "/login"); response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected the exchange to fail, got %d", response.StatusCode)
	}
}
