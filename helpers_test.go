package sociable_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/gonstruct/sociable"
	"golang.org/x/oauth2"
)

// authorizationServer is a fake provider: it hands out a code, exchanges it for
// a token when the PKCE verifier and the secret are right, and serves a
// profile to a bearer of that token.
type authorizationServer struct {
	*httptest.Server

	mutex     sync.Mutex
	secret    string
	challenge string
	scope     string
	profile   map[string]any
	deny      bool
	requests  []url.Values
}

func newAuthorizationServer(t *testing.T) *authorizationServer {
	t.Helper()

	as := &authorizationServer{
		secret:  "s3cret",
		profile: map[string]any{"id": float64(42), "login": "arjen", "email": "arjen@example.test"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", as.authorize)
	mux.HandleFunc("/token", as.token)
	mux.HandleFunc("/me", as.me)

	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)

	return as
}

func (as *authorizationServer) authorize(w http.ResponseWriter, r *http.Request) {
	as.mutex.Lock()
	as.requests = append(as.requests, r.URL.Query())
	as.challenge = r.URL.Query().Get("code_challenge")
	as.mutex.Unlock()

	back, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
	query := url.Values{"state": {r.URL.Query().Get("state")}}

	if as.deny {
		query.Set("error", "access_denied")
		query.Set("error_description", "the person said no")
	} else {
		query.Set("code", "c0de")
	}

	back.RawQuery = query.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (as *authorizationServer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	if r.PostForm.Get("code") != "c0de" || r.PostForm.Get("client_secret") != as.secret {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)

		return
	}

	as.mutex.Lock()
	challenge := as.challenge
	as.mutex.Unlock()

	if challenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, `{"error":"invalid_grant","error_description":"bad verifier"}`, http.StatusBadRequest)

			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "t0ken", "token_type": "bearer", "refresh_token": "r3fresh", "expires_in": 3600, "scope": as.scope,
	})
}

func (as *authorizationServer) me(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer t0ken" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(as.profile)
}

func (as *authorizationServer) lastRequest() url.Values {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	return as.requests[len(as.requests)-1]
}

func (as *authorizationServer) factory() sociable.Factory {
	return func(credentials sociable.Credentials) sociable.Provider {
		return sociable.OAuth2{
			Credentials: credentials,
			Endpoint:    oauth2.Endpoint{AuthURL: as.URL + "/authorize", TokenURL: as.URL + "/token"},
			Scopes:      []string{"profile"},
			ProfileURL:  as.URL + "/me",
			Map: func(raw map[string]any) sociable.User {
				return sociable.User{ID: sociable.String(raw, "id"), Nickname: sociable.String(raw, "login"), Email: sociable.String(raw, "email")}
			},
		}
	}
}

// application is a site with the two handlers, answering the callback with the
// user or the error as JSON so a test can read what happened.
type application struct {
	*httptest.Server

	auth   *sociable.Manager
	before func(sociable.Flow) sociable.Flow
}

type outcome struct {
	User  *sociable.User `json:"user"`
	Error string         `json:"error"`
}

func newApplication(t *testing.T, configure func(config *sociable.Config), extend func(auth *sociable.Manager)) *application {
	t.Helper()

	app := &application{before: func(flow sociable.Flow) sociable.Flow { return flow }}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/{driver}", func(w http.ResponseWriter, r *http.Request) {
		if err := app.before(app.auth.Driver(r.PathValue("driver"))).Redirect(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/auth/{driver}/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := app.before(app.auth.Driver(r.PathValue("driver"))).User(w, r)

		w.Header().Set("Content-Type", "application/json")

		if err != nil {
			_ = json.NewEncoder(w).Encode(outcome{Error: classify(err)})

			return
		}

		_ = json.NewEncoder(w).Encode(outcome{User: user})
	})

	app.Server = httptest.NewServer(mux)
	t.Cleanup(app.Close)

	config := sociable.Config{
		Key: "test-key",
		URL: app.URL,
		Drivers: sociable.Drivers{
			"acme": {ClientID: "client", ClientSecret: "s3cret", Redirect: "/auth/acme/callback"},
		},
	}
	if configure != nil {
		configure(&config)
	}

	auth, err := sociable.New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	app.auth = auth
	extend(auth)

	return app
}

func classify(err error) string {
	switch {
	case errors.Is(err, sociable.ErrAccessDenied):
		return "denied"
	case errors.Is(err, sociable.ErrInvalidState):
		return "state"
	case errors.Is(err, sociable.ErrExchange):
		return "exchange"
	case errors.Is(err, sociable.ErrIDToken):
		return "idtoken"
	case errors.Is(err, sociable.ErrUnknownDriver):
		return "unknown"
	default:
		return err.Error()
	}
}

func browser(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{Jar: jar}
}

func signIn(t *testing.T, client *http.Client, app *application, driver string) outcome {
	t.Helper()

	response, err := client.Get(app.URL + "/auth/" + driver)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	defer response.Body.Close()

	var result outcome
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}

	return result
}
