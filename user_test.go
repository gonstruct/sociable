package sociable

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestUserSignsIn(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	user, err := signIn(t, m.Driver("stub"))
	if err != nil {
		t.Fatal(err)
	}

	if user.ID != "42" || user.Name != "Test User" {
		t.Errorf("user = %+v", user)
	}

	if user.Token == nil || user.Token.AccessToken != "at" {
		t.Errorf("token = %+v", user.Token)
	}

	if !slices.Equal(user.ApprovedScopes, []string{"a", "b"}) {
		t.Errorf("approved = %v", user.ApprovedScopes)
	}

	if server.form.Get("code") != "c" || server.form.Get("grant_type") != "authorization_code" {
		t.Errorf("exchange posted %v", server.form)
	}

	if server.form.Get("redirect_uri") != "https://app.example/cb" {
		t.Errorf("exchange redirect_uri = %q", server.form.Get("redirect_uri"))
	}

	if server.form.Get("code_verifier") == "" {
		t.Error("verifier not posted")
	}

	if server.auth != "Bearer at" {
		t.Errorf("profile fetched with %q", server.auth)
	}
}

func TestApprovedScopes(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	server.token = map[string]any{"access_token": "at", "token_type": "bearer", "scope": "a,b"}

	user, err := signIn(t, manager[commaStub](server).Driver("stub"))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(user.ApprovedScopes, []string{"a", "b"}) {
		t.Errorf("comma separated: %v", user.ApprovedScopes)
	}

	server.token = map[string]any{"access_token": "at", "token_type": "bearer"}

	user, err = signIn(t, manager[stub](server).Driver("stub"))
	if err != nil {
		t.Fatal(err)
	}

	if user.ApprovedScopes != nil {
		t.Errorf("no scope in the response: %v", user.ApprovedScopes)
	}

	// A provider that names no separator is split on the space.
	granted := (&oauth2.Token{}).WithExtra(map[string]any{"scope": "a b"})
	if got := approved(granted, ""); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("no separator: %v", got)
	}
}

func TestCallbackRejectsAnInvalidState(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	query, cookies := redirected(t, m.Driver("stub"))
	state := query.Get("state")

	forged := []*http.Cookie{{Name: sessionKey, Value: "not-a-sealed-value"}}

	session, _ := newCookieSession("test-key", false)

	sealed := func(payload string) []*http.Cookie {
		recorder := httptest.NewRecorder()
		_ = session.Put(recorder, httptest.NewRequest(http.MethodGet, "/", nil), sessionKey, payload)

		return recorder.Result().Cookies()
	}

	expired, _ := json.Marshal(handshake{State: state, ExpiresAt: time.Now().Add(-time.Second)})

	cases := map[string]*http.Request{
		"no cookie":     callback("code=c&state="+state, nil),
		"forged cookie": callback("code=c&state="+state, forged),
		"other state":   callback("code=c&state=other", cookies),
		"no state":      callback("code=c", cookies),
		"not json":      callback("code=c&state="+state, sealed("{")),
		"expired":       callback("code=c&state="+state, sealed(string(expired))),
	}

	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			if _, err := m.Driver("stub").User(recorder, request); !errors.Is(err, ErrInvalidState) {
				t.Errorf("err = %v", err)
			}

			if server.form != nil {
				t.Error("the code was exchanged")
			}
		})
	}
}

func TestCallbackSpendsTheHandshake(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	query, cookies := redirected(t, m.Driver("stub"))
	request := callback("code=c&state="+query.Get("state"), cookies)

	recorder := httptest.NewRecorder()
	if _, err := m.Driver("stub").User(recorder, request); err != nil {
		t.Fatal(err)
	}

	// The cookie is cleared on the response, so the browser no longer has
	// it and the same callback again has no handshake to check against.
	cleared := recorder.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge != -1 || cleared[0].Value != "" {
		t.Errorf("cookie not cleared: %v", cleared)
	}

	server.form = nil

	if _, err := m.Driver("stub").User(httptest.NewRecorder(), callback("code=c&state="+query.Get("state"), nil)); !errors.Is(err, ErrInvalidState) {
		t.Errorf("replay: %v", err)
	}

	if server.form != nil {
		t.Error("the code was exchanged again")
	}
}

func TestCallbackReportsARefusal(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	query, cookies := redirected(t, m.Driver("stub"))

	_, err := m.Driver("stub").User(httptest.NewRecorder(),
		callback("error=access_denied&error_description=The+user+said+no&error_uri=https://x/e&state="+query.Get("state"), cookies))

	if !errors.Is(err, ErrAccessDenied) || !errors.Is(err, ErrAuthorization) {
		t.Errorf("err = %v", err)
	}

	var refusal *AuthorizationError
	if !errors.As(err, &refusal) || refusal.Code != "access_denied" || refusal.Description != "The user said no" || refusal.URI != "https://x/e" {
		t.Errorf("refusal = %+v", refusal)
	}

	query, cookies = redirected(t, m.Driver("stub"))

	_, err = m.Driver("stub").User(httptest.NewRecorder(), callback("error=server_error&state="+query.Get("state"), cookies))

	if errors.Is(err, ErrAccessDenied) || !errors.Is(err, ErrAuthorization) {
		t.Errorf("other refusal: %v", err)
	}
}

func TestCallbackReportsAFailedExchange(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	server.token = nil

	if _, err := signIn(t, manager[stub](server).Driver("stub")); !errors.Is(err, ErrExchange) {
		t.Errorf("err = %v", err)
	}
}

func TestUserReportsAFailedProfile(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	server.profile = nil

	if _, err := signIn(t, manager[stub](server).Driver("stub")); !errors.Is(err, ErrProfile) {
		t.Errorf("fetch failed: %v", err)
	}

	server.profile = map[string]any{"id": "42"}

	if _, err := signIn(t, manager[badMapStub](server).Driver("stub")); !errors.Is(err, ErrProfile) {
		t.Errorf("map failed: %v", err)
	}
}

func TestCallbackStateless(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	user, err := m.Driver("stub").Stateless().User(httptest.NewRecorder(), callback("code=c", nil))
	if err != nil || user.ID != "42" {
		t.Fatalf("user = %+v, %v", user, err)
	}

	if server.form.Has("code_verifier") {
		t.Error("verifier posted with nothing to keep it")
	}
}

func TestCallbackHandsBackTheToken(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	query, cookies := redirected(t, m.Driver("stub"))

	token, err := m.Driver("stub").Callback(httptest.NewRecorder(), callback("code=c&state="+query.Get("state"), cookies))
	if err != nil || token.AccessToken != "at" {
		t.Errorf("token = %+v, %v", token, err)
	}

	if server.auth != "" {
		t.Error("the profile was fetched")
	}
}

// The OpenID Connect tests share the issuer through oidcIssuer, so they run
// one after another.
func TestIDToken(t *testing.T) {
	provider := newIssuer(t)
	oidcIssuer = provider.URL

	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	// begin redirects and returns the callback request and the nonce issued.
	begin := func(t *testing.T, d DriverContract) (*http.Request, string) {
		t.Helper()

		query, cookies := redirected(t, d)

		return callback("code=c&state="+query.Get("state"), cookies), query.Get("nonce")
	}

	t.Run("verified", func(t *testing.T) {
		server := newProviderServer(t)
		m := manager[openidStub](server)

		request, nonce := begin(t, m.Driver("stub"))
		server.token["id_token"] = provider.idToken(t, "id", nonce, nil)

		user, err := m.Driver("stub").User(httptest.NewRecorder(), request)
		if err != nil || user.ID != "42" {
			t.Errorf("user = %+v, %v", user, err)
		}
	})

	t.Run("second sign-in uses the cached discovery", func(t *testing.T) {
		server := newProviderServer(t)
		m := manager[openidStub](server)

		request, nonce := begin(t, m.Driver("stub"))
		server.token["id_token"] = provider.idToken(t, "id", nonce, nil)

		if _, ok := issuers.Load(provider.URL); !ok {
			t.Fatal("discovery not cached")
		}

		if _, err := m.Driver("stub").User(httptest.NewRecorder(), request); err != nil {
			t.Error(err)
		}
	})

	failures := map[string]func(t *testing.T, nonce string) any{
		"missing":        func(*testing.T, string) any { return nil },
		"wrong nonce":    func(t *testing.T, _ string) any { return provider.idToken(t, "id", "other", nil) },
		"wrong key":      func(t *testing.T, nonce string) any { return provider.idToken(t, "id", nonce, other) },
		"wrong audience": func(t *testing.T, nonce string) any { return provider.idToken(t, "someone-else", nonce, nil) },
		"garbage":        func(*testing.T, string) any { return "not.a.jwt" },
	}

	for name, idToken := range failures {
		t.Run(name, func(t *testing.T) {
			server := newProviderServer(t)
			m := manager[openidStub](server)

			request, nonce := begin(t, m.Driver("stub"))

			if token := idToken(t, nonce); token != nil {
				server.token["id_token"] = token
			}

			if _, err := m.Driver("stub").User(httptest.NewRecorder(), request); !errors.Is(err, ErrIDToken) {
				t.Errorf("err = %v", err)
			}
		})
	}

	t.Run("no verification without openid", func(t *testing.T) {
		server := newProviderServer(t)
		m := manager[openidStub](server)

		user, err := signIn(t, m.Driver("stub").SetScopes("a"))
		if err != nil || user.ID != "42" {
			t.Errorf("user = %+v, %v", user, err)
		}
	})

	t.Run("stateless verifies without a nonce", func(t *testing.T) {
		server := newProviderServer(t)
		m := manager[openidStub](server)
		server.token["id_token"] = provider.idToken(t, "id", "whatever", nil)

		user, err := m.Driver("stub").Stateless().User(httptest.NewRecorder(), callback("code=c", nil))
		if err != nil || user.ID != "42" {
			t.Errorf("user = %+v, %v", user, err)
		}
	})

	t.Run("discovery fails", func(t *testing.T) {
		gone := newIssuer(t)
		gone.Close()
		oidcIssuer = gone.URL

		server := newProviderServer(t)
		m := manager[openidStub](server)

		request, nonce := begin(t, m.Driver("stub"))
		server.token["id_token"] = provider.idToken(t, "id", nonce, nil)

		if _, err := m.Driver("stub").User(httptest.NewRecorder(), request); !errors.Is(err, ErrIDToken) {
			t.Errorf("err = %v", err)
		}
	})
}
