package sociable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectURLIsResolvedAgainstAPIURL(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)

	cases := map[string]struct {
		api, redirect, want string
	}{
		"path":             {"https://app.example", "/cb", "https://app.example/cb"},
		"trailing slash":   {"https://app.example/", "/cb", "https://app.example/cb"},
		"full url":         {"https://app.example", "https://other.example/cb", "https://other.example/cb"},
		"path without api": {"", "/cb", "/cb"},
		"chain overrides":  {"https://app.example", "/cb", "https://app.example/other"},
		"chain with full":  {"https://app.example", "/cb", "https://elsewhere.example/x"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New(WithKey("k"), WithAPIURL(c.api),
				WithDriver[stub]("stub", Credentials{ClientID: "id", BaseURL: server.URL, RedirectURL: c.redirect}))

			d := m.Driver("stub")

			switch name {
			case "chain overrides":
				d = d.RedirectURL("/other")
			case "chain with full":
				d = d.RedirectURL("https://elsewhere.example/x")
			}

			query, _ := redirected(t, d)

			if got := query.Get("redirect_uri"); got != c.want {
				t.Errorf("redirect_uri = %q, want %q", got, c.want)
			}
		})
	}
}

func TestChainDoesNotLeakBetweenRequests(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	shaped := m.Driver("stub").Scopes("c").With(map[string]string{"prompt": "consent"}).RedirectURL("/other")
	plain := m.Driver("stub")

	query, _ := redirected(t, shaped)
	if query.Get("scope") != "a b c" || query.Get("prompt") != "consent" || query.Get("redirect_uri") != "https://app.example/other" {
		t.Errorf("shaped: %v", query)
	}

	query, _ = redirected(t, plain)
	if query.Get("scope") != "a b" || query.Has("prompt") || query.Get("redirect_uri") != "https://app.example/cb" {
		t.Errorf("plain was shaped too: %v", query)
	}
}

func TestScopes(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	query, _ := redirected(t, m.Driver("stub").Scopes("c", "d"))
	if query.Get("scope") != "a b c d" {
		t.Errorf("Scopes adds: %q", query.Get("scope"))
	}

	query, _ = redirected(t, m.Driver("stub").SetScopes("only"))
	if query.Get("scope") != "only" {
		t.Errorf("SetScopes replaces: %q", query.Get("scope"))
	}

	query, _ = redirected(t, m.Driver("stub").SetScopes("only").Scopes("more"))
	if query.Get("scope") != "only more" {
		t.Errorf("Scopes after SetScopes: %q", query.Get("scope"))
	}
}

func TestWithMergesAndTheLastWins(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	d := m.Driver("stub").
		With(map[string]string{"prompt": "none", "hd": "example.com"}).
		With(map[string]string{"prompt": "consent"})

	query, _ := redirected(t, d)

	if query.Get("prompt") != "consent" || query.Get("hd") != "example.com" {
		t.Errorf("params: %v", query)
	}

	// What is given wins over what the flow would send.
	query, _ = redirected(t, m.Driver("stub").With(map[string]string{"scope": "mine"}))
	if query.Get("scope") != "mine" {
		t.Errorf("scope override: %q", query.Get("scope"))
	}
}

func TestSessionIsRequired(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := New(WithDriver[stub]("stub", Credentials{ClientID: "id", BaseURL: server.URL, RedirectURL: "/cb"}))

	w, r := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)

	if err := m.Driver("stub").Redirect(w, r); !errors.Is(err, ErrMissingKeyOrSession) {
		t.Errorf("Redirect: %v", err)
	}

	if _, err := m.Driver("stub").User(w, r); !errors.Is(err, ErrMissingKeyOrSession) {
		t.Errorf("User: %v", err)
	}
}

func TestApplicationSession(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	session := &memorySession{values: map[string]string{}}
	m := manager[stub](server, WithSession(session))

	query, cookies := redirected(t, m.Driver("stub"))

	if len(cookies) != 0 {
		t.Errorf("cookie set with an application session: %v", cookies)
	}

	if session.values[sessionKey] == "" {
		t.Error("handshake not in the session")
	}

	user, err := m.Driver("stub").User(httptest.NewRecorder(), callback("code=c&state="+query.Get("state"), nil))
	if err != nil || user.ID != "42" {
		t.Errorf("user = %+v, %v", user, err)
	}

	if _, kept := session.values[sessionKey]; kept {
		t.Error("handshake not pulled")
	}

	// A session that cannot store the handshake stops the redirect.
	session.putErr = errors.New("full")

	if err := m.Driver("stub").Redirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, session.putErr) {
		t.Errorf("Redirect with failing session: %v", err)
	}
}

func TestCookieIsSecureOverTLS(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)

	_, cookies := redirected(t, manager[stub](server).Driver("stub")) // APIURL is https
	if !cookies[0].Secure {
		t.Error("https APIURL: cookie not Secure")
	}

	_, cookies = redirected(t, manager[stub](server, WithAPIURL("http://app.example")).Driver("stub"))
	if cookies[0].Secure {
		t.Error("http APIURL: cookie Secure")
	}

	recorder := httptest.NewRecorder()
	overTLS := httptest.NewRequest(http.MethodGet, "https://app.example/auth", nil)

	if err := manager[stub](server, WithAPIURL("http://app.example")).Driver("stub").Redirect(recorder, overTLS); err != nil {
		t.Fatal(err)
	}

	if !recorder.Result().Cookies()[0].Secure {
		t.Error("TLS request: cookie not Secure")
	}
}
