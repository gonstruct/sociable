package sociable_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gonstruct/sociable"
)

func TestSignIn(t *testing.T) {
	as := newAuthorizationServer(t)
	as.scope = "profile email"
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	result := signIn(t, browser(t), app, "acme")

	if result.Error != "" {
		t.Fatalf("sign in failed: %s", result.Error)
	}
	if result.User.ID != "42" || result.User.Nickname != "arjen" || result.User.Email != "arjen@example.test" {
		t.Errorf("user = %+v", result.User)
	}
	if result.User.Token.AccessToken != "t0ken" || result.User.Token.RefreshToken != "r3fresh" {
		t.Errorf("token = %+v", result.User.Token)
	}
	if strings.Join(result.User.ApprovedScopes, " ") != "profile email" {
		t.Errorf("approved scopes = %v", result.User.ApprovedScopes)
	}

	sent := as.lastRequest()
	if sent.Get("code_challenge") == "" || sent.Get("code_challenge_method") != "S256" {
		t.Errorf("PKCE was not on: %v", sent)
	}
	if sent.Get("redirect_uri") != app.URL+"/auth/acme/callback" {
		t.Errorf("redirect_uri = %s", sent.Get("redirect_uri"))
	}
	if sent.Get("scope") != "profile" {
		t.Errorf("scope = %s", sent.Get("scope"))
	}
}

func TestOptionsShapeTheAuthorizationRequest(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })
	app.before = func(flow sociable.Flow) sociable.Flow {
		return flow.Scopes("email").With(map[string]string{"login_hint": "arjen", "state": "overridden"})
	}

	signIn(t, browser(t), app, "acme")

	sent := as.lastRequest()
	if sent.Get("scope") != "profile email" {
		t.Errorf("scope = %s", sent.Get("scope"))
	}
	if sent.Get("login_hint") != "arjen" {
		t.Errorf("login_hint = %s", sent.Get("login_hint"))
	}
	if sent.Get("state") == "overridden" {
		t.Error("a call site could override the state")
	}
}

func TestStateTravelsThroughTheFlow(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })
	app.before = func(flow sociable.Flow) sociable.Flow {
		return flow.WithState(map[string]string{"user_id": "7", "domain": "example.test"})
	}

	result := signIn(t, browser(t), app, "acme")

	if result.Error != "" {
		t.Fatalf("sign in failed: %s", result.Error)
	}
	if result.User.State["user_id"] != "7" || result.User.State["domain"] != "example.test" {
		t.Errorf("state = %v", result.User.State)
	}
	if as.lastRequest().Has("user_id") {
		t.Error("state leaked to the provider")
	}
}

func TestDenial(t *testing.T) {
	as := newAuthorizationServer(t)
	as.deny = true
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	if result := signIn(t, browser(t), app, "acme"); result.Error != "denied" {
		t.Errorf("error = %q, want denied", result.Error)
	}
}

func TestACallbackCannotBeReplayed(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	client := browser(t)
	var callback string
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if strings.HasSuffix(r.URL.Path, "/callback") {
			callback = r.URL.String()
		}

		return nil
	}

	if result := signIn(t, client, app, "acme"); result.Error != "" {
		t.Fatalf("first sign in failed: %s", result.Error)
	}

	response, err := client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var result outcome
	_ = decode(response, &result)
	if result.Error != "state" {
		t.Errorf("replay error = %q, want state", result.Error)
	}
}

func TestACallbackNobodyStartedIsRefused(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	response, err := browser(t).Get(app.URL + "/auth/acme/callback?code=c0de&state=guess")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var result outcome
	_ = decode(response, &result)
	if result.Error != "state" {
		t.Errorf("error = %q, want state", result.Error)
	}
}

func TestAWrongSecretFailsTheExchange(t *testing.T) {
	as := newAuthorizationServer(t)
	as.secret = "another"
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	if result := signIn(t, browser(t), app, "acme"); result.Error != "exchange" {
		t.Errorf("error = %q, want exchange", result.Error)
	}
}

func TestAnUnknownDriverIsAnError(t *testing.T) {
	app := newApplication(t, nil, func(*sociable.Manager) {})

	err := app.auth.Driver("nope").Redirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, sociable.ErrUnknownDriver) {
		t.Errorf("err = %v", err)
	}

	// Configured, but no provider of that name.
	app2 := newApplication(t, func(config *sociable.Config) {
		config.Drivers["mystery"] = sociable.Credentials{ClientID: "x"}
	}, func(*sociable.Manager) {})

	err = app2.auth.Driver("mystery").Redirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, sociable.ErrUnknownDriver) {
		t.Errorf("err = %v", err)
	}
}

func TestAnApplicationSessionReplacesTheCookie(t *testing.T) {
	as := newAuthorizationServer(t)
	session := &memorySession{values: map[string]string{}}
	app := newApplication(t, func(config *sociable.Config) {
		config.Key = ""
		config.Session = session
	}, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })

	client := browser(t)
	if result := signIn(t, client, app, "acme"); result.Error != "" {
		t.Fatalf("sign in failed: %s", result.Error)
	}

	if session.puts != 1 || session.pulls != 1 {
		t.Errorf("session saw %d puts and %d pulls", session.puts, session.pulls)
	}

	for _, cookie := range client.Jar.Cookies(mustParse(app.URL)) {
		if cookie.Name == "sociable" {
			t.Error("a cookie was set alongside the session")
		}
	}
}

func TestStatelessSkipsTheHandshake(t *testing.T) {
	as := newAuthorizationServer(t)
	app := newApplication(t, nil, func(auth *sociable.Manager) { auth.Extend("acme", as.factory()) })
	app.before = func(flow sociable.Flow) sociable.Flow { return flow.Stateless() }

	response, err := browser(t).Get(app.URL + "/auth/acme/callback?code=c0de")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var result outcome
	_ = decode(response, &result)
	if result.Error != "" || result.User.ID != "42" {
		t.Errorf("result = %+v", result)
	}
}

func TestFake(t *testing.T) {
	app := newApplication(t, nil, func(auth *sociable.Manager) {
		auth.Fake("github", sociable.User{ID: "1", Email: "arjen@example.test"})
	})

	// The redirect goes nowhere real; a test calls the callback directly.
	recorder := httptest.NewRecorder()
	if err := app.auth.Driver("github").Redirect(recorder, httptest.NewRequest(http.MethodGet, "/auth/github", nil)); err != nil {
		t.Fatal(err)
	}
	if location := recorder.Header().Get("Location"); location != "https://sociable.fake/github/authorize" {
		t.Errorf("redirected to %s", location)
	}

	response, err := browser(t).Get(app.URL + "/auth/github/callback")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var result outcome
	_ = decode(response, &result)
	if result.Error != "" {
		t.Fatalf("callback failed: %s", result.Error)
	}
	if result.User.ID != "1" || result.User.Email != "arjen@example.test" || result.User.Token.AccessToken != "fake-token" {
		t.Errorf("user = %+v", result.User)
	}
}

func TestConfigureRequiresSomewhereToKeepTheHandshake(t *testing.T) {
	if _, err := sociable.New(sociable.Config{}); !errors.Is(err, sociable.ErrNoKey) {
		t.Errorf("err = %v", err)
	}
}

type memorySession struct {
	values      map[string]string
	puts, pulls int
}

func (self *memorySession) Put(_ http.ResponseWriter, _ *http.Request, key, value string) error {
	self.puts++
	self.values[key] = value

	return nil
}

func (self *memorySession) Pull(_ http.ResponseWriter, _ *http.Request, key string) (string, error) {
	self.pulls++
	value := self.values[key]
	delete(self.values, key)

	return value, nil
}
