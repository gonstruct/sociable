package sociable_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/gonstruct/sociable"
)

func TestTheDefaultManager(t *testing.T) {
	sociable.Configure(sociable.Config{
		Key: "test",
		URL: "https://app.test",
		Drivers: sociable.Drivers{
			"github": {ClientID: "id", ClientSecret: "s", Redirect: "/auth/github/callback"},
		},
	})

	recorder := httptest.NewRecorder()

	authURL, err := sociable.Driver("github").AuthURL(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}

	parsed := mustParse(authURL)
	if parsed.Host != "github.com" || parsed.Query().Get("redirect_uri") != "https://app.test/auth/github/callback" {
		t.Errorf("url = %s", authURL)
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sociable" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Errorf("cookies = %+v", cookies)
	}

	if err := sociable.Driver("nope").Redirect(recorder, httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, sociable.ErrUnknownDriver) {
		t.Errorf("err = %v", err)
	}
}

// A fake needs no configuration at all, the way Socialite::fake needs none.
func TestFakeNeedsNoConfiguration(t *testing.T) {
	var auth sociable.Manager

	fake := auth.Fake("google", sociable.User{ID: "1"})

	recorder := httptest.NewRecorder()
	err := auth.Driver("google").
		Scopes("https://www.googleapis.com/auth/drive.readonly").
		WithState(map[string]string{"invite": "abc"}).
		Redirect(recorder, httptest.NewRequest(http.MethodGet, "/auth/google", nil))
	if err != nil {
		t.Fatal(err)
	}

	fake.AssertRedirected(t, func(r sociable.Redirect) bool {
		return slices.Contains(r.Scopes, "https://www.googleapis.com/auth/drive.readonly") && r.State["invite"] == "abc"
	})
	fake.AssertNotRedirected(t, func(r sociable.Redirect) bool { return r.Params["prompt"] == "consent" })
	fake.AssertRedirectedCount(t, 1)

	user, err := auth.Driver("google").User(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/google/callback", nil))
	if err != nil {
		t.Fatal(err)
	}

	// What was given stays; what was not gets Socialite's fake user's values.
	if user.ID != "1" || user.Name != "Test User" || user.Email != "test@example.com" || user.Token.AccessToken != "fake-token" {
		t.Errorf("user = %+v", user)
	}
}

func TestDriversAreBuiltOnceUnderConcurrency(t *testing.T) {
	auth, err := sociable.New(sociable.Config{
		Key:     "k",
		URL:     "https://app.test",
		Drivers: sociable.Drivers{"github": {ClientID: "id", ClientSecret: "s", Redirect: "/cb"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			if _, err := auth.Driver("github").AuthURL(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
				t.Error(err)
			}
		})
	}
	wait.Wait()
}

func TestAFakeAnswersEveryCall(t *testing.T) {
	var auth sociable.Manager

	fake := auth.Fake("google", sociable.User{State: map[string]string{"user_id": "7"}})

	user, err := auth.Driver("google").User(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cb", nil))
	if err != nil || user.State["user_id"] != "7" {
		t.Fatalf("user = %+v, err = %v", user, err)
	}

	token, err := auth.Driver("google").RefreshToken(t.Context(), "r")
	if err != nil || token.AccessToken != "fake-token" {
		t.Errorf("token = %+v, err = %v", token, err)
	}

	if client := auth.Driver("google").Client(t.Context(), token); client == nil {
		t.Error("no client")
	}

	fake.Restore()

	if err := auth.Driver("google").Redirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, sociable.ErrUnknownDriver) {
		t.Errorf("after restore err = %v", err)
	}
}

func TestARelativeRedirectNeedsTheApplicationURL(t *testing.T) {
	auth, err := sociable.New(sociable.Config{
		Key:     "k",
		Drivers: sociable.Drivers{"github": {ClientID: "id", ClientSecret: "s", Redirect: "/cb"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.Driver("github").AuthURL(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, sociable.ErrNotConfigured) {
		t.Errorf("err = %v", err)
	}
}
