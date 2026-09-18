package sociable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestFakeRedirectsNowhere(t *testing.T) {
	t.Parallel()

	m := New() // nothing configured, not even a key
	m.Fake("github")

	recorder := httptest.NewRecorder()
	if err := m.Driver("github").Redirect(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil)); err != nil {
		t.Fatal(err)
	}

	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "https://sociable.fake/github/authorize" {
		t.Errorf("%d %s", recorder.Code, recorder.Header().Get("Location"))
	}

	if len(recorder.Result().Cookies()) != 0 {
		t.Error("a handshake was stored")
	}

	url, err := m.Driver("github").AuthURL(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil))
	if err != nil || url != "https://sociable.fake/github/authorize" {
		t.Errorf("AuthURL = %q, %v", url, err)
	}
}

func TestFakeAnswersTheCallback(t *testing.T) {
	t.Parallel()

	m := New()
	m.Fake("github", &User{ID: "github-123", Name: "Jason Beggs"})

	// Nothing on the request: no code, no state, no cookie.
	user, err := m.Driver("github").User(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cb", nil))
	if err != nil || user.ID != "github-123" {
		t.Errorf("user = %+v, %v", user, err)
	}
}

func TestFakeSurvivesTheChain(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))
	m.Fake("stub", &User{ID: "faked"})

	d := m.Driver("stub").Scopes("x").SetScopes("y").With(map[string]string{"a": "b"}).RedirectURL("/x").Stateless()

	recorder := httptest.NewRecorder()
	_ = d.Redirect(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil))

	if recorder.Header().Get("Location") != "https://sociable.fake/stub/authorize" {
		t.Errorf("the chain reached the real driver: %s", recorder.Header().Get("Location"))
	}

	if user, _ := d.User(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cb", nil)); user.ID != "faked" {
		t.Errorf("user = %+v", user)
	}
}

func TestFakeForwardsWhatItDoesNotFake(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)
	m.Fake("stub") // no user

	w, r := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cb", nil)

	// Without a user, User is the real one: it wants a handshake.
	if _, err := m.Driver("stub").User(w, r); !errors.Is(err, ErrInvalidState) {
		t.Errorf("User: %v", err)
	}

	if _, err := m.Driver("stub").Callback(w, r); !errors.Is(err, ErrInvalidState) {
		t.Errorf("Callback: %v", err)
	}

	if user, err := m.Driver("stub").UserFromToken(t.Context(), &oauth2.Token{AccessToken: "at"}); err != nil || user.ID != "42" {
		t.Errorf("UserFromToken: %+v, %v", user, err)
	}

	if token, err := m.Driver("stub").RefreshToken(t.Context(), "r"); err != nil || token.AccessToken != "at" {
		t.Errorf("RefreshToken: %+v, %v", token, err)
	}

	// Other drivers are untouched.
	if _, err := m.Driver("other").User(w, r); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("other driver: %v", err)
	}
}
