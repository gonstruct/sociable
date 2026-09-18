package sociable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewReadsTheEnvironment(t *testing.T) {
	t.Setenv("APP_KEY", "from-env")
	t.Setenv("API_URL", "https://env.example")

	m := New()

	if m.config.Key != "from-env" || m.config.APIURL != "https://env.example" {
		t.Errorf("config = %+v", m.config)
	}

	m = New(WithKey("from-option"), WithAPIURL("https://option.example"))

	if m.config.Key != "from-option" || m.config.APIURL != "https://option.example" {
		t.Errorf("options did not win: %+v", m.config)
	}
}

func TestConfigureStartsOver(t *testing.T) {
	t.Parallel()

	session := &memorySession{values: map[string]string{}}
	m := New(WithKey("k"), WithSession(session), WithDriver[stub]("stub", Credentials{}))

	if m.config.Session != session {
		t.Error("session not set")
	}

	if _, ok := m.config.Drivers["stub"]; !ok {
		t.Error("driver not registered")
	}

	m.Configure(WithKey("other"))

	if m.config.Key != "other" || m.config.Session != nil || len(m.config.Drivers) != 0 {
		t.Errorf("not from scratch: %+v", m.config)
	}
}

func TestUnknownDriver(t *testing.T) {
	t.Parallel()

	m := New(WithKey("k"))
	w, r := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)

	if err := m.Driver("nope").Redirect(w, r); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("Redirect: %v", err)
	}

	if _, err := m.Driver("nope").User(w, r); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("User: %v", err)
	}

	if _, err := m.Driver("nope").UserFromToken(t.Context(), nil); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("UserFromToken: %v", err)
	}

	if _, err := m.Driver("nope").RefreshToken(t.Context(), "r"); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("RefreshToken: %v", err)
	}

	// The chain must not panic on a driver that has no provider.
	err := m.Driver("nope").Scopes("x").SetScopes("y").With(map[string]string{"a": "b"}).RedirectURL("/x").Stateless().Redirect(w, r)
	if !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("chained Redirect: %v", err)
	}
}
