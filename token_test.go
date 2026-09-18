package sociable

import (
	"errors"
	"testing"

	"golang.org/x/oauth2"
)

func TestUserFromToken(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	m := manager[stub](server)

	token := &oauth2.Token{AccessToken: "at"}

	user, err := m.Driver("stub").UserFromToken(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}

	if user.ID != "42" || user.Token != token || server.auth != "Bearer at" {
		t.Errorf("user = %+v, fetched with %q", user, server.auth)
	}

	server.profile = nil

	if _, err := m.Driver("stub").UserFromToken(t.Context(), token); !errors.Is(err, ErrProfile) {
		t.Errorf("failed profile: %v", err)
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	server.token = map[string]any{"access_token": "fresh", "refresh_token": "next", "token_type": "bearer", "expires_in": 3600}
	m := manager[stub](server)

	token, err := m.Driver("stub").RefreshToken(t.Context(), "old")
	if err != nil {
		t.Fatal(err)
	}

	if token.AccessToken != "fresh" || token.RefreshToken != "next" || token.Expiry.IsZero() {
		t.Errorf("token = %+v", token)
	}

	if server.form.Get("grant_type") != "refresh_token" || server.form.Get("refresh_token") != "old" {
		t.Errorf("posted %v", server.form)
	}

	server.token = nil

	if _, err := m.Driver("stub").RefreshToken(t.Context(), "old"); !errors.Is(err, ErrExchange) {
		t.Errorf("failed refresh: %v", err)
	}
}
