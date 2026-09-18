package sociable

import (
	"testing"
	"time"
)

func TestRedirectAsksForACode(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	query, cookies := redirected(t, m.Driver("stub"))

	for key, want := range map[string]string{
		"client_id":             "id",
		"redirect_uri":          "https://app.example/cb",
		"response_type":         "code",
		"scope":                 "a b",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	if query.Get("state") == "" || query.Get("code_challenge") == "" {
		t.Errorf("no state or challenge: %v", query)
	}

	if query.Has("nonce") {
		t.Error("nonce on a plain OAuth 2 request")
	}

	issued := handshakeFrom(t, cookies)

	if issued.State != query.Get("state") {
		t.Error("stored state differs from the sent one")
	}

	if issued.Verifier == "" || issued.Nonce != "" {
		t.Errorf("handshake = %+v", issued)
	}

	if until := time.Until(issued.ExpiresAt); until < 9*time.Minute || until > handshakeLifetime {
		t.Errorf("expires in %s", until)
	}
}

func TestRedirectSendsANonceForOpenID(t *testing.T) {
	t.Parallel()

	m := manager[openidStub](newProviderServer(t))

	query, cookies := redirected(t, m.Driver("stub"))

	if query.Get("nonce") == "" {
		t.Fatal("no nonce")
	}

	if handshakeFrom(t, cookies).Nonce != query.Get("nonce") {
		t.Error("stored nonce differs from the sent one")
	}

	// Asking openid away makes it a plain request again.
	query, _ = redirected(t, m.Driver("stub").SetScopes("a"))
	if query.Has("nonce") {
		t.Error("nonce without openid")
	}
}

func TestRedirectWithoutPKCE(t *testing.T) {
	t.Parallel()

	m := manager[noPKCEStub](newProviderServer(t))

	query, cookies := redirected(t, m.Driver("stub"))

	if query.Has("code_challenge") || query.Has("code_challenge_method") {
		t.Errorf("challenge sent for a provider that cannot: %v", query)
	}

	if handshakeFrom(t, cookies).Verifier != "" {
		t.Error("verifier stored")
	}
}

func TestRedirectUsesTheProvidersSeparator(t *testing.T) {
	t.Parallel()

	m := manager[commaStub](newProviderServer(t))

	query, _ := redirected(t, m.Driver("stub").Scopes("c"))

	if query.Get("scope") != "a,b,c" {
		t.Errorf("scope = %q", query.Get("scope"))
	}
}

func TestRedirectStateless(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	query, cookies := redirected(t, m.Driver("stub").Stateless())

	if len(cookies) != 0 {
		t.Errorf("cookie set: %v", cookies)
	}

	if query.Has("code_challenge") {
		t.Error("PKCE with nowhere to keep the verifier")
	}

	if query.Get("state") == "" {
		t.Error("no state sent")
	}
}
