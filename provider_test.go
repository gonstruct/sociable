package sociable

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// same fails unless the mapped user is want, token and scopes aside.
func same(t *testing.T, got *User, want User) {
	t.Helper()

	if got.ID != want.ID || got.Nickname != want.Nickname || got.Name != want.Name ||
		got.Email != want.Email || got.EmailVerified != want.EmailVerified || got.Avatar != want.Avatar {
		t.Errorf("user = %+v, want %+v", *got, want)
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()

	client, last := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"id":"1"}`))
		case "/broken":
			_, _ = w.Write([]byte(`{"id":`))
		case "/truncated":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"id":"1"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	})

	document, err := fetch(t.Context(), client, "https://api.example/ok", map[string]string{"X-Extra": "yes"})
	if err != nil || string(document.GetStringBytes("id")) != "1" {
		t.Errorf("document = %v, %v", document, err)
	}

	if last.Header.Get("Accept") != "application/json" || last.Header.Get("X-Extra") != "yes" {
		t.Errorf("headers = %v", last.Header)
	}

	if _, err := fetch(t.Context(), client, "https://api.example/forbidden", nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("status: %v", err)
	}

	if _, err := fetch(t.Context(), client, "https://api.example/broken", nil); err == nil {
		t.Error("broken json accepted")
	}

	if _, err := fetch(t.Context(), client, "https://api.example/truncated", nil); err == nil {
		t.Error("truncated body accepted")
	}

	if _, err := fetch(t.Context(), client, "http://bad host/", nil); err == nil {
		t.Error("bad url accepted")
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	if _, err := fetch(t.Context(), closed.Client(), closed.URL, nil); err == nil {
		t.Error("unreachable server accepted")
	}
}

func TestGoogle(t *testing.T) {
	t.Parallel()

	var p GoogleProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Issuer() != "https://accounts.google.com" || p.Scoping().Scopes[0] != "openid" {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{
		"sub": "1", "given_name": "Ada", "name": "Ada L", "email": "ada@x", "email_verified": true, "picture": "p",
	}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
	if err != nil {
		t.Fatal(err)
	}

	if last.URL.Path != "/oauth2/v3/userinfo" {
		t.Errorf("fetched %s", last.URL.Path)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "1", Nickname: "Ada", Name: "Ada L", Email: "ada@x", EmailVerified: true, Avatar: "p"})
}

func TestGitHub(t *testing.T) {
	t.Parallel()

	var p GitHubProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Scoping().Scopes[0] != "read:user" {
		t.Error("configuration")
	}

	t.Run("email on the profile", func(t *testing.T) {
		t.Parallel()

		calls := 0
		client, last := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			encode(map[string]any{"id": 42, "login": "ada", "name": "Ada", "email": "ada@x", "avatar_url": "p"})(w, r)
		})

		raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
		if err != nil {
			t.Fatal(err)
		}

		if calls != 1 || last.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("calls = %d, accept = %q", calls, last.Header.Get("Accept"))
		}

		user, _ := p.MapUserToStruct(raw)
		same(t, user, User{ID: "42", Nickname: "ada", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})
	})

	t.Run("email from the emails endpoint", func(t *testing.T) {
		t.Parallel()

		client, _ := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/emails" {
				encode([]map[string]any{
					{"email": "old@x", "primary": false, "verified": true},
					{"email": "unverified@x", "primary": true, "verified": false},
					{"email": "ada@x", "primary": true, "verified": true},
				})(w, r)
				return
			}

			encode(map[string]any{"id": 42, "login": "ada", "email": nil})(w, r)
		})

		raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
		if err != nil {
			t.Fatal(err)
		}

		user, _ := p.MapUserToStruct(raw)
		if user.Email != "ada@x" || !user.EmailVerified {
			t.Errorf("user = %+v", *user)
		}
	})

	t.Run("emails endpoint fails", func(t *testing.T) {
		t.Parallel()

		client, _ := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user/emails" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			encode(map[string]any{"id": 42})(w, r)
		})

		if _, err := p.GetUserByToken(t.Context(), client, nil, Credentials{}); err == nil {
			t.Error("no error")
		}
	})

	t.Run("profile fails", func(t *testing.T) {
		t.Parallel()

		client, _ := rewritingClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })

		if _, err := p.GetUserByToken(t.Context(), client, nil, Credentials{}); err == nil {
			t.Error("no error")
		}
	})
}

func TestGitLab(t *testing.T) {
	t.Parallel()

	var p GitLabProvider

	if p.Endpoint(Credentials{}).AuthURL != "https://gitlab.com/oauth/authorize" {
		t.Errorf("default host: %s", p.Endpoint(Credentials{}).AuthURL)
	}

	hosted := Credentials{BaseURL: "https://git.acme.example/"}
	if p.Endpoint(hosted).TokenURL != "https://git.acme.example/oauth/token" {
		t.Errorf("self-hosted: %s", p.Endpoint(hosted).TokenURL)
	}

	if p.Scoping().Scopes[0] != "read_user" {
		t.Error("scopes")
	}

	client, last := rewritingClient(t, encode(map[string]any{"id": 7, "username": "ada", "name": "Ada", "email": "ada@x", "avatar_url": "p"}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, hosted)
	if err != nil {
		t.Fatal(err)
	}

	if last.URL.Path != "/api/v4/user" {
		t.Errorf("fetched %s", last.URL.Path)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "7", Nickname: "ada", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})
}

func TestFacebook(t *testing.T) {
	t.Parallel()

	var p FacebookProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Scoping().Separator != "," {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{
		"id": "9", "name": "Ada", "email": "ada@x", "picture": map[string]any{"data": map[string]any{"url": "p"}},
	}))

	token := &oauth2.Token{AccessToken: "at"}

	raw, err := p.GetUserByToken(t.Context(), client, token, Credentials{ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, []byte("s"))
	mac.Write([]byte("at"))

	if last.URL.Query().Get("appsecret_proof") != hex.EncodeToString(mac.Sum(nil)) || !strings.Contains(last.URL.Query().Get("fields"), "email") {
		t.Errorf("query = %v", last.URL.Query())
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "9", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})

	if _, err := p.GetUserByToken(t.Context(), client, token, Credentials{}); err != nil || last.URL.Query().Has("appsecret_proof") {
		t.Errorf("without a secret: proof=%q, %v", last.URL.Query().Get("appsecret_proof"), err)
	}
}

func TestBitbucket(t *testing.T) {
	t.Parallel()

	var p BitbucketProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Scoping().Scopes[0] != "email" {
		t.Error("configuration")
	}

	client, _ := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2.0/user/emails" {
			encode(map[string]any{"values": []map[string]any{
				{"email": "old@x", "is_primary": false, "is_confirmed": true},
				{"email": "ada@x", "is_primary": true, "is_confirmed": true},
			}})(w, r)
			return
		}

		encode(map[string]any{
			"uuid": "{u}", "username": "ada", "display_name": "Ada",
			"links": map[string]any{"avatar": map[string]any{"href": "p"}},
		})(w, r)
	})

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
	if err != nil {
		t.Fatal(err)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "{u}", Nickname: "ada", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})

	failing, _ := rewritingClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2.0/user/emails" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		encode(map[string]any{"uuid": "{u}"})(w, r)
	})

	if _, err := p.GetUserByToken(t.Context(), failing, nil, Credentials{}); err == nil {
		t.Error("emails failing: no error")
	}

	down, _ := rewritingClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })

	if _, err := p.GetUserByToken(t.Context(), down, nil, Credentials{}); err == nil {
		t.Error("profile failing: no error")
	}
}

func TestLinkedIn(t *testing.T) {
	t.Parallel()

	var p LinkedInProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Issuer() == "" || p.Scoping().Scopes[0] != "openid" {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{
		"sub": "1", "given_name": "Ada", "name": "Ada L", "email": "ada@x", "email_verified": true, "picture": "p",
	}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
	if err != nil {
		t.Fatal(err)
	}

	if last.URL.Path != "/v2/userinfo" {
		t.Errorf("fetched %s", last.URL.Path)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "1", Nickname: "Ada", Name: "Ada L", Email: "ada@x", EmailVerified: true, Avatar: "p"})
}

func TestSlack(t *testing.T) {
	t.Parallel()

	var p SlackProvider

	if p.Endpoint(Credentials{}).AuthURL != "https://slack.com/openid/connect/authorize" ||
		p.Issuer() != "https://slack.com" || p.Scoping().Scopes[0] != "openid" {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{
		"sub": "U1", "name": "Ada", "email": "ada@x", "email_verified": true, "picture": "p",
	}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
	if err != nil {
		t.Fatal(err)
	}

	if last.URL.Path != "/api/openid.connect.userInfo" {
		t.Errorf("fetched %s", last.URL.Path)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "U1", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})
}

func TestTwitch(t *testing.T) {
	t.Parallel()

	var p TwitchProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Scoping().Scopes[0] != "user:read:email" {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{"data": []map[string]any{
		{"id": "9", "login": "ada", "display_name": "Ada", "email": "ada@x", "profile_image_url": "p"},
	}}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}

	if last.Header.Get("Client-Id") != "cid" || last.URL.Path != "/helix/users" {
		t.Errorf("request = %s %v", last.URL.Path, last.Header)
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "9", Nickname: "ada", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})

	empty, _ := rewritingClient(t, encode(map[string]any{"data": []any{}}))

	if _, err := p.GetUserByToken(t.Context(), empty, nil, Credentials{}); err == nil {
		t.Error("empty data: no error")
	}

	down, _ := rewritingClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })

	if _, err := p.GetUserByToken(t.Context(), down, nil, Credentials{}); err == nil {
		t.Error("failing: no error")
	}
}

func TestX(t *testing.T) {
	t.Parallel()

	var p XProvider

	if p.Endpoint(Credentials{}).AuthURL == "" || p.Scoping().Scopes[0] != "users.read" {
		t.Error("configuration")
	}

	client, last := rewritingClient(t, encode(map[string]any{"data": map[string]any{
		"id": "9", "username": "ada", "name": "Ada", "confirmed_email": "ada@x", "profile_image_url": "p",
	}}))

	raw, err := p.GetUserByToken(t.Context(), client, nil, Credentials{})
	if err != nil {
		t.Fatal(err)
	}

	if last.URL.Path != "/2/users/me" || !strings.Contains(last.URL.Query().Get("user.fields"), "confirmed_email") {
		t.Errorf("request = %s %v", last.URL.Path, last.URL.Query())
	}

	user, _ := p.MapUserToStruct(raw)
	same(t, user, User{ID: "9", Nickname: "ada", Name: "Ada", Email: "ada@x", EmailVerified: true, Avatar: "p"})

	down, _ := rewritingClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })

	if _, err := p.GetUserByToken(t.Context(), down, nil, Credentials{}); err == nil {
		t.Error("failing: no error")
	}
}
