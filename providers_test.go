package sociable_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gonstruct/sociable"
)

func decode(response *http.Response, into any) error {
	return json.NewDecoder(response.Body).Decode(into)
}

func mustParse(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return parsed
}

func TestStringReadsDottedPathsAndNumbers(t *testing.T) {
	raw := map[string]any{
		"id":      float64(1234567),
		"picture": map[string]any{"data": map[string]any{"url": "https://example.test/p.png"}},
		"ok":      true,
	}

	if got := sociable.String(raw, "id"); got != "1234567" {
		t.Errorf("id = %q", got)
	}
	if got := sociable.String(raw, "picture.data.url"); got != "https://example.test/p.png" {
		t.Errorf("picture = %q", got)
	}
	if got := sociable.String(raw, "picture.missing.url"); got != "" {
		t.Errorf("missing = %q", got)
	}
	if !sociable.Bool(raw, "ok") {
		t.Error("ok = false")
	}
}

func TestBuiltInDriversAreConfigurable(t *testing.T) {
	auth, err := sociable.New(sociable.Config{
		Key: "k",
		URL: "https://app.test",
		Drivers: sociable.Drivers{
			"google":    {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"github":    {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"gitlab":    {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"facebook":  {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"linkedin":  {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"bitbucket": {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"slack":     {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"twitch":    {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
			"x":         {ClientID: "id", ClientSecret: "s", Redirect: "/cb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The plain OAuth 2 drivers need no network to produce an authorization URL.
	for _, name := range []string{"github", "gitlab", "facebook", "bitbucket", "twitch", "x"} {
		recorder := httptest.NewRecorder()

		authURL, err := auth.Driver(name).AuthURL(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		parsed := mustParse(authURL)
		if parsed.Query().Get("client_id") != "id" || parsed.Query().Get("code_challenge") == "" {
			t.Errorf("%s: %s", name, authURL)
		}
	}
}

func TestGitHubFallsBackToThePrimaryEmail(t *testing.T) {
	api := newAPI(t)
	api.reply("/user", map[string]any{"id": 9, "login": "arjen", "name": "Arjen", "email": nil, "avatar_url": "https://a"})
	api.reply("/user/emails", []map[string]any{
		{"email": "old@example.test", "primary": false, "verified": true},
		{"email": "arjen@example.test", "primary": true, "verified": true},
	})

	user, err := sociable.GitHub(sociable.Credentials{ClientID: "id"}).User(t.Context(), api.client(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if user.ID != "9" || user.Nickname != "arjen" || user.Email != "arjen@example.test" || !user.EmailVerified {
		t.Errorf("user = %+v", user)
	}
}

func TestTwitchSendsTheClientID(t *testing.T) {
	api := newAPI(t)
	api.reply("/helix/users", map[string]any{
		"data": []map[string]any{{"id": "77", "login": "arjen", "display_name": "Arjen", "email": "arjen@example.test"}},
	})

	user, err := sociable.Twitch(sociable.Credentials{ClientID: "twitch-client"}).User(t.Context(), api.client(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if user.ID != "77" || user.Email != "arjen@example.test" {
		t.Errorf("user = %+v", user)
	}

	if got := api.sent["/helix/users"].Get("Client-Id"); got != "twitch-client" {
		t.Errorf("Client-Id = %q", got)
	}
}

// api is a fake provider API: canned JSON per path, the request headers
// recorded, and a client that sends every host to it.
type api struct {
	*httptest.Server

	replies map[string]any
	sent    map[string]http.Header
}

func newAPI(t *testing.T) *api {
	t.Helper()

	a := &api{replies: map[string]any{}, sent: map[string]http.Header{}}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.sent[r.URL.Path] = r.Header.Clone()

		reply, ok := a.replies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(a.Close)

	return a
}

func (a *api) reply(path string, body any) { a.replies[path] = body }

func (a *api) client() *http.Client {
	return &http.Client{Transport: rewrite{to: mustParse(a.URL)}}
}

// rewrite sends every request to the test server, whatever host it named.
type rewrite struct{ to *url.URL }

func (self rewrite) RoundTrip(request *http.Request) (*http.Response, error) {
	request.URL.Scheme, request.URL.Host = self.to.Scheme, self.to.Host

	return http.DefaultTransport.RoundTrip(request)
}
