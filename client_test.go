package sociable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

// unhosted has no endpoints until it is told where its host is.
type unhosted struct{ stub }

func (unhosted) Endpoint(c Credentials) oauth2.Endpoint {
	if c.BaseURL == "" {
		return oauth2.Endpoint{}
	}

	return stub{}.Endpoint(c)
}

// recording is a transport that counts what went through it.
type recording struct {
	paths []string
}

func (self *recording) RoundTrip(request *http.Request) (*http.Response, error) {
	self.paths = append(self.paths, request.URL.Path)

	return http.DefaultTransport.RoundTrip(request)
}

func TestWithClientCarriesEveryCall(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)
	transport := &recording{}
	m := manager[stub](server, WithClient(&http.Client{Transport: transport}))

	if _, err := signIn(t, m.Driver("stub")); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Driver("stub").RefreshToken(t.Context(), "old"); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Driver("stub").UserFromToken(t.Context(), &oauth2.Token{AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}

	want := []string{"/token", "/user", "/token", "/user"}
	if len(transport.paths) != len(want) {
		t.Fatalf("through the client: %v, want %v", transport.paths, want)
	}

	for index, path := range want {
		if transport.paths[index] != path {
			t.Errorf("call %d went to %s, want %s", index, transport.paths[index], path)
		}
	}
}

func TestAuthURL(t *testing.T) {
	t.Parallel()

	m := manager[stub](newProviderServer(t))

	recorder := httptest.NewRecorder()

	url, err := m.Driver("stub").AuthURL(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil))
	if err != nil {
		t.Fatal(err)
	}

	if recorder.Code != http.StatusOK || recorder.Header().Get("Location") != "" {
		t.Errorf("AuthURL redirected: %d %s", recorder.Code, recorder.Header().Get("Location"))
	}

	if len(recorder.Result().Cookies()) != 1 {
		t.Error("the handshake was not started")
	}

	query := parse(t, url)
	if query.Get("state") == "" || query.Get("code_challenge") == "" || query.Get("client_id") != "id" {
		t.Errorf("url = %s", url)
	}

	if _, err := m.Driver("nope").AuthURL(recorder, httptest.NewRequest(http.MethodGet, "/auth", nil)); !errors.Is(err, ErrUnknownDriver) {
		t.Errorf("unknown: %v", err)
	}
}

func TestDriverNotConfigured(t *testing.T) {
	t.Parallel()

	server := newProviderServer(t)

	cases := map[string]Credentials{
		"no client id":    {ClientSecret: "s", BaseURL: server.URL, RedirectURL: "/cb"},
		"no endpoints":    {ClientID: "id", ClientSecret: "s", RedirectURL: "/cb"},
		"no redirect url": {ClientID: "id", ClientSecret: "s", BaseURL: server.URL},
	}

	for name, credentials := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New(WithKey("k"), WithAPIURL("https://app.example"), WithDriver[unhosted]("stub", credentials))
			w, r := httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)

			if err := m.Driver("stub").Redirect(w, r); !errors.Is(err, ErrDriverNotConfigured) {
				t.Errorf("Redirect: %v", err)
			}

			if _, err := m.Driver("stub").AuthURL(w, r); !errors.Is(err, ErrDriverNotConfigured) {
				t.Errorf("AuthURL: %v", err)
			}

			if _, err := m.Driver("stub").User(w, r); !errors.Is(err, ErrDriverNotConfigured) {
				t.Errorf("User: %v", err)
			}

			if _, err := m.Driver("stub").Callback(w, r); !errors.Is(err, ErrDriverNotConfigured) {
				t.Errorf("Callback: %v", err)
			}

			if _, err := m.Driver("stub").RefreshToken(t.Context(), "r"); !errors.Is(err, ErrDriverNotConfigured) {
				t.Errorf("RefreshToken: %v", err)
			}

			if len(w.Result().Cookies()) != 0 {
				t.Error("a handshake was started for a driver that cannot finish it")
			}
		})
	}
}
