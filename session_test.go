package sociable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCookieSession(t *testing.T) {
	t.Parallel()

	session, err := newCookieSession("key", false)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	if err := session.Put(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "name", "secret value"); err != nil {
		t.Fatal(err)
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}

	cookie := cookies[0]

	if cookie.Name != "name" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 600 || cookie.Secure {
		t.Errorf("cookie = %+v", cookie)
	}

	if strings.Contains(cookie.Value, "secret") {
		t.Error("value readable")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()

	value, err := session.Pull(recorder, request, "name")
	if err != nil || value != "secret value" {
		t.Errorf("pulled %q, %v", value, err)
	}

	if cleared := recorder.Result().Cookies(); len(cleared) != 1 || cleared[0].MaxAge != -1 {
		t.Errorf("not cleared: %v", cleared)
	}
}

func TestCookieSessionRefusesWhatItDidNotSeal(t *testing.T) {
	t.Parallel()

	session, _ := newCookieSession("key", false)
	otherKey, _ := newCookieSession("other", false)

	recorder := httptest.NewRecorder()
	_ = otherKey.Put(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "name", "value")
	underOtherKey := recorder.Result().Cookies()[0].Value

	recorder = httptest.NewRecorder()
	_ = session.Put(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "name", "value")
	genuine := recorder.Result().Cookies()[0].Value

	cases := map[string]string{
		"not base64": "***",
		"too short":  "YQ",
		"tampered":   genuine[:len(genuine)-2] + "zz",
		"other key":  underOtherKey,
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.AddCookie(&http.Cookie{Name: "name", Value: value})
			recorder := httptest.NewRecorder()

			if _, err := session.Pull(recorder, request, "name"); !errors.Is(err, ErrSessionSealed) {
				t.Errorf("err = %v", err)
			}

			if cleared := recorder.Result().Cookies(); len(cleared) != 1 || cleared[0].MaxAge != -1 {
				t.Error("a failed pull must still clear the cookie")
			}
		})
	}

	if _, err := session.Pull(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "name"); !errors.Is(err, http.ErrNoCookie) {
		t.Errorf("no cookie: %v", err)
	}
}

func TestCookieSessionNeedsAKey(t *testing.T) {
	t.Parallel()

	if _, err := newCookieSession("", false); !errors.Is(err, ErrMissingKeyOrSession) {
		t.Errorf("err = %v", err)
	}

	secure, _ := newCookieSession("key", true)
	recorder := httptest.NewRecorder()
	_ = secure.Put(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "name", "value")

	if !recorder.Result().Cookies()[0].Secure {
		t.Error("not Secure")
	}
}

func TestRandom(t *testing.T) {
	t.Parallel()

	a, b := random(32), random(32)

	if len(a) != 43 || a == b {
		t.Errorf("%q %q", a, b)
	}
}
