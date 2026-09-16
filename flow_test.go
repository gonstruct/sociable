package vouch_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonstruct/vouch"
	"golang.org/x/oauth2"
)

func TestRedirectCarriesAChallengeAndNotTheVerifier(t *testing.T) {
	recorder := redirect(t, setup(t, fake(true)), "/after")

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected a 302, got %d", recorder.Code)
	}
	query := issuedQuery(t, recorder)
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("expected an S256 challenge, got %s", query.Encode())
	}
	if query.Get("state") == "" {
		t.Fatal("no state was issued")
	}
	// The verifier is the secret half; only its hash may travel.
	if query.Get("code_verifier") != "" {
		t.Fatal("the verifier reached the provider")
	}
	if len(recorder.Result().Cookies()) != 1 || recorder.Result().Cookies()[0].Name != "vouch_handshake" {
		t.Fatalf("expected the handshake cookie, got %v", recorder.Result().Cookies())
	}
}

func TestRedirectRefusesAnUnconfiguredProvider(t *testing.T) {
	auth := setup(t, fake(false))
	recorder := httptest.NewRecorder()

	err := auth.Driver(recorder, httptest.NewRequest(http.MethodGet, "/login", nil), "fake").Redirect("")
	if !errors.Is(err, vouch.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	if recorder.Header().Get("Location") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestAnUnknownDriverIsAnErrorRatherThanAPanic(t *testing.T) {
	auth := setup(t, fake(true))
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := auth.Driver(httptest.NewRecorder(), request, "nope").Redirect(""); !errors.Is(err, vouch.ErrUnknownDriver) {
		t.Fatalf("redirect: expected ErrUnknownDriver, got %v", err)
	}
	if _, err := auth.Driver(httptest.NewRecorder(), request, "nope").User(); !errors.Is(err, vouch.ErrUnknownDriver) {
		t.Fatalf("user: expected ErrUnknownDriver, got %v", err)
	}
}

func TestNewRequiresASealer(t *testing.T) {
	if _, err := vouch.New(vouch.Configuration{}); !errors.Is(err, vouch.ErrNoSealer) {
		t.Fatalf("expected ErrNoSealer, got %v", err)
	}
}

func TestUserWithoutAHandshakeIsRefused(t *testing.T) {
	_, err, _ := callback(t, setup(t, fake(true)), "/callback?code=c&state=s", nil)
	if !errors.Is(err, vouch.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestUserRefusesAForgedState(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	_, err, _ := callback(t, auth, "/callback?code=c&state=forged", started)
	if !errors.Is(err, vouch.ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

func TestTheHandshakeIsSpentEvenByAFailedAttempt(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	_, err, cleared := callback(t, auth, "/callback?code=c&state=forged", started)
	if !errors.Is(err, vouch.ErrStateMismatch) {
		t.Fatalf("expected the first attempt to fail on state, got %v", err)
	}

	// The failed attempt cleared the cookie; the retry carries that.
	_, err, _ = callback(t, auth, "/callback?code=c&state=forged", cleared)
	if !errors.Is(err, vouch.ErrNoHandshake) {
		t.Fatalf("expected the handshake to be spent, got %v", err)
	}
}

func TestChallengeIsTheSha256OfTheVerifier(t *testing.T) {
	handshake := vouch.Handshake{CodeVerifier: "a-known-verifier"}

	sum := sha256.Sum256([]byte("a-known-verifier"))
	if expected := base64.RawURLEncoding.EncodeToString(sum[:]); handshake.Challenge() != expected {
		t.Fatalf("expected %q, got %q", expected, handshake.Challenge())
	}
}

func TestSafeRedirectKeepsOnlyLocalPaths(t *testing.T) {
	cases := map[string]string{
		"/runs":                   "/runs",
		"":                        "",
		"https://evil.test/steal": "",
		"//evil.test/steal":       "",
		"javascript:alert(1)":     "",
		"  /spaced  ":             "/spaced",
	}

	for candidate, expected := range cases {
		if got := vouch.SafeRedirect(candidate); got != expected {
			t.Errorf("SafeRedirect(%q) = %q, want %q", candidate, got, expected)
		}
	}
}

func TestAProviderCanAddItsOwnAuthorizationParameters(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, func() vouch.Provider { return parameterisedProvider{} }), ""))

	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Fatalf("the provider's parameters did not reach the provider: %s", query.Encode())
	}
	// PKCE is not an either/or with extra parameters.
	if query.Get("code_challenge") == "" {
		t.Fatal("adding parameters dropped the challenge")
	}
}

func TestAProviderCanOptOutOfPKCE(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, func() vouch.Provider { return unprotectedProvider{} }), ""))

	if query.Get("code_challenge") != "" || query.Get("code_challenge_method") != "" {
		t.Fatalf("a provider that opted out was still sent a challenge: %s", query.Encode())
	}
	// State is not part of the opt-out: it is the only thing left tying the
	// callback to this browser.
	if query.Get("state") == "" {
		t.Fatal("no state was issued")
	}
}

func TestACallSiteCanOverrideTheProviderOnPKCE(t *testing.T) {
	auth := setup(t, func() vouch.Provider { return unprotectedProvider{} })

	on := issuedQuery(t, redirect(t, auth, "", (*vouch.Flow).UsingPKCE))
	if on.Get("code_challenge") == "" {
		t.Fatal("UsingPKCE did not turn the challenge on")
	}

	off := issuedQuery(t, redirect(t, setup(t, fake(true)), "", (*vouch.Flow).WithoutPKCE))
	if off.Get("code_challenge") != "" {
		t.Fatal("WithoutPKCE did not turn the challenge off")
	}
}

func TestARefusalIsReadRatherThanExchanged(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	_, err, _ := callback(t, auth, "/callback?error=access_denied&error_description=The+user+said+no&state="+issuedState(t, started), started)

	// A cancelled sign-in is an answer, not a broken exchange.
	if !errors.Is(err, vouch.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
	if !errors.Is(err, vouch.ErrAuthorization) {
		t.Fatal("a denial should also match every refusal")
	}

	var refusal *vouch.AuthorizationError
	if !errors.As(err, &refusal) || refusal.Description != "The user said no" {
		t.Fatalf("the provider's own words were lost: %v", err)
	}
}

func TestARefusalThatIsNotADenialStillMatchesAuthorization(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	_, err, _ := callback(t, auth, "/callback?error=temporarily_unavailable&state="+issuedState(t, started), started)

	if errors.Is(err, vouch.ErrAccessDenied) {
		t.Fatal("an outage was reported as the person declining")
	}
	if !errors.Is(err, vouch.ErrAuthorization) {
		t.Fatalf("expected ErrAuthorization, got %v", err)
	}
}

func TestARefusalIsOnlyReadOnceTheStateMatches(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	// Anyone can send the browser here carrying an error. Until the state
	// ties the response to a handshake this server issued, what it says is
	// not worth reading.
	_, err, _ := callback(t, auth, "/callback?error=access_denied&state=forged", started)
	if !errors.Is(err, vouch.ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

func TestAProviderThatNamesItselfMustBeTheOneThatAnswered(t *testing.T) {
	auth := setup(t, func() vouch.Provider { return issuedProvider{} })
	started := redirect(t, auth, "")

	_, err, _ := callback(t, auth, "/callback?code=c&iss=https://attacker.test&state="+issuedState(t, started), started)
	if !errors.Is(err, vouch.ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestAMissingIssuerIsAMismatchForAProviderThatSendsOne(t *testing.T) {
	auth := setup(t, func() vouch.Provider { return issuedProvider{} })
	started := redirect(t, auth, "")

	// RFC 9207 only defeats a mix-up if a client that expects an issuer
	// refuses a response without one.
	_, err, _ := callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started)
	if !errors.Is(err, vouch.ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestScopesAddAndSetScopesReplace(t *testing.T) {
	auth := setup(t, func() vouch.Provider { return scopedProvider{} })

	added := issuedQuery(t, redirect(t, auth, "", func(flow *vouch.Flow) *vouch.Flow { return flow.Scopes("email", "profile") }))
	if scope := added.Get("scope"); scope != "profile email" {
		t.Fatalf("expected the provider's scope kept and one added, got %q", scope)
	}

	replaced := issuedQuery(t, redirect(t, auth, "", func(flow *vouch.Flow) *vouch.Flow { return flow.SetScopes("email") }))
	if scope := replaced.Get("scope"); scope != "email" {
		t.Fatalf("expected only the scope set, got %q", scope)
	}
}

func TestTheOpenIDScopeIsWhatIssuesANonce(t *testing.T) {
	tokenURL := tokenEndpoint(t)
	auth := setup(t, func() vouch.Provider { return exchangingProvider{tokenURL: tokenURL} })

	if issuedQuery(t, redirect(t, auth, "")).Get("nonce") != "" {
		t.Fatal("a plain OAuth2 request was sent a nonce")
	}

	openid := func(flow *vouch.Flow) *vouch.Flow { return flow.Scopes("openid") }
	started := redirect(t, auth, "", openid)
	nonce := issuedQuery(t, started).Get("nonce")
	if nonce == "" {
		t.Fatal("an OpenID Connect request was not sent a nonce")
	}

	// The provider has to be able to check the claim it gets back against it.
	user, err, _ := callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started, openid)
	if err != nil {
		t.Fatal(err)
	}
	if grant, ok := user.Raw.(vouch.Grant); !ok || grant.Nonce != nonce {
		t.Fatal("the nonce never reached the provider")
	}
	if grant := user.Raw.(vouch.Grant); grant.Client == nil {
		t.Fatal("the provider was not given an authenticated client")
	}
}

func TestWithCannotOverwriteWhatMakesTheCallbackTrustworthy(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, fake(true)), "", func(flow *vouch.Flow) *vouch.Flow {
		return flow.With(map[string]string{"login_hint": "person@provider.test", "state": "chosen"})
	}))

	if query.Get("login_hint") != "person@provider.test" {
		t.Fatal("an ordinary parameter was dropped")
	}
	if query.Get("state") == "chosen" {
		t.Fatal("a call site was allowed to choose the state")
	}
}

func TestRedirectURLOverridesTheProviders(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, fake(true)), "", func(flow *vouch.Flow) *vouch.Flow {
		return flow.RedirectURL("http://localhost/other")
	}))
	if query.Get("redirect_uri") != "http://localhost/other" {
		t.Fatalf("redirect_uri: %q", query.Get("redirect_uri"))
	}
}

func TestStatelessCarriesNoHandshakeAtAll(t *testing.T) {
	recorder := redirect(t, setup(t, fake(true)), "", (*vouch.Flow).Stateless)

	if len(recorder.Result().Cookies()) != 0 {
		t.Fatal("a stateless flow wrote a cookie")
	}
	query := issuedQuery(t, recorder)
	if query.Get("state") != "" || query.Get("code_challenge") != "" {
		t.Fatalf("a stateless flow issued what it cannot check: %s", query.Encode())
	}
}

func TestRedirectToComesBackFromTheHandshake(t *testing.T) {
	tokenURL := tokenEndpoint(t)
	auth := setup(t, func() vouch.Provider { return exchangingProvider{tokenURL: tokenURL} })
	started := redirect(t, auth, "/settings")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+issuedState(t, started), nil)
	for _, cookie := range started.Result().Cookies() {
		request.AddCookie(cookie)
	}
	flow := auth.Driver(recorder, request, "fake")
	if flow.RedirectTo() != "" {
		t.Fatal("RedirectTo should be empty before User")
	}
	if _, err := flow.User(); err != nil {
		t.Fatal(err)
	}
	if flow.RedirectTo() != "/settings" {
		t.Fatalf("expected /settings, got %q", flow.RedirectTo())
	}
	// The callback clears the handshake for good.
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "vouch_handshake" && cookie.MaxAge >= 0 {
			t.Fatal("the handshake cookie was not cleared")
		}
	}
}

func TestApprovedScopesComeFromTheProviderWhenItNamesThem(t *testing.T) {
	auth := setup(t, fake(true))
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	granted := (&oauth2.Token{AccessToken: "granted"}).WithExtra(map[string]any{"scope": "profile email"})
	user, err := auth.Driver(httptest.NewRecorder(), request, "fake").UserFromToken(granted)
	if err != nil {
		t.Fatal(err)
	}
	if !user.HasScope("email") || len(user.ApprovedScopes) != 2 {
		t.Fatalf("expected the granted scopes, got %v", user.ApprovedScopes)
	}

	// RFC 6749 section 5.1: leaving the scope out means it is the one asked for.
	silent, err := auth.Driver(httptest.NewRecorder(), request, "fake").UserFromToken(&oauth2.Token{AccessToken: "granted"})
	if err != nil {
		t.Fatal(err)
	}
	if len(silent.ApprovedScopes) != 0 {
		t.Fatalf("scopes were invented, got %v", silent.ApprovedScopes)
	}
}

func TestATokenThisPackageCannotPresentIsRefused(t *testing.T) {
	auth := setup(t, fake(true))
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, err := auth.Driver(httptest.NewRecorder(), request, "fake").UserFromToken(&oauth2.Token{}); !errors.Is(err, vouch.ErrExchange) {
		t.Fatalf("an empty access token was accepted: %v", err)
	}
	mac := &oauth2.Token{AccessToken: "a", TokenType: "mac"}
	if _, err := auth.Driver(httptest.NewRecorder(), request, "fake").UserFromToken(mac); !errors.Is(err, vouch.ErrExchange) {
		t.Fatalf("a token type this client cannot use was accepted: %v", err)
	}
}

func TestAnExpiredHandshakeIsNoHandshake(t *testing.T) {
	auth, err := vouch.New(vouch.Configuration{Sealer: plainSealer{}, Cookie: expired(), Drivers: vouch.Drivers{"fake": fake(true)}})
	if err != nil {
		t.Fatal(err)
	}
	started := redirect(t, auth, "")

	// The cookie's own max-age is the browser's to honour. The expiry inside
	// the sealed payload is not.
	_, err, _ = callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started)
	if !errors.Is(err, vouch.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestATamperedHandshakeIsNoHandshake(t *testing.T) {
	auth := setup(t, fake(true))
	started := redirect(t, auth, "")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+issuedState(t, started), nil)
	for _, cookie := range started.Result().Cookies() {
		cookie.Value = "not-" + cookie.Value
		request.AddCookie(cookie)
	}
	if _, err := auth.Driver(recorder, request, "fake").User(); !errors.Is(err, vouch.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestExtendAddsADriverAtRuntime(t *testing.T) {
	auth := setup(t, fake(true))
	auth.Extend("other", fake(true))

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	if err := auth.Driver(httptest.NewRecorder(), request, "other").Redirect(""); err != nil {
		t.Fatalf("the extended driver should work: %v", err)
	}
}

func TestCookieOptionsAreMirrored(t *testing.T) {
	auth, err := vouch.New(vouch.Configuration{
		Sealer:  plainSealer{},
		Cookie:  vouch.CookieOptions{Name: "hs", Path: "/auth", Domain: "example.test", Secure: true, SameSite: http.SameSiteStrictMode},
		Drivers: vouch.Drivers{"fake": fake(true)},
	})
	if err != nil {
		t.Fatal(err)
	}

	cookie := redirect(t, auth, "").Result().Cookies()[0]
	mirrored := cookie.Name == "hs" && cookie.Path == "/auth" && cookie.Domain == "example.test" &&
		cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode
	if !mirrored {
		t.Fatalf("cookie attributes not honoured: %+v", cookie)
	}
	if cookie.MaxAge != 600 {
		t.Fatalf("expected the default ten minutes, got %d", cookie.MaxAge)
	}
}
