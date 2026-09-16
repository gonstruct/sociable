package social_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonstruct/social"
	"golang.org/x/oauth2"
)

func TestRedirectCarriesAChallengeAndNotTheVerifier(t *testing.T) {
	recorder := redirect(t, setup(t, configured()), social.To("/after"))

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
	if cookies := recorder.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != "social_handshake" {
		t.Fatalf("expected the handshake cookie, got %v", cookies)
	}
}

func TestRedirectRefusesAnUnconfiguredProvider(t *testing.T) {
	auth := setup(t, fakeProvider{configured: false})
	recorder := httptest.NewRecorder()

	err := auth.Redirect(recorder, httptest.NewRequest(http.MethodGet, "/login", nil), "fake")
	if !errors.Is(err, social.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	if recorder.Header().Get("Location") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestAnUnknownDriverIsAnErrorRatherThanAPanic(t *testing.T) {
	auth := setup(t, configured())
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := auth.Redirect(httptest.NewRecorder(), request, "nope"); !errors.Is(err, social.ErrUnknownDriver) {
		t.Fatalf("redirect: expected ErrUnknownDriver, got %v", err)
	}
	if _, err := auth.Callback(httptest.NewRecorder(), request, "nope"); !errors.Is(err, social.ErrUnknownDriver) {
		t.Fatalf("callback: expected ErrUnknownDriver, got %v", err)
	}
	if _, err := auth.UserFromToken(context.Background(), "nope", &oauth2.Token{AccessToken: "a"}); !errors.Is(err, social.ErrUnknownDriver) {
		t.Fatalf("user from token: expected ErrUnknownDriver, got %v", err)
	}
}

func TestNewRequiresASealer(t *testing.T) {
	if _, err := social.New(social.Configuration{}); !errors.Is(err, social.ErrNoSealer) {
		t.Fatalf("expected ErrNoSealer, got %v", err)
	}
}

func TestCallbackWithoutAHandshakeIsRefused(t *testing.T) {
	_, err, _ := callback(t, setup(t, configured()), "/callback?code=c&state=s", nil)
	if !errors.Is(err, social.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestCallbackRefusesAForgedState(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	_, err, _ := callback(t, auth, "/callback?code=c&state=forged", started)
	if !errors.Is(err, social.ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

func TestTheHandshakeIsSpentEvenByAFailedAttempt(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	_, err, cleared := callback(t, auth, "/callback?code=c&state=forged", started)
	if !errors.Is(err, social.ErrStateMismatch) {
		t.Fatalf("expected the first attempt to fail on state, got %v", err)
	}

	// The failed attempt cleared the cookie; the retry carries that.
	_, err, _ = callback(t, auth, "/callback?code=c&state=forged", cleared)
	if !errors.Is(err, social.ErrNoHandshake) {
		t.Fatalf("expected the handshake to be spent, got %v", err)
	}
}

func TestChallengeIsTheSha256OfTheVerifier(t *testing.T) {
	handshake := social.Handshake{CodeVerifier: "a-known-verifier"}

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
		if got := social.SafeRedirect(candidate); got != expected {
			t.Errorf("SafeRedirect(%q) = %q, want %q", candidate, got, expected)
		}
	}
}

func TestAProviderCanAddItsOwnAuthorizationParameters(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, parameterisedProvider{configured()})))

	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Fatalf("the provider's parameters did not reach the provider: %s", query.Encode())
	}
	// PKCE is not an either/or with extra parameters.
	if query.Get("code_challenge") == "" {
		t.Fatal("adding parameters dropped the challenge")
	}
}

func TestAProviderCanOptOutOfPKCE(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, unprotectedProvider{configured()})))

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
	on := issuedQuery(t, redirect(t, setup(t, unprotectedProvider{configured()}), social.UsingPKCE()))
	if on.Get("code_challenge") == "" {
		t.Fatal("UsingPKCE did not turn the challenge on")
	}

	off := issuedQuery(t, redirect(t, setup(t, configured()), social.WithoutPKCE()))
	if off.Get("code_challenge") != "" {
		t.Fatal("WithoutPKCE did not turn the challenge off")
	}
}

func TestARefusalIsReadRatherThanExchanged(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	_, err, _ := callback(t, auth, "/callback?error=access_denied&error_description=The+user+said+no&state="+issuedState(t, started), started)

	// A cancelled sign-in is an answer, not a broken exchange.
	if !errors.Is(err, social.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
	if !errors.Is(err, social.ErrAuthorization) {
		t.Fatal("a denial should also match every refusal")
	}

	var refusal *social.AuthorizationError
	if !errors.As(err, &refusal) || refusal.Description != "The user said no" {
		t.Fatalf("the provider's own words were lost: %v", err)
	}
}

func TestARefusalThatIsNotADenialStillMatchesAuthorization(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	_, err, _ := callback(t, auth, "/callback?error=temporarily_unavailable&state="+issuedState(t, started), started)

	if errors.Is(err, social.ErrAccessDenied) {
		t.Fatal("an outage was reported as the person declining")
	}
	if !errors.Is(err, social.ErrAuthorization) {
		t.Fatalf("expected ErrAuthorization, got %v", err)
	}
}

func TestARefusalIsOnlyReadOnceTheStateMatches(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	// Anyone can send the browser here carrying an error. Until the state
	// ties the response to a handshake this server issued, what it says is
	// not worth reading.
	_, err, _ := callback(t, auth, "/callback?error=access_denied&state=forged", started)
	if !errors.Is(err, social.ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

func TestAProviderThatAsksForTheIssuerMustBeTheOneThatAnswered(t *testing.T) {
	auth := setup(t, issuedProvider{configured()})
	started := redirect(t, auth)

	_, err, _ := callback(t, auth, "/callback?code=c&iss=https://attacker.test&state="+issuedState(t, started), started)
	if !errors.Is(err, social.ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestAMissingIssuerIsAMismatchForAProviderThatAsksForOne(t *testing.T) {
	auth := setup(t, issuedProvider{configured()})
	started := redirect(t, auth)

	// RFC 9207 only defeats a mix-up if a client that expects an issuer
	// refuses a response without one.
	_, err, _ := callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started)
	if !errors.Is(err, social.ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestScopesAddAndSetScopesReplace(t *testing.T) {
	auth := setup(t, fakeProvider{configured: true, scopes: []string{"profile"}})

	if scope := issuedQuery(t, redirect(t, auth, social.Scopes("email", "profile"))).Get("scope"); scope != "profile email" {
		t.Fatalf("expected the provider's scope kept and one added, got %q", scope)
	}
	if scope := issuedQuery(t, redirect(t, auth, social.SetScopes("email"))).Get("scope"); scope != "email" {
		t.Fatalf("expected only the scope set, got %q", scope)
	}
}

func TestTheOpenIDScopeIsWhatIssuesANonce(t *testing.T) {
	auth := setup(t, fakeProvider{configured: true, tokenURL: tokenEndpoint(t)})

	if issuedQuery(t, redirect(t, auth)).Get("nonce") != "" {
		t.Fatal("a plain OAuth2 request was sent a nonce")
	}

	started := redirect(t, auth, social.Scopes("openid"))
	nonce := issuedQuery(t, started).Get("nonce")
	if nonce == "" {
		t.Fatal("an OpenID Connect request was not sent a nonce")
	}

	// The provider has to be able to check the claim it gets back against it.
	result, err, _ := callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started, social.Scopes("openid"))
	if err != nil {
		t.Fatal(err)
	}
	grant, ok := result.User.Raw.(social.Grant)
	if !ok || grant.Nonce != nonce {
		t.Fatal("the nonce never reached the provider")
	}
	if grant.Client == nil {
		t.Fatal("the provider was not given an authenticated client")
	}
}

func TestWithCannotOverwriteWhatMakesTheCallbackTrustworthy(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, configured()), social.With(map[string]string{"login_hint": "person@provider.test", "state": "chosen"})))

	if query.Get("login_hint") != "person@provider.test" {
		t.Fatal("an ordinary parameter was dropped")
	}
	if query.Get("state") == "chosen" {
		t.Fatal("a call site was allowed to choose the state")
	}
}

func TestRedirectURLOverridesTheProviders(t *testing.T) {
	query := issuedQuery(t, redirect(t, setup(t, configured()), social.RedirectURL("http://localhost/other")))
	if query.Get("redirect_uri") != "http://localhost/other" {
		t.Fatalf("redirect_uri: %q", query.Get("redirect_uri"))
	}
}

func TestStatelessCarriesNoHandshakeAtAll(t *testing.T) {
	recorder := redirect(t, setup(t, configured()), social.Stateless())

	if len(recorder.Result().Cookies()) != 0 {
		t.Fatal("a stateless flow wrote a cookie")
	}
	query := issuedQuery(t, recorder)
	if query.Get("state") != "" || query.Get("code_challenge") != "" {
		t.Fatalf("a stateless flow issued what it cannot check: %s", query.Encode())
	}
}

func TestTheResultCarriesWhereToLand(t *testing.T) {
	auth := setup(t, fakeProvider{configured: true, tokenURL: tokenEndpoint(t)})
	started := redirect(t, auth, social.To("/settings"))

	result, err, recorder := callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started)
	if err != nil {
		t.Fatal(err)
	}
	if result.RedirectTo != "/settings" || result.User.ID != "1" || result.User.Token.AccessToken != "granted" {
		t.Fatalf("result: %+v", result)
	}
	// The callback clears the handshake for good.
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "social_handshake" && cookie.MaxAge >= 0 {
			t.Fatal("the handshake cookie was not cleared")
		}
	}
}

func TestApprovedScopesComeFromTheProviderWhenItNamesThem(t *testing.T) {
	auth := setup(t, configured())
	ctx := context.Background()

	granted := (&oauth2.Token{AccessToken: "granted"}).WithExtra(map[string]any{"scope": "profile email"})
	user, err := auth.UserFromToken(ctx, "fake", granted)
	if err != nil {
		t.Fatal(err)
	}
	if !user.HasScope("email") || len(user.ApprovedScopes) != 2 {
		t.Fatalf("expected the granted scopes, got %v", user.ApprovedScopes)
	}

	// RFC 6749 section 5.1: leaving the scope out means it is the one asked for.
	silent, err := auth.UserFromToken(ctx, "fake", &oauth2.Token{AccessToken: "granted"}, social.Scopes("profile"))
	if err != nil {
		t.Fatal(err)
	}
	if len(silent.ApprovedScopes) != 1 || silent.ApprovedScopes[0] != "profile" {
		t.Fatalf("expected the requested scope, got %v", silent.ApprovedScopes)
	}
}

func TestATokenThisPackageCannotPresentIsRefused(t *testing.T) {
	auth := setup(t, configured())
	ctx := context.Background()

	if _, err := auth.UserFromToken(ctx, "fake", &oauth2.Token{}); !errors.Is(err, social.ErrExchange) {
		t.Fatalf("an empty access token was accepted: %v", err)
	}
	if _, err := auth.UserFromToken(ctx, "fake", &oauth2.Token{AccessToken: "a", TokenType: "mac"}); !errors.Is(err, social.ErrExchange) {
		t.Fatalf("a token type this client cannot use was accepted: %v", err)
	}
}

func TestAnExpiredHandshakeIsNoHandshake(t *testing.T) {
	auth, err := social.New(social.Configuration{Sealer: plainSealer{}, Cookie: expired(), Drivers: social.Drivers{"fake": configured()}})
	if err != nil {
		t.Fatal(err)
	}
	started := redirect(t, auth)

	// The cookie's own max-age is the browser's to honour. The expiry inside
	// the sealed payload is not.
	_, err, _ = callback(t, auth, "/callback?code=c&state="+issuedState(t, started), started)
	if !errors.Is(err, social.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestATamperedHandshakeIsNoHandshake(t *testing.T) {
	auth := setup(t, configured())
	started := redirect(t, auth)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+issuedState(t, started), nil)
	for _, cookie := range started.Result().Cookies() {
		cookie.Value = "not-" + cookie.Value
		request.AddCookie(cookie)
	}
	if _, err := auth.Callback(recorder, request, "fake"); !errors.Is(err, social.ErrNoHandshake) {
		t.Fatalf("expected ErrNoHandshake, got %v", err)
	}
}

func TestExtendAddsADriverAtRuntime(t *testing.T) {
	auth := setup(t, configured())
	auth.Extend("other", configured())

	if err := auth.Redirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/login", nil), "other"); err != nil {
		t.Fatalf("the extended driver should work: %v", err)
	}
}

func TestCookieOptionsAreMirrored(t *testing.T) {
	auth, err := social.New(social.Configuration{
		Sealer:  plainSealer{},
		Cookie:  social.CookieOptions{Name: "hs", Path: "/auth", Domain: "example.test", Secure: true, SameSite: http.SameSiteStrictMode},
		Drivers: social.Drivers{"fake": configured()},
	})
	if err != nil {
		t.Fatal(err)
	}

	cookie := redirect(t, auth).Result().Cookies()[0]
	mirrored := cookie.Name == "hs" && cookie.Path == "/auth" && cookie.Domain == "example.test" &&
		cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode
	if !mirrored {
		t.Fatalf("cookie attributes not honoured: %+v", cookie)
	}
	if cookie.MaxAge != 600 {
		t.Fatalf("expected the default ten minutes, got %d", cookie.MaxAge)
	}
}

func TestRefreshGoesThroughTheProvider(t *testing.T) {
	auth := setup(t, fakeProvider{configured: true, tokenURL: tokenEndpoint(t)})

	token, err := auth.Refresh(context.Background(), "fake", "refresh-me")
	if err != nil || token.AccessToken != "granted" {
		t.Fatalf("refresh: %+v %v", token, err)
	}
	if _, err := setup(t, fakeProvider{}).Refresh(context.Background(), "fake", "x"); !errors.Is(err, social.ErrNotConfigured) {
		t.Fatalf("an unconfigured provider cannot refresh: %v", err)
	}
}
