package social

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// openIDScope turns an OAuth2 request into an OpenID Connect one. The flow
// watches for it because that is what decides whether a nonce is owed.
const openIDScope = "openid"

// Flow is one provider bound to one request. It is returned by Driver and is
// not meant to be held: everything it does happens within the request it came
// from.
//
// The methods that shape it return the flow, so a call site reads as one
// sentence. Every one of them is optional: the defaults are what the provider
// registered, with PKCE on.
type Flow struct {
	writer   http.ResponseWriter
	request  *http.Request
	name     string
	provider Provider
	sealer   Sealer
	cookie   CookieOptions
	client   *http.Client

	scopes      []string
	parameters  []oauth2.AuthCodeOption
	redirectURL string
	stateless   bool
	pkce        *bool

	redirectTo string
}

// Scopes adds to what the provider already asks for.
func (self *Flow) Scopes(scopes ...string) *Flow {
	self.scopes = dedupe(append(self.Scoped(), scopes...))

	return self
}

// SetScopes replaces them, for the caller who wants exactly these and no more.
func (self *Flow) SetScopes(scopes ...string) *Flow {
	self.scopes = dedupe(scopes)

	return self
}

// Scoped is what will be asked for: the provider's own scopes until something
// here changes them.
func (self *Flow) Scoped() []string {
	if self.scopes != nil {
		return slices.Clone(self.scopes)
	}

	if self.provider == nil {
		return nil
	}

	return slices.Clone(self.provider.Config().Scopes)
}

// With adds parameters to the authorization URL. Use it for the ones that
// belong to this request rather than to the provider, a login_hint, a prompt,
// and implement Parameterised for the ones that are always sent.
//
// The parameters the flow owns cannot be overwritten from here: state,
// code_challenge and nonce are what make the callback trustworthy, and a call
// site is not the place to decide otherwise.
func (self *Flow) With(parameters map[string]string) *Flow {
	for key, value := range parameters {
		if reserved(key) {
			continue
		}

		self.parameters = append(self.parameters, oauth2.SetAuthURLParam(key, value))
	}

	return self
}

// RedirectURL overrides where the provider sends the browser back. It must
// still be one the provider has registered: RFC 6749 section 3.1.2.3 has the
// authorization server compare it exactly, so an unregistered value fails
// there rather than here.
func (self *Flow) RedirectURL(url string) *Flow {
	self.redirectURL = url

	return self
}

// Stateless drops the handshake, for a flow this server did not start: a
// native app or a single-page client that runs the redirect itself and brings
// back what it got.
//
// It costs both defences at once: no state to compare, and nowhere to keep a
// verifier, so no PKCE either. Whatever calls it takes on the job of deciding
// that the callback belongs to the session it will be used for.
func (self *Flow) Stateless() *Flow {
	self.stateless = true

	return self
}

// UsingPKCE turns PKCE on for a provider that opted out of it.
func (self *Flow) UsingPKCE() *Flow {
	enabled := true
	self.pkce = &enabled

	return self
}

// WithoutPKCE turns it off for one request. Prefer implementing Unprotected: a
// provider that cannot do PKCE cannot do it on any request, and that belongs
// with the provider rather than at one call site.
func (self *Flow) WithoutPKCE() *Flow {
	disabled := false
	self.pkce = &disabled

	return self
}

// Redirect sends the browser to the provider, remembering the state, verifier
// and nonce on the way out. The error is ErrUnknownDriver or ErrNotConfigured
// when nothing was sent, so a handler can answer those itself.
func (self *Flow) Redirect(redirectTo string) error {
	url, err := self.AuthorizationURL(redirectTo)
	if err != nil {
		return err
	}

	http.Redirect(self.writer, self.request, url, http.StatusFound)

	return nil
}

// AuthorizationURL is Redirect without the redirecting, for a caller that
// sends the browser itself. It still writes the handshake cookie, so whatever
// follows the URL must be the browser this was called for.
func (self *Flow) AuthorizationURL(redirectTo string) (string, error) {
	if self.provider == nil {
		return "", fmt.Errorf("%w: %s", ErrUnknownDriver, self.name)
	}

	if !self.provider.Configured() {
		return "", ErrNotConfigured
	}

	handshake := Handshake{}

	if !self.stateless {
		issued, err := self.cookie.begin(self.writer, self.sealer, redirectTo, self.usesPKCE(), self.usesNonce())
		if err != nil {
			return "", err
		}

		handshake = issued
	}

	return self.config().AuthCodeURL(handshake.State, self.authorization(handshake)...), nil
}

// User finishes the flow and returns the identity the provider vouches for.
//
// The code, state, issuer and any refusal are read from the request rather than
// passed in, because they are the provider's half of a conversation this
// package started: the caller has nothing to add to them.
func (self *Flow) User() (*User, error) {
	if self.provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDriver, self.name)
	}

	handshake, err := self.verified()
	if err != nil {
		return nil, err
	}

	// Only now, with the response tied to a handshake this server issued, is
	// what it says worth reading.
	if err := self.refusal(); err != nil {
		return nil, err
	}

	if !self.provider.Configured() {
		return nil, ErrNotConfigured
	}

	token, err := self.exchange(handshake)
	if err != nil {
		return nil, err
	}

	return self.profile(token, handshake.Nonce)
}

// UserFromToken skips the flow and asks the provider about a token the caller
// already holds: one a native app obtained itself, or one stored earlier.
func (self *Flow) UserFromToken(token *oauth2.Token) (*User, error) {
	if self.provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDriver, self.name)
	}

	if err := usable(token); err != nil {
		return nil, err
	}

	return self.profile(token, "")
}

// Refresh trades a refresh token for a live one. Nothing is stored: what comes
// back may carry a new refresh token, and RFC 6749 section 6 lets the provider
// retire the old one, so the caller persists the result.
func (self *Flow) Refresh(refreshToken string) (*oauth2.Token, error) {
	if self.provider == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDriver, self.name)
	}

	if !self.provider.Configured() {
		return nil, ErrNotConfigured
	}

	source := self.config().TokenSource(self.context(), &oauth2.Token{RefreshToken: refreshToken})

	token, err := source.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	return token, nil
}

// RedirectTo is where the user asked to land, recovered from the handshake by
// User. It is empty until User has run, and empty when none was asked for.
func (self *Flow) RedirectTo() string {
	return self.redirectTo
}

// context is the request's, carrying the configured HTTP client so the
// oauth2 library sends the exchange through it.
func (self *Flow) context() context.Context {
	return context.WithValue(self.request.Context(), oauth2.HTTPClient, self.client)
}

func (self *Flow) query(name string) string {
	return self.request.URL.Query().Get(name)
}

// verified reads back the handshake and checks the response against it: the
// state, and the issuer if the provider names itself. A stateless flow has
// neither, which is what stateless means.
func (self *Flow) verified() (Handshake, error) {
	if self.stateless {
		return Handshake{}, nil
	}

	handshake, ok := self.cookie.end(self.writer, self.request, self.sealer)
	if !ok {
		return Handshake{}, ErrNoHandshake
	}

	// A byte-by-byte comparison that stops early tells anyone who can time it
	// how much of a guessed state was right.
	if subtle.ConstantTimeCompare([]byte(handshake.State), []byte(self.query("state"))) != 1 {
		return Handshake{}, ErrStateMismatch
	}

	if err := self.issuer(); err != nil {
		return Handshake{}, err
	}

	self.redirectTo = handshake.RedirectTo

	return handshake, nil
}

// issuer applies RFC 9207. A provider that names itself must be the one that
// answered, and must have said so: an absent iss from a provider known to send
// one is the mix-up the extension exists to catch.
func (self *Flow) issuer() error {
	expected, ok := self.provider.(Issued)
	if !ok {
		return nil
	}

	if self.query("iss") != expected.Issuer() {
		return ErrIssuerMismatch
	}

	return nil
}

// refusal reads the error the provider may have redirected back with instead of
// a code, in the shape RFC 6749 section 4.1.2.1 defines.
func (self *Flow) refusal() error {
	code := self.query("error")
	if code == "" {
		return nil
	}

	return &AuthorizationError{
		Code:        code,
		Description: self.query("error_description"),
		URI:         self.query("error_uri"),
	}
}

func (self *Flow) exchange(handshake Handshake) (*oauth2.Token, error) {
	options := []oauth2.AuthCodeOption{}

	if handshake.CodeVerifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", handshake.CodeVerifier))
	}

	token, err := self.config().Exchange(self.context(), self.query("code"), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	if err := usable(token); err != nil {
		return nil, err
	}

	return token, nil
}

func (self *Flow) profile(token *oauth2.Token, nonce string) (*User, error) {
	ctx := self.context()
	grant := Grant{Token: token, Nonce: nonce, Client: self.config().Client(ctx, token)}

	user, err := self.provider.User(ctx, grant)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}

	user.Token = token
	user.ApprovedScopes = granted(token, self.Scoped())

	return user, nil
}

// authorization is everything the flow itself puts on the authorization URL,
// followed by whatever the provider and the call site added.
func (self *Flow) authorization(handshake Handshake) []oauth2.AuthCodeOption {
	options := []oauth2.AuthCodeOption{}

	if handshake.CodeVerifier != "" {
		options = append(options,
			oauth2.SetAuthURLParam("code_challenge", handshake.Challenge()),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	if handshake.Nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", handshake.Nonce))
	}

	if parameterised, ok := self.provider.(Parameterised); ok {
		options = append(options, parameterised.Parameters()...)
	}

	return append(options, self.parameters...)
}

// config is the provider's, with this request's changes applied to a copy so
// one request cannot change what the next one asks for.
func (self *Flow) config() *oauth2.Config {
	config := *self.provider.Config()

	if self.scopes != nil {
		config.Scopes = self.scopes
	}

	if self.redirectURL != "" {
		config.RedirectURL = self.redirectURL
	}

	return &config
}

// usesPKCE reports whether this request takes part in PKCE. Silence is yes:
// OAuth 2.1 makes it mandatory for every client, so opting out is the decision
// that should have to be written down.
func (self *Flow) usesPKCE() bool {
	// The verifier has nowhere to live between the two requests.
	if self.stateless {
		return false
	}

	if self.pkce != nil {
		return *self.pkce
	}

	unprotected, ok := self.provider.(Unprotected)

	return !ok || unprotected.UsesPKCE()
}

// usesNonce reports whether a nonce is owed. Asking for the openid scope is
// what makes this an OpenID Connect request, and section 3.1.2.1 of that spec
// is where the nonce comes from.
func (self *Flow) usesNonce() bool {
	return slices.ContainsFunc(self.Scoped(), func(scope string) bool {
		return strings.EqualFold(scope, openIDScope)
	})
}

// usable rejects a token this package cannot present. RFC 6750 covers bearer
// tokens, and a provider answering with anything else needs a client that knows
// what to do with it.
func usable(token *oauth2.Token) error {
	if token == nil || token.AccessToken == "" {
		return fmt.Errorf("%w: the response carried no access token", ErrExchange)
	}

	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "bearer") {
		return fmt.Errorf("%w: unsupported token type %q", ErrExchange, token.TokenType)
	}

	return nil
}

// granted is what the provider actually approved. RFC 6749 section 5.1 lets the
// token response name a different set than was asked for, and says that leaving
// it out means the two are the same.
func granted(token *oauth2.Token, requested []string) []string {
	scope, _ := token.Extra("scope").(string)

	if fields := strings.Fields(scope); len(fields) > 0 {
		return fields
	}

	return requested
}

// reserved names the parameters the flow decides. Letting a call site set them
// would let it disable the checks the callback depends on.
func reserved(key string) bool {
	switch strings.ToLower(key) {
	case "state", "nonce", "code_challenge", "code_challenge_method", "client_id", "redirect_uri", "response_type", "scope":
		return true
	default:
		return false
	}
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))

	for _, value := range values {
		if _, done := seen[value]; done {
			continue
		}

		seen[value] = struct{}{}
		unique = append(unique, value)
	}

	return unique
}
