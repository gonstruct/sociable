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

// flow is one provider bound to one request, shaped by the call's options.
type flow struct {
	writer   http.ResponseWriter
	request  *http.Request
	name     string
	provider Provider
	sealer   Sealer
	cookie   CookieOptions
	client   *http.Client

	to          string
	scopes      []string
	parameters  []oauth2.AuthCodeOption
	redirectURL string
	stateless   bool
	pkce        *bool
}

func (self *flow) authorizationURL() (string, error) {
	if !self.provider.Configured() {
		return "", ErrNotConfigured
	}

	handshake := Handshake{}

	if !self.stateless {
		issued, err := self.cookie.begin(self.writer, self.sealer, self.to, self.usesPKCE(), self.usesNonce())
		if err != nil {
			return "", err
		}

		handshake = issued
	}

	return self.config().AuthCodeURL(handshake.State, self.authorization(handshake)...), nil
}

func (self *flow) callback() (*Result, error) {
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

	user, err := self.profile(token, handshake.Nonce)
	if err != nil {
		return nil, err
	}

	return &Result{User: user, RedirectTo: handshake.RedirectTo}, nil
}

func (self *flow) userFromToken(token *oauth2.Token) (*User, error) {
	if err := usable(token); err != nil {
		return nil, err
	}

	return self.profile(token, "")
}

func (self *flow) refresh(refreshToken string) (*oauth2.Token, error) {
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

// context is the request's, carrying the configured HTTP client so the
// oauth2 library sends the exchange through it.
func (self *flow) context() context.Context {
	return context.WithValue(self.request.Context(), oauth2.HTTPClient, self.client)
}

func (self *flow) query(name string) string {
	if self.request.URL == nil {
		return ""
	}

	return self.request.URL.Query().Get(name)
}

// verified reads back the handshake and checks the response against it: the
// state, and the issuer if the provider asks. A stateless flow has neither,
// which is what stateless means.
func (self *flow) verified() (Handshake, error) {
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

	return handshake, nil
}

// issuer applies RFC 9207. A provider that names itself must be the one that
// answered, and must have said so: an absent iss from a provider known to send
// one is the mix-up the extension exists to catch.
func (self *flow) issuer() error {
	expected, ok := self.provider.(Issued)
	if !ok || expected.Issuer() == "" {
		return nil
	}

	if self.query("iss") != expected.Issuer() {
		return ErrIssuerMismatch
	}

	return nil
}

// refusal reads the error the provider may have redirected back with instead of
// a code, in the shape RFC 6749 section 4.1.2.1 defines.
func (self *flow) refusal() error {
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

func (self *flow) exchange(handshake Handshake) (*oauth2.Token, error) {
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

func (self *flow) profile(token *oauth2.Token, nonce string) (*User, error) {
	ctx := self.context()
	grant := Grant{Token: token, Nonce: nonce, Client: self.config().Client(ctx, token)}

	user, err := self.provider.User(ctx, grant)
	if err != nil {
		if isIDToken(err) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}

	user.Token = token
	user.ApprovedScopes = granted(token, self.scoped())

	return user, nil
}

// authorization is everything the flow itself puts on the authorization URL,
// followed by whatever the provider and the call site added.
func (self *flow) authorization(handshake Handshake) []oauth2.AuthCodeOption {
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

// scoped is what will be asked for: the provider's own scopes until an option
// changes them.
func (self *flow) scoped() []string {
	if self.scopes != nil {
		return slices.Clone(self.scopes)
	}

	return slices.Clone(self.provider.Config().Scopes)
}

// config is the provider's, with this request's changes applied to a copy so
// one request cannot change what the next one asks for.
func (self *flow) config() *oauth2.Config {
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
func (self *flow) usesPKCE() bool {
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
func (self *flow) usesNonce() bool {
	return slices.ContainsFunc(self.scoped(), func(scope string) bool {
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
