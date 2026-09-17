package sociable

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Flow is a driver bound to one request. It is a value: every method that
// shapes it returns a changed copy, so nothing leaks into the next request.
type Flow struct {
	manager     *Manager
	name        string
	credentials Credentials
	provider    Provider
	fake        *Faked
	err         error

	scopes    []string
	redirect  string
	params    map[string]string
	state     map[string]string
	stateless bool
}

// Scopes adds to the driver's scopes.
func (self Flow) Scopes(scopes ...string) Flow {
	self.scopes = dedupe(append(self.scoped(), scopes...))

	return self
}

// SetScopes replaces the driver's scopes.
func (self Flow) SetScopes(scopes ...string) Flow {
	self.scopes = dedupe(scopes)

	return self
}

// RedirectURL overrides the callback for this request.
func (self Flow) RedirectURL(url string) Flow {
	self.redirect = url

	return self
}

// With adds parameters to the authorization URL: login_hint, prompt,
// access_type, whatever the provider understands.
func (self Flow) With(params map[string]string) Flow {
	merged := maps.Clone(self.params)
	if merged == nil {
		merged = map[string]string{}
	}

	for key, value := range params {
		if !reserved(key) {
			merged[key] = value
		}
	}

	self.params = merged

	return self
}

// WithState carries values through the flow. They come back on User.State at
// the callback, and never travel through the provider.
func (self Flow) WithState(state map[string]string) Flow {
	self.state = maps.Clone(state)

	return self
}

// Stateless skips the handshake, for a callback this server did not start.
// Nothing is kept between the two steps, so PKCE is off and WithState has
// nowhere to go.
func (self Flow) Stateless() Flow {
	self.stateless = true

	return self
}

// Redirect sends the browser to the provider.
func (self Flow) Redirect(w http.ResponseWriter, r *http.Request) error {
	if self.err != nil {
		return self.err
	}

	if self.fake != nil {
		http.Redirect(w, r, self.fakeURL(), http.StatusFound)

		return nil
	}

	if redirector, ok := self.provider.(Redirector); ok {
		handshake, err := self.begin(w, r)
		if err != nil {
			return err
		}

		return redirector.Redirect(w, r, self.callback(), handshake.State)
	}

	url, err := self.AuthURL(w, r)
	if err != nil {
		return err
	}

	http.Redirect(w, r, url, http.StatusFound)

	return nil
}

// AuthURL is Redirect without the redirecting, for a handler that sends the
// browser itself. It still starts the handshake for this browser.
func (self Flow) AuthURL(w http.ResponseWriter, r *http.Request) (string, error) {
	if self.err != nil {
		return "", self.err
	}

	if self.fake != nil {
		return self.fakeURL(), nil
	}

	config := self.config()
	if config.ClientID == "" || config.Endpoint.AuthURL == "" || config.RedirectURL == "" {
		return "", ErrNotConfigured
	}

	handshake, err := self.begin(w, r)
	if err != nil {
		return "", err
	}

	options := []oauth2.AuthCodeOption{}
	if handshake.Verifier != "" {
		options = append(options, oauth2.S256ChallengeOption(handshake.Verifier))
	}
	if handshake.Nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", handshake.Nonce))
	}
	for _, key := range slices.Sorted(maps.Keys(self.params)) {
		options = append(options, oauth2.SetAuthURLParam(key, self.params[key]))
	}

	return config.AuthCodeURL(handshake.State, options...), nil
}

// User finishes the flow at the callback and returns the person the provider
// vouches for, with their token.
func (self Flow) User(w http.ResponseWriter, r *http.Request) (*User, error) {
	if self.err != nil {
		return nil, self.err
	}

	if self.fake != nil {
		return self.faked(), nil
	}

	handshake, err := self.end(w, r)
	if err != nil {
		return nil, err
	}

	if code := r.URL.Query().Get("error"); code != "" {
		return nil, &AuthorizationError{
			Code:        code,
			Description: r.URL.Query().Get("error_description"),
			URI:         r.URL.Query().Get("error_uri"),
		}
	}

	var user *User
	if authenticator, ok := self.provider.(Authenticator); ok {
		user, err = authenticator.Callback(r)
	} else {
		user, err = self.exchange(r, handshake)
	}
	if err != nil {
		return nil, err
	}

	user.State = handshake.Custom

	return user, nil
}

// UserFromToken asks the provider about a token the application already
// holds.
func (self Flow) UserFromToken(ctx context.Context, token *oauth2.Token) (*User, error) {
	if self.err != nil {
		return nil, self.err
	}

	if self.fake != nil {
		return self.faked(), nil
	}

	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("%w: no access token", ErrExchange)
	}

	return self.userFor(self.context(ctx), self.config(), token, "")
}

// RefreshToken trades a refresh token for a live token. Persist what comes
// back: it may carry a new refresh token, and the old one may be retired.
func (self Flow) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if self.err != nil {
		return nil, self.err
	}

	if self.fake != nil {
		return self.faked().Token, nil
	}

	config := self.config()
	if config.ClientID == "" || config.Endpoint.TokenURL == "" {
		return nil, ErrNotConfigured
	}

	token, err := config.TokenSource(self.context(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	return token, nil
}

// Client is an HTTP client that presents the token to the provider's API and
// refreshes it when it can.
func (self Flow) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	if self.err != nil || self.fake != nil {
		return oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	}

	return self.config().Client(self.context(ctx), token)
}

// fakeURL records the redirect on the fake and returns a URL that goes
// nowhere, the way Socialite's fake does.
func (self Flow) fakeURL() string {
	self.fake.record(Redirect{
		Scopes:      slices.Clone(self.scopes),
		Params:      maps.Clone(self.params),
		State:       maps.Clone(self.state),
		RedirectURL: self.redirect,
	})

	return "https://sociable.fake/" + self.name + "/authorize"
}

// faked is a copy of the fake's user, State included: a test that fakes a
// driver gives the user the state the handler expects to read.
func (self Flow) faked() *User {
	user := self.fake.user

	return &user
}

func (self Flow) begin(w http.ResponseWriter, r *http.Request) (handshake, error) {
	if self.stateless {
		return handshake{}, nil
	}

	issued := handshake{
		State:     random(32),
		Custom:    self.state,
		ExpiresAt: time.Now().Add(handshakeLifetime),
	}

	if self.usesPKCE() {
		issued.Verifier = oauth2.GenerateVerifier()
	}

	if self.usesNonce() {
		issued.Nonce = random(32)
	}

	payload, err := json.Marshal(issued)
	if err != nil {
		return handshake{}, err
	}

	if err := self.manager.session.Put(w, r, sessionKey, string(payload)); err != nil {
		return handshake{}, err
	}

	return issued, nil
}

// end reads the handshake back and checks the callback against it. The
// handshake is spent whether or not the check passes, so a failed attempt
// cannot be replayed.
func (self Flow) end(w http.ResponseWriter, r *http.Request) (handshake, error) {
	if self.stateless {
		return handshake{}, nil
	}

	payload, err := self.manager.session.Pull(w, r, sessionKey)
	if err != nil || payload == "" {
		return handshake{}, ErrInvalidState
	}

	var issued handshake
	if err := json.Unmarshal([]byte(payload), &issued); err != nil {
		return handshake{}, ErrInvalidState
	}

	if issued.State == "" || time.Now().After(issued.ExpiresAt) {
		return handshake{}, ErrInvalidState
	}

	// A comparison that stops at the first wrong byte tells anyone who can
	// time it how much of a guess was right.
	if subtle.ConstantTimeCompare([]byte(issued.State), []byte(r.URL.Query().Get("state"))) != 1 {
		return handshake{}, ErrInvalidState
	}

	return issued, nil
}

func (self Flow) exchange(r *http.Request, issued handshake) (*User, error) {
	config := self.config()
	if config.ClientID == "" || config.Endpoint.TokenURL == "" || config.RedirectURL == "" {
		return nil, ErrNotConfigured
	}

	ctx := self.context(r.Context())

	options := []oauth2.AuthCodeOption{}
	if issued.Verifier != "" {
		options = append(options, oauth2.VerifierOption(issued.Verifier))
	}

	token, err := config.Exchange(ctx, r.URL.Query().Get("code"), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	if token.AccessToken == "" {
		return nil, fmt.Errorf("%w: the response carried no access token", ErrExchange)
	}

	return self.userFor(ctx, config, token, issued.Nonce)
}

func (self Flow) userFor(ctx context.Context, config *oauth2.Config, token *oauth2.Token, nonce string) (*User, error) {
	ctx = withNonce(ctx, nonce)

	// The client presents the token and refreshes it when it can.
	user, err := self.provider.User(ctx, config.Client(ctx, token), token)
	if err != nil {
		if errors.Is(err, ErrIDToken) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}

	user.Token = token
	user.ApprovedScopes = approved(token, config.Scopes)

	return user, nil
}

// config is the provider's, with this request's changes applied to a copy.
func (self Flow) config() *oauth2.Config {
	config := *self.provider.Config()
	config.RedirectURL = self.callback()

	if self.scopes != nil {
		config.Scopes = self.scopes
	}

	return &config
}

// callback is the redirect URL for this request, resolved against the
// application's URL when it is a path. A path with no URL to resolve against
// is nothing, which the flow reports as not configured.
func (self Flow) callback() string {
	redirect := self.redirect
	if redirect == "" {
		redirect = self.credentials.Redirect
	}

	if !strings.HasPrefix(redirect, "/") {
		return redirect
	}

	if self.manager.config.URL == "" {
		return ""
	}

	return strings.TrimSuffix(self.manager.config.URL, "/") + redirect
}

// context carries the configured HTTP client to the oauth2 library.
func (self Flow) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, self.manager.config.Client)
}

func (self Flow) scoped() []string {
	if self.scopes != nil || self.provider == nil {
		return slices.Clone(self.scopes)
	}

	return slices.Clone(self.provider.Config().Scopes)
}

// usesPKCE is true unless the provider says it cannot. OAuth 2.1 requires it
// of every client, so opting out is the decision that has to be written down.
func (self Flow) usesPKCE() bool {
	if self.stateless {
		return false
	}

	unprotected, ok := self.provider.(Unprotected)

	return !ok || unprotected.UsesPKCE()
}

// usesNonce is true for an OpenID Connect request, which is what asking for
// the openid scope makes it.
func (self Flow) usesNonce() bool {
	return slices.ContainsFunc(self.scoped(), func(scope string) bool {
		return strings.EqualFold(scope, "openid")
	})
}

// approved is what the provider granted. RFC 6749 section 5.1 lets that differ
// from what was asked, and says that leaving it out means the two are equal.
func approved(token *oauth2.Token, requested []string) []string {
	scope, _ := token.Extra("scope").(string)

	if fields := strings.Fields(scope); len(fields) > 0 {
		return fields
	}

	return requested
}

// reserved names the parameters the flow decides. A call site that could set
// them could disable the checks the callback depends on.
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
