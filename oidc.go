package social

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrIDToken means the provider's ID token could not be verified: a bad
// signature, another issuer or audience, an expired token, or a nonce that is
// not the one this package issued. It is never wrapped as a profile failure,
// because it is the one error that must not be mistaken for one.
var ErrIDToken = errors.New("social: the id token could not be verified")

// OpenIDConnect is a provider that supports OpenID Connect discovery. Its
// endpoints and signing keys are read from the issuer, and the identity comes
// from a verified ID token rather than a profile request.
type OpenIDConnect struct {
	// Driver is the name the provider is registered and routed under.
	Driver string

	// IssuerURL is where discovery starts: IssuerURL/.well-known/openid-configuration.
	IssuerURL string

	ClientID     string
	ClientSecret string
	RedirectURL  string

	// Scopes default to openid, email and profile.
	Scopes []string

	// Extra parameters sent on every authorization request, such as
	// access_type=offline for a Google refresh token.
	Extra map[string]string

	// RequireIssuerParameter makes the iss parameter of RFC 9207 required on
	// the callback. Only turn it on for a provider that sends it.
	RequireIssuerParameter bool

	// WithoutPKCE opts out for a provider that rejects the challenge.
	WithoutPKCE bool

	// Client fetches the discovery document and the keys. nil is
	// http.DefaultClient.
	Client *http.Client

	// Profile overrides how the verified claims become a User.
	Profile func(claims map[string]any) User

	once       sync.Once
	discovered *oidc.Provider
	discovery  error
}

func (self *OpenIDConnect) Name() string { return self.Driver }

// Config is the provider's endpoints from discovery. When discovery failed the
// endpoints are empty, and Configured says so.
func (self *OpenIDConnect) Config() *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     self.ClientID,
		ClientSecret: self.ClientSecret,
		RedirectURL:  self.RedirectURL,
		Scopes:       self.scopes(),
	}
	if provider := self.provider(); provider != nil {
		config.Endpoint = provider.Endpoint()
	}

	return config
}

// Configured is true when the credentials are present and discovery
// succeeded. Discovery runs once, on first use.
func (self *OpenIDConnect) Configured() bool {
	return self.ClientID != "" && self.IssuerURL != "" && self.provider() != nil
}

func (self *OpenIDConnect) Parameters() []oauth2.AuthCodeOption {
	options := make([]oauth2.AuthCodeOption, 0, len(self.Extra))
	for key, value := range self.Extra {
		options = append(options, oauth2.SetAuthURLParam(key, value))
	}

	return options
}

func (self *OpenIDConnect) UsesPKCE() bool { return !self.WithoutPKCE }

func (self *OpenIDConnect) Issuer() string {
	if !self.RequireIssuerParameter {
		return ""
	}

	return self.IssuerURL
}

// User verifies the ID token and reads the identity from its claims. The
// token is checked for its signature against the issuer's keys, its issuer,
// its audience, its expiry, and the nonce this package sent.
func (self *OpenIDConnect) User(ctx context.Context, grant Grant) (*User, error) {
	raw, _ := grant.Token.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: the token response carried no id_token", ErrIDToken)
	}

	provider := self.provider()
	if provider == nil {
		return nil, fmt.Errorf("%w: discovery failed: %w", ErrIDToken, self.discovery)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: self.ClientID})
	token, err := verifier.Verify(oidc.ClientContext(ctx, self.httpClient()), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}
	if grant.Nonce != "" && token.Nonce != grant.Nonce {
		return nil, fmt.Errorf("%w: nonce does not match", ErrIDToken)
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	user := Claims(claims)
	if self.Profile != nil {
		user = self.Profile(claims)
	}
	if user.Raw == nil {
		user.Raw = claims
	}

	return &user, nil
}

// Claims is the standard mapping of OpenID Connect claims to a User.
func Claims(claims map[string]any) User {
	nickname := String(claims, "preferred_username")
	if nickname == "" {
		nickname = String(claims, "given_name")
	}

	return User{
		ID:            String(claims, "sub"),
		Nickname:      nickname,
		Name:          String(claims, "name"),
		Email:         String(claims, "email"),
		EmailVerified: Bool(claims, "email_verified"),
		Avatar:        String(claims, "picture"),
	}
}

func (self *OpenIDConnect) scopes() []string {
	if len(self.Scopes) > 0 {
		return self.Scopes
	}

	return []string{openIDScope, "email", "profile"}
}

func (self *OpenIDConnect) httpClient() *http.Client {
	if self.Client != nil {
		return self.Client
	}

	return http.DefaultClient
}

func (self *OpenIDConnect) provider() *oidc.Provider {
	self.once.Do(func() {
		ctx := oidc.ClientContext(context.Background(), self.httpClient())
		self.discovered, self.discovery = oidc.NewProvider(ctx, self.IssuerURL)
	})

	return self.discovered
}

func isIDToken(err error) bool {
	return errors.Is(err, ErrIDToken)
}
