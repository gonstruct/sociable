package sociable

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OpenID is a provider for any OpenID Connect issuer. Endpoints and signing
// keys come from discovery, and the identity from an ID token verified for its
// signature, issuer, audience, expiry and nonce.
//
//	sociable.Extend("okta", func(c sociable.Credentials) sociable.Provider {
//		return sociable.OpenID(c, "https://acme.okta.com")
//	})
func OpenID(credentials Credentials, issuer string) Provider {
	return &openID{credentials: credentials, issuer: issuer}
}

type openID struct {
	credentials Credentials
	issuer      string

	once       sync.Once
	discovered *oidc.Provider
	discovery  error
}

// Config is the endpoints from discovery. When discovery failed the endpoints
// are empty, and the flow reports the driver as not configured.
func (self *openID) Config() *oauth2.Config {
	scopes := self.credentials.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	config := &oauth2.Config{
		ClientID:     self.credentials.ClientID,
		ClientSecret: self.credentials.ClientSecret,
		Scopes:       scopes,
	}

	if provider := self.provider(); provider != nil {
		config.Endpoint = provider.Endpoint()
	}

	return config
}

func (self *openID) User(ctx context.Context, _ *http.Client, token *oauth2.Token) (*User, error) {
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: the token response carried no id_token", ErrIDToken)
	}

	provider := self.provider()
	if provider == nil {
		return nil, fmt.Errorf("%w: discovery failed: %w", ErrIDToken, self.discovery)
	}

	verified, err := provider.Verifier(&oidc.Config{ClientID: self.credentials.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	if nonce := nonceFrom(ctx); nonce != "" && verified.Nonce != nonce {
		return nil, fmt.Errorf("%w: nonce does not match", ErrIDToken)
	}

	var claims map[string]any
	if err := verified.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	user := Claims(claims)

	return &user, nil
}

func (self *openID) provider() *oidc.Provider {
	self.once.Do(func() {
		self.discovered, self.discovery = oidc.NewProvider(context.Background(), self.issuer)
	})

	return self.discovered
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
		Raw:           claims,
	}
}

type nonceKey struct{}

func withNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceKey{}, nonce)
}

func nonceFrom(ctx context.Context) string {
	nonce, _ := ctx.Value(nonceKey{}).(string)

	return nonce
}
