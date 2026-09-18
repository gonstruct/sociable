package sociable

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// User finishes the flow at the callback and returns the person the provider
// vouches for, with their token.
func (self driver) User(w http.ResponseWriter, r *http.Request) (*User, error) {
	if self.name == "" {
		return nil, ErrUnknownDriver
	}

	token, err := self.Callback(w, r)
	if err != nil {
		return nil, err
	}

	user, err := self.userFor(r.Context(), token)
	if err != nil {
		return nil, err
	}

	user.ApprovedScopes = approved(token, self.provider.Scoping().Separator)
	return user, nil
}

// userFor is Socialite's userInstance: the raw document fetched, mapped, and
// the token attached. The client presents the token and refreshes it when
// it can.
func (self driver) userFor(ctx context.Context, token *oauth2.Token) (*User, error) {
	ctx = self.outbound(ctx)

	raw, err := self.provider.GetUserByToken(ctx, self.config().Client(ctx, token), token, self.credentials)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}

	user, err := self.provider.MapUserToStruct(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfile, err)
	}

	user.Token = token
	return user, nil
}

// callback is the first half of the callback: the handshake read back and
// checked against the query, a refusal reported, and the code exchanged for
// a token.
func (self driver) Callback(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	if err := self.configured(); err != nil {
		return nil, err
	}

	issued, err := self.recall(w, r)
	if err != nil {
		return nil, err
	}

	query := r.URL.Query()

	if code := query.Get("error"); code != "" {
		return nil, &AuthorizationError{
			Code:        code,
			Description: query.Get("error_description"),
			URI:         query.Get("error_uri"),
		}
	}

	options := []oauth2.AuthCodeOption{}
	if issued.Verifier != "" {
		options = append(options, oauth2.VerifierOption(issued.Verifier))
	}

	ctx := self.outbound(r.Context())

	token, err := self.config().Exchange(ctx, query.Get("code"), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	// An ID token comes only with an OpenID Connect request, which is what
	// asking for openid makes it.
	if issuer, ok := self.provider.(openIDProvider); ok && slices.Contains(self.scoped(), "openid") {
		if err := self.verifyIDToken(ctx, issuer.Issuer(), token, issued.Nonce); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// recall reads the handshake back and checks the callback's state against
// it. The handshake is spent whether or not the check passes, so a failed
// attempt cannot be replayed. Stateless has nothing to recall.
func (self driver) recall(w http.ResponseWriter, r *http.Request) (handshake, error) {
	if self.stateless {
		return handshake{}, nil
	}

	session, err := self.session()
	if err != nil {
		return handshake{}, err
	}

	payload, err := session.Pull(w, r, sessionKey)
	if err != nil || payload == "" {
		return handshake{}, ErrInvalidState
	}

	var issued handshake
	if err := json.Unmarshal([]byte(payload), &issued); err != nil {
		return handshake{}, ErrInvalidState
	}

	if time.Now().After(issued.ExpiresAt) {
		return handshake{}, ErrInvalidState
	}

	// A comparison that stops at the first wrong byte tells anyone who can
	// time it how much of a guess was right.
	if subtle.ConstantTimeCompare([]byte(issued.State), []byte(r.URL.Query().Get("state"))) != 1 {
		return handshake{}, ErrInvalidState
	}

	return issued, nil
}

// verifyIDToken checks the id_token that came with the access token:
// signature against the issuer's published keys, issuer, audience, expiry,
// and the nonce the redirect sent. Socialite's getUserFromJwtToken.
func (self driver) verifyIDToken(ctx context.Context, issuer string, token *oauth2.Token, nonce string) error {
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return fmt.Errorf("%w: the token response carried no id_token", ErrIDToken)
	}

	provider, err := discover(ctx, issuer)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	verified, err := provider.Verifier(&oidc.Config{ClientID: self.credentials.ClientID}).Verify(ctx, raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIDToken, err)
	}

	if nonce != "" && verified.Nonce != nonce {
		return fmt.Errorf("%w: nonce does not match", ErrIDToken)
	}

	return nil
}

// issuers caches discovery per issuer, so the keys are fetched once and not
// on every sign-in.
var issuers sync.Map

func discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if cached, ok := issuers.Load(issuer); ok {
		return cached.(*oidc.Provider), nil
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	issuers.Store(issuer, provider)
	return provider, nil
}

// approved is what the provider granted. RFC 6749 section 5.1 lets that
// differ from what was asked. Socialite's setApprovedScopes.
func approved(token *oauth2.Token, separator string) []string {
	scope, _ := token.Extra("scope").(string)
	if scope == "" {
		return nil
	}

	if separator == "" {
		separator = " "
	}

	return strings.Split(scope, separator)
}
