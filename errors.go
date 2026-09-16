package social

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNotConfigured means the driver has no credentials. Environments
	// without them should refuse the route rather than redirect somewhere
	// half-built.
	ErrNotConfigured = errors.New("social: driver is not configured")

	// ErrNoHandshake means this callback was never started here, was already
	// used, or was started too long ago. All three are indistinguishable to the
	// caller on purpose.
	ErrNoHandshake = errors.New("social: no handshake for this callback")

	// ErrStateMismatch means the state did not match the one issued, which is
	// what RFC 6749 section 10.12 asks a client to check.
	ErrStateMismatch = errors.New("social: state does not match")

	// ErrIssuerMismatch means the authorization server that answered is not the
	// one the browser was sent to. RFC 9207 adds the iss parameter for exactly
	// this, and a client that expects it must reject a response without it.
	ErrIssuerMismatch = errors.New("social: the response came from another issuer")

	// ErrExchange means the authorization code could not be exchanged, or what
	// came back was not a token this package can use.
	ErrExchange = errors.New("social: failed to exchange the authorization code")

	// ErrProfile means the provider would not describe the user.
	ErrProfile = errors.New("social: failed to read the profile")

	// ErrUnknownDriver means no provider is registered under that name.
	ErrUnknownDriver = errors.New("social: unknown driver")

	// ErrAuthorization means the provider refused, and said so in the redirect
	// rather than by failing. Match it to catch every refusal.
	ErrAuthorization = errors.New("social: the provider refused the authorization request")

	// ErrAccessDenied is the refusal worth telling apart: the person said no,
	// or the provider decided on their behalf. It is not a fault, and a
	// sign-in page should say so differently than it says something broke.
	ErrAccessDenied = fmt.Errorf("%w: access_denied", ErrAuthorization)
)

// AuthorizationError is the provider refusing in the shape RFC 6749 section
// 4.1.2.1 requires: a code from a fixed set, and prose that may be aimed at a
// developer rather than at the person signing in.
type AuthorizationError struct {
	Code        string
	Description string
	URI         string
}

func (self *AuthorizationError) Error() string {
	message := "social: " + self.Code

	if self.Description != "" {
		message += ": " + self.Description
	}

	return message
}

// Is answers for the sentinels above, so a caller can match every refusal with
// ErrAuthorization or single out the one that is not a fault.
func (self *AuthorizationError) Is(target error) bool {
	if errors.Is(target, ErrAccessDenied) {
		return strings.EqualFold(self.Code, "access_denied")
	}

	return errors.Is(target, ErrAuthorization)
}
