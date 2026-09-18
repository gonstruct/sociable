package sociable

import (
	"errors"
	"fmt"
)

var (
	ErrUnknownDriver = errors.New("sociable: unknown driver")

	// ErrDriverNotConfigured means the driver has no client id, no endpoints
	// or no redirect URL. Refuse the route rather than redirect.
	ErrDriverNotConfigured = errors.New("sociable: driver not configured")

	ErrMissingKeyOrSession = errors.New("sociable: a Key or a Session is required")
	ErrSessionSealed       = errors.New("sociable: the cookie cannot be opened")
)

var (
	// ErrInvalidState means the callback was not started here, was already
	// used, or came back with another state.
	ErrInvalidState = errors.New("sociable: invalid state")

	// ErrAuthorization is what every provider refusal matches.
	ErrAuthorization = errors.New("sociable: the provider refused")

	// ErrAccessDenied is the refusal that means the person said no.
	ErrAccessDenied = fmt.Errorf("%w: access denied", ErrAuthorization)

	// ErrExchange means the code could not be exchanged for a token.
	ErrExchange = errors.New("sociable: token exchange failed")

	// ErrProfile means the provider would not describe the person.
	ErrProfile = errors.New("sociable: could not read the profile")

	// ErrIDToken means the ID token failed verification: signature, issuer,
	// audience, expiry or nonce.
	ErrIDToken = errors.New("sociable: the id token could not be verified")
)

// AuthorizationError is a refusal the provider sent back on the redirect, in
// the shape RFC 6749 section 4.1.2.1 defines.
type AuthorizationError struct {
	Code        string
	Description string
	URI         string
}

func (self *AuthorizationError) Error() string {
	if self.Description == "" {
		return "sociable: the provider refused: " + self.Code
	}

	return "sociable: the provider refused: " + self.Code + ": " + self.Description
}

// Is makes every refusal match ErrAuthorization, and access_denied match
// ErrAccessDenied as well.
func (self *AuthorizationError) Is(target error) bool {
	if target == ErrAccessDenied {
		return self.Code == "access_denied"
	}

	return target == ErrAuthorization
}
