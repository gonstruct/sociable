package social

import (
	"strings"

	"golang.org/x/oauth2"
)

// User is the identity a driver resolves, in the shape every driver must
// produce. It is deliberately small: the fields every provider has, plus the
// provider's own payload for everything else.
type User struct {
	ID            string
	Nickname      string
	Name          string
	Email         string
	EmailVerified bool
	Avatar        string

	// Raw is the provider's own profile, as it arrived.
	Raw any

	// Token is what the identity was read with, filled in by the flow rather
	// than by the driver. A caller that wants to keep talking to the provider,
	// or to store a refresh token, has it without running the exchange twice.
	Token *oauth2.Token

	// ApprovedScopes is what the provider actually granted, which RFC 6749
	// section 5.1 allows to differ from what was asked for. A feature that
	// depends on a scope should check here rather than assume.
	ApprovedScopes []string
}

// HasScope reports whether the provider granted a scope. It is the question
// worth asking before using one, since asking is not the same as receiving.
func (self *User) HasScope(scope string) bool {
	for _, granted := range self.ApprovedScopes {
		if strings.EqualFold(granted, scope) {
			return true
		}
	}

	return false
}
