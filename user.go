package sociable

import "golang.org/x/oauth2"

// User is who the provider vouches for.
type User struct {
	// ID is the provider's stable identifier for this person. Store this,
	// not the email, which can change.
	ID string

	Nickname      string
	Name          string
	Email         string
	EmailVerified bool
	Avatar        string

	// Raw is the provider's own document: the profile, or the ID token's
	// claims.
	Raw map[string]any

	// Token carries the access token, the refresh token when the provider
	// issued one, and the expiry.
	Token *oauth2.Token

	// ApprovedScopes are the scopes the provider granted, which need not be
	// the ones that were asked for.
	ApprovedScopes []string

	// State is what the call site put in with WithState.
	State map[string]string
}
