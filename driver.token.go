package sociable

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// UserFromToken asks the provider about a token the application already
// holds. Socialite's userFromToken.
func (self driver) UserFromToken(ctx context.Context, token *oauth2.Token) (*User, error) {
	if self.name == "" {
		return nil, ErrUnknownDriver
	}

	return self.userFor(ctx, token)
}

// RefreshToken trades a refresh token for a live token. Socialite's
// refreshToken. Persist what comes back: it may carry a new refresh token.
func (self driver) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if self.name == "" {
		return nil, ErrUnknownDriver
	}

	if err := self.configured(); err != nil {
		return nil, err
	}

	token, err := self.config().TokenSource(self.outbound(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}

	return token, nil
}
