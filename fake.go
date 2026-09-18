package sociable

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// fakeDriver is what Fake swaps in: Socialite's FakeProvider. It answers
// Redirect and User itself and hands everything else to the driver it
// replaced.
type fakeDriver struct {
	name string
	user *User

	// driver is the one this fake replaced. An unknown name wraps an empty
	// driver, so a test needs no credentials.
	driver DriverContract
}

// Redirect is a 302 to a URL nobody serves. No session, no state, no PKCE.
func (self fakeDriver) Redirect(w http.ResponseWriter, r *http.Request) error {
	http.Redirect(w, r, "https://sociable.fake/"+self.name+"/authorize", http.StatusFound)
	return nil
}

// User is the user Fake was given. Nothing on the request is read.
func (self fakeDriver) User(w http.ResponseWriter, r *http.Request) (*User, error) {
	if self.user != nil {
		return self.user, nil
	}

	return self.driver.User(w, r)
}

func (self fakeDriver) Callback(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	return self.driver.Callback(w, r)
}

func (self fakeDriver) UserFromToken(ctx context.Context, token *oauth2.Token) (*User, error) {
	return self.driver.UserFromToken(ctx, token)
}

func (self fakeDriver) RefreshToken(ctx context.Context, refresh string) (*oauth2.Token, error) {
	return self.driver.RefreshToken(ctx, refresh)
}

// The chain returns the fake itself, so Driver("x").Scopes(...).Redirect(...)
// stays faked.
func (self fakeDriver) Scopes(...string) DriverContract       { return self }
func (self fakeDriver) SetScopes(...string) DriverContract    { return self }
func (self fakeDriver) With(map[string]string) DriverContract { return self }
func (self fakeDriver) RedirectURL(string) DriverContract     { return self }
func (self fakeDriver) Stateless() DriverContract             { return self }
