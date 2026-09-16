// Package github signs people in with GitHub.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gonstruct/vouch"
)

// Name is what the provider is registered and routed under.
const Name = "github"

// Options are the application's credentials. Scopes default to read:user and
// user:email, which is what it takes to learn who somebody is.
type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type provider struct {
	*vouch.OAuth2

	emailsURL string
}

// New is a constructor for a vouch.Drivers entry.
func New(options Options) func() vouch.Provider {
	return func() vouch.Provider {
		scopes := options.Scopes
		if len(scopes) == 0 {
			scopes = []string{"read:user", "user:email"}
		}

		return &provider{emailsURL: "https://api.github.com/user/emails", OAuth2: &vouch.OAuth2{
			Driver:       Name,
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			RedirectURL:  options.RedirectURL,
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			ProfileURL:   "https://api.github.com/user",
			Scopes:       scopes,
		}}
	}
}

// User reads the profile and, when the profile hides the address, the
// primary verified one from the emails endpoint.
func (self *provider) User(ctx context.Context, grant vouch.Grant) (*vouch.User, error) {
	raw, err := vouch.FetchJSON(grant, self.ProfileURL)
	if err != nil {
		return nil, err
	}

	user := Profile(raw)
	user.Raw = raw

	if user.Email == "" {
		email, verified, err := primaryEmail(grant, self.emailsURL)
		if err != nil {
			return nil, err
		}
		user.Email, user.EmailVerified = email, verified
	}

	return &user, nil
}

// Profile maps the user document. The numeric id is the stable identifier;
// the login is the nickname. An address on the profile is one GitHub shows
// publicly, which it only does once it is verified.
func Profile(raw map[string]any) vouch.User {
	id := ""
	if number, ok := raw["id"].(float64); ok {
		id = strconv.FormatInt(int64(number), 10)
	}

	email := vouch.String(raw, "email")

	return vouch.User{
		ID:            id,
		Nickname:      vouch.String(raw, "login"),
		Name:          vouch.String(raw, "name"),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        vouch.String(raw, "avatar_url"),
	}
}

type email struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func primaryEmail(grant vouch.Grant, url string) (string, bool, error) {
	response, err := grant.Client.Get(url)
	if err != nil {
		return "", false, fmt.Errorf("get emails: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("get emails: status %d", response.StatusCode)
	}

	var emails []email
	if err := json.NewDecoder(response.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("decode emails: %w", err)
	}

	for _, candidate := range emails {
		if candidate.Primary {
			return candidate.Email, candidate.Verified, nil
		}
	}

	return "", false, nil
}
