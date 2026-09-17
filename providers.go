package sociable

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// builtin are the drivers a name picks without an Extend.
var builtin = map[string]Factory{
	"google":    Google,
	"github":    GitHub,
	"gitlab":    GitLab,
	"facebook":  Facebook,
	"linkedin":  LinkedIn,
	"bitbucket": Bitbucket,
	"slack":     Slack,
	"twitch":    Twitch,
	"x":         X,
}

// Google signs in through OpenID Connect. For a refresh token, redirect with
// With(map[string]string{"access_type": "offline", "prompt": "consent"}).
func Google(credentials Credentials) Provider {
	return OpenID(credentials, "https://accounts.google.com")
}

// LinkedIn signs in through OpenID Connect.
func LinkedIn(credentials Credentials) Provider {
	return OpenID(credentials, "https://www.linkedin.com/oauth")
}

// Slack signs in through OpenID Connect.
func Slack(credentials Credentials) Provider {
	return OpenID(credentials, "https://slack.com")
}

// GitHub reads the profile and, when the profile hides the address, the
// primary verified one from the emails endpoint.
func GitHub(credentials Credentials) Provider {
	return github{OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.GitHub,
		Scopes:      []string{"read:user", "user:email"},
		ProfileURL:  "https://api.github.com/user",
		Map: func(raw map[string]any) User {
			email := String(raw, "email")

			return User{
				ID:            String(raw, "id"),
				Nickname:      String(raw, "login"),
				Name:          String(raw, "name"),
				Email:         email,
				EmailVerified: email != "",
				Avatar:        String(raw, "avatar_url"),
			}
		},
	}}
}

type github struct{ OAuth2 }

func (self github) User(ctx context.Context, client *http.Client, token *oauth2.Token) (*User, error) {
	user, err := self.OAuth2.User(ctx, client, token)
	if err != nil || user.Email != "" {
		return user, err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := GetJSON(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
		return nil, err
	}

	for _, candidate := range emails {
		if candidate.Primary {
			user.Email, user.EmailVerified = candidate.Email, candidate.Verified

			break
		}
	}

	return user, nil
}

// GitLab signs in against gitlab.com. For a self-hosted instance, Extend with
// an OAuth2 that points at it.
func GitLab(credentials Credentials) Provider {
	return OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.GitLab,
		Scopes:      []string{"read_user"},
		ProfileURL:  "https://gitlab.com/api/v4/user",
		Map: func(raw map[string]any) User {
			return User{
				ID:            String(raw, "id"),
				Nickname:      String(raw, "username"),
				Name:          String(raw, "name"),
				Email:         String(raw, "email"),
				EmailVerified: String(raw, "email") != "",
				Avatar:        String(raw, "avatar_url"),
			}
		},
	}
}

// Facebook reads the Graph API's me document.
func Facebook(credentials Credentials) Provider {
	return OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.Facebook,
		Scopes:      []string{"email"},
		ProfileURL:  "https://graph.facebook.com/v19.0/me?fields=id,name,email,picture.width(400)",
		Map: func(raw map[string]any) User {
			return User{
				ID:            String(raw, "id"),
				Name:          String(raw, "name"),
				Email:         String(raw, "email"),
				EmailVerified: String(raw, "email") != "",
				Avatar:        String(raw, "picture.data.url"),
			}
		},
	}
}

// Bitbucket reads the user document and the primary address from the emails
// endpoint, which is the only place Bitbucket puts it.
func Bitbucket(credentials Credentials) Provider {
	return bitbucket{OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.Bitbucket,
		Scopes:      []string{"email"},
		ProfileURL:  "https://api.bitbucket.org/2.0/user",
		Map: func(raw map[string]any) User {
			return User{
				ID:       String(raw, "uuid"),
				Nickname: String(raw, "username"),
				Name:     String(raw, "display_name"),
				Avatar:   String(raw, "links.avatar.href"),
			}
		},
	}}
}

type bitbucket struct{ OAuth2 }

func (self bitbucket) User(ctx context.Context, client *http.Client, token *oauth2.Token) (*User, error) {
	user, err := self.OAuth2.User(ctx, client, token)
	if err != nil {
		return nil, err
	}

	var emails struct {
		Values []map[string]any `json:"values"`
	}
	if err := GetJSON(ctx, client, "https://api.bitbucket.org/2.0/user/emails", &emails); err != nil {
		return nil, err
	}

	for _, candidate := range emails.Values {
		if Bool(candidate, "is_primary") {
			user.Email, user.EmailVerified = String(candidate, "email"), Bool(candidate, "is_confirmed")

			break
		}
	}

	return user, nil
}

// Twitch reads the Helix users document, which needs the client id on the
// request as well as the token.
func Twitch(credentials Credentials) Provider {
	return twitch{OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.Twitch,
		Scopes:      []string{"user:read:email"},
		ProfileURL:  "https://api.twitch.tv/helix/users",
	}}
}

type twitch struct{ OAuth2 }

func (self twitch) User(ctx context.Context, client *http.Client, _ *oauth2.Token) (*User, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.ProfileURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Client-Id", self.Credentials.ClientID)
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get users: status %d", response.StatusCode)
	}

	var users struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}

	if len(users.Data) == 0 {
		return nil, errors.New("twitch: empty users response")
	}

	raw := users.Data[0]

	return &User{
		ID:            String(raw, "id"),
		Nickname:      String(raw, "login"),
		Name:          String(raw, "display_name"),
		Email:         String(raw, "email"),
		EmailVerified: String(raw, "email") != "",
		Avatar:        String(raw, "profile_image_url"),
		Raw:           raw,
	}, nil
}

// X reads the users/me document. X issues no email.
func X(credentials Credentials) Provider {
	return OAuth2{
		Credentials: credentials,
		Endpoint:    endpoints.X,
		Scopes:      []string{"users.read", "tweet.read"},
		ProfileURL:  "https://api.x.com/2/users/me?user.fields=profile_image_url",
		Map: func(raw map[string]any) User {
			return User{
				ID:       String(raw, "data.id"),
				Nickname: String(raw, "data.username"),
				Name:     String(raw, "data.name"),
				Avatar:   String(raw, "data.profile_image_url"),
			}
		},
	}
}
