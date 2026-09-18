package sociable

import (
	"context"
	"net/http"
	"strconv"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// GitHubProvider reads the profile and, when the profile hides the address,
// the primary verified one from the emails endpoint.
type GitHubProvider struct{}

func (self GitHubProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.GitHub
}

func (self GitHubProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"read:user", "user:email"},
		Separator: " ",
	}
}

func (self GitHubProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	headers := map[string]string{"Accept": "application/vnd.github+json"}

	profile, err := fetch(ctx, client, "https://api.github.com/user", headers)
	if err != nil {
		return nil, err
	}

	if len(profile.GetStringBytes("email")) > 0 {
		return profile, nil
	}

	emails, err := fetch(ctx, client, "https://api.github.com/user/emails", headers)
	if err != nil {
		return nil, err
	}

	var arena fastjson.Arena

	for _, email := range emails.GetArray() {
		if email.GetBool("primary") && email.GetBool("verified") {
			profile.Set("email", arena.NewStringBytes(email.GetStringBytes("email")))

			break
		}
	}

	return profile, nil
}

func (self GitHubProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("email"))

	return &User{
		ID:            strconv.FormatInt(json.GetInt64("id"), 10),
		Nickname:      string(json.GetStringBytes("login")),
		Name:          string(json.GetStringBytes("name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("avatar_url")),
	}, nil
}
