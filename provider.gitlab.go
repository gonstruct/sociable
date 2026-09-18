package sociable

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

// GitLabProvider signs in against gitlab.com, or a self-hosted instance
// given as BaseURL.
type GitLabProvider struct{}

func (self GitLabProvider) host(credentials Credentials) string {
	if credentials.BaseURL != "" {
		return strings.TrimSuffix(credentials.BaseURL, "/")
	}

	return "https://gitlab.com"
}

func (self GitLabProvider) Endpoint(credentials Credentials) oauth2.Endpoint {
	host := self.host(credentials)

	return oauth2.Endpoint{
		AuthURL:  host + "/oauth/authorize",
		TokenURL: host + "/oauth/token",
	}
}

func (self GitLabProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"read_user"},
		Separator: " ",
	}
}

func (self GitLabProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, credentials Credentials) (*fastjson.Value, error) {
	return fetch(ctx, client, self.host(credentials)+"/api/v4/user", nil)
}

func (self GitLabProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("email"))

	return &User{
		ID:            strconv.FormatInt(json.GetInt64("id"), 10),
		Nickname:      string(json.GetStringBytes("username")),
		Name:          string(json.GetStringBytes("name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("avatar_url")),
	}, nil
}
