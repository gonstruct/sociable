package sociable

import (
	"context"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

// SlackProvider signs in through OpenID Connect. These are Slack's Sign in
// with Slack endpoints, not the workspace-app ones in x/oauth2.
type SlackProvider struct{}

func (self SlackProvider) Endpoint(Credentials) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  "https://slack.com/openid/connect/authorize",
		TokenURL: "https://slack.com/api/openid.connect.token",
	}
}

func (self SlackProvider) Issuer() string {
	return "https://slack.com"
}

func (self SlackProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"openid", "email", "profile"},
		Separator: " ",
	}
}

func (self SlackProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	return fetch(ctx, client, "https://slack.com/api/openid.connect.userInfo", nil)
}

func (self SlackProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	return &User{
		ID:            string(json.GetStringBytes("sub")),
		Name:          string(json.GetStringBytes("name")),
		Email:         string(json.GetStringBytes("email")),
		EmailVerified: json.GetBool("email_verified"),
		Avatar:        string(json.GetStringBytes("picture")),
	}, nil
}
