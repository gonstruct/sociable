package sociable

import (
	"context"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleProvider signs in through OpenID Connect. For a refresh token,
// redirect With(map[string]string{"access_type": "offline", "prompt": "consent"}).
type GoogleProvider struct{}

func (self GoogleProvider) Endpoint(Credentials) oauth2.Endpoint {
	return google.Endpoint
}

func (self GoogleProvider) Issuer() string {
	return "https://accounts.google.com"
}

func (self GoogleProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"openid", "profile", "email"},
		Separator: " ",
	}
}

func (self GoogleProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	return fetch(ctx, client, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
}

func (self GoogleProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	return &User{
		ID:            string(json.GetStringBytes("sub")),
		Nickname:      string(json.GetStringBytes("given_name")),
		Name:          string(json.GetStringBytes("name")),
		Email:         string(json.GetStringBytes("email")),
		EmailVerified: json.GetBool("email_verified"),
		Avatar:        string(json.GetStringBytes("picture")),
	}, nil
}
