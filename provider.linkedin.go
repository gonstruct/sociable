package sociable

import (
	"context"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// LinkedInProvider signs in through OpenID Connect.
type LinkedInProvider struct{}

func (self LinkedInProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.LinkedIn
}

func (self LinkedInProvider) Issuer() string {
	return "https://www.linkedin.com/oauth"
}

func (self LinkedInProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"openid", "profile", "email"},
		Separator: " ",
	}
}

func (self LinkedInProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	return fetch(ctx, client, "https://api.linkedin.com/v2/userinfo", nil)
}

func (self LinkedInProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	return &User{
		ID:            string(json.GetStringBytes("sub")),
		Nickname:      string(json.GetStringBytes("given_name")),
		Name:          string(json.GetStringBytes("name")),
		Email:         string(json.GetStringBytes("email")),
		EmailVerified: json.GetBool("email_verified"),
		Avatar:        string(json.GetStringBytes("picture")),
	}, nil
}
