package sociable

import (
	"context"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// XProvider reads the users/me document. X issues an email only to apps
// approved for it.
type XProvider struct{}

func (self XProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.X
}

func (self XProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"users.read", "tweet.read"},
		Separator: " ",
	}
}

func (self XProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	user, err := fetch(ctx, client, "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email", nil)
	if err != nil {
		return nil, err
	}

	return user.Get("data"), nil
}

func (self XProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("confirmed_email"))

	return &User{
		ID:            string(json.GetStringBytes("id")),
		Nickname:      string(json.GetStringBytes("username")),
		Name:          string(json.GetStringBytes("name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("profile_image_url")),
	}, nil
}
