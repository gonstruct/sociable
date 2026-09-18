package sociable

import (
	"context"
	"errors"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// TwitchProvider reads the Helix users document, which needs the client id
// on the request as well as the token.
type TwitchProvider struct{}

func (self TwitchProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.Twitch
}

func (self TwitchProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"user:read:email"},
		Separator: " ",
	}
}

func (self TwitchProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, credentials Credentials) (*fastjson.Value, error) {
	users, err := fetch(ctx, client, "https://api.twitch.tv/helix/users", map[string]string{"Client-Id": credentials.ClientID})
	if err != nil {
		return nil, err
	}

	data := users.GetArray("data")
	if len(data) == 0 {
		return nil, errors.New("twitch: empty users response")
	}

	return data[0], nil
}

func (self TwitchProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("email"))

	return &User{
		ID:            string(json.GetStringBytes("id")),
		Nickname:      string(json.GetStringBytes("login")),
		Name:          string(json.GetStringBytes("display_name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("profile_image_url")),
	}, nil
}
