package sociable

import (
	"context"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// BitbucketProvider reads the user document and the primary confirmed
// address from the emails endpoint, which is the only place Bitbucket puts
// it.
type BitbucketProvider struct{}

func (self BitbucketProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.Bitbucket
}

func (self BitbucketProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"email"},
		Separator: " ",
	}
}

func (self BitbucketProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, _ Credentials) (*fastjson.Value, error) {
	profile, err := fetch(ctx, client, "https://api.bitbucket.org/2.0/user", nil)
	if err != nil {
		return nil, err
	}

	emails, err := fetch(ctx, client, "https://api.bitbucket.org/2.0/user/emails", nil)
	if err != nil {
		return nil, err
	}

	var arena fastjson.Arena

	for _, email := range emails.GetArray("values") {
		if email.GetBool("is_primary") && email.GetBool("is_confirmed") {
			profile.Set("email", arena.NewStringBytes(email.GetStringBytes("email")))

			break
		}
	}

	return profile, nil
}

func (self BitbucketProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("email"))

	return &User{
		ID:            string(json.GetStringBytes("uuid")),
		Nickname:      string(json.GetStringBytes("username")),
		Name:          string(json.GetStringBytes("display_name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("links", "avatar", "href")),
	}, nil
}
