package sociable

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// FacebookProvider reads the Graph API's me document, with the
// appsecret_proof Facebook asks for from server-side apps.
type FacebookProvider struct{}

func (self FacebookProvider) Endpoint(Credentials) oauth2.Endpoint {
	return endpoints.Facebook
}

func (self FacebookProvider) Scoping() Scoping {
	return Scoping{
		Scopes:    []string{"email"},
		Separator: ",",
	}
}

func (self FacebookProvider) GetUserByToken(ctx context.Context, client *http.Client, token *oauth2.Token, credentials Credentials) (*fastjson.Value, error) {
	url := "https://graph.facebook.com/v22.0/me?fields=id,name,email,picture.width(1920)"

	if credentials.ClientSecret != "" {
		mac := hmac.New(sha256.New, []byte(credentials.ClientSecret))
		mac.Write([]byte(token.AccessToken))
		url += "&appsecret_proof=" + hex.EncodeToString(mac.Sum(nil))
	}

	return fetch(ctx, client, url, nil)
}

func (self FacebookProvider) MapUserToStruct(json *fastjson.Value) (*User, error) {
	email := string(json.GetStringBytes("email"))

	return &User{
		ID:            string(json.GetStringBytes("id")),
		Name:          string(json.GetStringBytes("name")),
		Email:         email,
		EmailVerified: email != "",
		Avatar:        string(json.GetStringBytes("picture", "data", "url")),
	}, nil
}
