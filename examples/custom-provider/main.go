// A provider of your own: any OpenID Connect issuer, given as BaseURL.
//
// A provider is its endpoints, its scopes, how it fetches the person's
// document, and how it maps it. Declaring Issuer makes the flow verify the
// ID token. The provider is a zero value, so the issuer comes in through
// the credentials.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gonstruct/sociable"
	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

type OktaProvider struct{}

func (OktaProvider) Endpoint(c sociable.Credentials) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  c.BaseURL + "/oauth2/v1/authorize",
		TokenURL: c.BaseURL + "/oauth2/v1/token",
	}
}

func (OktaProvider) Issuer() string { return "https://acme.okta.com" }

func (OktaProvider) Scoping() sociable.Scoping {
	return sociable.Scoping{Scopes: []string{"openid", "profile", "email"}, Separator: " "}
}

func (OktaProvider) GetUserByToken(ctx context.Context, client *http.Client, _ *oauth2.Token, c sociable.Credentials) (*fastjson.Value, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/oauth2/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request) // the client already presents the token
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return fastjson.ParseBytes(body)
}

func (OktaProvider) MapUserToStruct(json *fastjson.Value) (*sociable.User, error) {
	return &sociable.User{
		ID:            string(json.GetStringBytes("sub")),
		Nickname:      string(json.GetStringBytes("preferred_username")),
		Name:          string(json.GetStringBytes("name")),
		Email:         string(json.GetStringBytes("email")),
		EmailVerified: json.GetBool("email_verified"),
	}, nil
}

func main() {
	social := sociable.New(
		sociable.WithKey(os.Getenv("APP_KEY")),
		sociable.WithDriver[OktaProvider]("okta", sociable.Credentials{
			ClientID:     os.Getenv("OKTA_CLIENT_ID"),
			ClientSecret: os.Getenv("OKTA_CLIENT_SECRET"),
			BaseURL:      "https://acme.okta.com",
			RedirectURL:  "http://localhost:8080/auth/okta/callback",
		}),
	)

	http.HandleFunc("/auth/okta", func(w http.ResponseWriter, r *http.Request) {
		social.Driver("okta").Redirect(w, r)
	})

	http.HandleFunc("/auth/okta/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := social.Driver("okta").User(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write([]byte("hello " + user.Name))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
