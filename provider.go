package sociable

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

// Provider is what a driver is made of: the oauth2 configuration it was
// issued, and how to read the person behind a token. The flow around those two
// things is this package's.
//
// The client already presents the token, so a provider reads its profile
// with a plain Get.
type Provider interface {
	Config() *oauth2.Config
	User(ctx context.Context, client *http.Client, token *oauth2.Token) (*User, error)
}

// Factory builds a Provider from the credentials configured under its name.
type Factory func(credentials Credentials) Provider

// Redirector is a provider that sends the browser itself, for a sign-in that
// is not an authorization URL: a widget, a form. It receives the callback URL
// and the state the callback must bring back.
type Redirector interface {
	Redirect(w http.ResponseWriter, r *http.Request, callback, state string) error
}

// Authenticator is a provider that reads the person from the callback itself,
// with no code to exchange.
type Authenticator interface {
	Callback(r *http.Request) (*User, error)
}

// Unprotected is a provider that cannot do PKCE. Every provider that stays
// silent does it.
type Unprotected interface {
	UsesPKCE() bool
}

// OAuth2 is a provider described by its endpoints and a profile mapping, which
// is all most providers need.
type OAuth2 struct {
	Credentials Credentials
	Endpoint    oauth2.Endpoint

	// Scopes are the defaults, for credentials that name none.
	Scopes []string

	// ProfileURL is fetched with the token, and Map turns the document into a
	// User. Raw is filled in when Map leaves it empty, or when there is no
	// Map at all.
	ProfileURL string
	Map        func(raw map[string]any) User

	WithoutPKCE bool
}

func (self OAuth2) Config() *oauth2.Config {
	scopes := self.Credentials.Scopes
	if len(scopes) == 0 {
		scopes = self.Scopes
	}

	return &oauth2.Config{
		ClientID:     self.Credentials.ClientID,
		ClientSecret: self.Credentials.ClientSecret,
		Endpoint:     self.Endpoint,
		Scopes:       scopes,
	}
}

func (self OAuth2) UsesPKCE() bool { return !self.WithoutPKCE }

func (self OAuth2) User(ctx context.Context, client *http.Client, _ *oauth2.Token) (*User, error) {
	var raw map[string]any
	if err := GetJSON(ctx, client, self.ProfileURL, &raw); err != nil {
		return nil, err
	}

	user := User{}
	if self.Map != nil {
		user = self.Map(raw)
	}

	if user.Raw == nil {
		user.Raw = raw
	}

	return &user, nil
}

// GetJSON fetches a JSON document into any value, with a client that
// presents the token. A status other than 200 is an error.
func GetJSON(ctx context.Context, client *http.Client, url string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("get %s: %w", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("get %s: status %d", url, response.StatusCode)
	}

	if err := json.NewDecoder(response.Body).Decode(into); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}

	return nil
}

// String reads a string at a dotted path, such as "picture.data.url". A number
// is formatted, so a numeric id reads as one.
func String(raw map[string]any, path string) string {
	switch value := lookup(raw, path).(type) {
	case string:
		return value
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}

		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

// Bool reads a boolean at a dotted path.
func Bool(raw map[string]any, path string) bool {
	value, _ := lookup(raw, path).(bool)

	return value
}

func lookup(raw map[string]any, path string) any {
	var current any = raw

	for _, key := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}

		current = object[key]
	}

	return current
}
