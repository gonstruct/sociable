package sociable

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// handshake is what the callback needs to trust what came back: the state it
// issued and the PKCE verifier whose challenge it sent.
type handshake struct {
	State     string    `json:"state"`
	Verifier  string    `json:"verifier,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

const (
	sessionKey        = "sociable"
	handshakeLifetime = 10 * time.Minute
)

// Redirect sends the browser to the provider. The state and verifier it
// sends along are kept in the session, so the callback can check what came
// back and finish the exchange.
func (self driver) Redirect(w http.ResponseWriter, r *http.Request) error {
	url, err := self.AuthURL(w, r)
	if err != nil {
		return err
	}

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// AuthURL is Redirect without the redirecting, for a handler that sends the
// browser itself. It still starts the handshake for this browser.
func (self driver) AuthURL(w http.ResponseWriter, r *http.Request) (string, error) {
	if self.name == "" {
		return "", ErrUnknownDriver
	}

	if err := self.configured(); err != nil {
		return "", err
	}

	config := self.config()
	scoping := self.provider.Scoping()

	issued := handshake{State: random(32), ExpiresAt: time.Now().Add(handshakeLifetime)}
	options := []oauth2.AuthCodeOption{}

	// PKCE is on unless the provider says it cannot, or there is no session
	// to keep the verifier in.
	if unprotected, ok := self.provider.(unprotectedProvider); !self.stateless && (!ok || unprotected.UsesPKCE()) {
		issued.Verifier = oauth2.GenerateVerifier()
		options = append(options, oauth2.S256ChallengeOption(issued.Verifier))
	}

	// An OpenID Connect request, which asking for openid makes it, carries a
	// nonce the ID token must echo.
	if slices.Contains(config.Scopes, "openid") {
		issued.Nonce = random(32)
		options = append(options, oauth2.SetAuthURLParam("nonce", issued.Nonce))
	}

	for _, key := range slices.Sorted(maps.Keys(self.params)) {
		options = append(options, oauth2.SetAuthURLParam(key, self.params[key]))
	}

	// x/oauth2 joins scopes with a space. A provider that separates them
	// otherwise gets the parameter set over it.
	if scoping.Separator != "" && scoping.Separator != " " {
		options = append(options, oauth2.SetAuthURLParam("scope", strings.Join(config.Scopes, scoping.Separator)))
	}

	if !self.stateless {
		if err := self.remember(w, r, issued); err != nil {
			return "", err
		}
	}

	return config.AuthCodeURL(issued.State, options...), nil
}

func (self driver) remember(w http.ResponseWriter, r *http.Request, issued handshake) error {
	session, err := self.session()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(issued)
	if err != nil {
		return err
	}

	return session.Put(w, r, sessionKey, string(payload))
}
