package social

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Sealer encrypts the handshake so it can be held by the browser between the
// redirect and the callback. The application supplies it, so choosing a cipher
// or a key store is not this package's business; AESSealer is the one to use
// when there is nothing to integrate with.
type Sealer interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// CookieOptions are the attributes the handshake cookie is written with. They
// should mirror the application's own session cookie so the two behave alike.
type CookieOptions struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
	Lifetime time.Duration
}

const (
	defaultCookieName     = "social_handshake"
	defaultCookieLifetime = 10 * time.Minute
)

func (self CookieOptions) withDefaults() CookieOptions {
	if self.Name == "" {
		self.Name = defaultCookieName
	}
	if self.Path == "" {
		self.Path = "/"
	}
	if self.SameSite == 0 {
		self.SameSite = http.SameSiteLaxMode
	}
	if self.Lifetime == 0 {
		self.Lifetime = defaultCookieLifetime
	}

	return self
}

// Handshake is what the callback needs in order to trust what came back: the
// state it issued, the verifier whose challenge it sent, and the nonce it asked
// the provider to echo into an ID token.
//
// The verifier is empty for a provider that does not do PKCE, and the nonce is
// empty unless the openid scope was asked for.
type Handshake struct {
	State        string    `json:"state"`
	CodeVerifier string    `json:"codeVerifier"`
	Nonce        string    `json:"nonce"`
	RedirectTo   string    `json:"redirectTo"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Challenge is the S256 hash of the verifier, the only transformation RFC 7636
// section 4.2 allows a client that can compute it. Only this reaches the
// provider, so an intercepted authorization code cannot be exchanged without
// the cookie.
func (self Handshake) Challenge() string {
	sum := sha256.Sum256([]byte(self.CodeVerifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (self CookieOptions) write(writer http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(writer, &http.Cookie{
		Name:     self.Name,
		Value:    value,
		Path:     self.Path,
		Domain:   self.Domain,
		MaxAge:   maxAge,
		Secure:   self.Secure,
		HttpOnly: true,
		SameSite: self.SameSite,
	})
}

// begin issues a handshake and hands it to the browser sealed. What the
// handshake contains is decided here rather than by the caller, so a flow
// cannot accidentally be started without the halves that make it safe.
func (self CookieOptions) begin(writer http.ResponseWriter, sealer Sealer, redirectTo string, pkce, nonce bool) (Handshake, error) {
	handshake := Handshake{
		State:      randomToken(32),
		RedirectTo: SafeRedirect(redirectTo),
		ExpiresAt:  time.Now().Add(self.Lifetime),
	}

	if pkce {
		handshake.CodeVerifier = randomToken(48)
	}

	if nonce {
		handshake.Nonce = randomToken(32)
	}

	payload, err := json.Marshal(handshake)
	if err != nil {
		return Handshake{}, err
	}

	sealed, err := sealer.Seal(payload)
	if err != nil {
		return Handshake{}, err
	}

	self.write(writer, sealed, int(self.Lifetime.Seconds()))

	return handshake, nil
}

// end reads and clears the handshake. It clears whether or not the value
// validates, so a failed attempt cannot be replayed, and it checks the expiry
// it carries rather than trusting the cookie's own: the browser decides when to
// stop sending a cookie, and this does not depend on that decision.
func (self CookieOptions) end(writer http.ResponseWriter, request *http.Request, sealer Sealer) (Handshake, bool) {
	defer self.write(writer, "", -1)

	cookie, err := request.Cookie(self.Name)
	if err != nil || cookie.Value == "" {
		return Handshake{}, false
	}

	payload, err := sealer.Open(cookie.Value)
	if err != nil {
		return Handshake{}, false
	}

	var handshake Handshake
	if err := json.Unmarshal(payload, &handshake); err != nil {
		return Handshake{}, false
	}

	if handshake.State == "" || time.Now().After(handshake.ExpiresAt) {
		return Handshake{}, false
	}

	return handshake, true
}

// SafeRedirect keeps only a path on this site. An absolute or protocol-relative
// URL would turn the callback into an open redirect.
func SafeRedirect(candidate string) string {
	candidate = strings.TrimSpace(candidate)

	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") {
		return ""
	}

	return candidate
}

func randomToken(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		// A system that cannot produce randomness must not carry on issuing
		// tokens that are supposed to be unguessable.
		panic("social: failed to read random bytes: " + err.Error())
	}

	return base64.RawURLEncoding.EncodeToString(buffer)
}
