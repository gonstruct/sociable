package sociable

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// Session keeps the handshake between the redirect and the callback, the way
// Socialite keeps it in Laravel's session. The default is an encrypted
// cookie; an application with a session of its own hands that over with
// WithSession.
//
// The value holds the PKCE verifier, so a Session must keep it server-side
// or encrypted, and bound to the browser that started the flow.
type Session interface {
	Put(w http.ResponseWriter, r *http.Request, key, value string) error
	Pull(w http.ResponseWriter, r *http.Request, key string) (string, error)
}

// cookieSession is the default Session: one cookie per key, AES-GCM under a
// key derived from Config.Key.
type cookieSession struct {
	aead   cipher.AEAD
	secure bool
}

func newCookieSession(key string, secure bool) (*cookieSession, error) {
	if key == "" {
		return nil, ErrMissingKeyOrSession
	}

	derived := sha256.Sum256([]byte(key))

	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &cookieSession{aead: aead, secure: secure}, nil
}

func (self *cookieSession) Put(w http.ResponseWriter, r *http.Request, key, value string) error {
	nonce := make([]byte, self.aead.NonceSize())
	_, _ = rand.Read(nonce) // cannot fail since Go 1.24

	sealed := self.aead.Seal(nonce, nonce, []byte(value), nil)

	self.write(w, r, key, base64.RawURLEncoding.EncodeToString(sealed), 600)

	return nil
}

// Pull reads and clears the cookie. It clears whether or not the value opens,
// so a failed attempt cannot be replayed.
func (self *cookieSession) Pull(w http.ResponseWriter, r *http.Request, key string) (string, error) {
	defer self.write(w, r, key, "", -1)

	cookie, err := r.Cookie(key)
	if err != nil {
		return "", err
	}

	data, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(data) < self.aead.NonceSize() {
		return "", ErrSessionSealed
	}

	size := self.aead.NonceSize()

	plain, err := self.aead.Open(nil, data[:size], data[size:], nil)
	if err != nil {
		return "", ErrSessionSealed
	}

	return string(plain), nil
}

func (self *cookieSession) write(w http.ResponseWriter, r *http.Request, key, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     key,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   self.secure || r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
