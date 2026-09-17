package sociable

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// Session keeps the handshake between the redirect and the callback. The
// default is an encrypted cookie; an application with a session of its own
// hands that over instead.
//
// The value is the handshake as plain JSON, PKCE verifier included, so a
// Session must keep it server-side or encrypt it. It must also be bound to
// the browser that started the flow, which is what makes the state check
// mean anything.
type Session interface {
	Put(w http.ResponseWriter, r *http.Request, key, value string) error
	Pull(w http.ResponseWriter, r *http.Request, key string) (string, error)
}

// handshake is what the callback needs to trust what came back: the state it
// issued, the PKCE verifier whose challenge it sent, the nonce it asked the
// provider to echo into an ID token, and whatever the call site put in.
type handshake struct {
	State     string            `json:"state"`
	Verifier  string            `json:"verifier,omitempty"`
	Nonce     string            `json:"nonce,omitempty"`
	Custom    map[string]string `json:"custom,omitempty"`
	ExpiresAt time.Time         `json:"expiresAt"`
}

const (
	sessionKey        = "sociable"
	handshakeLifetime = 10 * time.Minute
)

// ErrSealed means a cookie that was forged, truncated or issued under another
// key. The flow treats it as no handshake.
var ErrSealed = errors.New("sociable: the cookie cannot be opened")

type cookieSession struct {
	aead   cipher.AEAD
	secure bool
}

func newCookieSession(key string, secure bool) *cookieSession {
	derived := sha256.Sum256([]byte(key))

	block, err := aes.NewCipher(derived[:])
	if err != nil {
		panic("sociable: " + err.Error())
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("sociable: " + err.Error())
	}

	return &cookieSession{aead: aead, secure: secure}
}

func (self *cookieSession) Put(w http.ResponseWriter, r *http.Request, key, value string) error {
	nonce := make([]byte, self.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	sealed := self.aead.Seal(nonce, nonce, []byte(value), nil)

	self.write(w, r, key, base64.RawURLEncoding.EncodeToString(sealed), int(handshakeLifetime.Seconds()))

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
		return "", ErrSealed
	}

	size := self.aead.NonceSize()

	plain, err := self.aead.Open(nil, data[:size], data[size:], nil)
	if err != nil {
		return "", ErrSealed
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

func random(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		// A system that cannot produce randomness must not go on issuing
		// values that are supposed to be unguessable.
		panic("sociable: " + err.Error())
	}

	return base64.RawURLEncoding.EncodeToString(buffer)
}
