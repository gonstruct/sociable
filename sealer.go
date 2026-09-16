package social

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrSealed is returned by a sealer that cannot open what it was given: a
// forged, truncated or foreign value. The flow treats it as no handshake.
var ErrSealed = errors.New("social: the sealed value cannot be opened")

type aesSealer struct {
	aead cipher.AEAD
}

// AESSealer seals with AES-GCM under a 16, 24 or 32 byte key. It is the
// sealer to use when the application has no encryption of its own to hand
// over; the key must be the same on every instance that handles a callback.
func AESSealer(key []byte) (Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("social: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("social: %w", err)
	}

	return &aesSealer{aead: aead}, nil
}

func (self *aesSealer) Seal(plain []byte) (string, error) {
	nonce := make([]byte, self.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("social: %w", err)
	}

	sealed := self.aead.Seal(nonce, nonce, plain, nil)

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (self *aesSealer) Open(sealed string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(data) < self.aead.NonceSize() {
		return nil, ErrSealed
	}

	size := self.aead.NonceSize()
	plain, err := self.aead.Open(nil, data[:size], data[size:], nil)
	if err != nil {
		return nil, ErrSealed
	}

	return plain, nil
}
