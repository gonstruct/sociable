package sociable

import (
	"crypto/rand"
	"encoding/base64"
)

// random is an unguessable string of size bytes. rand.Read cannot fail since
// Go 1.24, so there is no error to handle.
func random(size int) string {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)

	return base64.RawURLEncoding.EncodeToString(buffer)
}
