package sociable

import (
	"net/http"
	"os"
)

type config struct {
	Key string

	// APIURL is the application's own URL, where the callback routes live.
	// A RedirectURL given as a path is resolved against it, and it decides
	// whether the handshake cookie is marked Secure.
	APIURL string

	// Session holds the handshake. nil is a cookie encrypted under Key.
	Session Session

	// Client talks to the providers: the exchange, the refresh, the profile
	// and discovery all go through it. nil is http.DefaultClient.
	Client *http.Client

	Drivers map[string]DriverContract
}

func configure() config {
	return config{
		Key:     os.Getenv("APP_KEY"),
		APIURL:  os.Getenv("API_URL"),
		Drivers: map[string]DriverContract{},
	}
}

type option func(*Manager)

func WithKey(key string) option {
	return func(m *Manager) {
		m.config.Key = key
	}
}

func WithSession(session Session) option {
	return func(m *Manager) {
		m.config.Session = session
	}
}

// WithClient sets the HTTP client every call to a provider goes through, so
// a traced or timed-out transport there covers all of them.
func WithClient(client *http.Client) option {
	return func(m *Manager) {
		m.config.Client = client
	}
}

func WithAPIURL(url string) option {
	return func(m *Manager) {
		m.config.APIURL = url
	}
}

// WithDriver registers a provider type under a name.
func WithDriver[T Provider](name string, credentials Credentials) option {
	return func(m *Manager) {
		var provider T

		m.config.Drivers[name] = driver{
			manager:     m,
			name:        name,
			provider:    provider,
			credentials: credentials,
		}
	}
}
