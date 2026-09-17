// Package sociable authenticates people with Google, GitHub, GitLab, Facebook,
// LinkedIn, Bitbucket, Slack, Twitch, X, or any OAuth 2 or OpenID Connect
// provider, on net/http. It hands back who they are and a token to use.
//
//	sociable.Configure(sociable.Config{
//		Key: os.Getenv("APP_KEY"),
//		Drivers: sociable.Drivers{
//			"github": {ClientID: id, ClientSecret: secret, Redirect: "/auth/github/callback"},
//		},
//	})
//
//	sociable.Driver("github").Redirect(w, r)
//	user, err := sociable.Driver("github").User(w, r)
package sociable

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Credentials are what a provider issued the application.
type Credentials struct {
	ClientID     string
	ClientSecret string

	// Redirect is the callback URL the provider sends the browser back to. A
	// path is resolved against Config.URL.
	Redirect string

	// Scopes replace the driver's defaults.
	Scopes []string
}

// Drivers maps a driver name to its credentials. The name picks the built-in
// provider of that name, or one registered with Extend.
type Drivers map[string]Credentials

// Config is set once at boot.
type Config struct {
	// Key encrypts the cookie that carries the handshake between the redirect
	// and the callback. Any string; required unless Session is set.
	Key string

	// URL is the application's own, for resolving a relative Redirect.
	URL string

	Drivers Drivers

	// Session holds the handshake instead of the cookie, for an application
	// that has a session already.
	Session Session

	// Client talks to the providers. nil is http.DefaultClient.
	Client *http.Client
}

// ErrNoKey is returned by New when there is nowhere to keep a handshake.
var ErrNoKey = errors.New("sociable: a Key or a Session is required")

// Manager is a configured set of drivers. Configure sets up the default one;
// New makes another, for tests or a multi-tenant application.
type Manager struct {
	mutex     sync.RWMutex
	config    Config
	session   Session
	factories map[string]Factory
	providers map[string]Provider
	fakes     map[string]*Faked
}

var std = newManager()

func newManager() *Manager {
	return &Manager{factories: maps.Clone(builtin), providers: map[string]Provider{}, fakes: map[string]*Faked{}}
}

// Configure sets up the default manager. It panics on a configuration that
// cannot work, because that is a mistake at boot rather than at runtime.
func Configure(config Config) {
	if err := std.configure(config); err != nil {
		panic(err)
	}
}

// Driver picks a configured driver on the default manager.
func Driver(name string) Flow { return std.Driver(name) }

// Extend registers a provider under a name on the default manager. The factory
// receives the credentials configured under that name.
func Extend(name string, factory Factory) { std.Extend(name, factory) }

// Fake replaces a driver on the default manager with one that returns the
// given user at the callback, for tests. Nothing needs configuring, and any
// field left blank gets a test value, so Fake("github", User{}) is a whole
// person. What comes back records every redirect, for asserting on.
func Fake(name string, user User) *Faked { return std.Fake(name, user) }

// New makes a manager of its own.
func New(config Config) (*Manager, error) {
	manager := newManager()

	if err := manager.configure(config); err != nil {
		return nil, err
	}

	return manager, nil
}

func (self *Manager) configure(config Config) error {
	session := config.Session
	if session == nil {
		if config.Key == "" {
			return ErrNoKey
		}

		session = newCookieSession(config.Key, strings.HasPrefix(config.URL, "https://"))
	}

	if config.Client == nil {
		config.Client = http.DefaultClient
	}

	config.Drivers = maps.Clone(config.Drivers)
	if config.Drivers == nil {
		config.Drivers = Drivers{}
	}

	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.config = config
	self.session = session
	clear(self.providers)

	return nil
}

// Driver picks a configured driver. An unknown name is not an error here but
// on every call that follows, so a handler has one place to check.
func (self *Manager) Driver(name string) Flow {
	self.mutex.RLock()
	faked, isFake := self.fakes[name]
	credentials, configured := self.config.Drivers[name]
	factory, known := self.factories[name]
	session := self.session
	provider, built := self.providers[name]
	self.mutex.RUnlock()

	flow := Flow{manager: self, name: name}

	switch {
	case isFake:
		flow.fake = faked
	case !configured || !known:
		flow.err = fmt.Errorf("%w: %s", ErrUnknownDriver, name)
	case session == nil:
		flow.err = ErrNoKey
	default:
		if !built {
			provider = self.build(name, factory, credentials)
		}

		flow.credentials = credentials
		flow.provider = provider
	}

	return flow
}

// build makes the provider once. Two requests racing for the same driver
// both end up with the one that was cached first.
func (self *Manager) build(name string, factory Factory, credentials Credentials) Provider {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	if provider, built := self.providers[name]; built {
		return provider
	}

	provider := factory(credentials)
	self.providers[name] = provider

	return provider
}

// Extend registers a provider under a name. The factory receives the
// credentials configured under that name.
func (self *Manager) Extend(name string, factory Factory) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.factories[name] = factory
	delete(self.providers, name)
}

// Fake replaces a driver with one that returns the given user at the
// callback. The redirect goes to a URL that does not exist, and the callback
// checks nothing: a test calls it directly and gets the user.
func (self *Manager) Fake(name string, user User) *Faked {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	if self.fakes == nil {
		self.fakes = map[string]*Faked{}
	}

	faked := &Faked{manager: self, driver: name, user: fakeUser(user)}
	self.fakes[name] = faked

	return faked
}

func (self *Manager) restore(name string, faked *Faked) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	if self.fakes[name] == faked {
		delete(self.fakes, name)
	}
}

// fakeUser fills the blanks with the values Socialite's fake user has, so a
// test names only what it cares about.
func fakeUser(user User) User {
	user.ID = cmp.Or(user.ID, "123456789")
	user.Nickname = cmp.Or(user.Nickname, "testuser")
	user.Name = cmp.Or(user.Name, "Test User")
	user.Email = cmp.Or(user.Email, "test@example.com")
	user.EmailVerified = true
	user.Avatar = cmp.Or(user.Avatar, "https://example.com/avatar.jpg")

	if user.Token == nil {
		user.Token = &oauth2.Token{AccessToken: "fake-token", RefreshToken: "fake-refresh-token", Expiry: time.Now().Add(time.Hour)}
	}

	if user.Raw == nil {
		user.Raw = map[string]any{"id": user.ID, "nickname": user.Nickname, "name": user.Name, "email": user.Email}
	}

	return user
}
