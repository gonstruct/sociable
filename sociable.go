package sociable

import "sync"

// Credentials are what a provider issued the application.
type Credentials struct {
	ClientID     string
	ClientSecret string

	// BaseURL is the provider's, for one that is self-hosted or an OpenID
	// Connect issuer. A built-in provider has its own default.
	BaseURL     string
	RedirectURL string
}

// Manager is a configured set of drivers, Socialite's SocialiteManager. An
// application makes one with New at boot and hands it to its handlers; a
// test makes its own and fakes on it, so tests share nothing and run in
// parallel.
type Manager struct {
	mutex  sync.RWMutex
	config config
}

// New makes a manager of its own.
func New(options ...option) *Manager {
	manager := &Manager{}
	manager.Configure(options...)

	return manager
}

// Configure sets the manager up from scratch: the environment first, then
// the options over it.
func (self *Manager) Configure(options ...option) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.config = configure()

	for _, option := range options {
		option(self)
	}
}

// Driver picks a configured driver by name.
func (self *Manager) Driver(name string) DriverContract {
	self.mutex.RLock()
	defer self.mutex.RUnlock()

	if d, ok := self.config.Drivers[name]; ok {
		return d
	}

	return driver{}
}

// Fake swaps the driver for one that redirects to a URL nobody serves and
// answers the callback with user, the way Socialite::fake does. Without a
// user, User falls through to the real driver.
func (self *Manager) Fake(name string, user ...*User) {
	fake := &fakeDriver{name: name, driver: self.Driver(name)}

	if len(user) > 0 {
		fake.user = user[0]
	}

	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.config.Drivers[name] = fake
}
