package sociable

import (
	"fmt"
	"slices"
	"sync"
	"testing"
)

// Faked is a faked driver: the user it answers with, and every redirect it
// was asked for, so a test can check what the handler sent the person off
// with.
type Faked struct {
	manager *Manager
	driver  string
	user    User

	mutex     sync.Mutex
	redirects []Redirect
}

// Redirect is one call to Redirect or AuthURL on a faked driver, as the
// handler shaped it.
type Redirect struct {
	Scopes      []string
	Params      map[string]string
	State       map[string]string
	RedirectURL string
}

// Restore puts the real driver back. Register it with t.Cleanup so a fake on
// the default manager does not outlive its test.
func (self *Faked) Restore() {
	self.manager.restore(self.driver, self)
}

// Redirects are the redirects so far, oldest first.
func (self *Faked) Redirects() []Redirect {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	return slices.Clone(self.redirects)
}

// AssertRedirected fails the test unless a redirect happened that every
// condition accepts.
func (self *Faked) AssertRedirected(t testing.TB, conditions ...func(Redirect) bool) {
	t.Helper()

	for _, redirect := range self.Redirects() {
		if accepted(redirect, conditions) {
			return
		}
	}

	t.Errorf("sociable: %s was not redirected to as expected; redirects: %s", self.driver, self.describe())
}

// AssertNotRedirected fails the test if a redirect happened that every
// condition accepts. With no conditions, any redirect fails it.
func (self *Faked) AssertNotRedirected(t testing.TB, conditions ...func(Redirect) bool) {
	t.Helper()

	for _, redirect := range self.Redirects() {
		if accepted(redirect, conditions) {
			t.Errorf("sociable: %s was redirected to: %+v", self.driver, redirect)

			return
		}
	}
}

// AssertRedirectedCount fails the test unless exactly count redirects
// happened.
func (self *Faked) AssertRedirectedCount(t testing.TB, count int) {
	t.Helper()

	if got := len(self.Redirects()); got != count {
		t.Errorf("sociable: %s was redirected to %d times, want %d", self.driver, got, count)
	}
}

func (self *Faked) record(redirect Redirect) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.redirects = append(self.redirects, redirect)
}

func (self *Faked) describe() string {
	redirects := self.Redirects()
	if len(redirects) == 0 {
		return "none"
	}

	return fmt.Sprintf("%+v", redirects)
}

func accepted(redirect Redirect, conditions []func(Redirect) bool) bool {
	for _, condition := range conditions {
		if !condition(redirect) {
			return false
		}
	}

	return true
}
