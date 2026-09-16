package social

import "golang.org/x/oauth2"

// Option shapes one request. Every one is optional: the defaults are what the
// provider registered, with PKCE on.
type Option func(*flow)

// To is where the browser should land once the sign-in is complete. It must
// be a path on this site; anything else is dropped, see SafeRedirect. It
// comes back from Callback as Result.RedirectTo.
func To(path string) Option {
	return func(f *flow) { f.to = path }
}

// Scopes adds to what the provider already asks for.
func Scopes(scopes ...string) Option {
	return func(f *flow) { f.scopes = dedupe(append(f.scoped(), scopes...)) }
}

// SetScopes replaces them, for the caller who wants exactly these and no more.
func SetScopes(scopes ...string) Option {
	return func(f *flow) { f.scopes = dedupe(scopes) }
}

// With adds parameters to the authorization URL. Use it for the ones that
// belong to this request rather than to the provider, a login_hint, a prompt,
// and implement Parameterised for the ones that are always sent.
//
// The parameters the flow owns cannot be overwritten from here: state,
// code_challenge and nonce are what make the callback trustworthy, and a call
// site is not the place to decide otherwise.
func With(parameters map[string]string) Option {
	return func(f *flow) {
		for key, value := range parameters {
			if reserved(key) {
				continue
			}
			f.parameters = append(f.parameters, oauth2.SetAuthURLParam(key, value))
		}
	}
}

// RedirectURL overrides where the provider sends the browser back. It must
// still be one the provider has registered: RFC 6749 section 3.1.2.3 has the
// authorization server compare it exactly, so an unregistered value fails
// there rather than here.
func RedirectURL(url string) Option {
	return func(f *flow) { f.redirectURL = url }
}

// Stateless drops the handshake, for a flow this server did not start: a
// native app or a single-page client that runs the redirect itself and brings
// back what it got.
//
// It costs both defences at once: no state to compare, and nowhere to keep a
// verifier, so no PKCE either. Whatever uses it takes on the job of deciding
// that the callback belongs to the session it will be used for.
func Stateless() Option {
	return func(f *flow) { f.stateless = true }
}

// UsingPKCE turns PKCE on for a provider that opted out of it.
func UsingPKCE() Option {
	enabled := true

	return func(f *flow) { f.pkce = &enabled }
}

// WithoutPKCE turns it off for one request. Prefer implementing Unprotected: a
// provider that cannot do PKCE cannot do it on any request, and that belongs
// with the provider rather than at one call site.
func WithoutPKCE() Option {
	disabled := false

	return func(f *flow) { f.pkce = &disabled }
}
