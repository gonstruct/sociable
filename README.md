# vouch

Sign people in with somebody else's account. The OAuth 2.0 authorization code
flow with PKCE, on plain `net/http`, for any provider.

```go
auth, err := vouch.New(vouch.Configuration{
    Sealer: sealer,                                 // encrypts the handshake cookie; vouch.AESSealer(key) will do
    Drivers: vouch.Drivers{
        "google": google.New(google.Options{ClientID: id, ClientSecret: secret, RedirectURL: "https://app/auth/google/callback"}),
        "github": github.New(github.Options{ClientID: id, ClientSecret: secret, RedirectURL: "https://app/auth/github/callback"}),
    },
})

// The handler that starts it.
err := auth.Driver(w, r, "google").Redirect("/dashboard")

// The handler the provider sends the browser back to.
user, err := auth.Driver(w, r, "google").User()
```

`user` carries the stable `ID`, `Email` and whether the provider verified it,
`Name`, `Nickname`, `Avatar`, the provider's `Raw` profile, the `Token` and
the scopes that were actually `ApprovedScopes`. What to do with that person
is the application's business; vouch stops at the identity.

## What it does that most clients do not

- **PKCE is on** unless a provider says it cannot. OAuth 2.1 requires it of
  every client; here opting out is the decision that has to be written down.
- **A refusal is an answer.** A provider that sends `error=access_denied`
  back is `ErrAccessDenied`, so a cancelled sign-in is not reported as a
  broken one. Every refusal matches `ErrAuthorization`.
- **The issuer is checked** (RFC 9207) for a provider that names itself,
  which is what defeats a mix-up between two authorization servers.
- **State is compared in constant time**, the handshake carries its own
  expiry, is cleared by any callback whether it succeeds or not, and a nonce
  is issued whenever `openid` is asked for.
- **Granted scopes come back on the user**, because RFC 6749 lets them
  differ from the ones requested.
- **Open redirects are refused**: the path to land on after sign-in must be
  a path on this site.

## Shaping a request

```go
auth.Driver(w, r, "google").
    Scopes("https://www.googleapis.com/auth/drive.readonly").   // add to the provider's
    With(map[string]string{"login_hint": address}).              // extra authorization parameters
    Redirect("/settings/integrations")
```

`SetScopes` replaces instead of adds. `RedirectURL` overrides the callback.
`Stateless` runs a flow this server did not start, for a native app that
brings back its own code, and gives up state and PKCE with it. `UsingPKCE`
and `WithoutPKCE` override the provider for one request.

`AuthorizationURL` is `Redirect` without the redirect, when the handler
sends the browser itself. `UserFromToken` reads a profile for a token the
application already holds. `Refresh` trades a refresh token for a live one.
`RedirectTo` is the path the sign-in asked to land on, once `User` has run.

## Providers

`google` and `github` are included. Any other provider is a `vouch.OAuth2`
described by its endpoints, no code needed:

```go
"acme": func() vouch.Provider {
    return &vouch.OAuth2{
        Driver: "acme", ClientID: id, ClientSecret: secret, RedirectURL: callback,
        AuthURL: "https://acme.example/oauth/authorize",
        TokenURL: "https://acme.example/oauth/token",
        ProfileURL: "https://acme.example/api/me",
        Scopes: []string{"profile"},
        Profile: func(raw map[string]any) vouch.User {
            return vouch.User{ID: vouch.String(raw, "id"), Email: vouch.String(raw, "email")}
        },
    }
},
```

A provider with more to say implements `vouch.Provider` itself, and the
optional `Parameterised`, `Unprotected` and `Issued` interfaces.

## Errors

All typed, none to parse:

| Error | Meaning |
|---|---|
| `ErrUnknownDriver` | no provider registered under that name |
| `ErrNotConfigured` | the provider has no credentials; refuse the route rather than redirect |
| `ErrNoHandshake` | the callback was never started here, was already used, or expired |
| `ErrStateMismatch` | the state is not the one issued |
| `ErrIssuerMismatch` | another authorization server answered |
| `ErrAuthorization`, `ErrAccessDenied` | the provider refused; `*AuthorizationError` carries its words |
| `ErrExchange` | the code could not be exchanged, or the token is not usable |
| `ErrProfile` | the provider would not describe the user |

## Configuration

`Sealer` is required: it encrypts the handshake so the browser can hold it.
`AESSealer(key)` is one; an application with its own encryption hands that
over instead. `Cookie` mirrors the session cookie's attributes and defaults
to `vouch_handshake`, path `/`, `Lax`, ten minutes. `Client` is the HTTP
client used to talk to providers; give it a traced transport to see the
exchange and the profile fetch.

## Tests

The suite runs the whole flow through a fake authorization server with a
cookie-carrying client: redirect, consent, callback, code exchange with the
verifier checked, profile fetch, and the refusals and replays in between.
