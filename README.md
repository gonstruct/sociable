# social

Sign people in with somebody else's account. The OAuth 2.0 authorization code
flow with PKCE, and OpenID Connect on top of it, on plain `net/http`, for any
provider.

```go
auth, err := social.New(social.Configuration{
    Sealer: sealer,   // encrypts the handshake cookie; social.AESSealer(key) will do
    Drivers: social.Drivers{
        "google": google.New(google.Options{ClientID: id, ClientSecret: secret, RedirectURL: "https://app/auth/google/callback"}),
        "github": github.New(github.Options{ClientID: id, ClientSecret: secret, RedirectURL: "https://app/auth/github/callback"}),
    },
})

// The handler that starts it.
err := auth.Redirect(w, r, "google", social.To("/dashboard"))

// The handler the provider sends the browser back to.
result, err := auth.Callback(w, r, "google")
// result.User, result.RedirectTo
```

`result.User` carries the stable `ID`, `Email` and whether the provider
verified it, `Name`, `Nickname`, `Avatar`, the provider's `Raw` claims or
profile, the `Token`, and the scopes that were actually `ApprovedScopes`.
What to do with that person is the application's business; social stops at
the identity.

## What it does that most clients do not

- **PKCE is on** unless a provider says it cannot. OAuth 2.1 requires it of
  every client; here opting out is the decision that has to be written down.
- **ID tokens are verified.** An OpenID Connect provider's token is checked
  for its signature against the issuer's published keys, its issuer, its
  audience, its expiry and the nonce this package sent. The identity comes
  from those claims, with no profile request.
- **A refusal is an answer.** A provider that sends `error=access_denied`
  back is `ErrAccessDenied`, so a cancelled sign-in is not reported as a
  broken one. Every refusal matches `ErrAuthorization`.
- **The issuer parameter is checked** (RFC 9207) for a provider that asks
  for it, which is what defeats a mix-up between two authorization servers.
- **State is compared in constant time**, the handshake carries its own
  expiry, and any callback spends it whether it succeeds or not.
- **Granted scopes come back on the user**, because RFC 6749 lets them
  differ from the ones requested.
- **Open redirects are refused**: the path to land on after sign-in must be
  a path on this site.

## Shaping a request

Options trail the call and most calls have none:

```go
auth.Redirect(w, r, "google",
    social.To("/settings/integrations"),                               // where to land afterwards
    social.Scopes("https://www.googleapis.com/auth/drive.readonly"),  // add to the provider's
    social.With(map[string]string{"login_hint": address}),            // extra authorization parameters
)
```

`SetScopes` replaces instead of adds. `RedirectURL` overrides the callback.
`Stateless` runs a flow this server did not start, for a native app that
brings back its own code, and gives up state and PKCE with it. `UsingPKCE`
and `WithoutPKCE` override the provider for one request.

`AuthorizationURL` is `Redirect` without the redirect, when the handler
sends the browser itself. `UserFromToken` reads an identity for a token the
application already holds. `Refresh` trades a refresh token for a live one.

## Providers

`google` (OpenID Connect through discovery) and `github` are included. Any
OpenID Connect provider is a `social.OpenIDConnect` with an issuer, and
endpoints and keys come from discovery:

```go
"okta": &social.OpenIDConnect{Driver: "okta", IssuerURL: "https://acme.okta.com", ClientID: id, ClientSecret: secret, RedirectURL: callback},
```

Any plain OAuth 2 provider is a `social.OAuth2` described by its endpoints:

```go
"acme": &social.OAuth2{
    Driver: "acme", ClientID: id, ClientSecret: secret, RedirectURL: callback,
    AuthURL:    "https://acme.example/oauth/authorize",
    TokenURL:   "https://acme.example/oauth/token",
    ProfileURL: "https://acme.example/api/me",
    Scopes:     []string{"profile"},
    Profile: func(raw map[string]any) social.User {
        return social.User{ID: social.String(raw, "id"), Email: social.String(raw, "email")}
    },
},
```

A provider with more to say implements `social.Provider` itself, and the
optional `Parameterised`, `Unprotected` and `Issued` interfaces.

## Errors

All typed, none to parse:

| Error | Meaning |
|---|---|
| `ErrUnknownDriver` | no provider registered under that name |
| `ErrNotConfigured` | the provider has no credentials, or discovery failed; refuse the route rather than redirect |
| `ErrNoHandshake` | the callback was never started here, was already used, or expired |
| `ErrStateMismatch` | the state is not the one issued |
| `ErrIssuerMismatch` | another authorization server answered |
| `ErrAuthorization`, `ErrAccessDenied` | the provider refused; `*AuthorizationError` carries its words |
| `ErrExchange` | the code could not be exchanged, or the token is not usable |
| `ErrIDToken` | the ID token failed verification: signature, issuer, audience, expiry or nonce |
| `ErrProfile` | the provider would not describe the user |

## Configuration

`Sealer` is required: it encrypts the handshake so the browser can hold it.
`AESSealer(key)` is one; an application with its own encryption hands that
over instead. `Cookie` mirrors the session cookie's attributes and defaults
to `social_handshake`, path `/`, `Lax`, ten minutes. `Client` is the HTTP
client used to talk to providers: discovery, keys, the exchange and the
profile; give it a traced transport to see them.

One handshake lives in the browser at a time, so two sign-ins started in two
tabs resolve the later one. That is the cost of a cookie handshake and the
reason it needs no server-side store.

## Tests

The suite runs the whole flow through fake providers with a cookie-carrying
client: redirect, consent, callback, the code exchange with the verifier
checked, the profile fetch or the ID token verified, and the refusals,
replays, wrong audiences, wrong issuers and wrong nonces in between.
