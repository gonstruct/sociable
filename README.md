# sociable

Authenticate with Google, GitHub, GitLab, Facebook, LinkedIn, Bitbucket,
Slack, Twitch, X, or any OAuth 2 or OpenID Connect provider, on `net/http`.
You get back who the person is and a token to use.

```go
sociable.Configure(sociable.Config{
    Key: os.Getenv("APP_KEY"),
    Drivers: sociable.Drivers{
        "github": {ClientID: id, ClientSecret: secret, Redirect: "/auth/github/callback"},
        "google": {ClientID: id, ClientSecret: secret, Redirect: "/auth/google/callback"},
    },
})
```

```go
http.HandleFunc("/auth/github", func(w http.ResponseWriter, r *http.Request) {
    sociable.Driver("github").Redirect(w, r)
})

http.HandleFunc("/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
    user, err := sociable.Driver("github").User(w, r)
    if err != nil {
        http.Error(w, "sign-in failed", http.StatusBadRequest)
        return
    }

    user.ID, user.Nickname, user.Name, user.Email, user.EmailVerified, user.Avatar
    user.Token.AccessToken, user.Token.RefreshToken, user.Token.Expiry
    user.ApprovedScopes
    user.Raw
})
```

## Configuration

| Field | |
|---|---|
| `Key` | encrypts the cookie that carries the handshake between redirect and callback. Any string. |
| `URL` | the application's own URL, for a `Redirect` given as a path. |
| `Drivers` | a name to its `ClientID`, `ClientSecret`, `Redirect` and optional `Scopes`. |
| `Session` | an application's own session, instead of the cookie. `Key` is then not needed. |
| `Client` | the HTTP client used to talk to providers. |

`Redirect` is a full URL, or a path resolved against `URL`.

## Shaping the redirect

All optional, all chainable:

```go
sociable.Driver("google").
    Scopes("https://www.googleapis.com/auth/drive.readonly").   // adds to the driver's
    With(map[string]string{"access_type": "offline", "prompt": "consent"}).
    Redirect(w, r)

sociable.Driver("google").SetScopes("openid", "email").Redirect(w, r)  // replaces them
sociable.Driver("github").RedirectURL("https://other.example/cb").Redirect(w, r)
```

`WithState` carries values through the flow. They come back on `user.State`
at the callback and never travel through the provider:

```go
sociable.Driver("github").WithState(map[string]string{"invite": code}).Redirect(w, r)

user, _ := sociable.Driver("github").User(w, r)
user.State["invite"]
```

`AuthURL(w, r)` is `Redirect` without the redirecting, for a handler that
sends the browser itself.

## Tokens

```go
user, err := sociable.Driver("github").UserFromToken(ctx, token)          // a token you already hold
token, err := sociable.Driver("google").RefreshToken(ctx, refreshToken)   // a live one; persist what comes back
client := sociable.Driver("google").Client(ctx, token)                    // an *http.Client that presents and refreshes it
```

`Stateless()` runs a callback this server did not start, for a native app
that brings its own code.

## Errors

```go
user, err := sociable.Driver("github").User(w, r)

switch {
case errors.Is(err, sociable.ErrAccessDenied):   // the person said no
case errors.Is(err, sociable.ErrInvalidState):   // not started here, already used, or expired
case errors.Is(err, sociable.ErrUnknownDriver):
case errors.Is(err, sociable.ErrNotConfigured):
case err != nil:                                 // the provider refused, the exchange failed, the id token did not verify
}
```

Every provider refusal matches `ErrAuthorization` and carries the provider's
words as an `*AuthorizationError`. A failed ID token is `ErrIDToken`, a
failed exchange `ErrExchange`, a profile that would not load `ErrProfile`.

## Your own provider

Any OpenID Connect provider is its issuer:

```go
sociable.Extend("okta", func(c sociable.Credentials) sociable.Provider {
    return sociable.OpenID(c, "https://acme.okta.com")
})
```

Any OAuth 2 provider is its endpoints and a mapping:

```go
sociable.Extend("acme", func(c sociable.Credentials) sociable.Provider {
    return sociable.OAuth2{
        Credentials: c,
        Endpoint:    oauth2.Endpoint{AuthURL: base + "/oauth/authorize", TokenURL: base + "/oauth/token"},
        Scopes:      []string{"profile", "email"},
        ProfileURL:  base + "/oauth/userinfo",
        Map: func(raw map[string]any) sociable.User {
            return sociable.User{ID: sociable.String(raw, "sub"), Name: sociable.String(raw, "name"), Email: sociable.String(raw, "email")}
        },
    }
})
```

Then it is configured and used like a built-in:

```go
"acme": {ClientID: id, ClientSecret: secret, Redirect: "/auth/acme/callback"},
sociable.Driver("acme").Redirect(w, r)
```

A provider with more to read than one document implements `User` itself.
It gets an `*http.Client` that already presents the token:

```go
func (self github) User(ctx context.Context, client *http.Client, token *oauth2.Token) (*sociable.User, error) {
    user, err := self.OAuth2.User(ctx, client, token)
    if err != nil || user.Email != "" {
        return user, err
    }

    var emails []email
    if err := sociable.GetJSON(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
        return nil, err
    }
    // ...
}
```

A provider that is not OAuth at all, a login widget for instance, implements
`Redirect(w, r, callback, state)` and `Callback(r)` itself and the flow gets
out of the way. The state check still runs.

## Tests

`Fake` swaps a driver for one that returns the user you give it, the way
`Socialite::fake` does. Fields you leave blank get a test person's values,
the same ones as Socialite's fake user. Nothing else needs configuring,
nothing talks to a provider, and a test drives the callback directly:

```go
fake := sociable.Fake("github", sociable.User{Email: "arjen@example.test"})
t.Cleanup(fake.Restore)

recorder := httptest.NewRecorder()
app.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil))

if recorder.Header().Get("Location") != "/dashboard" {
    t.Fatalf("landed on %s", recorder.Header().Get("Location"))
}
```

What `Fake` returns records every redirect the handler asked for, so a
test of the redirect side can check how the person was sent off:

```go
fake := sociable.Fake("google", sociable.User{})

app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/connect/drive", nil))

fake.AssertRedirected(t, func(r sociable.Redirect) bool {
    return slices.Contains(r.Scopes, "https://www.googleapis.com/auth/drive.readonly")
})
```

`AssertNotRedirected`, `AssertRedirectedCount` and `Redirects` go with it.

## What is on by default

PKCE on every request, a nonce and a verified ID token for every OpenID
Connect provider, state compared in constant time, a handshake that expires
and is spent whether the callback succeeds or not. None of it needs
mentioning at the call site.

Built on [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) for
the protocol and [go-oidc](https://github.com/coreos/go-oidc) for ID tokens.
Every request to a provider, the exchange included, goes through `Client`,
so a traced transport there traces all of it.
