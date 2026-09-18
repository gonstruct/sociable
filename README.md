# sociable

Social sign-in on `net/http`, shaped after Laravel Socialite. You get back
who the person is and a token to use.

```go
social := sociable.New(
    sociable.WithKey(os.Getenv("APP_KEY")),
    sociable.WithAPIURL("https://api.example"),
    sociable.WithDriver[sociable.GoogleProvider]("google", sociable.Credentials{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "/auth/google/callback",
    }),
)
```

```go
http.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
    social.Driver("google").Redirect(w, r)
})

http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
    user, err := social.Driver("google").User(w, r)
    if err != nil {
        http.Error(w, "sign-in failed", http.StatusBadRequest)
        return
    }

    user.ID, user.Nickname, user.Name, user.Email, user.EmailVerified, user.Avatar
    user.Token.AccessToken, user.Token.RefreshToken, user.Token.Expiry
    user.ApprovedScopes
})
```

## Configuration

| Option | |
|---|---|
| `WithKey` | encrypts the cookie that carries the handshake between redirect and callback. Any string. |
| `WithSession` | an application's own session, instead of the cookie. `WithKey` is then not needed. |
| `WithAPIURL` | the application's own URL. A `RedirectURL` given as a path is resolved against it, and `https://` marks the cookie Secure behind a proxy. |
| `WithDriver[Provider]` | registers a provider type under a name, with its `ClientID`, `ClientSecret`, `RedirectURL` and, for a self-hosted provider, `BaseURL`. |

`APP_KEY` and `API_URL` are read from the environment when the option is not given.

## Shaping the redirect

All optional, all chainable, the same names as Socialite:

```go
social.Driver("google").
    Scopes("https://www.googleapis.com/auth/drive.readonly").              // adds to the provider's
    With(map[string]string{"access_type": "offline", "prompt": "consent"}). // extra auth URL parameters
    Redirect(w, r)

social.Driver("google").SetScopes("openid", "email").Redirect(w, r)      // replaces them
social.Driver("google").RedirectURL("https://other.example/cb").Redirect(w, r)
social.Driver("google").Stateless().Redirect(w, r)                       // no session, no state check
```

## Tokens

```go
user, err := social.Driver("google").UserFromToken(ctx, token)        // a token you already hold
token, err := social.Driver("google").RefreshToken(ctx, refreshToken) // a live one; persist what comes back
```

## Errors

```go
user, err := social.Driver("google").User(w, r)

switch {
case errors.Is(err, sociable.ErrAccessDenied):  // the person said no
case errors.Is(err, sociable.ErrInvalidState):  // not started here, already used, or tampered with
case errors.Is(err, sociable.ErrUnknownDriver): // no driver configured under that name
case errors.Is(err, sociable.ErrIDToken):       // the OpenID Connect id token did not verify
case err != nil:                                // the provider refused, the exchange or the profile failed
}
```

Every provider refusal matches `ErrAuthorization` and carries the provider's
words as an `*AuthorizationError`.

## Your own provider

A provider is its endpoints, its scopes, and how it reads the person behind
a token. The client it gets already presents the token.

```go
type Acme struct{}

func (Acme) Endpoint(c sociable.Credentials) oauth2.Endpoint {
    return oauth2.Endpoint{AuthURL: c.BaseURL + "/oauth/authorize", TokenURL: c.BaseURL + "/oauth/token"}
}

func (Acme) Scoping() sociable.Scoping {
    return sociable.Scoping{Scopes: []string{"profile", "email"}, Separator: " "}
}

func (Acme) GetUserByToken(ctx context.Context, client *http.Client, token *oauth2.Token, c sociable.Credentials) (*fastjson.Value, error) {
    response, err := client.Get(c.BaseURL + "/oauth/userinfo")
    // ... read the body, fastjson.ParseBytes
}

func (Acme) MapUserToStruct(json *fastjson.Value) (*sociable.User, error) {
    return &sociable.User{ID: string(json.GetStringBytes("sub")), Email: string(json.GetStringBytes("email"))}, nil
}
```

The provider is a zero value: what it needs to know, an issuer or a host,
comes in through `Credentials.BaseURL`.

Optional, when it applies:

```go
func (Acme) Issuer() string { return "https://acme.example" } // OpenID Connect: the id token is verified
func (Acme) UsesPKCE() bool { return false }                  // a provider that cannot do PKCE
```

Then it is configured and used like a built-in:

```go
sociable.WithDriver[Acme]("acme", sociable.Credentials{BaseURL: "https://acme.example", ...})
social.Driver("acme").Redirect(w, r)
```

## Tests

`Fake` swaps a driver for one that returns the user you give it, the way
`Socialite::fake` does. A test makes a manager of its own and hands it to
the application, so nothing needs configuring, nothing talks to a provider,
and tests run in parallel:

```go
social := sociable.New()
social.Fake("github", &sociable.User{ID: "github-123", Email: "jason@example.com"})

recorder := httptest.NewRecorder()
App(social).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil))

if recorder.Header().Get("Location") != "/dashboard" {
    t.Fatalf("landed on %s", recorder.Header().Get("Location"))
}
```

`Fake("github")` without a user makes the redirect go to a URL nobody
serves, for testing the redirect side.

## What is on by default

PKCE on every request, a nonce and a verified ID token for every OpenID
Connect provider, state compared in constant time, and a handshake that
expires after ten minutes and is spent whether the callback succeeds or
not. None of it needs mentioning at the call site.

Built on [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) for
the protocol and [go-oidc](https://github.com/coreos/go-oidc) for ID tokens.
