// A sign-in handler and its test, with Fake standing in for GitHub.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gonstruct/sociable"
)

// App is the part under test: two routes and an in-memory account store. It
// takes the manager, so tests hand in one of their own and run in parallel.
func App(social *sociable.Manager) http.Handler {
	accounts := map[string]string{} // github id -> name

	mux := http.NewServeMux()

	mux.HandleFunc("/auth/github", func(w http.ResponseWriter, r *http.Request) {
		social.Driver("github").Scopes("read:org").Redirect(w, r)
	})

	mux.HandleFunc("/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := social.Driver("github").User(w, r)
		if err != nil {
			http.Error(w, "sign-in failed", http.StatusBadRequest)
			return
		}

		accounts[user.ID] = user.Name

		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	return mux
}

func main() {
	social := sociable.New(
		sociable.WithKey(os.Getenv("APP_KEY")),
		sociable.WithDriver[sociable.GitHubProvider]("github", sociable.Credentials{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  "http://localhost:8080/auth/github/callback",
		}),
	)

	log.Fatal(http.ListenAndServe(":8080", App(social)))
}
