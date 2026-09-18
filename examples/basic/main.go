// Sign in with Google on net/http.
//
//	GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... APP_KEY=anything go run ./examples/basic
//
// Then open http://localhost:8080/auth/google.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/gonstruct/sociable"
)

func main() {
	social := sociable.New(
		sociable.WithKey(os.Getenv("APP_KEY")),
		sociable.WithAPIURL("http://localhost:8080"),
		sociable.WithDriver[sociable.GoogleProvider]("google", sociable.Credentials{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  "/auth/google/callback", // resolved against APIURL
		}),
	)

	http.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		if err := social.Driver("google").Redirect(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := social.Driver("google").User(w, r)

		switch {
		case errors.Is(err, sociable.ErrAccessDenied):
			http.Error(w, "you said no", http.StatusForbidden)
			return
		case errors.Is(err, sociable.ErrInvalidState):
			http.Error(w, "start again", http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	log.Println("listening on http://localhost:8080/auth/google")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
