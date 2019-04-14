package authres_test

import (
	"log"

	"github.com/emersion/go-msgauth/authres"
)

func Example() {
	// Format
	results := []authres.Result{
		&authres.SPFResult{Value: authres.ResultPass, From: "example.net"},
		&authres.AuthResult{Value: authres.ResultPass, Auth: "sender@example.com"},
	}
	s := authres.Format("example.com", results)
	log.Println(s)

	// Parse
	identifier, results, err := authres.Parse(s)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(identifier, results)
}
