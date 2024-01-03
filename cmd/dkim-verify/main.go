package main

import (
	"log"
	"os"

	"github.com/emersion/go-msgauth/dkim"
)

func main() {
	verifications, err := dkim.Verify(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range verifications {
		if v.Err == nil {
			log.Printf("Valid signature for %v (selector=%s) (algo=%s)", v.Domain, v.Selector, v.QueryResult.KeyAlgo)
		} else {
			log.Printf("Invalid signature for %v (selector=%s) (algo=%s): %v", v.Domain, v.Selector, v.QueryResult.KeyAlgo, v.Err)
		}
	}
}
