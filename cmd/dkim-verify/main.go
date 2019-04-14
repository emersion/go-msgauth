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
			log.Printf("Valid signature for %v", v.Domain)
		} else {
			log.Printf("Invalid signature for %v: %v", v.Domain, v.Err)
		}
	}
}
