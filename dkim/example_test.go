package dkim_test

import (
	"bytes"
	"crypto"
	"log"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

var (
	mailString string
	privateKey crypto.Signer
)

func ExampleSign() {
	r := strings.NewReader(mailString)

	options := &dkim.SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   privateKey,
	}

	var b bytes.Buffer
	if err := dkim.Sign(&b, r, options); err != nil {
		log.Fatal(err)
	}
}

func ExampleVerify() {
	r := strings.NewReader(mailString)

	verifications, err := dkim.Verify(r)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range verifications {
		if v.Err == nil {
			log.Println("Valid signature for:", v.Domain)
		} else {
			log.Println("Invalid signature for:", v.Domain, v.Err)
		}
	}
}
