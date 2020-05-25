package dkim

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

const signedEd25519MailString = "DKIM-Signature: a=ed25519-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;" + "\r\n" +
	" " + "c=simple/simple; d=football.example.com;" + "\r\n" +
	" " + "h=From:To:Subject:Date:Message-ID; s=brisbane; t=424242; v=1;" + "\r\n" +
	" " + "b=k1LzRxs9/DfN/whlMICYKNIJhqUSmup0d5yw8tpi+Cfiqe6I3oSBmJ+HEp+moWy7/XvcUY/t" + "\r\n" +
	" " + "ERHc3D2m7vw1AA==" + "\r\n" +
	mailHeaderString +
	"\r\n" +
	mailBodyString

func init() {
	randReader = rand.New(rand.NewSource(42))
}

func TestSignEd25519(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "football.example.com",
		Selector: "brisbane",
		Signer:   testEd25519PrivateKey,
	}

	var b bytes.Buffer
	if err := Sign(&b, r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}

	if s := b.String(); s != signedEd25519MailString {
		t.Errorf("Expected signed message to be \n%v\n but got \n%v", signedEd25519MailString, s)
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "football.example.com",
		Selector: "brisbane",
		Signer:   testEd25519PrivateKey,
	}

	var b bytes.Buffer
	if err := Sign(&b, r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}

	verifications, err := Verify(&b)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	}
	if len(verifications) != 1 {
		t.Error("Expected exactly one verification")
	} else {
		v := verifications[0]
		if err := v.Err; err != nil {
			t.Errorf("Expected no error when verifying signature, got: %v", err)
		}
		if v.Domain != options.Domain {
			t.Errorf("Expected domain to be %q but got %q", options.Domain, v.Domain)
		}
	}
}
