package dkim

import (
	"bytes"
	"crypto"
	"math/rand"
	"strings"
	"testing"
)

const mailHeaderString = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"

const mailBodyString = "Hi.\r\n" +
	"\r\n" +
	"We lost the game. Are you hungry yet?\r\n" +
	"\r\n" +
	"Joe."

const mailString = mailHeaderString + "\r\n" + mailBodyString

const signedMailString = "DKIM-Signature: a=rsa-sha256;" + "\r\n" +
	" " + "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; c=simple/simple;" + "\r\n" +
	" " + "d=example.org; h=From:To:Subject:Date:Message-ID; s=brisbane; t=424242;" + "\r\n" +
	" " + "v=1;" + "\r\n" +
	" " + "b=KXuOIdcHesiuc+CNVJC0ooTO9LvodnM01dstXNTA7elICw7r9LKD5zrPnGwtP5Ye+sOndhJO" + "\r\n" +
	" " + "23pJIY3LP5oXzCnV3nkZiEwIb0rKIgYxgxx8JfCWbZgurhN35rQjnwCtmcGvN1aJ7ba1x1x63Vf" + "\r\n" +
	" " + "xp0zwssLR2w8R+PkR4r1ROlM=" + "\r\n" +
	mailHeaderString +
	"\r\n" +
	mailBodyString

func init() {
	randReader = rand.New(rand.NewSource(42))
}

func TestSign(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	}

	var b bytes.Buffer
	if err := Sign(&b, r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}

	if s := b.String(); s != signedMailString {
		t.Errorf("Expected signed message to be \n%v\n but got \n%v", signedMailString, s)
	}
}

func TestSignAndVerify(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
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

func TestSignAndVerify_relaxed(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:                 "example.org",
		Selector:               "brisbane",
		Signer:                 testPrivateKey,
		HeaderCanonicalization: "relaxed",
		BodyCanonicalization:   "relaxed",
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
	}
}

func TestSign_invalidOptions(t *testing.T) {
	r := strings.NewReader(mailString)
	var b bytes.Buffer

	if err := Sign(&b, r, nil); err == nil {
		t.Error("Expected an error when signing a message without options")
	}

	options := &SignOptions{}
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message without domain")
	}
	options.Domain = "example.org"

	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message without selector")
	}
	options.Selector = "brisbane"

	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message without signer")
	}
	options.Signer = testPrivateKey

	options.HeaderCanonicalization = "pasta"
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message with an invalid header canonicalization")
	}
	options.HeaderCanonicalization = ""

	options.BodyCanonicalization = "potatoe"
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message with an invalid body canonicalization")
	}
	options.BodyCanonicalization = ""

	options.BodyCanonicalization = "potatoe"
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message with an invalid body canonicalization")
	}
	options.BodyCanonicalization = ""

	options.Hash = ^crypto.Hash(0)
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message with an invalid hash algorithm")
	}
	options.Hash = 0

	options.HeaderKeys = []string{"To"}
	if err := Sign(&b, r, options); err == nil {
		t.Error("Expected an error when signing a message without the From header")
	}
	options.HeaderKeys = nil
}
