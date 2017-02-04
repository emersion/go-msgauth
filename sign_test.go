package dkim

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"time"
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

const signedMailString = mailHeaderString +
	"DKIM-Signature: a=rsa-sha256; " +
	"b=a+c/h2CohBY0lCVAchFpxkvBtayibWV7YyqrYDHh4FnwtvEBAiBY1A5tBx8VYytQZs6rxCODzEOjq64+lCHD8+pSfOcbPbNYzluTbyWV88vRV6VQG6p1eDvTdB1Lug5SNAbF+HfCEE25niBGQLF/YteoYRfK1bVnI/4EtYF1/EI=; " +
	"bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; " +
	"c=simple/simple; d=example.org; h=From:To:Subject:Date:Message-ID; s=; t=424242; v=1;\r\n" +
	"\r\n" +
	mailBodyString

func init() {
	randReader = rand.New(rand.NewSource(42))
	now = func() time.Time {
		return time.Unix(424242, 0)
	}
}

func TestSign(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain: "example.org",
		Signer: testPrivateKey,
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
		Domain: "example.org",
		Signer: testPrivateKey,
	}

	var b bytes.Buffer
	if err := Sign(&b, r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}

	if err := Verify(&b); err != nil {
		t.Errorf("Expected no error while verifying signature, got: %v", err)
	}
}
