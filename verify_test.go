package dkim

import (
	"reflect"
	"strings"
	"testing"
)

const verifiedMailString = `DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
Received: from client1.football.example.com  [192.0.2.1]
      by submitserver.example.com with SUBMISSION;
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.
`

var testVerification = &Verification{
	Domain:     "example.com",
	Identifier: "joe@football.example.com",
	HeaderKeys: []string{"Received", "From", "To", "Subject", "Date", "Message-ID"},
	BodyLength: -1,
}

func TestVerify(t *testing.T) {
	r := strings.NewReader(strings.Replace(verifiedMailString, "\n", "\r\n", -1))

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testVerification, v) {
		t.Errorf("Expected verification to be \n%+v\n but got \n%+v", testVerification, v)
	}
}
