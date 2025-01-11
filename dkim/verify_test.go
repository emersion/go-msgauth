package dkim

import (
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newMailStringReader(s string) io.Reader {
	return strings.NewReader(strings.Replace(s, "\n", "\r\n", -1))
}

const unsignedMailString = `From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.
`

func TestVerify_unsigned(t *testing.T) {
	r := newMailStringReader(unsignedMailString)

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 0 {
		t.Fatalf("Expected exactly zero verification, got %v", len(verifications))
	}
}

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
}

func TestVerify(t *testing.T) {
	r := newMailStringReader(verifiedMailString)

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

func TestVerifyWithOption(t *testing.T) {
	r := newMailStringReader(verifiedMailString)
	option := VerifyOptions{}
	verifications, err := VerifyWithOptions(r, &option)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testVerification, v) {
		t.Errorf("Expected verification to be \n%+v\n but got \n%+v", testVerification, v)
	}

	r = newMailStringReader(verifiedMailString)
	option = VerifyOptions{LookupTXT: net.LookupTXT}
	verifications, err = VerifyWithOptions(r, &option)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}

	v = verifications[0]
	if !reflect.DeepEqual(testVerification, v) {
		t.Errorf("Expected verification to be \n%+v\n but got \n%+v", testVerification, v)
	}
}

const verifiedRawRSAMailString = `DKIM-Signature: a=rsa-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 c=simple/simple; d=example.com;
 h=Received:From:To:Subject:Date:Message-ID; i=joe@football.example.com;
 s=newengland; t=1615825284; v=1;
 b=Xh4Ujb2wv5x54gXtulCiy4C0e+plRm6pZ4owF+kICpYzs/8WkTVIDBrzhJP0DAYCpnL62T0G
 k+0OH8pi/yqETVjKtKk+peMnNvKkut0GeWZMTze0bfq3/JUK3Ln3jTzzpXxrgVnvBxeY9EZIL4g
 s4wwFRRKz/1bksZGSjD8uuSU=
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

var testRawRSAVerification = &Verification{
	Domain:     "example.com",
	Identifier: "joe@football.example.com",
	HeaderKeys: []string{"Received", "From", "To", "Subject", "Date", "Message-ID"},
	Time:       time.Unix(1615825284, 0),
}

func TestVerify_rawRSA(t *testing.T) {
	r := newMailStringReader(verifiedRawRSAMailString)

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testRawRSAVerification, v) {
		t.Errorf("Expected verification to be \n%+v\n but got \n%+v", testRawRSAVerification, v)
	}
}

const verifiedEd25519MailString = `DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.`

var testEd25519Verification = &Verification{
	Domain:     "football.example.com",
	Identifier: "@football.example.com",
	HeaderKeys: []string{"from", "to", "subject", "date", "message-id", "from", "subject", "date"},
	Time:       time.Unix(1528637909, 0),
}

func TestVerify_ed25519(t *testing.T) {
	r := newMailStringReader(verifiedEd25519MailString)

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature, got: %v", err)
	} else if len(verifications) != 2 {
		t.Fatalf("Expected exactly two verifications, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testEd25519Verification, v) {
		t.Errorf("Expected verification to be \n%+v\n but got \n%+v", testEd25519Verification, v)
	}
}

// errorReader reads from r and then returns an arbitrary error.
type errorReader struct {
	r   io.Reader
	err error
}

func (r *errorReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if err == io.EOF {
		return n, r.err
	}
	return n, err
}

func TestVerify_invalid(t *testing.T) {
	r := newMailStringReader("asdf")
	_, err := Verify(r)
	if err == nil {
		t.Fatalf("Expected error while verifying signature, got nil")
	}

	expectedErr := errors.New("expected test error")

	r = &errorReader{
		r:   newMailStringReader(verifiedEd25519MailString),
		err: expectedErr,
	}
	_, err = Verify(r)
	if err != expectedErr {
		t.Fatalf("Expected error while verifying signature, got: %v", err)
	}
}

const tooManySignaturesMailString = `DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
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

func TestVerify_tooManySignatures(t *testing.T) {
	r := strings.NewReader(tooManySignaturesMailString)
	options := VerifyOptions{MaxVerifications: 2}
	verifs, err := VerifyWithOptions(r, &options)
	if err != ErrTooManySignatures {
		t.Fatalf("Expected ErrTooManySignatures, got %v", err)
	}
	if len(verifs) != options.MaxVerifications {
		t.Fatalf("Expected %v verifications, got %v", options.MaxVerifications, len(verifs))
	}
}

const validSignatureWithSFlag = `DKIM-Signature: a=rsa-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 c=simple/simple; d=example.com;
 h=Received:From:To:Subject:Date:Message-ID; s=helsinki; t=1627654546; v=1;
 b=IKIukw2EoRWxb86Ke2ingZFWLoAeNnKYAwGghFe1y0bbn5QLSoyk78o36JXT8z1DzmPquMHt
 C//jnBna6DtqBneiKAUo3OyYmv1+EbTWWEvHGGtUkrKge2VdIXM3ttaOpuTHJRG+6irPKq0Ul4T
 Ofa99PVg4o6nfY6Ctakv3aYc=
Received: from helsinki.example.com  [192.0.2.1]
 by submitserver.example.com with SUBMISSION;
 Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe Helsinki <joe@helsinki.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2021 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@helsinki.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.`

var testSFlagVerification = &Verification{
	Domain:     "example.com",
	Identifier: "@example.com",
	HeaderKeys: []string{"Received", "From", "To", "Subject", "Date", "Message-ID"},
	Time: time.Unix(1627654546, 0),
}

func TestVerify_SFlag(t *testing.T) {
	r := newMailStringReader(validSignatureWithSFlag)

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature with flags, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification with flags, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testSFlagVerification, v) {
		t.Errorf("Expected verification with flags to be \n%+v\n but got \n%+v", testSFlagVerification, v)
	}
}

const invalidSignatureWithSFlag = `DKIM-Signature: a=rsa-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 c=simple/simple; d=example.com;
 h=Received:From:To:Subject:Date:Message-ID; i=anton@id.example.com;
 s=helsinki; t=1627654996; v=1;
 b=k07JuWvk3PZkanimQ0QtIXRwXC5W4EhG/0sPH+r7zWKQ731fNZE//9+ofz+vcA3K5YQ0cOR2
 EXY9qjriMPHFlaYsKZ4gj5YebNhRHyjJ9xlsTPNtFLqs9wnnaKCZu3VxJpualfTaY+Vs3RMjYLq
 7IvOY4tqxnifJg2uFC/5kRbY=
Received: from helsinki.example.com  [192.0.2.1]
 by submitserver.example.com with SUBMISSION;
 Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe Helsinki <joe@helsinki.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2021 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@helsinki.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.`

var testSFlagVerificationFail = &Verification{
	Domain:     "example.com",
	Identifier: "anton@id.example.com",
	HeaderKeys: []string{"Received", "From", "To", "Subject", "Date", "Message-ID"},
	Time: time.Unix(1627654996, 0),
	Err: permFailError("identifier and domain mismatch"),
}

func TestVerify_InvalidSFlag(t *testing.T) {
	r := newMailStringReader(invalidSignatureWithSFlag)

	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signature with flags, got: %v", err)
	} else if len(verifications) != 1 {
		t.Fatalf("Expected exactly one verification with flags, got %v", len(verifications))
	}

	v := verifications[0]
	if !reflect.DeepEqual(testSFlagVerificationFail, v) {
		t.Errorf("Expected verification with flags to be \n%+v\n but got \n%+v", testSFlagVerificationFail, v)
	}
}
