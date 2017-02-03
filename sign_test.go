package dkim

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"time"
)

const mailHeaderString = "From: Mitsuha Miyamizu <mitsuha.miyamizu@example.org>\r\n" +
	"Subject: Your Name\r\n" +
	"Content-Type: text/plain\r\n"

const mailBodyString = "Who are you?\r\n"

const mailString = mailHeaderString + "\r\n" + mailBodyString

const signedMailString = mailHeaderString +
	"DKIM-Signature: a=rsa-sha256; " +
	"b=gyHs2YdaLu8UiF8Ibzxb+Bn50KWgQIeoAYlY74mXT+411sFg64dRSeiHoXac7Hx+wCHjudrBL2wZd3fj4Zws2XU2CcvuQnsh1uzyXiSGftO1WPr/UQdYseqkP8hsBWLpILGi304S5/s30lQU66D3zzt+o2pzsqJN1uNL+Ov3uipXFDGbxCYbSfJS++yLjDqDN4WSMaW9pXo5eiCGLVFGvUen2ZWJlVT6efMYn3sgQ/yN63gpoBhEvImJ8tZLQBQfZEA2FQpUlhUs7zII9uqVdGDathCXHzKNXcbugPqYScSZaL5JFiRIdXKOD7QutxE9n40/ITiYElX31ZSrA9Aryw==; " +
	"bh=Jz/ArJAosnRBrFEDG4XXE/gwPU5KZcfNrQXkmGl1QWyknOF6Jd9ikFEGCPb7FlMNiuarLWGKVtaK9TiCAAVdCteTDUrubGtZ5m+waDKd5dvTztHLPO+yMtel//svzmdzysAPO9vWvvHMpTQc5s/Jbcp1Ny5kqfOyw5JPTgiyru4vp8sHRAzxVpyKvtOjNAranh7Ha5ksUbHCSvwCzaA/blE5tRGUxlS6JHthDesBpGMCUOkoL/pVQtFuNbfCJhK4GaY3CQYKzxdgSrz5Xde5BtoTghBe7kLt5ukdmpF3Zd8e/XMPp7gcU5KaCEvL09J/urnJctgKzkHY1mDlRbrgFg==; " +
	"c=simple/simple; d=example.org; h=From:Subject:Content-Type; s=; t=424242; v=1;\r\n" +
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
	options := &Options{
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
