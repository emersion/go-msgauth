package arc

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// These tests are adapted from ValiMail's ARC signing test suite:
// https://github.com/ValiMail/arc_test_suite/blob/f137dcb9d6d5baeef1310024ce9ccca94a9a92c8/tests/arc-draft-sign-tests.yml
// Copyright 2017 ValiMail Inc.; source licensed under the MIT License:
// https://github.com/ValiMail/arc_test_suite/blob/f137dcb9d6d5baeef1310024ce9ccca94a9a92c8/LICENSE.txt
//
// The source vectors target ARC draft 12/16 and prescribe an alphabetic tag
// order for deterministic output. The tests below retain their behavioral
// assertions while allowing this package to emit RFC 8617 header syntax, in
// which the instance tag precedes the remaining AMS and AS tags.

// AI assistance disclosure: OpenAI Codex (GPT-5) assisted in translating the
// cited ValiMail YAML vectors into idiomatic Go test cases. I reviewed the
// adaptations against the original vectors, verified them against this
// implementation, and retain full responsibility for their correctness and
// inclusion in this project.

const valimailPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
-----END RSA PRIVATE KEY-----`

const baseMessage = "Authentication-Results: lists.example.org; arc=none;\r\n" +
	" spf=pass smtp.mfrom=jqd@d1.example;\r\n" +
	" dkim=pass (1024-bit key) header.i=@d1.example;\r\n" +
	" dmarc=pass\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Return-Path: <jqd@d1.example.org>\r\n" +
	"Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\r\n" +
	"Message-ID: <54B84785.1060301@d1.example.org>\r\n" +
	"Date: Thu, 14 Jan 2015 15:00:01 -0800\r\n" +
	"From: John Q Doe <jqd@d1.example.org>\r\n" +
	"To: arc@dmarc.org\r\n" +
	"Subject: Example 1\r\n" +
	"\r\n" +
	"Hey gang,\r\n" +
	"This is a test message.\r\n" +
	"--J.\r\n"

func testPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(valimailPrivateKeyPEM))
	if block == nil {
		t.Fatal("failed to decode ValiMail test key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ValiMail test key: %v", err)
	}
	return key
}

func sealMessage(t *testing.T, message string, key *rsa.PrivateKey, cv ChainValidation, timestamp int64) (string, *arcSet, error) {
	return sealMessageWithChainValidation(t, message, key, cv, false, timestamp)
}

func sealMessageWithChainValidation(t *testing.T, message string, key *rsa.PrivateKey, cv ChainValidation, dontCare bool, timestamp int64) (string, *arcSet, error) {
	t.Helper()
	previousNow := now
	now = func() time.Time { return time.Unix(timestamp, 0) }
	defer func() { now = previousNow }()

	var output bytes.Buffer
	err := Seal(&output, strings.NewReader(message), &SealOptions{
		Domain:                    "example.org",
		Selector:                  "dummy",
		Signer:                    key,
		AuthservID:                "lists.example.org",
		AMSHeaderCanonicalization: dkim.CanonicalizationRelaxed,
		AMSBodyCanonicalization:   dkim.CanonicalizationRelaxed,
		AMSHeaderKeys: []string{
			"mime-version",
			"date",
			"from",
			"to",
			"subject",
		},
		ChainValidationStatus:   cv,
		DontCareChainValidation: dontCare,
	})
	if err != nil {
		return "", nil, err
	}

	reader := bufio.NewReader(strings.NewReader(output.String()))
	headers, err := dkim.ReadHeader(reader)
	if err != nil {
		return "", nil, err
	}
	chain, err := collectSets(headers)
	if err != nil {
		return "", nil, err
	}
	return output.String(), chain.getLatestSet(), nil
}

func compactTagValue(value string) string {
	return strings.Join(strings.Fields(value), "")
}

func corruptLatestSeal(message string) string {
	const marker = " b="
	index := strings.Index(message, marker)
	if index < 0 || index+len(marker) >= len(message) {
		return message
	}
	position := index + len(marker)
	corrupted := []byte(message)
	if corrupted[position] == 'A' {
		corrupted[position] = 'B'
	} else {
		corrupted[position] = 'A'
	}
	return string(corrupted)
}

func TestCanonicalization(t *testing.T) {
	key := testPrivateKey(t)
	_, baseline, err := sealMessage(t, baseMessage, key, "", 12345)
	if err != nil {
		t.Fatalf("baseline Seal() failed: %v", err)
	}

	const wantBodyHash = "KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ="
	if got := compactTagValue(baseline.amsParams["bh"]); got != wantBodyHash {
		t.Fatalf("baseline body hash = %q, want ValiMail vector %q", got, wantBodyHash)
	}

	tests := map[string]string{
		// message body eol whitespace ignored
		"message_body_eol_wsp": strings.Replace(
			baseMessage,
			"Hey gang,\r\n",
			"Hey gang,  \r\n",
			1,
		),
		// message body inline whitespace reduced
		"message_body_inl_wsp": strings.Replace(
			strings.Replace(baseMessage, "Hey gang,", "Hey   gang,", 1),
			"a test message.",
			"a   test message.",
			1,
		),
		// message body ignore trailing empty lines
		"message_body_end_lines": baseMessage + "\r\n\r\n",
		// message body add crlf to end if na
		"message_body_trail_crlf": strings.TrimSuffix(
			baseMessage,
			"\r\n",
		),
		// header field names case insensitive
		"headers_field_name_case": strings.NewReplacer(
			"From:", "FROM:",
			"To:", "to:",
		).Replace(baseMessage),
		// header
		"headers_field_unfold": strings.Replace(
			baseMessage,
			"From: John Q Doe <jqd@d1.example.org>",
			"From: John Q Doe\r\n <jqd@d1.example.org>",
			1,
		),
		// headers ignore eol whitespace
		"headers_eol_wsp": strings.Replace(
			baseMessage,
			"MIME-Version: 1.0\r\n",
			"MIME-Version: 1.0   \r\n",
			1,
		),
		// header reduce inline whitespace
		"headers_inl_wsp": strings.Replace(
			baseMessage,
			"Date: Thu, 14 Jan 2015 15:00:01 -0800",
			"Date: Thu, 14 Jan   2015   15:00:01 -0800",
			1,
		),
		// headers whitespace surrounding colon ignored
		"headers_col_wsp": strings.Replace(
			baseMessage,
			"From: John Q Doe",
			"From:   John Q Doe",
			1,
		),
	}

	wantAMS := compactTagValue(baseline.amsParams["b"])
	wantAS := compactTagValue(baseline.asParams["b"])
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			_, set, err := sealMessage(t, message, key, "", 12345)
			if err != nil {
				t.Fatalf("Seal() failed: %v", err)
			}
			if got := compactTagValue(set.amsParams["bh"]); got != wantBodyHash {
				t.Errorf("body hash = %q, want %q", got, wantBodyHash)
			}
			if got := compactTagValue(set.amsParams["b"]); got != wantAMS {
				t.Errorf("AMS differs from the canonically equivalent baseline")
			}
			if got := compactTagValue(set.asParams["b"]); got != wantAS {
				t.Errorf("ARC-Seal differs from the canonically equivalent baseline")
			}
		})
	}
}

func TestExistingSealHeaders(t *testing.T) {
	key := testPrivateKey(t)

	// i=0 basic test
	firstMessage, first, err := sealMessage(t, baseMessage, key, "", 12345)
	if err != nil {
		t.Fatalf("i0_base: Seal() failed: %v", err)
	}
	t.Run("i0_base", func(t *testing.T) {
		assertInstance(t, first, 1, ChainValidationNone)
	})

	// i=1 basic test
	secondMessage, second, err := sealMessage(t, firstMessage, key, ChainValidationPass, 12346)
	if err != nil {
		t.Fatalf("i1_base: Seal() failed: %v", err)
	}
	t.Run("i1_base", func(t *testing.T) {
		assertInstance(t, second, 2, ChainValidationPass)
	})

	// i=2 basic test
	_, third, err := sealMessage(t, secondMessage, key, ChainValidationPass, 12347)
	if err != nil {
		t.Fatalf("i2_base: Seal() failed: %v", err)
	}
	t.Run("i2_base", func(t *testing.T) {
		assertInstance(t, third, 3, ChainValidationPass)
	})

	// i=1 basic test with failing arc set
	failedMessage, failedSecond, err := sealMessage(
		t,
		corruptLatestSeal(firstMessage),
		key,
		ChainValidationFail,
		12346,
	)
	if err != nil {
		t.Fatalf("i1_base_fail: Seal() failed: %v", err)
	}
	t.Run("i1_base_fail", func(t *testing.T) {
		assertInstance(t, failedSecond, 2, ChainValidationFail)
	})

	// i=2 basic test with failing arc set
	_, failedThird, err := sealMessage(
		t,
		corruptLatestSeal(secondMessage),
		key,
		ChainValidationFail,
		12347,
	)
	if err != nil {
		t.Fatalf("i2_base_fail: Seal() failed: %v", err)
	}
	t.Run("i2_base_fail", func(t *testing.T) {
		assertInstance(t, failedThird, 3, ChainValidationFail)
	})

	// if a chain is failing, dont add another set
	t.Run("no_additional_sig", func(t *testing.T) {
		_, _, err := sealMessage(t, failedMessage, key, ChainValidationFail, 12347)
		if err == nil || !strings.Contains(err.Error(), "latest ARC-Seal reports cv=fail") {
			t.Fatalf("Seal() error = %v, want terminal cv=fail error", err)
		}
	})
}

func TestSealDontCareChainValidation(t *testing.T) {
	key := testPrivateKey(t)

	firstMessage, first, err := sealMessageWithChainValidation(t, baseMessage, key, "", true, 12345)
	if err != nil {
		t.Fatalf("first Seal() failed: %v", err)
	}
	assertInstance(t, first, 1, ChainValidationNone)

	_, second, err := sealMessageWithChainValidation(t, firstMessage, key, "", true, 12346)
	if err != nil {
		t.Fatalf("second Seal() failed: %v", err)
	}
	assertInstance(t, second, 2, ChainValidationPass)

	_, _, err = sealMessageWithChainValidation(t, baseMessage, key, ChainValidationPass, true, 12347)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting chain validation options error = %v, want mutually exclusive error", err)
	}
}

func assertInstance(t *testing.T, set *arcSet, wantInstance int, wantCV ChainValidation) {
	t.Helper()
	if set.instance != wantInstance {
		t.Errorf("instance = %d, want %d", set.instance, wantInstance)
	}
	if got := ChainValidation(set.asParams["cv"]); got != wantCV {
		t.Errorf("cv = %q, want %q", got, wantCV)
	}
}

func TestAuthenticationResultsMerging(t *testing.T) {
	key := testPrivateKey(t)
	_, baseline, err := sealMessage(t, baseMessage, key, "", 12345)
	if err != nil {
		t.Fatalf("baseline Seal() failed: %v", err)
	}
	messageTail := baseMessage[strings.Index(baseMessage, "MIME-Version:"):]
	tests := map[string]string{
		"ar_merged1": "Authentication-Results: lists.example.org; arc=none\r\n" +
			"Authentication-Results: lists.example.org; spf=pass smtp.mfrom=jqd@d1.example\r\n" +
			"Authentication-Results: lists.example.org; dkim=pass (1024-bit key) header.i=@d1.example\r\n" +
			"Authentication-Results: lists.example.org; dmarc=pass\r\n" +
			"Authentication-Results: nobody.example.org; something=ignored\r\n" +
			messageTail,
		"ar_merged2": "Authentication-Results: lists.example.org; arc=none;\r\n" +
			" spf=pass smtp.mfrom=jqd@d1.example\r\n" +
			"Authentication-Results: lists.example.org; dkim=pass (1024-bit key) header.i=@d1.example\r\n" +
			"Authentication-Results: lists.example.org; dmarc=pass\r\n" +
			"Authentication-Results: nobody.example.org; something=ignored\r\n" +
			messageTail,
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			_, set, err := sealMessage(t, message, key, "", 12345)
			if err != nil {
				t.Fatalf("Seal() failed: %v", err)
			}
			if set.authservID != "lists.example.org" {
				t.Errorf("AAR authserv-id = %q, want lists.example.org", set.authservID)
			}
			if len(set.authResults) != 4 {
				t.Errorf("AAR result count = %d, want 4", len(set.authResults))
			}
			if strings.Contains(set.aar, "something=ignored") {
				t.Errorf("AAR contains result from a different authserv-id: %q", set.aar)
			}
			if set.aar != baseline.aar {
				t.Errorf("merged AAR differs from the source baseline\ngot:  %q\nwant: %q", set.aar, baseline.aar)
			}
			if got, want := compactTagValue(set.amsParams["b"]), compactTagValue(baseline.amsParams["b"]); got != want {
				t.Errorf("AMS differs from the source baseline")
			}
			if got, want := compactTagValue(set.asParams["b"]), compactTagValue(baseline.asParams["b"]); got != want {
				t.Errorf("ARC-Seal differs from the source baseline")
			}
		})
	}
}

func TestAuthenticationResultsWithoutAuthservID(t *testing.T) {
	key := testPrivateKey(t)
	messageTail := baseMessage[strings.Index(baseMessage, "MIME-Version:"):]
	message := "Authentication-Results: spf=pass (sender IP is 192.0.2.1)\r\n" +
		" smtp.mailfrom=example.org; dkim=pass (signature was verified)\r\n" +
		" header.d=example.org; dmarc=pass action=none header.from=example.org;\r\n" +
		" compauth=pass reason=100\r\n" +
		messageTail

	_, set, err := sealMessage(t, message, key, "", 12345)
	if err != nil {
		t.Fatalf("Seal() failed: %v", err)
	}
	if set.authservID != "lists.example.org" {
		t.Errorf("AAR authserv-id = %q, want lists.example.org", set.authservID)
	}
	if len(set.authResults) != 4 {
		t.Fatalf("AAR result count = %d, want 4", len(set.authResults))
	}
	if want := "ARC-Authentication-Results: i=1; lists.example.org;" +
		" spf=pass smtp.mailfrom=example.org;" +
		" dkim=pass header.d=example.org;" +
		" dmarc=pass header.from=example.org;" +
		" compauth=pass reason=100\r\n"; set.aar != want {
		t.Errorf("AAR = %q, want %q", set.aar, want)
	}
}
