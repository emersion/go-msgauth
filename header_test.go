package dkim

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

var headerTests = []struct {
	h header
	s string
}{
	{
		h: header{"From: <mistuha@kiminonawa.moe>\r\n"},
		s: "From: <mistuha@kiminonawa.moe>\r\n\r\n",
	},
	{
		h: header{
			"From: <mistuha@kiminonawa.moe>\r\n",
			"Subject: Your Name\r\n",
		},
		s: "From: <mistuha@kiminonawa.moe>\r\n" +
			"Subject: Your Name\r\n" +
			"\r\n",
	},
}

func TestReadHeader(t *testing.T) {
	for _, test := range headerTests {
		r := strings.NewReader(test.s)
		h, err := readHeader(bufio.NewReader(r))
		if err != nil {
			t.Fatalf("Expected no error while reading error, got: %v", err)
		}

		if !reflect.DeepEqual(h, test.h) {
			t.Errorf("Expected header to be \n%v\n but got \n%v", test.h, h)
		}
	}
}

func TestFormatHeaderParams(t *testing.T) {
	params := map[string]string{
		"v": "1",
		"a": "rsa-sha256",
		"d": "example.org",
	}

	expected := "a=rsa-sha256; d=example.org; v=1;"

	s := formatHeaderParams(params)
	if s != expected {
		t.Errorf("Expected formatted params to be %q, but got %q", expected, s)
	}
}
