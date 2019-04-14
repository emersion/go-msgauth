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

func TestReadHeader_incomplete(t *testing.T) {
	r := strings.NewReader("From: <mistuha@kiminonawa.moe>\r\nTo")
	_, err := readHeader(bufio.NewReader(r))
	if err == nil {
		t.Error("Expected an error while reading incomplete header")
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

func TestParseHeaderParams_malformed(t *testing.T) {
	_, err := parseHeaderParams("abc; def")
	if err == nil {
		t.Error("Expected an error when parsing malformed header params")
	}
}

func TestHeaderPicker_Pick(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		predefinedHeaders := []string{"From", "to"}
		headers := header{
			"from: fst",
			"To: snd",
		}
		picker := newHeaderPicker(headers)
		for i, k := range predefinedHeaders {
			if headers[i] != picker.Pick(k) {
				t.Errorf("Parameter %s not found in headers %s", k, headers)
			}
		}
	})
	t.Run("a few same headers", func(t *testing.T) {
		predefinedHeaders := []string{"to", "to", "to"}
		// same headers must returns from Bottom to Top
		headers := header{
			"To: trd",
			"To: snd",
			"To: fst",
		}
		var lh = len(headers) - 1
		picker := newHeaderPicker(headers)
		for i, k := range predefinedHeaders {
			if headers[lh-i] != picker.Pick(k) {
				t.Errorf("Parameter %s not found in headers %s", k, headers)
			}
		}

	})
}
