package dkim

import (
	"bytes"
	"testing"
)

var simpleCanonicalizerBodyTests = []struct{
	original  string
	canonical string
}{
	{
		"",
		"\r\n",
	},
	{
		"\r\n",
		"\r\n",
	},
	{
		"\r\n\r\n\r\n",
		"\r\n",
	},
	{
		"Hey\r\n\r\n",
		"Hey\r\n",
	},
	{
		"Hey\r\nHow r u?\r\n\r\n\r\n",
		"Hey\r\nHow r u?\r\n",
	},
	{
		"Hey\r\n\r\nHow r u?",
		"Hey\r\n\r\nHow r u?\r\n",
	},
}

func TestSimpleCanonicalizer_CanonicalBody(t *testing.T) {
	c := new(simpleCanonicalizer)

	var b bytes.Buffer
	for _, test := range simpleCanonicalizerBodyTests {
		b.Reset()

		wc := c.CanonicalizeBody(&b)
		if _, err := wc.Write([]byte(test.original)); err != nil {
			t.Errorf("Expected no error while writing to simple body canonicalizer, got: %v", err)
		} else if err := wc.Close(); err != nil {
			t.Errorf("Expected no error while closing simple body canonicalizer, got: %v", err)
		} else if s := b.String(); s != test.canonical {
			t.Errorf("Expected canonical body for %q to be %q, but got %q", test.original, test.canonical, s)
		}
	}
}

var relaxedCanonicalizerHeaderTests = []struct{
	original  string
	canonical string
}{
	{
		"SubjeCT: Your Name\r\n",
		"subject:Your Name\r\n",
	},
	{
		"Subject \t:\t Your Name\t \r\n",
		"subject:Your Name\r\n",
	},
	{
		"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n",
		"subject:Kimi No Na Wa\r\n",
	},
}

func TestRelaxedCanonicalizer_CanonicalizeHeader(t *testing.T) {
	c := new(relaxedCanonicalizer)

	for _, test := range relaxedCanonicalizerHeaderTests {
		if s := c.CanonicalizeHeader(test.original); s != test.canonical {
			t.Errorf("Expected relaxed canonical header to be %q but got %q", test.canonical, s)
		}
	}
}

var relaxedCanonicalizerBodyTests = []struct{
	original  string
	canonical string
}{
	{
		"",
		"",
	},
	{
		"\r\n",
		"",
	},
	{
		"\r\n\r\n\r\n",
		"",
	},
	{
		"Hey\r\n\r\n",
		"Hey",
	},
	{
		"Hey\r\nHow r u?\r\n\r\n\r\n",
		"Hey\r\nHow r u?",
	},
	{
		"Hey\r\n\r\nHow r u?",
		"Hey\r\n\r\nHow r u?",
	},
	{
		"Hey \t you!",
		"Hey you!",
	},
	{
		"Hey \t \r\nyou!",
		"Hey\r\nyou!",
	},
	{
		"Hey\r\n \t you!\r\n",
		"Hey\r\n \t you!",
	},
	{
		"Hey\r\n \t \r\n \r\n",
		"Hey",
	},
}

func TestRelaxedCanonicalizer_CanonicalBody(t *testing.T) {
	c := new(relaxedCanonicalizer)

	var b bytes.Buffer
	for _, test := range relaxedCanonicalizerBodyTests {
		b.Reset()

		wc := c.CanonicalizeBody(&b)
		if _, err := wc.Write([]byte(test.original)); err != nil {
			t.Errorf("Expected no error while writing to simple body canonicalizer, got: %v", err)
		} else if err := wc.Close(); err != nil {
			t.Errorf("Expected no error while closing simple body canonicalizer, got: %v", err)
		} else if s := b.String(); s != test.canonical {
			t.Errorf("Expected canonical body for %q to be %q, but got %q", test.original, test.canonical, s)
		}
	}
}
