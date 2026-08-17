package authres

import (
	"reflect"
	"testing"
)

func TestFormat(t *testing.T) {
	for _, test := range msgauthTests {
		v := Format(test.identifier, test.results)
		if v != test.value {
			t.Errorf("Expected formatted header field to be \n%q\n but got \n%q", test.value, v)
		}
	}
}

func TestFormatARC(t *testing.T) {
	value := Format("mx.example", []Result{&ARCResult{
		Value:      ResultPass,
		RemoteIP:   "192.0.2.1",
		OldestPass: 2,
	}, &DKIMResult{Value: ResultPass, Domain: "example.org"}})
	want := "mx.example; arc=pass header.oldest-pass=2 smtp.remote-ip=192.0.2.1; dkim=pass header.d=example.org"
	if value != want {
		t.Fatalf("Format() = %q, want %q", value, want)
	}
}

func TestFormatParseQuotedReason(t *testing.T) {
	want := []Result{&DKIMResult{
		Value:  ResultFail,
		Reason: `body "was" modified; retry\later`,
		Domain: "example.org",
	}}

	formatted := Format("mx.example", want)
	identifier, got, err := Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(Format()) failed: %v", err)
	}
	if identifier != "mx.example" {
		t.Errorf("identifier = %q, want %q", identifier, "mx.example")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse(Format()) results = %#v, want %#v", got, want)
	}
}
