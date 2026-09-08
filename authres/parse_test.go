package authres

import (
	"reflect"
	"testing"
)

var parseTests = []msgauthTest{
	{
		value:      "",
		identifier: "",
		results:    nil,
	},
	{
		value:      "example.com 1; none",
		identifier: "example.com",
		results:    nil,
	},
	{
		value: "example.com; \r\n" +
			" \t spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		value:      "example.com; arc=pass header.oldest-pass=0",
		identifier: "example.com",
		results: []Result{
			&ARCResult{Value: ResultPass, OldestPass: 0},
		},
	},
	{
		value:      `example.com; dkim=fail (bad; signature) reason="body was modified; retry" header.d=example.org`,
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultFail, Reason: "body was modified; retry", Domain: "example.org"},
		},
	},
}

func TestParse(t *testing.T) {
	for _, test := range append(msgauthTests, parseTests...) {
		identifier, results, err := Parse(test.value)
		if err != nil {
			t.Errorf("Expected no error when parsing header, got: %v", err)
		} else if test.identifier != identifier {
			t.Errorf("Expected identifier to be %q, but got %q", test.identifier, identifier)
		} else if len(test.results) != len(results) {
			t.Errorf("Expected number of results to be %v, but got %v", len(test.results), len(results))
		} else {
			for i := range results {
				if !reflect.DeepEqual(test.results[i], results[i]) {
					t.Errorf("Expected result to be \n%v\n but got \n%v", test.results[i], results[i])
				}
			}
		}
	}
}

func TestParseWithDefaultAuthservID(t *testing.T) {
	tests := []struct {
		name              string
		value             string
		defaultAuthservID string
		identifier        string
		results           []Result
		wantError         bool
	}{
		{
			name:              "regular header",
			value:             "mx.example.org; spf=pass smtp.mailfrom=example.org",
			defaultAuthservID: "default.example.org",
			identifier:        "mx.example.org",
			results: []Result{
				&SPFResult{Value: ResultPass, From: "example.org"},
			},
		},
		{
			name: "missing authserv-id",
			value: "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.org; " +
				"dkim=pass (signature was verified) header.d=example.org; " +
				"dmarc=pass action=none header.from=example.org; " +
				"compauth=pass reason=100",
			defaultAuthservID: "default.example.org",
			identifier:        "default.example.org",
			results: []Result{
				&SPFResult{Value: ResultPass, From: "example.org"},
				&DKIMResult{Value: ResultPass, Domain: "example.org"},
				&DMARCResult{Value: ResultPass, From: "example.org"},
				&GenericResult{
					Method: "compauth",
					Value:  ResultPass,
					Params: map[string]string{"reason": "100"},
				},
			},
		},
		{
			name:              "single result without authserv-id",
			value:             "dkim=pass header.d=example.org",
			defaultAuthservID: "default.example.org",
			identifier:        "default.example.org",
			results: []Result{
				&DKIMResult{Value: ResultPass, Domain: "example.org"},
			},
		},
		{
			name:              "quoted authserv-id containing equals sign",
			value:             `"mx=example"; spf=pass smtp.mailfrom=example.org`,
			defaultAuthservID: "default.example.org",
			identifier:        "mx=example",
			results: []Result{
				&SPFResult{Value: ResultPass, From: "example.org"},
			},
		},
		{
			name:      "missing authserv-id and default",
			value:     "spf=pass smtp.mailfrom=example.org",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identifier, results, err := ParseWithDefaultAuthservID(test.value, test.defaultAuthservID)
			if test.wantError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWithDefaultAuthservID() failed: %v", err)
			}
			if identifier != test.identifier {
				t.Errorf("identifier = %q, want %q", identifier, test.identifier)
			}
			if !reflect.DeepEqual(results, test.results) {
				t.Errorf("results = %#v, want %#v", results, test.results)
			}
		})
	}
}
