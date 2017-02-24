package msgauth

import (
	"reflect"
	"testing"
)

var parseTests = []struct{
	value string
	identifier string
	results []Result
}{
	{
		value: "",
		identifier: "",
		results: nil,
	},
	{
		value: "example.org; none",
		identifier: "example.org",
		results: nil,
	},
	{
		value: "example.com;\r\n" +
			" spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		value: "example.com;\r\n" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;\r\n" +
			" spf=pass smtp.mailfrom=example.com",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultPass, From: "example.com"},
		},
	},
	{
		value: "example.com;\r\n" +
			" sender-id=pass header.from=example.com",
		identifier: "example.com",
		results: []Result{
			&SenderIDResult{Value: ResultPass, HeaderKey: "from", HeaderValue: "example.com"},
		},
	},
	{
		value: "example.com;\r\n" +
			" sender-id=hardfail header.from=example.com;\r\n" +
			" dkim=pass (good signature) header.i=sender@example.com",
		identifier: "example.com",
		results: []Result{
			&SenderIDResult{Value: ResultHardFail, HeaderKey: "from", HeaderValue: "example.com"},
			&DKIMResult{Value: ResultPass, Identifier: "sender@example.com"},
		},
	},
	{
		value: "example.com;\r\n" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;\r\n" +
			" spf=hardfail smtp.mailfrom=example.com",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultHardFail, From: "example.com"},
		},
	},
	{
		value: "example.com;\r\n" +
			" dkim=pass (good signature) header.i=@mail-router.example.net;\r\n" +
			" dkim=fail (bad signature) header.i=@newyork.example.com",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Identifier: "@mail-router.example.net"},
			&DKIMResult{Value: ResultFail, Identifier: "@newyork.example.com"},
		},
	},
}

func TestParse(t *testing.T) {
	for _, test := range parseTests {
		identifier, results, err := Parse(test.value)
		if err != nil {
			t.Errorf("Excpected no error when parsing header, got: %v", err)
		} else if test.identifier != identifier {
			t.Errorf("Expected identifier to be %q, but got %q", test.identifier, identifier)
		} else if len(test.results) != len(results) {
			t.Errorf("Expected number of results to be %v, but got %v", len(test.results), len(results))
		} else {
			for i := 0; i < len(results); i++ {
				if !reflect.DeepEqual(test.results[i], results[i]) {
					t.Errorf("Expected result to be \n%v\n but got \n%v", test.results[i], results[i])
				}
			}
		}
	}
}
