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
			for i := 0; i < len(results); i++ {
				if !reflect.DeepEqual(test.results[i], results[i]) {
					t.Errorf("Expected result to be \n%v\n but got \n%v", test.results[i], results[i])
				}
			}
		}
	}
}
