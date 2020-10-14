package authres

import (
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
