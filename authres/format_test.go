package authres

import (
	"testing"
)

func TestFormat(t *testing.T) {
	for _, test := range msgauthTests {
		v := Format(test.identifier, test.results)
		if v != test.value {
			t.Errorf("Expected formatted header field to be \n%v\n but got \n%v", test.value, v)
		}
	}
}
