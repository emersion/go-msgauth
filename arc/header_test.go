package arc

import (
	"reflect"
	"testing"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

func TestParseAAR(t *testing.T) {
	value := "i=2; mx.example; spf=pass smtp.mailfrom=example.org; " +
		"arc=pass header.oldest-pass=0"

	instance, identifier, results, err := parseAAR(value)
	if err != nil {
		t.Fatalf("parseAAR() failed: %v", err)
	}
	if instance != 2 {
		t.Errorf("instance = %d, want 2", instance)
	}
	if identifier != "mx.example" {
		t.Errorf("identifier = %q, want %q", identifier, "mx.example")
	}
	want := []authres.Result{
		&authres.SPFResult{Value: authres.ResultPass, From: "example.org"},
		&authres.ARCResult{Value: authres.ResultPass, OldestPass: 0},
	}
	if !reflect.DeepEqual(results, want) {
		t.Errorf("results = %#v, want %#v", results, want)
	}
}

func TestCollectSetsKeepsMalformedAARPayload(t *testing.T) {
	headers := dkim.Header{
		"ARC-Authentication-Results: i=1; mx.example; dkim=fail reason=\"unterminated\r\n",
		"ARC-Message-Signature: i=1; a=rsa-sha256;\r\n",
		"ARC-Seal: i=1; cv=none;\r\n",
	}

	chain, err := collectSets(headers)
	if err != nil {
		t.Fatalf("collectSets() failed: %v", err)
	}
	if len(chain.sets) != 1 || chain.sets[0].aar != headers[0] {
		t.Fatalf("collectSets() did not preserve malformed AAR: %#v", chain.sets)
	}
	if chain.sets[0].authservID != "" || chain.sets[0].authResults != nil {
		t.Errorf("malformed AAR unexpectedly produced parsed metadata: %#v", chain.sets[0])
	}
}
