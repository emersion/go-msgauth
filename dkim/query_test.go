package dkim

import (
	"fmt"
)

const dnsPublicKey = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
	"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
	"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
	"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
	"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

const dnsEd25519PublicKey = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

func init() {
	queryMethods["dns/txt"] = queryTest
}

func queryTest(domain, selector string, txtLookup txtLookupFunc) (*queryResult, error) {
	record := selector + "._domainkey." + domain
	switch record {
	case "brisbane._domainkey.example.com", "brisbane._domainkey.example.org", "test._domainkey.football.example.com":
		return parsePublicKey(dnsPublicKey)
	case "brisbane._domainkey.football.example.com":
		return parsePublicKey(dnsEd25519PublicKey)
	}
	return nil, fmt.Errorf("unknown test DNS record %v", record)
}
