package dkim

const dnsPublicKey = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
	"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
	"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
	"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
	"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

func init() {
	queryMethods["dns/txt"] = queryTest
}

func queryTest(domain, selector string) (*queryResult, error) {
	return parsePublicKey(dnsPublicKey)
}
