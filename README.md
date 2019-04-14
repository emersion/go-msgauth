# go-msgauth

[![GoDoc](https://godoc.org/github.com/emersion/go-msgauth?status.svg)](https://godoc.org/github.com/emersion/go-msgauth)

A Go library to authenticate e-mails:

* Create and verify [DKIM signatures][DKIM]
* Create and parse [Authentication-Results header fields][Authentication-Results]

## DKIM

[![GoDoc](https://godoc.org/github.com/emersion/go-msgauth/dkim?status.svg)](https://godoc.org/github.com/emersion/go-msgauth/dkim)

### Sign

```go
r := strings.NewReader(mailString)

options := &dkim.SignOptions{
	Domain: "example.org",
	Selector: "brisbane",
	Signer: privateKey,
}

var b bytes.Buffer
if err := dkim.Sign(&b, r, options); err != nil {
	log.Fatal(err)
}
```

### Verify

```go
r := strings.NewReader(mailString)

verifications, err := dkim.Verify(r)
if err != nil {
	log.Fatal(err)
}

for _, v := range verifications {
	if v.Err == nil {
		log.Println("Valid signature for:", v.Domain)
	} else {
		log.Println("Invalid signature for:", v.Domain, v.Err)
	}
}
```

### FAQ

**Why can't I verify a `mail.Message` directly?** A `mail.Message` header is
already parsed, and whitespace characters (especially continuation lines) are
removed. Thus, the signature computed from the parsed header is not the same as
the one computed from the raw header.

**How can I publish my public key?** You have to add a TXT record to your DNS
zone. See [RFC 6376 appendix C](https://tools.ietf.org/html/rfc6376#appendix-C).

## Authentication-Results

[![GoDoc](https://godoc.org/github.com/emersion/go-msgauth/authres?status.svg)](https://godoc.org/github.com/emersion/go-msgauth/authres)

```go
// Format
results := []authres.Result{
	&authres.SPFResult{Value: authres.ResultPass, From: "example.net"},
	&authres.AuthResult{Value: authres.ResultPass, Auth: "sender@example.com"},
}
s := authres.Format("example.com", results)
log.Println(s)

// Parse
identifier, results, err := authres.Parse(s)
if err != nil {
	log.Fatal(err)
}

log.Println(identifier, results)
```

## License

MIT

[DKIM]: https://tools.ietf.org/html/rfc6376
[Authentication-Results]: https://tools.ietf.org/html/rfc7601
