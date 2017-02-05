# go-dkim

[![GoDoc](https://godoc.org/github.com/emersion/go-dkim?status.svg)](https://godoc.org/github.com/emersion/go-dkim)
[![Build Status](https://travis-ci.org/emersion/go-dkim.svg?branch=master)](https://travis-ci.org/emersion/go-dkim)
[![codecov](https://codecov.io/gh/emersion/go-dkim/branch/master/graph/badge.svg)](https://codecov.io/gh/emersion/go-dkim)

A Go library to create and verify [DKIM signatures](https://tools.ietf.org/html/rfc6376).

## Usage

### Sign

```go
r := strings.NewReader(mailString)

options := &SignOptions{
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

if err := dkim.Verify(r); err != nil {
	log.Fatal(err)
}
```

## License

MIT
