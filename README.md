# go-msgauth

[![GoDoc](https://godoc.org/github.com/emersion/go-msgauth?status.svg)](https://godoc.org/github.com/emersion/go-msgauth)
[![Build Status](https://travis-ci.org/emersion/go-msgauth.svg?branch=master)](https://travis-ci.org/emersion/go-msgauth)

A Go library to create and parse [Authentication-Results header fields](https://tools.ietf.org/html/rfc7601).

## Usage

```go
// Format
results := []msgauth.Result{
	&msgauth.SPFResult{Value: ResultPass, From: "example.net"},
	&msgauth.AuthResult{Value: ResultPass, Auth: "sender@example.com"},
}
s := msgauth.Format("example.com", results)
log.Println(s)

// Parse
identifier, results, err := msgauth.Parse(s)
if err != nil {
	log.Fatal(err)
}

log.Println(identifier, results)
```

## License

MIT
