# go-msgauth

[![Go Reference](https://pkg.go.dev/badge/github.com/emersion/go-msgauth.svg)](https://pkg.go.dev/github.com/emersion/go-msgauth)
[![builds.sr.ht status](https://builds.sr.ht/~emersion/go-msgauth/commits/master.svg?)](https://builds.sr.ht/~emersion/go-msgauth/commits/master)

A Go library and tools to authenticate e-mails.

## Libraries

* [`dkim`]: create and verify [DKIM signatures][DKIM]
* [`authres`]: create and parse [Authentication-Results header fields][Authentication-Results]
* [`dmarc`]: fetch [DMARC] records

## Tools

A few tools are included in go-msgauth:

- `dkim-keygen`: generate a DKIM key
- `dkim-milter`: a mail filter to sign and verify DKIM signatures
- `dkim-verify`: verify a DKIM-signed email
- `dmarc-lookup`: lookup the DMARC policy of a domain

## License

MIT

[DKIM]: https://tools.ietf.org/html/rfc6376
[Authentication-Results]: https://tools.ietf.org/html/rfc7601
[DMARC]: https://tools.ietf.org/html/rfc7489
[`dkim`]: https://pkg.go.dev/github.com/emersion/go-msgauth/dkim
[`authres`]: https://pkg.go.dev/github.com/emersion/go-msgauth/authres
[`dmarc`]: https://pkg.go.dev/github.com/emersion/go-msgauth/dmarc
