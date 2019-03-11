package dkim

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type verifier interface {
	Public() crypto.PublicKey
	Verify(hash crypto.Hash, hashed []byte, sig []byte) error
}

type rsaVerifier struct {
	*rsa.PublicKey
}

func (v *rsaVerifier) Public() crypto.PublicKey {
	return v.PublicKey
}

func (v *rsaVerifier) Verify(hash crypto.Hash, hashed, sig []byte) error {
	return rsa.VerifyPKCS1v15(v.PublicKey, hash, hashed, sig)
}

type queryResult struct {
	Verifier  verifier
	KeyAlgo   string
	HashAlgos []string
	Notes     string
	Services  []string
	Flags     []string
}

// QueryMethod is a DKIM query method.
type QueryMethod string

const (
	// DNS TXT resource record (RR) lookup algorithm
	QueryMethodDNSTXT QueryMethod = "dns/txt"
)

type queryFunc func(domain, selector string) (*queryResult, error)

var queryMethods = map[QueryMethod]queryFunc{
	QueryMethodDNSTXT: queryDNSTXT,
}

func queryDNSTXT(domain, selector string) (*queryResult, error) {
	txts, err := net.LookupTXT(selector + "._domainkey." + domain)
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return nil, tempFailError("key unavailable: " + err.Error())
	} else if err != nil {
		return nil, permFailError("no key for signature: " + err.Error())
	}

	// Long keys are split in multiple parts
	txt := strings.Join(txts, "")

	return parsePublicKey(txt)
}

func parsePublicKey(s string) (*queryResult, error) {
	params, err := parseHeaderParams(s)
	if err != nil {
		return nil, permFailError("key syntax error: " + err.Error())
	}

	res := new(queryResult)

	if v, ok := params["v"]; ok && v != "DKIM1" {
		return nil, permFailError("incompatible public key version")
	}

	p, ok := params["p"]
	if !ok {
		return nil, permFailError("key syntax error: missing public key data")
	}
	if p == "" {
		return nil, permFailError("key revoked")
	}
	b, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, permFailError("key syntax error: " + err.Error())
	}
	switch params["k"] {
	case "rsa", "":
		pub, err := x509.ParsePKIXPublicKey(b)
		if err != nil {
			return nil, permFailError("key syntax error: " + err.Error())
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, permFailError("key syntax error: not an RSA public key")
		}
		// RFC 8301 section 3.2: verifiers MUST NOT consider signatures using
		// RSA keys of less than 1024 bits as valid signatures.
		if rsaPub.Size() * 8 < 1024 {
			return nil, permFailError(fmt.Sprintf("key is too short: want 1024 bits, has %v bits", rsaPub.Size() * 8))
		}
		res.Verifier = &rsaVerifier{rsaPub}
		res.KeyAlgo = "rsa"
	default:
		return nil, permFailError("unsupported key algorithm")
	}

	if hashesStr, ok := params["h"]; ok {
		res.HashAlgos = parseTagList(hashesStr)
	}
	if notes, ok := params["n"]; ok {
		res.Notes = notes
	}
	if servicesStr, ok := params["s"]; ok {
		services := parseTagList(servicesStr)

		hasWildcard := false
		for _, s := range services {
			if s == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			res.Services = services
		}
	}
	if flagsStr, ok := params["t"]; ok {
		res.Flags = parseTagList(flagsStr)
	}

	return res, nil
}
