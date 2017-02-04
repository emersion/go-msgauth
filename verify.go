package dkim

import (
	"bufio"
	"crypto"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

var ErrNoSignature = errors.New("dkim: no signature found")

type permFailError string

func (err permFailError) Error() string {
	return "dkim: " + string(err)
}

func IsPermFail(err error) bool {
	_, ok := err.(permFailError)
	return ok
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dkim: " + string(err)
}

func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

var requiredTags = []string{"v", "a", "b", "bh", "d", "h", "s"}

func Verify(r io.Reader) error {
	// Read header
	br := bufio.NewReader(r)
	h, err := readHeader(br)
	if err != nil {
		return err
	}

	// TODO: support multiple signatures
	for _, kv := range h {
		k, v := parseHeaderField(kv)

		if strings.ToLower(k) == "dkim-signature" {
			return verify(h, br, v)
		}
	}
	return ErrNoSignature
}

func verify(h header, r io.Reader, signature string) error {
	params, err := parseHeaderParams(signature)
	if err != nil {
		return err
	}

	if params["v"] != "1" {
		return permFailError("incompatible signature version")
	}

	for _, tag := range requiredTags {
		if _, ok := params[tag]; !ok {
			return permFailError("signature missing required tag")
		}
	}

	if i, ok := params["i"]; ok {
		if !strings.HasSuffix(i, "@"+params["d"]) && !strings.HasSuffix(i, "."+params["d"]) {
			return permFailError("domain mismatch")
		}
	} else {
		params["i"] = "@" + params["d"]
	}

	keys := parseTagList(params["h"])
	ok := false
	for _, k := range keys {
		if strings.ToLower(k) == "from" {
			ok = true
			break
		}
	}
	if !ok {
		return permFailError("From field not signed")
	}

	// TODO: permFailError("signature has expired")

	// Query public key
	// TODO: compute hash in parallel
	methods := []string{"dns/txt"}
	if methodsStr, ok := params["q"]; ok {
		methods = parseTagList(methodsStr)
	}
	var res *queryResult
	for _, method := range methods {
		if query, ok := queryMethods[method]; ok {
			res, err = query(params["d"], params["s"])
			break
		}
	}
	if err != nil {
		return err
	} else if res == nil {
		return permFailError("unsupported public key query method")
	}

	// Parse algos
	algos := strings.SplitN(params["a"], "-", 2)
	if len(algos) != 2 {
		return permFailError("malformed algorithm name")
	}
	keyAlgo := algos[0]
	hashAlgo := algos[1]

	// Check hash algo
	if res.HashAlgos != nil {
		ok := false
		for _, algo := range res.HashAlgos {
			if algo == hashAlgo {
				ok = true
				break
			}
		}
		if !ok {
			return permFailError("inappropriate hash algorithm")
		}
	}
	var hash crypto.Hash
	switch hashAlgo {
	case "sha1":
		hash = crypto.SHA1
	case "sha256":
		hash = crypto.SHA256
	default:
		return permFailError("unsupported hash algorithm")
	}

	// Check key algo
	if res.KeyAlgo != keyAlgo {
		return permFailError("inappropriate key algorithm")
	}

	// TODO: check service

	headerCan, bodyCan := parseCanonicalization(params["c"])
	if _, ok := canonicalizers[headerCan]; !ok {
		return permFailError("unsupported header canonicalization algorithm")
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return permFailError("unsupported body canonicalization algorithm")
	}

	// Parse signatures
	// TODO: parse header signature
	bodySig, err := base64.StdEncoding.DecodeString(params["bh"])
	if err != nil {
		return permFailError("malformed body signature: " + err.Error())
	}

	// Check body signature
	// TODO: support body length
	hasher := hash.New()
	wc := canonicalizers[bodyCan].CanonicalizeBody(hasher)
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	hashed := hasher.Sum(nil)
	if err := res.Verifier.Verify(hash, hashed, bodySig); err != nil {
		return permFailError("body hash did not verify: " + err.Error())
	}

	// TODO: check header signature

	return nil
}

func parseTagList(s string) []string {
	tags := strings.Split(s, ":")
	for i, t := range tags {
		tags[i] = strings.TrimSpace(t)
	}
	return tags
}

func parseCanonicalization(s string) (headerCan, bodyCan string) {
	headerCan = "simple"
	bodyCan = "simple"

	cans := strings.SplitN(s, "/", 2)
	if cans[0] != "" {
		headerCan = cans[0]
	}
	if len(cans) > 1 {
		bodyCan = cans[1]
	}
	return
}
