package dkim

import (
	"bytes"
	"bufio"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type permFailError string

func (err permFailError) Error() string {
	return "dkim: " + string(err)
}

// IsPermFail returns true if the error returned by Verify is a permanent
// failure.
func IsPermFail(err error) bool {
	_, ok := err.(permFailError)
	return ok
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dkim: " + string(err)
}

// IsTempFail returns true if the error returned by Verify is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

var requiredTags = []string{"v", "a", "b", "bh", "d", "h", "s"}

// A Verification is produced by Verify when it checks if one signature is
// valid. If the signature is valid, Err is nil.
type Verification struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream.
	Domain string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	Identifier string

	// The list of signed header fields.
	HeaderKeys []string
	// The number of bytes in the body which are signed. If the whole body is
	// signed, BodyLength is < 0.
	BodyLength int64

	// The time that this signature was created. If unknown, it's set to zero.
	Time time.Time
	// The expiration time. If the signature doesn't expire, it's set to zero.
	Expiration time.Time

	// Err is nil if the signature is valid.
	Err error
}

type signature struct {
	i int
	v string
}

// Verify checks if a message's signatures are valid. It returns on verification
// per signature.
func Verify(r io.Reader) ([]*Verification, error) {
	// TODO: be able to specify options such as the max number of signatures to
	// check

	// Read header
	bufr := bufio.NewReader(r)
	h, err := readHeader(bufr)
	if err != nil {
		return nil, err
	}

	// Scan header fields for signatures
	var signatures []*signature
	for i, kv := range h {
		k, v := parseHeaderField(kv)
		if strings.ToLower(k) == "dkim-signature" {
			signatures = append(signatures, &signature{i, v})
		}
	}

	// Copy body in a buffer if multiple signatures are checked
	var br *bytes.Reader
	if len(signatures) > 1 {
		b, err := ioutil.ReadAll(bufr)
		if err != nil {
			return nil, err
		}
		br = bytes.NewReader(b)
	}

	verifications := make([]*Verification, len(signatures))
	for i, sig := range signatures {
		// Use the bytes.Reader if there is one
		var r io.Reader = bufr
		if br != nil {
			br.Seek(0, io.SeekStart)
			r = br
		}

		v, err := verify(h, r, h[sig.i], sig.v)
		if err != nil && !IsTempFail(err) && !IsPermFail(err) {
			return verifications, err
		}

		v.Err = err
		verifications[i] = v
	}
	return verifications, nil
}

func verify(h header, r io.Reader, sigField, sigValue string) (*Verification, error) {
	verif := new(Verification)

	params, err := parseHeaderParams(sigValue)
	if err != nil {
		return verif, permFailError("malformed signature tags: " + err.Error())
	}

	if params["v"] != "1" {
		return verif, permFailError("incompatible signature version")
	}

	verif.Domain = params["d"]

	for _, tag := range requiredTags {
		if _, ok := params[tag]; !ok {
			return verif, permFailError("signature missing required tag")
		}
	}

	if i, ok := params["i"]; ok {
		if !strings.HasSuffix(i, "@"+params["d"]) && !strings.HasSuffix(i, "."+params["d"]) {
			return verif, permFailError("domain mismatch")
		}
	} else {
		params["i"] = "@" + params["d"]
	}
	verif.Identifier = params["i"]

	headerKeys := parseTagList(params["h"])
	ok := false
	for _, k := range headerKeys {
		if strings.ToLower(k) == "from" {
			ok = true
			break
		}
	}
	if !ok {
		return verif, permFailError("From field not signed")
	}
	verif.HeaderKeys = headerKeys

	if timeStr, ok := params["t"]; ok {
		t, err := parseTime(timeStr)
		if err != nil {
			return verif, permFailError("malformed time: " + err.Error())
		}
		verif.Time = t
	}
	if expiresStr, ok := params["x"]; ok {
		t, err := parseTime(expiresStr)
		if err != nil {
			return verif, permFailError("malformed expiration time: " + err.Error())
		}
		verif.Expiration = t
		if now().After(t) {
			return verif, permFailError("signature has expired")
		}
	}

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
		return verif, err
	} else if res == nil {
		return verif, permFailError("unsupported public key query method")
	}

	// Parse algos
	algos := strings.SplitN(params["a"], "-", 2)
	if len(algos) != 2 {
		return verif, permFailError("malformed algorithm name")
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
			return verif, permFailError("inappropriate hash algorithm")
		}
	}
	var hash crypto.Hash
	switch hashAlgo {
	case "sha1":
		hash = crypto.SHA1
	case "sha256":
		hash = crypto.SHA256
	default:
		return verif, permFailError("unsupported hash algorithm")
	}

	// Check key algo
	if res.KeyAlgo != keyAlgo {
		return verif, permFailError("inappropriate key algorithm")
	}

	if res.Services != nil {
		ok := false
		for _, s := range res.Services {
			if s == "email" {
				ok = true
				break
			}
		}
		if !ok {
			return verif, permFailError("inappropriate service")
		}
	}

	headerCan, bodyCan := parseCanonicalization(params["c"])
	if _, ok := canonicalizers[headerCan]; !ok {
		return verif, permFailError("unsupported header canonicalization algorithm")
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return verif, permFailError("unsupported body canonicalization algorithm")
	}

	var bodyLen int64 = -1
	if lenStr, ok := params["l"]; ok {
		l, err := strconv.ParseInt(lenStr, 10, 64)
		if err != nil {
			return verif, permFailError("malformed body length: " + err.Error())
		} else if l < 0 {
			return verif, permFailError("malformed body length: negative value")
		}
		bodyLen = l
	}
	verif.BodyLength = bodyLen

	// Parse body hash and signature
	bodyHashed, err := decodeBase64String(params["bh"])
	if err != nil {
		return verif, permFailError("malformed body hash: " + err.Error())
	}
	sig, err := decodeBase64String(params["b"])
	if err != nil {
		return verif, permFailError("malformed signature: " + err.Error())
	}

	// Check body hash
	hasher := hash.New()
	var w io.Writer = hasher
	if bodyLen > 0 {
		w = &limitedWriter{W: w, N: bodyLen}
	}
	wc := canonicalizers[bodyCan].CanonicalizeBody(w)
	if _, err := io.Copy(wc, r); err != nil {
		return verif, err
	}
	if err := wc.Close(); err != nil {
		return verif, err
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), bodyHashed) != 1 {
		return verif, permFailError("body hash did not verify")
	}

	// Compute data hash
	hasher.Reset()
	picker := newHeaderPicker(h)
	for _, key := range headerKeys {
		kv := picker.Pick(key)
		if kv == "" {
			continue
		}

		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return verif, err
		}
	}
	canSigField := removeSignature(sigField)
	canSigField = canonicalizers[headerCan].CanonicalizeHeader(canSigField)
	canSigField = strings.TrimRight(canSigField, "\r\n")
	if _, err := hasher.Write([]byte(canSigField)); err != nil {
		return verif, err
	}
	hashed := hasher.Sum(nil)

	// Check signature
	if err := res.Verifier.Verify(hash, hashed, sig); err != nil {
		return verif, permFailError("signature did not verify: " + err.Error())
	}

	return verif, nil
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

func parseTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

func decodeBase64String(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(s)
}

func removeSignature(s string) string {
	return regexp.MustCompile(`(b\s*=)[^;]+`).ReplaceAllString(s, "$1")
}
