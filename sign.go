package dkim

import (
	"bytes"
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var (
	randReader io.Reader = rand.Reader
	now func() time.Time = time.Now
)

type Options struct {
	Domain string
	Selector string

	Signer crypto.Signer

	HeaderCanonicalization string
	BodyCanonicalization string

	Hash crypto.Hash

	HeaderKeys []string
}

func Sign(w io.Writer, r io.Reader, options *Options) error {
	if options == nil {
		return fmt.Errorf("dkim: no options specified")
	}
	if options.Domain == "" {
		return fmt.Errorf("dkim: no domain specified")
	}
	if options.Signer == nil {
		return fmt.Errorf("dkim: no signer specified")
	}

	headerCan := options.HeaderCanonicalization
	if headerCan == "" {
		headerCan = "simple"
	}
	if _, ok := canonicalizers[headerCan]; !ok {
		return fmt.Errorf("dkim: unknown header canonicalization %q", headerCan)
	}

	bodyCan := options.BodyCanonicalization
	if bodyCan == "" {
		bodyCan = "simple"
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return fmt.Errorf("dkim: unknown body canonicalization %q", bodyCan)
	}

	var keyAlgo string
	switch options.Signer.Public().(type) {
	case *rsa.PublicKey:
		keyAlgo = "rsa"
	default:
		return fmt.Errorf("dkim: unsupported key algorithm %T", options.Signer.Public())
	}

	var hashAlgo string
	switch options.Hash {
	case crypto.SHA1:
		hashAlgo = "sha1"
	case 0:
		options.Hash = crypto.SHA256
		fallthrough
	case crypto.SHA256:
		hashAlgo = "sha256"
	default:
		return fmt.Errorf("dkim: unsupported hash algorithm")
	}

	if options.HeaderKeys != nil {
		ok := false
		for _, k := range options.HeaderKeys {
			if strings.ToLower(k) == "from" {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("dkim: the From header field must be signed")
		}
	}

	// Read header
	br := bufio.NewReader(r)
	h, err := readHeader(br)
	if err != nil {
		return err
	}

	// Sign body
	// We need to keep a copy of the body in memory
	var b bytes.Buffer
	hash := options.Hash.New()
	can := canonicalizers[bodyCan].CanonicalizeBody(hash)
	mw := io.MultiWriter(&b, can)
	if _, err := io.Copy(mw, br); err != nil {
		return err
	}
	if err := can.Close(); err != nil {
		return err
	}

	signature, err := signHash(hash, options.Signer, options)
	if err != nil {
		return err
	}

	params := map[string]string{
		"v": "1",
		"a": keyAlgo + "-" + hashAlgo,
		"bh": signature,
		"c": headerCan + "/" + bodyCan,
		"d": options.Domain,
		//"i": "", // TODO
		//"l": "", // TODO
		//"q": "", // TODO
		"s": options.Selector,
		"t": strconv.FormatInt(now().Unix(), 10),
		//"x": "", // TODO
		//"z": "", // TODO
	}

	// TODO: support options.HeaderKeys
	var headerKeys []string
	for _, kv := range h {
		k := headerKey(kv)
		headerKeys = append(headerKeys, k)
	}
	params["h"] = strings.Join(headerKeys, ":")

	h = append(h, formatSignature(params))

	// Hash and sign headers
	hash.Reset()
	for _, kv := range h {
		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)

		if _, err := hash.Write([]byte(kv)); err != nil {
			return err
		}
	}
	signature, err = signHash(hash, options.Signer, options)
	if err != nil {
		return err
	}
	params["b"] = signature
	h[len(h)-1] = formatSignature(params)

	if err := writeHeader(w, h); err != nil {
		return err
	}

	_, err = io.Copy(w, &b)
	return err
}

func formatSignature(params map[string]string) string {
	// TODO: fold lines
	return "DKIM-Signature: " + formatHeaderParams(params) + crlf
}

func signHash(h hash.Hash, signer crypto.Signer, options *Options) (string, error) {
	sum := h.Sum(nil)
	signature, err := signer.Sign(randReader, sum, options.Hash)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
