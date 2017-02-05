package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var randReader io.Reader = rand.Reader

// SignOptions is used to configure Sign. Domain, Selector and Signer are
// mandatory.
type SignOptions struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream. Hence, the SDID value is used to form the query for the public
	// key. The SDID MUST correspond to a valid DNS name under which the DKIM key
	// record is published.
	Domain string
	// The selector subdividing the namespace for the domain.
	Selector string

	// The key used to sign the message.
	Signer crypto.Signer
	// The hash algorithm used to sign the message.
	Hash crypto.Hash

	// Header and body canonicalization algorithms.
	HeaderCanonicalization string
	BodyCanonicalization   string

	// A list of header fields to include in the signature. If nil, all headers
	// will be included. If not nil, "From" MUST be in the list.
	//
	// See RFC 6376 section 5.4.1 for recommended header fields.
	HeaderKeys []string

	// The expiration time. A zero value means no expiration.
	Expiration time.Time
}

// Sign signs a message. It reads it from r and writes the signed version to w.
func Sign(w io.Writer, r io.Reader, options *SignOptions) error {
	if options == nil {
		return fmt.Errorf("dkim: no options specified")
	}
	if options.Domain == "" {
		return fmt.Errorf("dkim: no domain specified")
	}
	if options.Selector == "" {
		return fmt.Errorf("dkim: no selector specified")
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

	// Hash body
	// We need to keep a copy of the body in memory
	var b bytes.Buffer
	hasher := options.Hash.New()
	can := canonicalizers[bodyCan].CanonicalizeBody(hasher)
	mw := io.MultiWriter(&b, can)
	if _, err := io.Copy(mw, br); err != nil {
		return err
	}
	if err := can.Close(); err != nil {
		return err
	}
	bodyHashed := hasher.Sum(nil)

	params := map[string]string{
		"v":  "1",
		"a":  keyAlgo + "-" + hashAlgo,
		"bh": base64.StdEncoding.EncodeToString(bodyHashed),
		"c":  headerCan + "/" + bodyCan,
		"d":  options.Domain,
		//"i": "", // TODO
		//"l": "", // TODO
		//"q": "", // TODO
		"s": options.Selector,
		"t": strconv.FormatInt(now().Unix(), 10),
		//"x": "", // TODO
		//"z": "", // TODO
	}

	var headerKeys []string
	if options.HeaderKeys != nil {
		headerKeys = options.HeaderKeys
	} else {
		for _, kv := range h {
			k, _ := parseHeaderField(kv)
			headerKeys = append(headerKeys, k)
		}
	}
	params["h"] = strings.Join(headerKeys, ":")

	// Hash and sign headers
	hasher.Reset()
	picker := newHeaderPicker(h)
	for _, k := range headerKeys {
		kv := picker.Pick(k)
		if kv == "" {
			continue
		}

		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return err
		}
	}

	params["b"] = ""
	sigField := strings.TrimRight(formatSignature(params), crlf)
	if _, err := hasher.Write([]byte(sigField)); err != nil {
		return err
	}
	hashed := hasher.Sum(nil)

	sig, err := options.Signer.Sign(randReader, hashed, options.Hash)
	if err != nil {
		return err
	}
	params["b"] = base64.StdEncoding.EncodeToString(sig)
	sigField = formatSignature(params)

	if _, err := w.Write([]byte(sigField)); err != nil {
		return err
	}
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
