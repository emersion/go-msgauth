package arc

import (
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

func createAMS(h dkim.Header, bodyHash []byte, headerKeys []string, instance int, timestamp time.Time, options *SealOptions) (string, error) {
	keyAlgorithm, algorithm, err := signatureAlgorithm(options.Signer)
	if err != nil {
		return "", err
	}

	params := map[string]string{
		"i":  strconv.Itoa(instance),
		"a":  algorithm,
		"bh": base64.StdEncoding.EncodeToString(bodyHash),
		"c":  string(options.AMSHeaderCanonicalization) + "/" + string(options.AMSBodyCanonicalization),
		"d":  options.Domain,
		"h":  dkim.FormatTagList(headerKeys),
		"s":  options.Selector,
		"t":  strconv.FormatInt(timestamp.Unix(), 10),
		"b":  "",
	}

	// q is omitted for the default DNS/TXT lookup method.
	if options.AMSQueryMethods != nil {
		methods := make([]string, len(options.AMSQueryMethods))
		for i, method := range options.AMSQueryMethods {
			methods[i] = string(method)
		}
		params["q"] = dkim.FormatTagList(methods)
	}

	// A zero expiration means that the AMS does not expire.
	if !options.Expiration.IsZero() {
		params["x"] = strconv.FormatInt(options.Expiration.Unix(), 10)
	}

	hasher := options.Hash.New()
	// Header selection follows DKIM's bottom-up rule for repeated fields.
	picker := dkim.NewHeaderPicker(h)
	for _, name := range headerKeys {
		field := picker.Pick(name)
		if field == "" {
			continue
		}
		canonical, err := dkim.CanonicalizeHeader(options.AMSHeaderCanonicalization, field)
		if err != nil {
			return "", err
		}
		if _, err := io.WriteString(hasher, canonical); err != nil {
			return "", err
		}
	}

	sigField := dkim.FormatHeaderParamsWithFirst(arcMessageSignatureHeader, params, "i")
	canonical, err := dkim.CanonicalizeHeader(options.AMSHeaderCanonicalization, sigField)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(hasher, strings.TrimRight(canonical, "\r\n")); err != nil {
		return "", err
	}

	signature, err := signDigest(options.Signer, keyAlgorithm, options.Hash, hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	params["b"] = base64.StdEncoding.EncodeToString(signature)
	return dkim.FormatHeaderParamsWithFirst(arcMessageSignatureHeader, params, "i"), nil
}
