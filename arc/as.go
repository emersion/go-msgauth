package arc

import (
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

func createSeal(chain *arcChain, current *arcSet, timestamp time.Time, options *SealOptions) (string, error) {
	keyAlgorithm, algorithm, err := signatureAlgorithm(options.Signer)
	if err != nil {
		return "", err
	}

	// RFC 8617, Section 4.1.3 permits only these AS tags. In particular, an
	// ARC-Seal never contains DKIM's h or bh tags.
	params := map[string]string{
		"i":  strconv.Itoa(current.instance),
		"cv": string(options.ChainValidationStatus),
		"a":  algorithm,
		"d":  options.Domain,
		"s":  options.Selector,
		"t":  strconv.FormatInt(timestamp.Unix(), 10),
		"b":  "",
	}

	unsigned := dkim.FormatHeaderParamsWithFirst(arcSealHeader, params, "i")
	current.as = unsigned

	sets := []*arcSet{current}
	if options.ChainValidationStatus != ChainValidationFail {
		// A passing chain covers every set in increasing instance order. A
		// failed chain deliberately covers only the newly generated set.
		sets = make([]*arcSet, 0, len(chain.sets)+1)
		sets = append(sets, chain.sets...)
		sets = append(sets, current)
	}

	hasher := options.Hash.New()
	if err := hashARCSeal(hasher, sets, current); err != nil {
		return "", err
	}
	signature, err := signDigest(options.Signer, keyAlgorithm, options.Hash, hasher.Sum(nil))
	if err != nil {
		return "", err
	}
	params["b"] = base64.StdEncoding.EncodeToString(signature)
	return dkim.FormatHeaderParamsWithFirst(arcSealHeader, params, "i"), nil
}

func hashARCSeal(hasher io.Writer, sets []*arcSet, current *arcSet) error {
	for _, set := range sets {
		fields := []string{set.aar, set.ams, set.as}
		for i, field := range fields {
			if field == "" {
				return fmt.Errorf("arc: incomplete ARC set %d", set.instance)
			}
			isCurrentSeal := set == current && i == 2 // i=2 determines the AS fields, as seen in the fields definition
			if isCurrentSeal {
				field = dkim.RemoveSignature(field)
			}
			canonical, err := dkim.CanonicalizeHeader(dkim.CanonicalizationRelaxed, field)
			if err != nil {
				return err
			}
			if isCurrentSeal {
				canonical = strings.TrimRight(canonical, "\r\n")
			}
			if _, err := io.WriteString(hasher, canonical); err != nil {
				return err
			}
		}
	}
	return nil
}
