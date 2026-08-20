package arc

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

var randReader io.Reader = rand.Reader
var now = time.Now

// SealOptions configures an ARC sealer. Domain, Selector, and Signer are
// required.
type SealOptions struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream. Hence, the SDID value is used to form the query for the public
	// key. The SDID MUST correspond to a valid DNS name under which the DKIM key
	// record is published.
	//
	// This can't be empty.
	Domain string
	// The selector subdividing the namespace for the domain.
	//
	// This can't be empty.
	Selector string

	// The key used to sign the message.
	//
	// Supported Signer.Public() values are *rsa.PublicKey and
	// ed25519.PublicKey.
	Signer crypto.Signer
	// The hash algorithm used to sign the message. If zero, a default hash will
	// be chosen.
	//
	// The only supported hash algorithm is crypto.SHA256.
	Hash crypto.Hash

	// AuthservID identifies the authentication service that produced the AAR.
	// It defaults to Domain.
	AuthservID string
	// AuthenticationResults contains the results to place in the AAR. If nil,
	// matching Authentication-Results fields are collected from the message.
	AuthenticationResults []authres.Result

	// AMSHeaderCanonicalization and AMSBodyCanonicalization control AMS
	// canonicalization. Empty values select the DKIM simple algorithm.
	AMSHeaderCanonicalization dkim.Canonicalization
	AMSBodyCanonicalization   dkim.Canonicalization
	// AMSHeaderKeys lists the message headers covered by the AMS. If nil, all
	// eligible message headers are signed. ARC and Authentication-Results
	// fields are never eligible.
	AMSHeaderKeys []string
	// AMSQueryMethods lists alternative public-key lookup methods. A nil slice
	// implicitly selects DNS/TXT.
	AMSQueryMethods []dkim.QueryMethod

	// Expiration is the optional AMS expiration time.
	Expiration time.Time

	// ChainValidationStatus is the result of validating the ARC chain received
	// with the message. Leave it empty for a message without a chain; the
	// sealer then uses "none". Extending an existing chain requires an explicit
	// "pass" or "fail" because sealing does not itself validate signatures.
	ChainValidationStatus ChainValidation
	// DontCareChainValidation selects "none" for a message without an ARC chain
	// and "pass" when extending an existing chain. It must not be combined with
	// an explicit ChainValidationStatus. This option will be removed once ARC
	// validation is supported.
	DontCareChainValidation bool
}

// Sealer generates an ARC set.
//
// The complete message must be written to the Sealer. Close must always be
// called and its error checked. After a successful Close, Set returns the ARC
// header fields to prepend to the message.
type Sealer struct {
	pw   *io.PipeWriter
	done <-chan error
	set  *arcSet
}

// NewSealer creates an ARC sealer and validates the supplied options.
func NewSealer(options *SealOptions) (*Sealer, error) {
	options, err := validateSealOptions(options)
	if err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	pr, pw := io.Pipe()

	s := &Sealer{pw: pw, done: done}

	finish := func(err error) {
		_ = pr.CloseWithError(err)
		done <- err
	}

	go func() {
		defer close(done)

		br := bufio.NewReader(pr)
		headers, err := dkim.ReadHeader(br)
		if err != nil {
			finish(err)
			return
		}

		// Existing ARC fields determine the new instance and which sets the AS
		// must cover.
		chain, err := collectSets(headers)
		if err != nil {
			finish(err)
			return
		}

		chainValidationStatus := options.ChainValidationStatus
		if options.DontCareChainValidation {
			chainValidationStatus = ChainValidationPass
			if chain.getLatestSet() == nil {
				chainValidationStatus = ChainValidationNone
			}
		}

		instance, cv, err := nextARCSet(chain, chainValidationStatus)
		if err != nil {
			finish(err)
			return
		}
		options.ChainValidationStatus = cv

		// Collect Authentication-Results data (from given params or headers)
		authenticationResults := options.AuthenticationResults
		if authenticationResults == nil {
			authenticationResults, err = collectAuthenticationResults(headers, options.AuthservID)
			if err != nil {
				finish(err)
				return
			}
		}
		aar := formatAAR(instance, options.AuthservID, authenticationResults)

		// Define set
		currentSet := &arcSet{
			instance:   instance,
			aar:        aar,
			authservID: options.AuthservID,
		}

		// Hash body (required for AMS)
		hasher := options.Hash.New()
		bodyCanonicalizer, err := dkim.CanonicalizeBody(options.AMSBodyCanonicalization, hasher)
		if err != nil {
			finish(err)
			return
		}
		if _, err := io.Copy(bodyCanonicalizer, br); err != nil {
			finish(err)
			return
		}
		if err := bodyCanonicalizer.Close(); err != nil {
			finish(err)
			return
		}
		bodyHashed := hasher.Sum(nil)

		// Select the keys to sign for AMS
		headerKeys, err := selectAMSHeaderKeys(headers, options.AMSHeaderKeys)
		if err != nil {
			finish(err)
			return
		}

		// timestamp is used for t= value in signatures
		timestamp := now()

		// Create ARC-Message-Signature
		ams, err := createAMS(headers, bodyHashed, headerKeys, instance, timestamp, options)
		if err != nil {
			finish(err)
			return
		}
		currentSet.ams = ams

		// Create ARC-Seal
		seal, err := createSeal(chain, currentSet, timestamp, options)
		if err != nil {
			finish(err)
			return
		}
		currentSet.as = seal

		// After all headers were generated successfully, add the set to the sealer instance and finish.
		s.set = currentSet
		finish(nil)
	}()
	return s, nil
}

// Seal seals a message, writing the new ARC set before the original message.
func Seal(w io.Writer, r io.Reader, options *SealOptions) error {
	s, err := NewSealer(options)
	if err != nil {
		return err
	}
	// We need to keep the message in a buffer so we can write the new ARC
	// set before the rest of the message
	var b bytes.Buffer
	mw := io.MultiWriter(&b, s)

	_, copyErr := io.Copy(mw, r)
	closeErr := s.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}

	if _, err := io.WriteString(w, s.Set()); err != nil {
		return err
	}
	_, err = io.Copy(w, &b)
	return err
}

// Write implements io.WriteCloser.
func (s *Sealer) Write(b []byte) (n int, err error) {
	return s.pw.Write(b)
}

// Close finishes sealing. Its error return must be checked.
func (s *Sealer) Close() error {
	closeErr := s.pw.Close()
	doneErr := <-s.done
	if doneErr != nil {
		return doneErr
	}
	return closeErr
}

// Set returns the complete ARC set in message-header order. It must only be
// called after Close has succeeded.
func (s *Sealer) Set() string {
	arcSet := s.set
	if arcSet == nil || arcSet.aar == "" || arcSet.ams == "" || arcSet.as == "" {
		panic("arc: Sealer.Set must only be called after a successful Sealer.Close")
	}
	return arcSet.as + arcSet.ams + arcSet.aar
}

// validateSealOptions applies defaults and validates all sealing options.
func validateSealOptions(input *SealOptions) (*SealOptions, error) {
	if input == nil {
		return nil, fmt.Errorf("arc: no options specified")
	}
	options := *input
	if options.Domain == "" {
		return nil, fmt.Errorf("arc: no domain specified")
	}
	if options.Selector == "" {
		return nil, fmt.Errorf("arc: no selector specified")
	}
	if options.Signer == nil {
		return nil, fmt.Errorf("arc: no signer specified")
	}
	if options.AuthservID == "" {
		options.AuthservID = options.Domain
	}
	parsedAuthservID, _, authservErr := authres.Parse(options.AuthservID + "; none")
	if authservErr != nil || parsedAuthservID != options.AuthservID {
		return nil, fmt.Errorf("arc: invalid authentication service identifier %q", options.AuthservID)
	}

	// Validate canonicalization method for AMS
	// The canonicalization types are the same as for dkim.
	if options.AMSHeaderCanonicalization == "" {
		options.AMSHeaderCanonicalization = dkim.CanonicalizationSimple
	}
	if _, ok := dkim.Canonicalizers[options.AMSHeaderCanonicalization]; !ok {
		return nil, fmt.Errorf("arc: unknown header canonicalization %q", options.AMSHeaderCanonicalization)
	}

	if options.AMSBodyCanonicalization == "" {
		options.AMSBodyCanonicalization = dkim.CanonicalizationSimple
	}
	if _, ok := dkim.Canonicalizers[options.AMSBodyCanonicalization]; !ok {
		return nil, fmt.Errorf("arc: unknown body canonicalization %q", options.AMSBodyCanonicalization)
	}

	// Validate algorithm for signing
	// ARC supports the same algorithms as dkim.
	switch options.Signer.Public().(type) {
	case *rsa.PublicKey:
	case ed25519.PublicKey:
		break
	default:
		return nil, fmt.Errorf("arc: unsupported key algorithm %T", options.Signer.Public())
	}

	// Validate algorithm for hashing
	// ARC supports the same algorithms as dkim, which for sealing only is SHA-256.
	switch options.Hash {
	case 0: // sha256 is the default
		options.Hash = crypto.SHA256
	case crypto.SHA256:
		break
	case crypto.SHA1:
		return nil, fmt.Errorf("arc: hash algorithm too weak: sha1")
	default:
		return nil, fmt.Errorf("arc: unsupported hash algorithm")
	}

	// Validate AMS sign field list
	for _, name := range options.AMSHeaderKeys {
		if name == "" || strings.ContainsAny(name, ":;\r\n\t ") {
			return nil, fmt.Errorf("arc: invalid AMS header field name %q", name)
		}
		if isAMSForbiddenHeader(name) {
			return nil, fmt.Errorf("arc: AMS must not sign %s", name)
		}
	}
	// Signing the From header is required (see RFC6376, section 5.4.)
	if options.AMSHeaderKeys != nil && !containsHeader(options.AMSHeaderKeys, "From") {
		return nil, fmt.Errorf("arc: AMS must sign From")
	}
	switch options.ChainValidationStatus {
	case "", ChainValidationNone, ChainValidationPass, ChainValidationFail:
	default:
		return nil, fmt.Errorf("arc: invalid chain validation status %q", options.ChainValidationStatus)
	}
	if options.DontCareChainValidation && options.ChainValidationStatus != "" {
		return nil, fmt.Errorf("arc: chain validation status and dont-care option are mutually exclusive")
	}

	return &options, nil
}

// nextARCSet determines the next instance and its chain validation status.
func nextARCSet(chain *arcChain, cv ChainValidation) (int, ChainValidation, error) {
	latest := chain.getLatestSet()
	if latest == nil {
		if cv == "" {
			cv = ChainValidationNone
		}
		if cv != ChainValidationNone {
			return 0, "", fmt.Errorf("arc: chain validation status must be none when no ARC chain exists")
		}
		return 1, cv, nil
	}

	if latest.instance == MaximumSets {
		return 0, "", fmt.Errorf("arc: cannot add more than %d ARC sets", MaximumSets)
	}
	if latestCV, err := latest.getChainValidationStatus(); err == nil && latestCV == ChainValidationFail {
		return 0, "", fmt.Errorf("arc: cannot extend a chain whose latest ARC-Seal reports cv=fail")
	}
	if cv == "" {
		return 0, "", fmt.Errorf("arc: chain validation status is required when extending an ARC chain")
	}
	if cv == ChainValidationNone {
		return 0, "", fmt.Errorf("arc: chain validation status must be pass or fail when an ARC chain exists")
	}
	if cv == ChainValidationPass {
		if err := chain.validateStructure(); err != nil {
			return 0, "", fmt.Errorf("arc: cannot seal structurally invalid chain with cv=pass: %w", err)
		}
	}
	return latest.instance + 1, cv, nil
}

// selectAMSHeaderKeys returns the message header fields to sign with the AMS.
func selectAMSHeaderKeys(headers dkim.Header, configured []string) ([]string, error) {
	if configured != nil {
		return configured, nil
	}

	keys := make([]string, 0, len(headers))
	for _, field := range headers {
		name, _ := dkim.ParseHeaderField(field)
		if name == "" || isAMSForbiddenHeader(name) {
			continue
		}
		keys = append(keys, name)
	}
	if !containsHeader(keys, "From") {
		return nil, fmt.Errorf("arc: message has no From header field to sign with AMS")
	}
	return keys, nil
}

// signatureAlgorithm returns the ARC compatible algorithm names for a signing key.
func signatureAlgorithm(signer crypto.Signer) (keyAlgorithm, algorithm string, err error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return "rsa", "rsa-sha256", nil
	case ed25519.PublicKey:
		return "ed25519", "ed25519-sha256", nil
	default:
		return "", "", fmt.Errorf("arc: unsupported key algorithm %T", signer.Public())
	}
}

// isAMSForbiddenHeader reports whether RFC 8617 forbids signing a field with
// the AMS.
func isAMSForbiddenHeader(name string) bool {
	return strings.EqualFold(name, authres.AuthenticationResultsHeader) ||
		strings.EqualFold(name, arcAuthenticationResultsHeader) ||
		strings.EqualFold(name, arcMessageSignatureHeader) ||
		strings.EqualFold(name, arcSealHeader)
}

// containsHeader reports whether headers contains name, ignoring case.
func containsHeader(headers []string, name string) bool {
	for _, header := range headers {
		if strings.EqualFold(header, name) {
			return true
		}
	}
	return false
}

// signDigest signs a digest with the options required by the key algorithm.
func signDigest(signer crypto.Signer, keyAlgorithm string, hash crypto.Hash, digest []byte) ([]byte, error) {
	options := crypto.SignerOpts(hash)
	if keyAlgorithm == "ed25519" {
		options = crypto.Hash(0)
	}
	signature, err := signer.Sign(randReader, digest, options)
	if err != nil {
		return nil, fmt.Errorf("arc: failed to sign: %w", err)
	}
	return signature, nil
}
