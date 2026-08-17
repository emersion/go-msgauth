package arc

// ChainValidation is the validation status of the ARC chain received by a
// sealer.
type ChainValidation string

const (
	// ChainValidationNone indicates that the received message had no ARC chain.
	ChainValidationNone ChainValidation = "none"
	// ChainValidationFail indicates that validation of the received ARC chain
	// failed.
	ChainValidationFail ChainValidation = "fail"
	// ChainValidationPass indicates that validation of the received ARC chain
	// succeeded.
	ChainValidationPass ChainValidation = "pass"
)

const (
	arcAuthenticationResultsHeader = "ARC-Authentication-Results"
	arcMessageSignatureHeader      = "ARC-Message-Signature"
	arcSealHeader                  = "ARC-Seal"

	// MaximumSets is the largest ARC instance value permitted by RFC 8617.
	MaximumSets = 50
)
