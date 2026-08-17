package arc

import (
	"fmt"

	"github.com/emersion/go-msgauth/authres"
)

type arcSet struct {
	instance    int
	aar         string
	ams         string
	as          string
	authservID  string
	authResults []authres.Result
	amsParams   map[string]string
	asParams    map[string]string
}

type arcChain struct {
	sets []*arcSet
}

// getLatestSet returns the latest set with the highest instance
// number from the Authenticated Received Chain.
func (chain *arcChain) getLatestSet() *arcSet {
	if len(chain.sets) == 0 {
		return nil
	}
	return chain.sets[len(chain.sets)-1]
}

// getChainValidationStatus retrieves the chain validation status from a
// ARC Sets ARC-Seal header.
func (set *arcSet) getChainValidationStatus() (ChainValidation, error) {
	cv := set.asParams["cv"]
	switch cv {
	case "none":
		return ChainValidationNone, nil
	case "pass":
		return ChainValidationPass, nil
	case "fail":
		return ChainValidationFail, nil
	default:
		return "", fmt.Errorf("arc: invalid or missing cv tag in ARC-Seal for instance %d", set.instance)
	}
}

// validateStructure checks the structural conditions that must hold before a
// sealer can truthfully extend a chain with cv=pass.
func (chain *arcChain) validateStructure() error {
	for i, set := range chain.sets {
		wantInstance := i + 1
		if set.instance != wantInstance {
			return fmt.Errorf("arc: ARC set instances are not continuous: got %d, want %d", set.instance, wantInstance)
		}
		if set.aar == "" || set.ams == "" || set.as == "" {
			return fmt.Errorf("arc: incomplete ARC set %d", set.instance)
		}

		cv, err := set.getChainValidationStatus()
		if err != nil {
			return err
		}
		wantCV := ChainValidationPass
		// if the instance is the first, it should have the chain validation status "none".
		if set.instance == 1 {
			wantCV = ChainValidationNone
		}
		if cv != wantCV {
			return fmt.Errorf("arc: ARC-Seal for instance %d has cv=%s, want cv=%s", set.instance, cv, wantCV)
		}
	}
	return nil
}
