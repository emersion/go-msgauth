package arc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

// collectSets retrieves all ARC sets from the given headers
// and returns the Authenticated Received Chain.
func collectSets(h dkim.Header) (*arcChain, error) {
	instanceMap := make(map[int]*arcSet)
	arcFieldCount := 0
	for _, field := range h {
		name, value := dkim.ParseHeaderField(field)
		// Check if the field is an ARC header field.
		if !strings.EqualFold(name, arcAuthenticationResultsHeader) &&
			!strings.EqualFold(name, arcMessageSignatureHeader) &&
			!strings.EqualFold(name, arcSealHeader) {
			continue
		}
		arcFieldCount++

		// Extract the ARC header data needed to associate the field with a set.
		var instance int
		var params map[string]string
		var authservID string
		var authResults []authres.Result
		var err error
		if strings.EqualFold(name, arcAuthenticationResultsHeader) {
			var payload string
			instance, payload, err = splitAAR(value)
			if err == nil {
				// The authres payload is useful metadata, but RFC 8617, Section
				// 3.4 says its syntax does not affect ARC chain validity.
				identifier, results, parseErr := authres.Parse(payload)
				if parseErr == nil {
					authservID, authResults = identifier, results
				}
			}
		} else {
			params, err = dkim.ParseHeaderParams(value)
			if err == nil {
				instance, err = parseInstance(params["i"])
			}
		}
		if err != nil {
			return nil, fmt.Errorf("arc: malformed %s: %w", name, err)
		}

		set := instanceMap[instance]
		if set == nil {
			set = &arcSet{instance: instance}
			instanceMap[instance] = set
		}

		// Find duplicate headers in a single instance.
		// Each ARC set should contain the three header fields exactly once.
		switch {
		case strings.EqualFold(name, arcAuthenticationResultsHeader):
			if set.aar != "" {
				return nil, fmt.Errorf("arc: duplicate ARC-Authentication-Results for instance %d", instance)
			}
			set.aar = field
			set.authservID = authservID
			set.authResults = authResults
		case strings.EqualFold(name, arcMessageSignatureHeader):
			if set.ams != "" {
				return nil, fmt.Errorf("arc: duplicate ARC-Message-Signature for instance %d", instance)
			}
			set.ams = field
			set.amsParams = params
		case strings.EqualFold(name, arcSealHeader):
			if set.as != "" {
				return nil, fmt.Errorf("arc: duplicate ARC-Seal for instance %d", instance)
			}
			set.as = field
			set.asParams = params
		}
	}

	if arcFieldCount == 0 {
		return &arcChain{sets: []*arcSet{}}, nil
	}

	if len(instanceMap) > MaximumSets {
		return nil, fmt.Errorf("arc: too many ARC sets")
	}

	// Sort sets by their instance
	sets := make([]*arcSet, 0, len(instanceMap))
	for _, set := range instanceMap {
		sets = append(sets, set)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].instance < sets[j].instance })
	return &arcChain{sets: sets}, nil
}
