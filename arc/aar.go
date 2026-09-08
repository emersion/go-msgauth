package arc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

func collectAuthenticationResults(headers dkim.Header, authservID string) ([]authres.Result, error) {
	var combined []authres.Result
	for _, field := range headers {
		name, value := dkim.ParseHeaderField(field)
		if !strings.EqualFold(name, authres.AuthenticationResultsHeader) {
			continue
		}

		identifier, results, err := authres.ParseWithDefaultAuthservID(value, authservID)
		if err != nil {
			return nil, fmt.Errorf("arc: malformed Authentication-Results: %w", err)
		}
		if !strings.EqualFold(identifier, authservID) {
			// Authentication-Results from another ADMD are not local evidence
			// and therefore must not be copied into the new AAR.
			continue
		}
		combined = append(combined, results...)
	}
	return combined, nil
}

func formatAAR(instance int, authservID string, results []authres.Result) string {
	payload := authres.Format(authservID, results)
	return arcAuthenticationResultsHeader + ": i=" + strconv.Itoa(instance) + "; " + payload + "\r\n"
}
