package msgauth

import (
	"sort"
)

// Format formats an Authentication-Results header.
func Format(identity string, results []Result) string {
	s := identity

	if len(results) == 0 {
		s += "; none"
		return s
	}

	for _, r := range results {
		method := resultMethod(r)
		value, params := r.format()

		s += "; " + method + "=" + string(value) + " " + formatParams(params)
	}

	return s
}

func resultMethod(r Result) string {
	switch r := r.(type) {
	case *AuthResult:
		return "auth"
	case *DKIMResult:
		return "dkim"
	case *DomainKeysResult:
		return "domainkeys"
	case *IPRevResult:
		return "iprev"
	case *SenderIDResult:
		return "sender-id"
	case *SPFResult:
		return "spf"
	case *GenericResult:
		return r.Method
	default:
		return ""
	}
}

func formatParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s := ""
	i := 0
	for _, k := range keys {
		if params[k] == "" {
			continue
		}

		if i > 0 {
			s += " "
		}
		s += k + "=" + params[k]
		i++
	}

	return s
}
