package msgauth

import (
	"errors"
	"strings"
)

// ResultValue is an authentication result value, as defined in RFC 5451 section
// 6.3.
type ResultValue string

const (
	ResultNone ResultValue = "none"
	ResultPass = "pass"
	ResultFail = "fail"
	ResultPolicy = "policy"
	ResultNeutral = "neutral"
	ResultTempError = "temperror"
	ResultPermError = "permerror"
	ResultHardFail = "hardfail"
	ResultSoftFail = "softfail"
)

// Result is an authentication result.
type Result interface {}

type AuthResult struct {
	Value ResultValue
	Auth string
}

type DKIMResult struct {
	Value ResultValue
	Domain string
	Identifier string
}

type DomainKeysResult struct {
	Value ResultValue
	Domain string
	From string
	Sender string
}

type IPRevResult struct {
	Value ResultValue
	IP string
}

type SenderIDResult struct {
	Value ResultValue
	HeaderKey string
	HeaderValue string
}

type SPFResult struct {
	Value ResultValue
	From string
	Helo string
}

type unknownResult struct {
	Value ResultValue
	Params map[string]string
}

type newResultFunc func(v ResultValue, params map[string]string) Result

var results = map[string]newResultFunc{
	"auth": func(v ResultValue, params map[string]string) Result {
		return &AuthResult{Value: v, Auth: params["smtp.auth"]}
	},
	"dkim": func(v ResultValue, params map[string]string) Result {
		return &DKIMResult{Value: v, Domain: params["header.d"], Identifier: params["header.i"]}
	},
	"domainkeys": func(v ResultValue, params map[string]string) Result {
		return &DomainKeysResult{Value: v, Domain: params["header.d"], From: params["header.from"], Sender: params["header.sender"]}
	},
	"iprev": func(v ResultValue, params map[string]string) Result {
		return &IPRevResult{Value: v, IP: params["policy.iprev"]}
	},
	"sender-id": func(v ResultValue, params map[string]string) Result {
		result := &SenderIDResult{Value: v}
		for k, v := range params {
			if strings.HasPrefix(k, "header.") {
				result.HeaderKey = strings.TrimPrefix(k, "header.")
				result.HeaderValue = v
				break
			}
		}
		return result
	},
	"spf": func(v ResultValue, params map[string]string) Result {
		return &SPFResult{Value: v, From: params["smtp.mailfrom"], Helo: params["smtp.helo"]}
	},
}

// Parse parses the provided Authentication-Results header field. It returns the
// authentication service identifier and authentication results.
func Parse(v string) (identifier string, results []Result, err error) {
	parts := strings.Split(v, ";")
	identifier = strings.TrimSpace(parts[0])

	for i := 1; i < len(parts); i++ {
		s := strings.TrimSpace(parts[i])
		if s == "" {
			continue
		}

		result, err := parseResult(s)
		if err != nil {
			return identifier, results, err
		}
		if result != nil {
			results = append(results, result)
		}
	}
	return
}

func parseResult(s string) (Result, error) {
	// TODO: ignore header comments in parenthesis

	// TODO: split on \t too?
	parts := strings.Split(s, " ")

	if parts[0] == "none" {
		return nil, nil
	}

	k, v, err := parseParam(parts[0])
	if err != nil {
		return nil, err
	}
	method, value := k, ResultValue(strings.ToLower(v))

	params := make(map[string]string)
	for i := 1; i < len(parts); i++ {
		k, v, err := parseParam(parts[i])
		if err != nil {
			continue
		}

		params[k] = v
	}

	newResult, ok := results[method]
	if !ok {
		return &unknownResult{Value: value, Params: params}, nil
	}

	return newResult(value, params), nil
}

func parseParam(s string) (k string, v string, err error) {
	kv := strings.SplitN(s, "=", 2)
	if len(kv) != 2 {
		return "", "", errors.New("msgauth: malformed authentication method and value")
	}
	return strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1]), nil
}
