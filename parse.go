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
type Result interface {
	parse(value ResultValue, params map[string]string)
	format() (value ResultValue, params map[string]string)
}

type AuthResult struct {
	Value ResultValue
	Auth string
}

func (r *AuthResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Auth = params["smtp.auth"]
}

func (r *AuthResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{"smtp.auth": r.Auth}
}

type DKIMResult struct {
	Value ResultValue
	Domain string
	Identifier string
}

func (r *DKIMResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Domain = params["header.d"]
	r.Identifier = params["header.i"]
}

func (r *DKIMResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"header.d": r.Domain,
		"header.i": r.Identifier,
	}
}

type DomainKeysResult struct {
	Value ResultValue
	Domain string
	From string
	Sender string
}

func (r *DomainKeysResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Domain = params["header.d"]
	r.From = params["header.from"]
	r.Sender = params["header.sender"]
}

func (r *DomainKeysResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"header.d": r.Domain,
		"header.from": r.From,
		"header.sender": r.Sender,
	}
}

type IPRevResult struct {
	Value ResultValue
	IP string
}

func (r *IPRevResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.IP = params["policy.iprev"]
}

func (r *IPRevResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{"policy.iprev": r.IP}
}

type SenderIDResult struct {
	Value ResultValue
	HeaderKey string
	HeaderValue string
}

func (r *SenderIDResult) parse(value ResultValue, params map[string]string) {
	r.Value = value

	for k, v := range params {
		if strings.HasPrefix(k, "header.") {
			r.HeaderKey = strings.TrimPrefix(k, "header.")
			r.HeaderValue = v
			break
		}
	}
}

func (r *SenderIDResult) format() (value ResultValue, params map[string]string) {
	return r.Value, map[string]string{
		"header."+strings.ToLower(r.HeaderKey): r.HeaderValue,
	}
}

type SPFResult struct {
	Value ResultValue
	From string
	Helo string
}

func (r *SPFResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.From = params["smtp.mailfrom"]
	r.Helo = params["smtp.helo"]
}

func (r *SPFResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"smtp.mailfrom": r.From,
		"smtp.helo": r.Helo,
	}
}

type GenericResult struct {
	Value ResultValue
	Params map[string]string
}

func (r *GenericResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Params = params
}

func (r *GenericResult) format() (ResultValue, map[string]string) {
	return r.Value, r.Params
}

func newGenericResult() Result {
	return new(GenericResult)
}

type newResultFunc func() Result

var results = map[string]newResultFunc{
	"auth": func() Result {
		return new(AuthResult)
	},
	"dkim": func() Result {
		return new(DKIMResult)
	},
	"domainkeys": func() Result {
		return new(DomainKeysResult)
	},
	"iprev": func() Result {
		return new(IPRevResult)
	},
	"sender-id": func() Result {
		return new(SenderIDResult)
	},
	"spf": func() Result {
		return new(SPFResult)
	},
}

// Parse parses the provided Authentication-Results header field. It returns the
// authentication service identifier and authentication results.
func Parse(v string) (identifier string, results []Result, err error) {
	parts := strings.Split(v, ";")
	identifier = strings.TrimSpace(parts[0]) // TODO: parse version

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
		newResult = newGenericResult
	}
	r := newResult()

	r.parse(value, params)
	return r, nil
}

func parseParam(s string) (k string, v string, err error) {
	kv := strings.SplitN(s, "=", 2)
	if len(kv) != 2 {
		return "", "", errors.New("msgauth: malformed authentication method and value")
	}
	return strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1]), nil
}
