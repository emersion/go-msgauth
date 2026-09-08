package authres

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ResultValue is an authentication result value, as defined in RFC 5451 section
// 6.3.
type ResultValue string

const (
	ResultNone      ResultValue = "none"
	ResultPass      ResultValue = "pass"
	ResultFail      ResultValue = "fail"
	ResultPolicy    ResultValue = "policy"
	ResultNeutral   ResultValue = "neutral"
	ResultTempError ResultValue = "temperror"
	ResultPermError ResultValue = "permerror"
	ResultHardFail  ResultValue = "hardfail"
	ResultSoftFail  ResultValue = "softfail"
)

// Result is an authentication result.
type Result interface {
	parse(value ResultValue, params map[string]string) error
	format() (value ResultValue, params map[string]string)
}

type AuthResult struct {
	Value  ResultValue
	Reason string
	Auth   string
}

func (r *AuthResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.Auth = params["smtp.auth"]
	return nil
}

func (r *AuthResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":    r.Reason,
		"smtp.auth": r.Auth,
	}
}

type DKIMResult struct {
	Value      ResultValue
	Reason     string
	Domain     string
	Identifier string
}

func (r *DKIMResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.Domain = params["header.d"]
	r.Identifier = params["header.i"]
	return nil
}

func (r *DKIMResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":   r.Reason,
		"header.d": r.Domain,
		"header.i": r.Identifier,
	}
}

type DomainKeysResult struct {
	Value  ResultValue
	Reason string
	Domain string
	From   string
	Sender string
}

func (r *DomainKeysResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.Domain = params["header.d"]
	r.From = params["header.from"]
	r.Sender = params["header.sender"]
	return nil
}

func (r *DomainKeysResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":        r.Reason,
		"header.d":      r.Domain,
		"header.from":   r.From,
		"header.sender": r.Sender,
	}
}

type IPRevResult struct {
	Value  ResultValue
	Reason string
	IP     string
}

func (r *IPRevResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.IP = params["policy.iprev"]
	return nil
}

func (r *IPRevResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":       r.Reason,
		"policy.iprev": r.IP,
	}
}

type SenderIDResult struct {
	Value       ResultValue
	Reason      string
	HeaderKey   string
	HeaderValue string
}

func (r *SenderIDResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]

	for k, v := range params {
		if strings.HasPrefix(k, "header.") {
			r.HeaderKey = strings.TrimPrefix(k, "header.")
			r.HeaderValue = v
			break
		}
	}

	return nil
}

func (r *SenderIDResult) format() (value ResultValue, params map[string]string) {
	return r.Value, map[string]string{
		"reason":                                 r.Reason,
		"header." + strings.ToLower(r.HeaderKey): r.HeaderValue,
	}
}

type SPFResult struct {
	Value  ResultValue
	Reason string
	From   string
	Helo   string
}

func (r *SPFResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.From = params["smtp.mailfrom"]
	r.Helo = params["smtp.helo"]
	return nil
}

func (r *SPFResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":        r.Reason,
		"smtp.mailfrom": r.From,
		"smtp.helo":     r.Helo,
	}
}

type DMARCResult struct {
	Value  ResultValue
	Reason string
	From   string
}

func (r *DMARCResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Reason = params["reason"]
	r.From = params["header.from"]
	return nil
}

func (r *DMARCResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":      r.Reason,
		"header.from": r.From,
	}
}

type ARCResult struct {
	Value      ResultValue
	RemoteIP   string
	OldestPass int
}

func (r *ARCResult) parse(value ResultValue, params map[string]string) error {
	var oldestPass int
	if s, ok := params["header.oldest-pass"]; ok {
		var err error
		oldestPass, err = strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid header.oldest-pass param: %v", err)
		} else if oldestPass < 0 {
			return fmt.Errorf("invalid header.oldest-pass param: must be >= 0")
		}
	}

	r.Value = value
	r.RemoteIP = params["smtp.remote-ip"]
	r.OldestPass = oldestPass
	return nil
}

func (r *ARCResult) format() (ResultValue, map[string]string) {
	oldestPass := ""
	if r.OldestPass >= 0 {
		oldestPass = strconv.Itoa(r.OldestPass)
	}

	return r.Value, map[string]string{
		"smtp.remote-ip":     r.RemoteIP,
		"header.oldest-pass": oldestPass,
	}
}

type GenericResult struct {
	Method string
	Value  ResultValue
	Params map[string]string
}

func (r *GenericResult) parse(value ResultValue, params map[string]string) error {
	r.Value = value
	r.Params = params
	return nil
}

func (r *GenericResult) format() (ResultValue, map[string]string) {
	return r.Value, r.Params
}

type newResultFunc func() Result

var results = map[string]newResultFunc{
	"arc": func() Result {
		return new(ARCResult)
	},
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
	"dmarc": func() Result {
		return new(DMARCResult)
	},
}

// Parse parses the provided Authentication-Results header field. It returns the
// authentication service identifier and authentication results.
func Parse(v string) (identifier string, results []Result, err error) {
	parts, err := splitAuthres(v)
	if err != nil {
		return "", nil, err
	}

	identifierFields, err := authresFields(parts[0])
	if err != nil {
		return "", nil, err
	}
	if len(identifierFields) > 0 {
		identifier, err = parseValue(identifierFields[0])
		if err != nil {
			return "", nil, fmt.Errorf("msgauth: malformed authentication service identifier: %w", err)
		}
	}
	if len(identifierFields) > 2 {
		return identifier, nil, errors.New("msgauth: malformed authentication service identifier")
	}
	if len(identifierFields) == 2 && identifierFields[1] != "1" {
		return identifier, nil, errors.New("msgauth: unsupported version")
	}

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

// ParseWithDefaultAuthservID parses an Authentication-Results header field and
// uses defaultAuthservID when the payload starts with an authentication method
// instead of an authserv-id. Standards-compliant payloads are parsed exactly as
// Parse would parse them.
//
// An authserv-id identifies the trust domain that produced the results. Callers
// must only provide a default for header fields received from a trusted source;
// otherwise, an untrusted sender could inject results that appear to be local.
func ParseWithDefaultAuthservID(v, defaultAuthservID string) (identifier string, results []Result, err error) {
	parts, err := splitAuthres(v)
	if err != nil {
		return "", nil, err
	}

	fields, err := authresFields(parts[0])
	if err != nil {
		return "", nil, err
	}
	if len(fields) == 0 || !looksLikeMethodSpec(fields[0]) {
		return Parse(v)
	}
	if defaultAuthservID == "" {
		return "", nil, errors.New("msgauth: missing default authentication service identifier")
	}

	return Parse(defaultAuthservID + "; " + v)
}

func looksLikeMethodSpec(s string) bool {
	// A quoted string can be a valid authserv-id and may contain an equals sign.
	if strings.HasPrefix(s, `"`) {
		return false
	}
	method, result, ok := strings.Cut(s, "=")
	return ok && method != "" && result != ""
}

func parseResult(s string) (Result, error) {
	parts, err := authresFields(s)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 || parts[0] == "none" {
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
			return nil, err
		}

		params[k] = v
	}

	newResult, ok := results[method]

	var r Result
	if ok {
		r = newResult()
	} else {
		r = &GenericResult{
			Method: method,
			Value:  value,
			Params: params,
		}
	}

	err = r.parse(value, params)
	return r, err
}

func parseParam(s string) (k string, v string, err error) {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return "", "", errors.New("msgauth: malformed authentication method and value")
	}
	v, err = parseValue(strings.TrimSpace(v))
	if err != nil {
		return "", "", err
	}
	return strings.ToLower(strings.TrimSpace(k)), v, nil
}

// splitAuthres splits an Authentication-Results payload at semicolons while
// preserving semicolons contained in quoted strings or comments.
func splitAuthres(s string) ([]string, error) {
	var parts []string
	start := 0
	inQuote := false
	escaped := false
	commentDepth := 0

	for i, ch := range s {
		if escaped {
			escaped = false
			continue
		}
		if inQuote {
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inQuote = false
			}
			continue
		}
		if commentDepth > 0 {
			switch ch {
			case '\\':
				escaped = true
			case '(':
				commentDepth++
			case ')':
				commentDepth--
			}
			continue
		}

		switch ch {
		case '"':
			inQuote = true
		case '(':
			commentDepth = 1
		case ';':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}

	if inQuote {
		return nil, errors.New("msgauth: unterminated quoted string")
	}
	if commentDepth != 0 {
		return nil, errors.New("msgauth: unterminated comment")
	}
	parts = append(parts, s[start:])
	return parts, nil
}

// authresFields splits a result into whitespace-delimited fields, keeps
// quoted strings intact, and removes RFC comments (including nested ones).
func authresFields(s string) ([]string, error) {
	var fields []string
	var field strings.Builder
	inQuote := false
	escaped := false
	commentDepth := 0

	flush := func() {
		if field.Len() == 0 {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
	}

	for _, ch := range s {
		if escaped {
			if commentDepth == 0 {
				field.WriteRune(ch)
			}
			escaped = false
			continue
		}
		if inQuote {
			field.WriteRune(ch)
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inQuote = false
			}
			continue
		}
		if commentDepth > 0 {
			switch ch {
			case '\\':
				escaped = true
			case '(':
				commentDepth++
			case ')':
				commentDepth--
			}
			continue
		}

		switch {
		case ch == '"':
			inQuote = true
			field.WriteRune(ch)
		case ch == '(':
			flush()
			commentDepth = 1
		case unicode.IsSpace(ch):
			flush()
		default:
			field.WriteRune(ch)
		}
	}

	if inQuote {
		return nil, errors.New("msgauth: unterminated quoted string")
	}
	if commentDepth != 0 {
		return nil, errors.New("msgauth: unterminated comment")
	}
	flush()
	return fields, nil
}

func parseValue(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return s, nil
	}
	if len(s) < 2 || !strings.HasSuffix(s, `"`) {
		return "", errors.New("msgauth: unterminated quoted string")
	}

	var value strings.Builder
	escaped := false
	for _, ch := range s[1 : len(s)-1] {
		if escaped {
			value.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		value.WriteRune(ch)
	}
	if escaped {
		return "", errors.New("msgauth: unterminated quoted pair")
	}
	return value.String(), nil
}
