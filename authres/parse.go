package authres

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode"
)

// ResultValue is an authentication result value, as defined in RFC 5451 section
// 6.3.
type ResultValue string

const (
	ResultNone      ResultValue = "none"
	ResultPass                  = "pass"
	ResultFail                  = "fail"
	ResultPolicy                = "policy"
	ResultNeutral               = "neutral"
	ResultTempError             = "temperror"
	ResultPermError             = "permerror"
	ResultHardFail              = "hardfail"
	ResultSoftFail              = "softfail"
)

// Result is an authentication result.
type Result interface {
	parse(value ResultValue, params map[string]string)
	format() (value ResultValue, params map[string]string)
}

type AuthResult struct {
	Value  ResultValue
	Reason string
	Auth   string
}

func (r *AuthResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.Auth = params["smtp.auth"]
}

func (r *AuthResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{"smtp.auth": r.Auth}
}

type DKIMResult struct {
	Value      ResultValue
	Reason     string
	Domain     string
	Identifier string
}

func (r *DKIMResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.Domain = params["header.d"]
	r.Identifier = params["header.i"]
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

func (r *DomainKeysResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.Domain = params["header.d"]
	r.From = params["header.from"]
	r.Sender = params["header.sender"]
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

func (r *IPRevResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.IP = params["policy.iprev"]
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

func (r *SenderIDResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]

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

func (r *SPFResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.From = params["smtp.mailfrom"]
	r.Helo = params["smtp.helo"]
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

func (r *DMARCResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Reason = params["reason"]
	r.From = params["header.from"]
}

func (r *DMARCResult) format() (ResultValue, map[string]string) {
	return r.Value, map[string]string{
		"reason":      r.Reason,
		"header.from": r.From,
	}
}

type GenericResult struct {
	Method string
	Value  ResultValue
	Params map[string]string
}

func (r *GenericResult) parse(value ResultValue, params map[string]string) {
	r.Value = value
	r.Params = params
}

func (r *GenericResult) format() (ResultValue, map[string]string) {
	return r.Value, r.Params
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
	"dmarc": func() Result {
		return new(DMARCResult)
	},
}

// Parse parses the provided Authentication-Results header field. It returns the
// authentication service identifier and authentication results.
func Parse(v string) (identifier string, results []Result, err error) {
	p := newParser(v)

	identifier, err = p.getIndentifier()
	if err != nil {
		return identifier, nil, err
	}

	for {
		result, err := p.getResult()
		if result == nil {
			break
		}
		results = append(results, result)
		if err == io.EOF {
			break
		} else if err != nil {
			return identifier, results, err
		}
	}

	return identifier, results, nil
}

type parser struct {
	r *bufio.Reader
}

func newParser(v string) *parser {
	return &parser{r: bufio.NewReader(strings.NewReader(v))}
}

// getIdentifier parses the authserv-id of the authres header and checks the
// version id when present. Ignore header comments in parenthesis.
func (p *parser) getIndentifier() (identifier string, err error) {
	for {
		c, err := p.r.ReadByte()
		if err == io.EOF {
			return identifier, nil
		} else if err != nil {
			return identifier, err
		}
		if c == '(' {
			p.r.UnreadByte()
			p.readComment()
			continue
		}
		if c == ';' {
			break
		}
		identifier += string(c)
	}

	fields := strings.Fields(identifier)
	if len(fields) > 1 {
		version := strings.TrimSpace(fields[1])
		if version != "1" {
			return "", errors.New("msgauth: unknown version")
		}
	} else if len(fields) == 0 {
		return "", errors.New("msgauth: no identifier found")
	}
	return strings.TrimSpace(fields[0]), nil
}

// getResults parses the authentication part of the authres header and returns
// a Result struct. Ignore header comments in parenthesis.
func (p *parser) getResult() (result Result, err error) {
	method, resultvalue, err := p.keyValue()
	if method == "none" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := ResultValue(strings.ToLower(resultvalue))

	params := make(map[string]string)
	var k, v string
	for {
		k, v, err = p.keyValue()
		if k != "" {
			params[k] = v
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
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

	r.parse(value, params)
	return r, nil
}

// keyValue parses a sequence of key=value parameters
func (p *parser) keyValue() (k, v string, err error) {
	k, err = p.readKey()
	if err != nil {
		return
	}
	v, err = p.readValue()
	if err != nil {
		return
	}
	return
}

// readKey reads a method, reason or ptype.property as defined in RFC 8601
// Section 2.2. Ignore the method-version of the methodspec. Stop at EOF or the
// equal sign.
func (p *parser) readKey() (k string, err error) {
	var c byte
	for err != io.EOF {
		c, err = p.r.ReadByte()
		if err != nil {
			break
		}
		switch c {
		case ';':
			err = io.EOF
			break
		case '=':
			break
		case '(':
			p.r.UnreadByte()
			_, err = p.readComment()
			continue
		case '/':
			p.r.ReadBytes('=')
			p.r.UnreadByte()
		default:
			if !unicode.IsSpace(rune(c)) {
				k += string(c)
			}
		}
		if c == '=' {
			break
		}
	}
	k = strings.TrimSpace(strings.ToLower(k))
	return
}

// readValue reads a result or value as defined in RFC 8601 Section 2.2. Value
// is defined as either a token or quoted string according to RFC 2045 Section
// 5.1. Stop at EOF, white space or semi-colons.
func (p *parser) readValue() (v string, err error) {
	var c byte
	for err != io.EOF {
		c, err = p.r.ReadByte()
		if err != nil {
			break
		}
		switch c {
		case ';':
			err = io.EOF
			break
		case '(':
			p.r.UnreadByte()
			_, err = p.readComment()
			continue
		case '"':
			v, err = p.r.ReadString(c)
			v = strings.TrimSuffix(v, string(c))
		default:
			if !unicode.IsSpace(rune(c)) {
				v += string(c)
			}
		}
		if unicode.IsSpace(rune(c)) {
			if v != "" {
				break
			}
		}
	}
	v = strings.TrimSpace(v)
	return
}

func (p *parser) readComment() (comment string, err error) {
	count := 0
	var c byte
	for {
		c, err = p.r.ReadByte()
		if err != nil {
			break
		}
		switch c {
		case '\\':
			c, _ = p.r.ReadByte()
			comment += "\\" + string(c)
		case '(':
			count++
		case ')':
			count--
		default:
			comment += string(c)
		}
		if count == 0 {
			break
		}
	}
	comment = strings.TrimSpace(comment)
	return
}
