// Package dmarc implements DMARC as specified in RFC 7489.
package dmarc

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type AlignmentMode string

const (
	AlignmentStrict  AlignmentMode = "s"
	AlignmentRelaxed               = "r"
)

type FailureOptions int

const (
	FailureAll FailureOptions = 1 << iota // "0"
	FailureAny
	FailureDKIM
	FailureSPF
)

type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyQuarantine        = "quarantine"
	PolicyReject            = "reject"
)

type ReportFormat string

const (
	ReportFormatAFRF ReportFormat = "afrf"
)

// Record is a DMARC record, as defined in RFC 7489 section 6.3.
type Record struct {
	DKIMAlignment      AlignmentMode  // "adkim"
	SPFAlignment       AlignmentMode  // "aspf"
	FailureOptions     FailureOptions // "fo"
	Policy             Policy         // "p"
	Percent            *int           // "pct"
	ReportFormat       []ReportFormat // "rf"
	ReportInterval     time.Duration  // "ri"
	ReportURIAggregate []string       // "rua"
	ReportURIFailure   []string       // "ruf"
	SubdomainPolicy    Policy         // "sp"
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dmarc: " + string(err)
}

// IsTempFail returns true if the error returned by Verify is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

// Lookup queries a DMARC record for a specified domain.
func Lookup(domain string) (*Record, error) {
	txts, err := net.LookupTXT("_dmarc." + domain)
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return nil, tempFailError("TXT record unavailable: " + err.Error())
	} else if err != nil {
		return nil, errors.New("dmarc: failed to lookup TXT record: " + err.Error())
	}

	// Long keys are split in multiple parts
	txt := strings.Join(txts, "")
	params, err := parseParams(txt)
	if err != nil {
		return nil, err
	}

	if params["v"] != "DMARC1" {
		return nil, errors.New("dmarc: unsupported DMARC version")
	}

	rec := new(Record)

	p, ok := params["p"]
	if !ok {
		return nil, errors.New("dmarc: record is missing a 'p' parameter")
	}
	rec.Policy, err = parsePolicy(p, "p")
	if err != nil {
		return nil, err
	}

	if adkim, ok := params["adkim"]; ok {
		rec.DKIMAlignment, err = parseAlignmentMode(adkim, "adkim")
		if err != nil {
			return nil, err
		}
	}

	if aspf, ok := params["aspf"]; ok {
		rec.SPFAlignment, err = parseAlignmentMode(aspf, "aspf")
		if err != nil {
			return nil, err
		}
	}

	if fo, ok := params["fo"]; ok {
		rec.FailureOptions, err = parseFailureOptions(fo)
		if err != nil {
			return nil, err
		}
	}

	if pct, ok := params["pct"]; ok {
		i, err := strconv.Atoi(pct)
		if err != nil {
			return nil, fmt.Errorf("dmarc: invalid parameter 'pct': %v", err)
		}
		if i < 0 || i > 100 {
			return nil, fmt.Errorf("dmarc: invalid parameter 'pct': value %v out of bounds", i)
		}
		rec.Percent = &i
	}

	if rf, ok := params["rf"]; ok {
		l := strings.Split(rf, ":")
		rec.ReportFormat = make([]ReportFormat, len(l))
		for i, f := range l {
			switch f {
			case "afrf":
				rec.ReportFormat[i] = ReportFormat(f)
			default:
				return nil, errors.New("dmarc: invalid parameter 'rf'")
			}
		}
	}

	if ri, ok := params["ri"]; ok {
		i, err := strconv.Atoi(ri)
		if err != nil {
			return nil, fmt.Errorf("dmarc: invalid parameter 'ri': %v", err)
		}
		if i <= 0 {
			return nil, fmt.Errorf("dmarc: invalid parameter 'ri': negative or zero duration")
		}
		rec.ReportInterval = time.Duration(i) * time.Second
	}

	if rua, ok := params["rua"]; ok {
		rec.ReportURIAggregate = parseURIList(rua)
	}

	if ruf, ok := params["ruf"]; ok {
		rec.ReportURIFailure = parseURIList(ruf)
	}

	if sp, ok := params["sp"]; ok {
		rec.SubdomainPolicy, err = parsePolicy(sp, "sp")
		if err != nil {
			return nil, err
		}
	}

	return rec, nil
}

func parseParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("dmarc: malformed params")
		}

		params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return params, nil
}

func parsePolicy(s, param string) (Policy, error) {
	switch s {
	case "none", "quarantine", "reject":
		return Policy(s), nil
	default:
		return "", fmt.Errorf("dmarc: invalid policy for parameter '%v'", param)
	}
}

func parseAlignmentMode(s, param string) (AlignmentMode, error) {
	switch s {
	case "r", "s":
		return AlignmentMode(s), nil
	default:
		return "", fmt.Errorf("dmarc: invalid alignment mode for parameter '%v'", param)
	}
}

func parseFailureOptions(s string) (FailureOptions, error) {
	l := strings.Split(s, ":")
	var opts FailureOptions
	for _, o := range l {
		switch strings.TrimSpace(o) {
		case "0":
			opts |= FailureAll
		case "1":
			opts |= FailureAny
		case "d":
			opts |= FailureDKIM
		case "s":
			opts |= FailureSPF
		default:
			return 0, errors.New("dmarc: invalid failure option in parameter 'fo'")
		}
	}
	return opts, nil
}

func parseURIList(s string) []string {
	l := strings.Split(s, ",")
	for i, u := range l {
		l[i] = strings.TrimSpace(u)
	}
	return l
}
