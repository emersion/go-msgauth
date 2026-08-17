package arc

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

func parseInstance(value string) (int, error) {
	instance, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid instance value: %w", err)
	}
	if instance < 1 || instance > MaximumSets {
		return 0, fmt.Errorf("instance must be between 1 and %d", MaximumSets)
	}
	return instance, nil
}

var aarInstance = regexp.MustCompile(`(?is)^\s*i\s*=\s*([0-9]+)\s*;`)

func splitAAR(value string) (instance int, payload string, err error) {
	match := aarInstance.FindStringSubmatchIndex(value)
	if match == nil {
		return 0, "", fmt.Errorf("ARC-Authentication-Results missing i= tag")
	}
	instance, err = parseInstance(value[match[2]:match[3]])
	if err != nil {
		return 0, "", err
	}
	payload = strings.TrimSpace(value[match[1]:])
	if payload == "" {
		return 0, "", fmt.Errorf("ARC-Authentication-Results has empty authres payload")
	}
	return instance, payload, nil
}

func parseAAR(value string) (instance int, identifier string, results []authres.Result, err error) {
	instance, payload, err := splitAAR(value)
	if err != nil {
		return 0, "", nil, err
	}
	identifier, results, err = authres.Parse(payload)
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid authres payload: %w", err)
	}
	if identifier == "" {
		return 0, "", nil, fmt.Errorf("ARC-Authentication-Results missing authserv-id")
	}
	return instance, identifier, results, nil
}

type headerPicker struct {
	h      dkim.Header
	picked map[string]int
}

func (p *headerPicker) Pick(name string) string {
	name = strings.ToLower(name)
	at := p.picked[name]
	for _, v := range slices.Backward(p.h) {
		fieldName, _ := dkim.ParseHeaderField(v)
		if !strings.EqualFold(fieldName, name) {
			continue
		}
		if at == 0 {
			p.picked[name]++
			return v
		}
		at--
	}
	return ""
}
