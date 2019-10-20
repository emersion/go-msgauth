package authres

import (
	"sort"
	"strings"
	"unicode"
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
	case *DMARCResult:
		return "dmarc"
	case *GenericResult:
		return r.Method
	default:
		return ""
	}
}

func formatParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "reason" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if params["reason"] != "" {
		keys = append([]string{"reason"}, keys...)
	}

	s := ""
	i := 0
	for _, k := range keys {
		if params[k] == "" {
			continue
		}

		if i > 0 {
			s += " "
		}

		var value string
		if k == "reason" {
			value = formatValue(params[k])
		} else {
			value = formatPvalue(params[k])
		}
		s += k + "=" + value
		i++
	}

	return s
}

var tspecials = map[rune]struct{}{
	'(': {}, ')': {}, '<': {}, '>': {}, '@': {},
	',': {}, ';': {}, ':': {}, '\\': {}, '"': {},
	'/': {}, '[': {}, ']': {}, '?': {}, '=': {},
}

func formatValue(s string) string {
	// value := token / quoted-string
	// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
	//            or tspecials>
	// tspecials :=  "(" / ")" / "<" / ">" / "@" /
	//               "," / ";" / ":" / "\" / <">
	//               "/" / "[" / "]" / "?" / "="
	//               ; Must be in quoted-string,
	//               ; to use within parameter values

	shouldQuote := false
	for _, ch := range s {
		if _, special := tspecials[ch]; ch <= ' ' /* SPACE or CTL */ || special {
			shouldQuote = true
		}
	}

	if shouldQuote {
		return `"` + strings.Replace(s, `"`, `\"`, -1) + `"`
	}
	return s
}

var addressOk = map[rune]struct{}{
	// Most ASCII punctuation except for:
	//  ( ) = "
	// as these can cause issues due to ambiguous ABNF rules.
	// I.e. technically mentioned characters can be left unquoted, but they can
	// be interpreted as parts of non-quoted parameters or comments so it is
	// better to quote them.
	'#': {}, '$': {}, '%': {}, '&': {},
	'\'': {}, '*': {}, '+': {}, ',': {},
	'.': {}, '/': {}, '-': {}, '@': {},
	'[': {}, ']': {}, '\\': {}, '^': {},
	'_': {}, '`': {}, '{': {}, '|': {},
	'}': {}, '~': {},
}

func formatPvalue(s string) string {
	// pvalue = [CFWS] ( value / [ [ local-part ] "@" ] domain-name )
	//          [CFWS]

	// Experience shows that implementers often "forget" that things can
	// be quoted in various places where they are usually not quoted
	// so we can't get away by just quoting everything.

	// Relevant ABNF rules are much complicated than that, but this
	// will catch most of the cases and we can fallback to quoting
	// for others.
	addressLike := true
	for _, ch := range s {
		if _, ok := addressOk[ch]; !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && !ok {
			addressLike = false
		}
	}

	if addressLike {
		return s
	}
	return formatValue(s)
}
