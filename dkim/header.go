package dkim

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strings"
)

const crlf = "\r\n"

type header []string

func readHeader(r *bufio.Reader) (header, error) {
	tr := textproto.NewReader(r)

	var h header
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return h, fmt.Errorf("failed to read header: %v", err)
		}

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l+crlf)
		}
	}

	return h, nil
}

func writeHeader(w io.Writer, h header) error {
	for _, kv := range h {
		if _, err := w.Write([]byte(kv)); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(crlf))
	return err
}

func foldHeaderField(kv string) string {
	buf := bytes.NewBufferString(kv)

	line := make([]byte, 75) // 78 - len("\r\n\s")
	first := true
	var fold strings.Builder
	for len, err := buf.Read(line); err != io.EOF; len, err = buf.Read(line) {
		if first {
			first = false
		} else {
			fold.WriteString("\r\n ")
		}
		fold.Write(line[:len])
	}

	return fold.String()
}

func parseHeaderField(s string) (k string, v string) {
	kv := strings.SplitN(s, ":", 2)
	k = strings.TrimSpace(kv[0])
	if len(kv) > 1 {
		v = strings.TrimSpace(kv[1])
	}
	return
}

func parseHeaderParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("dkim: malformed header params")
		}

		params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return params, nil
}

// "Folding whitespace (FWS) MAY be included on either side of the colon separator."
// https://tools.ietf.org/html/rfc6376#section-3.5
func wrapHeaders(values string) string {
	var s strings.Builder
	s.WriteString("h=")

	headers := strings.Split(values, ":")
	avail := 75 - len(" h=")

	for i, header := range headers {
		chars := len(header) + 1
		if avail < chars {
			avail = 75
			s.WriteString(crlf)
			s.WriteByte(' ')
		}
		avail -= chars

		s.WriteString(header)
		if i == len(headers) - 1 {
			s.WriteByte(';')
		} else {
			s.WriteByte(':')
		}
	}
	return s.String()
}

func formatHeaderParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	found := false
	for k := range params {
		if k == "b" {
			found = true
		} else {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(params[keys[i]]) == len(params[keys[j]]) {
			return keys[i] < keys[j]
		}
		return len(params[keys[i]]) < len(params[keys[j]])
	})
	if found {
		keys = append(keys, "b")
	}

	var s strings.Builder
	avail := 75 - len(headerFieldName) - len(": ")

	for _, k := range keys {
		v := params[k]

		chars := len(k) + len(v) + 3 // "=; "
		if avail < chars || k == "b" {
			avail = 75
			s.WriteString(crlf)
		}
		s.WriteByte(' ')

		avail -= chars
		if avail < 0 {
			if k == "h" {
				s.WriteString(wrapHeaders(v))
			} else {
				s.WriteString(foldHeaderField(k + "=" + v + ";"))
			}
		} else {
			s.WriteString(k)
			s.WriteByte('=')
			s.WriteString(v)
			s.WriteByte(';')
		}
	}
	return s.String()
}

type headerPicker struct {
	h      header
	picked map[string]int
}

func newHeaderPicker(h header) *headerPicker {
	return &headerPicker{
		h:      h,
		picked: make(map[string]int),
	}
}

func (p *headerPicker) Pick(key string) string {
	key = strings.ToLower(key)
	at := p.picked[key]
	for i := len(p.h) - 1; i >= 0; i-- {
		kv := p.h[i]
		k, _ := parseHeaderField(kv)

		if strings.ToLower(k) != key {
			continue
		}

		if at == 0 {
			p.picked[key]++
			return kv
		}
		at--
	}

	return ""
}
