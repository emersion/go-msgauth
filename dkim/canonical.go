package dkim

import (
	"io"
	"regexp"
	"strings"
)

var rxReduceWS = regexp.MustCompile(`[ \t\r\n]+`)

// Canonicalization is a canonicalization algorithm.
type Canonicalization string

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed                  = "relaxed"
)

type canonicalizer interface {
	CanonicalizeHeader(s string) string
	CanonicalizeBody(w io.Writer) io.WriteCloser
}

var canonicalizers = map[Canonicalization]canonicalizer{
	CanonicalizationSimple:  new(simpleCanonicalizer),
	CanonicalizationRelaxed: new(relaxedCanonicalizer),
}

// Fix any \n without a matching \r
func fixCRLF(b []byte) []byte {
	res := make([]byte, 0, len(b))
	for i := range b {
		if b[i] == '\n' && (i == 0 || b[i-1] != '\r') {
			res = append(res, '\r')
		}
		res = append(res, b[i])
	}
	return res
}

type simpleCanonicalizer struct{}

func (c *simpleCanonicalizer) CanonicalizeHeader(s string) string {
	return s
}

type simpleBodyCanonicalizer struct {
	w       io.Writer
	crlfBuf []byte
}

func (c *simpleBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)
	b = append(c.crlfBuf, b...)

	b = fixCRLF(b)

	end := len(b)
	// If it ends with \r, maybe the next write will begin with \n
	if end > 0 && b[end-1] == '\r' {
		end--
	}
	// Keep all \r\n sequences
	for end >= 2 {
		prev := b[end-2]
		cur := b[end-1]
		if prev != '\r' || cur != '\n' {
			break
		}
		end -= 2
	}

	c.crlfBuf = b[end:]

	var err error
	if end > 0 {
		_, err = c.w.Write(b[:end])
	}
	return written, err
}

func (c *simpleBodyCanonicalizer) Close() error {
	// Flush crlfBuf if it ends with a single \r (without a matching \n)
	if len(c.crlfBuf) > 0 && c.crlfBuf[len(c.crlfBuf)-1] == '\r' {
		if _, err := c.w.Write(c.crlfBuf); err != nil {
			return err
		}
	}
	c.crlfBuf = nil

	if _, err := c.w.Write([]byte(crlf)); err != nil {
		return err
	}
	return nil
}

func (c *simpleCanonicalizer) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &simpleBodyCanonicalizer{w: w}
}

type relaxedCanonicalizer struct{}

func (c *relaxedCanonicalizer) CanonicalizeHeader(s string) string {
	kv := strings.SplitN(s, ":", 2)

	k := strings.TrimSpace(strings.ToLower(kv[0]))

	var v string
	if len(kv) > 1 {
		v = rxReduceWS.ReplaceAllString(kv[1], " ")
		v = strings.TrimSpace(v)

	}

	return k + ":" + v + crlf
}

type relaxedBodyCanonicalizer struct {
	w       io.Writer
	crlfBuf []byte
	wspBuf  []byte
	written bool
}

func (c *relaxedBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)

	b = fixCRLF(b)

	canonical := make([]byte, 0, len(b))
	for _, ch := range b {
		if ch == ' ' || ch == '\t' {
			c.wspBuf = append(c.wspBuf, ch)
		} else if ch == '\r' || ch == '\n' {
			c.wspBuf = nil
			c.crlfBuf = append(c.crlfBuf, ch)
		} else {
			if len(c.crlfBuf) > 0 {
				canonical = append(canonical, c.crlfBuf...)
				c.crlfBuf = nil
			}
			if len(c.wspBuf) > 0 {
				canonical = append(canonical, ' ')
				c.wspBuf = nil
			}

			canonical = append(canonical, ch)
		}
	}

	if !c.written && len(canonical) > 0 {
		c.written = true
	}

	_, err := c.w.Write(canonical)
	return written, err
}

func (c *relaxedBodyCanonicalizer) Close() error {
	if c.written {
		if _, err := c.w.Write([]byte(crlf)); err != nil {
			return err
		}
	}
	return nil
}

func (c *relaxedCanonicalizer) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &relaxedBodyCanonicalizer{w: w}
}

type limitedWriter struct {
	W io.Writer
	N int64
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	if w.N <= 0 {
		return len(b), nil
	}

	skipped := 0
	if int64(len(b)) > w.N {
		b = b[:w.N]
		skipped = int(int64(len(b)) - w.N)
	}

	n, err := w.W.Write(b)
	w.N -= int64(n)
	return n + skipped, err
}
