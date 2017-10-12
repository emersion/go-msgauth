package dkim

import (
	"io"
	"strings"
)

type canonicalizer interface {
	CanonicalizeHeader(s string) string
	CanonicalizeBody(w io.Writer) io.WriteCloser
}

var canonicalizers = map[string]canonicalizer{
	"simple":  new(simpleCanonicalizer),
	"relaxed": new(relaxedCanonicalizer),
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
	b = append(c.crlfBuf, b...)

	end := len(b)
	for end > 0 {
		if ch := b[end-1]; ch != '\r' && ch != '\n' {
			break
		}
		end--
	}
	if end == 0 {
		c.crlfBuf = b
		return len(b), nil
	}

	if end > 0 {
		n, err := c.w.Write(c.crlfBuf)
		c.crlfBuf = c.crlfBuf[n:]
		if err != nil {
			return 0, err
		}
	}

	c.crlfBuf = b[end:]

	var err error
	if end > 0 {
		_, err = c.w.Write(b[:end])
	}
	return len(b), err
}

func (c *simpleBodyCanonicalizer) Close() error {
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
		v = kv[1]
	}
	lines := strings.Split(v, crlf)
	lines[0] = strings.TrimLeft(lines[0], " \t")

	v = ""
	for _, l := range lines {
		if len(l) == 0 {
			break
		}

		if l[0] == ' ' || l[0] == '\t' {
			v += " "
		}
		v += strings.Trim(l, " \t")
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

	if _, err := c.w.Write(canonical); err != nil {
		return len(b), err
	}
	return len(b), nil
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
