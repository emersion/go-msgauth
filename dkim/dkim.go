// Package dkim creates and verifies DKIM signatures, as specified in RFC 6376.
package dkim

import (
	"bytes"
	"strings"
	"time"
)

var now = time.Now

const headerFieldName = "DKIM-Signature"

type DKIMTag interface {
	Reset()
	GetString(limit int) (chars string, ok bool)
	GetRemaining() string
	Done() bool
}

type DKIMTagBase64 struct {
	TagLen int
	TagAndValue string
	Idx int
}

func (t *DKIMTagBase64) Reset() {
	t.Idx = 0
}

func (t *DKIMTagBase64) NextBreak(idx int, max int) int {
	if idx == 0 {
		return t.TagLen
	} else if idx == t.TagLen {
		return t.TagLen+1
	} else {
		end := len(t.TagAndValue)
		if max < end {
			return max
		} else {
			return end
		}
	}
}

func (t *DKIMTagBase64) GetString(limit int) (chars string, ok bool) {
	end_max := len(t.TagAndValue)
	if end_max - t.Idx <= limit {
		chars = t.TagAndValue[t.Idx:]
		t.Idx = end_max
		ok = true
		return
	}
	if t.Idx + limit < end_max {
		end_max = t.Idx + limit
	}
	end := t.Idx
	for end < end_max {
		idx := t.NextBreak(end, end_max)
		if idx <= end_max {
			end = idx
		} else {
			break
		}
	}
	if t.Idx < end {
		chars = t.TagAndValue[t.Idx:end]
		t.Idx = end
		ok = true
	}
	return
}

func (t *DKIMTagBase64) GetRemaining() string {
	chars := t.TagAndValue[t.Idx:]
	t.Idx = len(t.TagAndValue)
	return chars
}

func (t *DKIMTagBase64) Done() bool {
	return t.Idx == len(t.TagAndValue)
}

type DKIMTagDelim struct {
	TagLen int
	TagAndValue string
	Delimiter string
	Idx int
}

func (t *DKIMTagDelim) Reset() {
	t.Idx = 0
}

func (t *DKIMTagDelim) NextBreak(idx int) int {
	if idx == 0 {
		return t.TagLen
	} else if idx == t.TagLen {
		return t.TagLen+1
	} else {
		if t.Delimiter == "" {
			return len(t.TagAndValue)
		} else {
			i := strings.Index(t.TagAndValue[idx:], t.Delimiter)
			if i == -1 {
				return len(t.TagAndValue)
			} else {
				if i == 0 {
					return idx + len(t.Delimiter)
				} else {
					return i + idx
				}
			}
		}
	}
}

func (t *DKIMTagDelim) GetString(limit int) (chars string, ok bool) {
	end_max := len(t.TagAndValue)
	if end_max - t.Idx <= limit {
		chars = t.TagAndValue[t.Idx:]
		t.Idx = end_max
		ok = true
		return
	}
	if t.Idx + limit < end_max {
		end_max = t.Idx + limit
	}
	end := t.Idx
	for end < end_max {
		idx := t.NextBreak(end)
		if idx <= end_max {
			end = idx
		} else {
			break
		}
	}
	if t.Idx < end {
		chars = t.TagAndValue[t.Idx:end]
		t.Idx = end
		ok = true
	}
	return
}

func (t *DKIMTagDelim) GetRemaining() string {
	chars := t.TagAndValue[t.Idx:]
	t.Idx = len(t.TagAndValue)
	return chars
}

func (t *DKIMTagDelim) Done() bool {
	return t.Idx == len(t.TagAndValue)
}

func NewDKIMTagPlain(tag string, value string) DKIMTag {
	dtag := &DKIMTagDelim{
		TagLen: len(tag),
		TagAndValue: tag+"="+value,
	}
	return dtag
}

func NewDKIMTagDelim(tag string, values []string, delimiter string) DKIMTag {
	var sbuf bytes.Buffer
	sbuf.WriteString(tag)
	sbuf.WriteString("=")
	for idx, value := range values {
		if idx > 0 {
			sbuf.WriteString(delimiter)
		}
		sbuf.WriteString(value)
	}
	dtag := &DKIMTagDelim{
		TagLen: len(tag),
		TagAndValue: sbuf.String(),
		Delimiter: delimiter,
	}
	return dtag
}

func NewDKIMTagBase64(tag string, value string) DKIMTag {
	dtag := &DKIMTagBase64{
		TagLen: len(tag),
		TagAndValue: tag+"="+value,
	}
	return dtag
}

type DKIMSignature struct {
	Buf bytes.Buffer
	LineLen int
}

func (sig *DKIMSignature) AddTag(tag DKIMTag) {
	tag.Reset()
	for ! tag.Done() {
		max_chars := 80 - sig.LineLen - 1 - 2 // allow for CRLF and also the semi-colon
		if max_chars <= 0 {
			sig.Buf.WriteString("\r\n ")
			sig.LineLen = 1
			continue
		}
		s, ok := tag.GetString(max_chars)
		if !ok {
			if sig.LineLen > 1 {
				sig.Buf.WriteString("\r\n ")
				sig.LineLen = 1
				continue
			} else {
				// we can't break the line, we are forced to just put it in
				s = tag.GetRemaining()
			}
		}
		sig.Buf.WriteString(s)
		sig.LineLen += len(s)
		if tag.Done() {
			sig.Buf.WriteString(";")
			sig.LineLen += 1
		}
	}
}

func (sig *DKIMSignature) AddPlainTag(tag string, value string) {
	sig.AddTag(NewDKIMTagPlain(tag, value))
}

func (sig *DKIMSignature) AddDelimTag(tag string, values []string, delimiter string) {
	sig.AddTag(NewDKIMTagDelim(tag, values, delimiter))
}

func (sig *DKIMSignature) AddBase64Tag(tag string, value string) {
	sig.AddTag(NewDKIMTagBase64(tag, value))
}

func NewDKIMSignature() *DKIMSignature {
	sig := DKIMSignature{}
	sig.Buf.WriteString(headerFieldName)
	sig.Buf.WriteString(": ")
	sig.LineLen = len(headerFieldName)+2
	return &sig
}
