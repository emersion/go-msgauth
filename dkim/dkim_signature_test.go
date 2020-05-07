package dkim

import "testing"

func TestNewDKIMTagPlain(t *testing.T) {
	t1 := NewDKIMTagPlain("a", "123456")
	if t1.Done() {
		t.Errorf("tag Done after init")
	}
	s := t1.GetRemaining()
	if s != "a=123456" {
		t.Errorf("GetRemaining failed after init")
	}
	if ! t1.Done() {
		t.Errorf("!Done after GetRemaining")
	}
	t1.Reset()
	var ok bool
	s, ok = t1.GetString(3)
	if !ok {
		t.Errorf("failed to break after =")
	}
	if s != "a=" {
		t.Errorf("failed to get name=")
	}
	s, ok = t1.GetString(8)
	if ! ok {
		t.Errorf("!ok for entire values")
	}
	if s != "123456" {
		t.Errorf("s bad for GetString")
	}
	if ! t1.Done() {
		t.Errorf("!Done after GetString for all")
	}
	t1.Reset()
	s, ok = t1.GetString(2)
	if !ok {
		t.Errorf("GetString <name>= failed")
	}
	if s != "a=" {
		t.Errorf("GetString <name>= resulted in %v", s)
	}
	if t1.Done() {
		t.Errorf("Done after partial")
	}
	s, ok = t1.GetString(3)
	if ok {
		t.Errorf("GetString returned partial value")
	}
	s, ok = t1.GetString(6)
	if !ok {
		t.Errorf("GetString did not return value")
	}
	if s != "123456" {
		t.Errorf("GetString returned wrong partial %v", s)
	}
	if ! t1.Done() {
		t.Errorf("!Done after getting last bit")
	}
	t1.Reset()
	s, ok = t1.GetString(1)
	if ! ok {
		t.Errorf("GetString <tagname> failed")
	}
	if s != "a" {
		t.Errorf("GetString <tagname> incorrect %v", s)
	}
	s, ok = t1.GetString(4)
	if !ok {
		t.Errorf("GetString failed getting partial")
	}
	if s != "=" {
		t.Errorf("GetString != =")
	}
	s, ok = t1.GetString(6)
	if !ok {
		t.Errorf("GetString remaining failed")
	}
	if s != "123456" {
		t.Errorf("GetString remaining failed: %v", s)
	}
	if ! t1.Done() {
		t.Errorf("Not done after partial")
	}

	t2 := NewDKIMTagPlain("ab", "123456")
	s, ok = t2.GetString(1)
	if ok {
		t.Errorf("incorrectly got part of name: %v", s)
	}
}

func TestNewDKIMTagDelim(t *testing.T) {
	dt := NewDKIMTagDelim("h", []string{"To", "From", "Subject", "Date", "Message-ID",
		"MIME-Version", "Content-Type", "Content-Transfer-Encoding"}, ":")
	s, ok := dt.GetString(1)
	if !ok {
		t.Errorf("failed to get tag-name")
	}
	if s != "h" {
		t.Errorf("tag-name is wrong: %v", s)
	}
	s, ok = dt.GetString(2)
	if !ok {
		t.Errorf("failed to get =")
	}
	if s != "=" {
		t.Errorf("'=' != %v", s)
	}
	s, ok = dt.GetString(2)
	if !ok {
		t.Errorf("did not get To")
	}
	if s != "To" {
		t.Errorf("'%v' != To", s)
	}
	s, ok = dt.GetString(2)
	if !ok {
		t.Errorf("failed to get ;")
	}
	if s != ":" {
		t.Errorf("':' != %v", s)
	}
}

func TestNewDKIMTagBase64(t *testing.T) {
	dt := NewDKIMTagBase64("bh", "7Xgui0yFAxLMluvjaRLRKJPgrOpPtHSIYy/BndZ2zLg=")
	s, ok := dt.GetString(1)
	if ok {
		t.Errorf("got partial tag-name")
	}
	s, ok = dt.GetString(3)
	if !ok {
		t.Errorf("failed to get name=")
		return
	}
	if s != "bh=" {
		t.Errorf("'%v' != bh=", s)
	}
	s, ok = dt.GetString(5)
	if !ok {
		t.Errorf("failed to get b64 data")
	}
	if s != "7Xgui" {
		t.Errorf("'%v' != 7Xgui", s)
	}
	s = dt.GetRemaining()
	if s != "0yFAxLMluvjaRLRKJPgrOpPtHSIYy/BndZ2zLg=" {
		t.Errorf("remaining is incorrect")
	}
}