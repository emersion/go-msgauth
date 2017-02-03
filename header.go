package dkim

import (
	"bufio"
	"io"
)

const crlf = "\r\n"

type header []string

func readHeader(r io.Reader) (header, error) {
	s := bufio.NewScanner(r)

	var h header
	for s.Scan() {
		l := s.Text()

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l + crlf)
		}
	}

	return h, s.Err()
}
