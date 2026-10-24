package dkim

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
		want int64
	}{
		{"default clock", time.Time{}, 424242},
		{"explicit Unix epoch", time.Unix(0, 0), 0},
		{"before second boundary", time.Unix(424240, 999999999), 424240},
		{"after second boundary", time.Unix(424241, 1), 424241},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expires := time.Unix(tc.want, 0).Add(5 * 24 * time.Hour)
			s, err := NewSigner(&SignOptions{
				Domain: "example.org", Selector: "brisbane", Signer: testPrivateKey,
				Timestamp: tc.at, Expiration: expires,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write([]byte(mailString)); err != nil {
				_ = s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			_, value := parseHeaderField(s.Signature())
			params, err := parseHeaderParams(value)
			if err != nil {
				t.Fatal(err)
			}
			if params["t"] != strconv.FormatInt(tc.want, 10) || params["x"] != strconv.FormatInt(expires.Unix(), 10) {
				t.Fatalf("t=%s x=%s, want %d %d", params["t"], params["x"], tc.want, expires.Unix())
			}
			v, err := Verify(strings.NewReader(s.Signature() + mailString))
			if err != nil || len(v) != 1 {
				t.Fatalf("verify = %v, %v", v, err)
			}
			if v[0].Err != nil {
				t.Fatalf("signature verification: %v", v[0].Err)
			}
		})
	}
}

func TestSignTimestampRange(t *testing.T) {
	for _, at := range []time.Time{time.Unix(-1, 0), time.Unix(1000000000000, 0)} {
		_, err := NewSigner(&SignOptions{
			Domain: "example.org", Selector: "brisbane", Signer: testPrivateKey,
			Timestamp: at,
		})
		if err == nil {
			t.Fatalf("timestamp %d accepted outside the RFC range", at.Unix())
		}
	}
	var out strings.Builder
	if err := Sign(&out, strings.NewReader(mailString), &SignOptions{
		Domain: "example.org", Selector: "brisbane", Signer: testPrivateKey,
		Timestamp: time.Unix(999999999999, 0),
	}); err != nil {
		t.Fatalf("upper-bound timestamp refused: %v", err)
	}
	if !strings.Contains(out.String(), "t=999999999999;") {
		t.Fatal("upper-bound timestamp was not preserved")
	}
}
