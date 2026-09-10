package arc

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// Run the benchmarks with:
//
//	go test ./arc -run '^$' -bench '^BenchmarkSeal' -benchmem -count=10
//
// Use -cpuprofile and -memprofile to inspect CPU and allocation hotspots.

var (
	benchmarkRSAOnce sync.Once
	benchmarkRSAKey  *rsa.PrivateKey
	benchmarkRSAErr  error

	benchmarkEd25519Once sync.Once
	benchmarkEd25519Key  ed25519.PrivateKey
	benchmarkEd25519Err  error

	benchmarkSetLength int
)

// BenchmarkSealMessageSize measures the Seal helper function for different
// message sizes. Seal buffers the original message before writing the ARC set.
func BenchmarkSealMessageSize(b *testing.B) {
	signer := benchmarkRSASigner(b)

	for _, bodySize := range []int{1 << 10, 100 << 10, 1 << 20, 10 << 20} {
		message := benchmarkMessage(bodySize)
		b.Run(benchmarkSizeName(bodySize), func(b *testing.B) {
			benchmarkSeal(b, message, benchmarkOptions(signer, dkim.CanonicalizationRelaxed))
		})
	}
}

// BenchmarkSealerMessageSize measures the streaming Sealer API without the
// complete-message buffer used by Seal.
func BenchmarkSealerMessageSize(b *testing.B) {
	signer := benchmarkRSASigner(b)

	for _, bodySize := range []int{1 << 10, 100 << 10, 1 << 20, 10 << 20} {
		message := benchmarkMessage(bodySize)
		b.Run(benchmarkSizeName(bodySize), func(b *testing.B) {
			options := benchmarkOptions(signer, dkim.CanonicalizationRelaxed)
			b.ReportAllocs()
			b.SetBytes(int64(len(message)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				sealer, err := NewSealer(options)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(sealer, bytes.NewReader(message)); err != nil {
					b.Fatal(err)
				}
				if err := sealer.Close(); err != nil {
					b.Fatal(err)
				}
				benchmarkSetLength = len(sealer.Set())
			}
		})
	}
}

// BenchmarkSealChainLength measures the cost of extending ARC chains of
// increasing length. A chain of 49 sets exercises the largest extendable
// chain because RFC 8617 limits the resulting instance to 50 (see 4.2.1. Instance Tags).
func BenchmarkSealChainLength(b *testing.B) {
	signer := benchmarkRSASigner(b)

	for _, chainLength := range []int{0, 1, 10, 25, MaximumSets - 1} {
		message := benchmarkMessageWithChain(b, signer, 100<<10, chainLength)
		b.Run(fmt.Sprintf("sets=%d", chainLength), func(b *testing.B) {
			benchmarkSeal(b, message, benchmarkOptions(signer, dkim.CanonicalizationRelaxed))
		})
	}
}

// BenchmarkSealAlgorithm compares the supported signing algorithms while
// keeping message size and canonicalization constant.
func BenchmarkSealAlgorithm(b *testing.B) {
	message := benchmarkMessage(100 << 10)
	algorithms := []struct {
		name   string
		signer crypto.Signer
	}{
		{name: "rsa-2048", signer: benchmarkRSASigner(b)},
		{name: "ed25519", signer: benchmarkEd25519Signer(b)},
	}

	for _, algorithm := range algorithms {
		b.Run(algorithm.name, func(b *testing.B) {
			benchmarkSeal(b, message, benchmarkOptions(algorithm.signer, dkim.CanonicalizationRelaxed))
		})
	}
}

// BenchmarkSealCanonicalization compares simple and relaxed canonicalization
// for the same message and signing key.
func BenchmarkSealCanonicalization(b *testing.B) {
	message := benchmarkMessage(1 << 20)
	signer := benchmarkRSASigner(b)

	for _, canonicalization := range []dkim.Canonicalization{
		dkim.CanonicalizationSimple,
		dkim.CanonicalizationRelaxed,
	} {
		b.Run(string(canonicalization), func(b *testing.B) {
			benchmarkSeal(b, message, benchmarkOptions(signer, canonicalization))
		})
	}
}

func benchmarkSeal(b *testing.B, message []byte, options *SealOptions) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := Seal(io.Discard, bytes.NewReader(message), options); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOptions(signer crypto.Signer, canonicalization dkim.Canonicalization) *SealOptions {
	return &SealOptions{
		Domain:                    "example.org",
		Selector:                  "benchmark",
		Signer:                    signer,
		AuthservID:                "mx.example.org",
		AMSHeaderCanonicalization: canonicalization,
		AMSBodyCanonicalization:   canonicalization,
		AMSHeaderKeys: []string{
			"From",
			"To",
			"Subject",
			"Date",
			"Message-ID",
		},
		DontCareChainValidation: true,
	}
}

func benchmarkMessage(bodySize int) []byte {
	const headers = "Authentication-Results: mx.example.org; dkim=pass header.d=example.org\r\n" +
		"From: sender@example.org\r\n" +
		"To: recipient@example.net\r\n" +
		"Subject: ARC sealing benchmark\r\n" +
		"Date: Thu, 14 Jan 2015 15:00:01 -0800\r\n" +
		"Message-ID: <benchmark@example.org>\r\n" +
		"\r\n"
	const bodyLine = "The quick brown fox jumps over the lazy dog. 0123456789\r\n"

	message := make([]byte, 0, len(headers)+bodySize)
	message = append(message, headers...)
	for len(message)-len(headers) < bodySize {
		remaining := bodySize - (len(message) - len(headers))
		if remaining < len(bodyLine) {
			message = append(message, bodyLine[:remaining]...)
			break
		}
		message = append(message, bodyLine...)
	}
	return message
}

func benchmarkMessageWithChain(b *testing.B, signer crypto.Signer, bodySize, chainLength int) []byte {
	b.Helper()
	message := benchmarkMessage(bodySize)
	options := benchmarkOptions(signer, dkim.CanonicalizationRelaxed)

	for i := range chainLength {
		var output bytes.Buffer
		if err := Seal(&output, bytes.NewReader(message), options); err != nil {
			b.Fatalf("build benchmark chain at instance %d: %v", i+1, err)
		}
		message = bytes.Clone(output.Bytes())
	}
	return message
}

func benchmarkSizeName(size int) string {
	if size%(1<<20) == 0 {
		return fmt.Sprintf("%dMiB", size>>20)
	}
	return fmt.Sprintf("%dKiB", size>>10)
}

func benchmarkRSASigner(b *testing.B) crypto.Signer {
	b.Helper()
	benchmarkRSAOnce.Do(func() {
		benchmarkRSAKey, benchmarkRSAErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if benchmarkRSAErr != nil {
		b.Fatalf("generate RSA benchmark key: %v", benchmarkRSAErr)
	}
	return benchmarkRSAKey
}

func benchmarkEd25519Signer(b *testing.B) crypto.Signer {
	b.Helper()
	benchmarkEd25519Once.Do(func() {
		_, benchmarkEd25519Key, benchmarkEd25519Err = ed25519.GenerateKey(rand.Reader)
	})
	if benchmarkEd25519Err != nil {
		b.Fatalf("generate Ed25519 benchmark key: %v", benchmarkEd25519Err)
	}
	return benchmarkEd25519Key
}
