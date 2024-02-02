package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	keyType  string
	nBits    int
	filename string
)

func init() {
	flag.StringVar(&keyType, "t", "rsa", "key type (rsa, ed25519)")
	flag.IntVar(&nBits, "b", 3072, "number of bits in the key (only for RSA)")
	flag.StringVar(&filename, "f", "dkim.priv", "private key filename")
	flag.Parse()
}

type privateKey interface {
	Public() crypto.PublicKey
}

func main() {
	privKey := genPrivKey()
	writePrivKey(privKey)
	printPubKey(privKey.Public())
}

func genPrivKey() privateKey {
	var (
		privKey crypto.Signer
		err     error
	)
	switch keyType {
	case "rsa":
		log.Printf("Generating a %v-bit RSA key", nBits)
		privKey, err = rsa.GenerateKey(rand.Reader, nBits)
	case "ed25519":
		log.Printf("Generating an Ed25519 key")
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		log.Fatalf("Unsupported key type %q", keyType)
	}
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	return privKey
}

func writePrivKey(privKey privateKey) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create key file: %v", err)
	}
	defer f.Close()

	privBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	if err := pem.Encode(f, &privBlock); err != nil {
		log.Fatalf("Failed to write key PEM block: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Failed to close key file: %v", err)
	}
	log.Printf("Private key written to %q", filename)
}

func printPubKey(pubKey crypto.PublicKey) {
	var pubBytes []byte
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		// RFC 6376 is inconsistent about whether RSA public keys should
		// be formatted as RSAPublicKey or SubjectPublicKeyInfo.
		// Erratum 3017 (https://www.rfc-editor.org/errata/eid3017)
		// proposes allowing both.  We use SubjectPublicKeyInfo for
		// consistency with other implementations including opendkim,
		// Gmail, and Fastmail.
		var err error
		pubBytes, err = x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Fatalf("Failed to marshal public key: %v", err)
		}
	case ed25519.PublicKey:
		pubBytes = pubKey
	default:
		panic("unreachable")
	}

	params := []string{
		"v=DKIM1",
		"k=" + keyType,
		"p=" + base64.StdEncoding.EncodeToString(pubBytes),
	}
	log.Println("Public key, to be stored in the TXT record \"<selector>._domainkey\":")
	fmt.Println(strings.Join(params, "; "))
}
