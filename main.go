package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/rand"
	"os"
	"runtime"

	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

var aKeySuffixStr = flag.String("authorized-key-suffix", "", "")
var fingerprintPrefixStr = flag.String("fingerprint-prefix", "", "")
var fingerprintSuffixStr = flag.String("fingerprint-suffix", "", "")

var (
	aKey                 []byte
	aKeyLen              int
	fingerprintPrefix    []byte
	fingerprintPrefixLen int
	fingerprintSuffix    []byte
	fingerprintSuffixLen int
)

const (
	// this should be base64.StdEncoding.EncodedLen(32+1).
	encodedPublicKeyLen = 44
	// this should be base64.RawStdEncoding.EncodedLen(32).
	fingerprintLen = 43
)

type fastRandReaderImpl struct {
	*rand.Rand
}

// reduce allocation for seed rather than calling ed25519.GenerateKey directly.
func generateKey(rand io.Reader, seed [ed25519.SeedSize]byte) ed25519.PrivateKey {
	_, _ = io.ReadFull(rand, seed[:])
	return ed25519.NewKeyFromSeed(seed[:])
}

func bruteAuthorizedKey(privateKeyChan chan<- ed25519.PrivateKey) {
	rand.NewSource(rand.Int63()).Int63()
	fastRandReader := &fastRandReaderImpl{rand.New(rand.NewSource(rand.Int63()))}
	var seed [ed25519.SeedSize]byte
	var encodedPublicKey [encodedPublicKeyLen]byte
	for {
		privateKey := generateKey(fastRandReader, seed)

		// the process itself is the same as the end of ssh.MarshalAuthorizedKeys.
		// the public key is included after the private key, so encode it with a shift of 1 character to consider
		// padding.
		base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

		if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
			privateKeyChan <- privateKey
			break
		}
	}
}

func bruteFingerprint(privateKeyChan chan<- ed25519.PrivateKey) {
	fastRandReader := &fastRandReaderImpl{rand.New(rand.NewSource(rand.Int63()))}
	var seed [ed25519.SeedSize]byte
	var fingerprint [fingerprintLen]byte
	d := sha256.New()
	for {
		privateKey := generateKey(fastRandReader, seed)

		// the process itself is the same as ssh.FingerprintSHA256, but it does not use a buffer directly to avoid
		// allocating it every time.
		// however, allocation occurs with sha256.New().Sum(). see also: https://github.com/golang/go/issues/21948
		d.Reset()
		d.Write([]byte{0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20})
		d.Write(privateKey[32:])
		sha256sum := d.Sum(nil)
		base64.RawStdEncoding.Encode(fingerprint[:], sha256sum[:])

		if (fingerprintPrefixLen == 0 || bytes.Equal(fingerprint[:fingerprintPrefixLen], fingerprintPrefix)) &&
			(fingerprintSuffixLen == 0 || bytes.Equal(fingerprint[fingerprintLen-fingerprintSuffixLen:], fingerprintSuffix)) {
			privateKeyChan <- privateKey
			break
		}
	}
}

func bruteCombined(privateKeyChan chan<- ed25519.PrivateKey) {
	fastRandReader := &fastRandReaderImpl{rand.New(rand.NewSource(rand.Int63()))}
	var seed [ed25519.SeedSize]byte
	var encodedPublicKey [encodedPublicKeyLen]byte
	var fingerprint [fingerprintLen]byte
	d := sha256.New()
	for {
		privateKey := generateKey(fastRandReader, seed)
		base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

		if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
			d.Reset()
			d.Write([]byte{0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20})
			d.Write(privateKey[32:])
			sha256sum := d.Sum(nil)
			base64.RawStdEncoding.Encode(fingerprint[:], sha256sum[:])

			if (fingerprintPrefixLen == 0 || bytes.Equal(fingerprint[:fingerprintPrefixLen], fingerprintPrefix)) &&
				(fingerprintSuffixLen == 0 || bytes.Equal(fingerprint[fingerprintLen-fingerprintSuffixLen:], fingerprintSuffix)) {
				privateKeyChan <- privateKey
				break
			}
		}
	}
}

func main() {
	flag.Parse()

	aKey = []byte(*aKeySuffixStr)
	aKeyLen = len(aKey)
	fingerprintPrefix = []byte(*fingerprintPrefixStr)
	fingerprintPrefixLen = len(fingerprintPrefix)
	fingerprintSuffix = []byte(*fingerprintSuffixStr)
	fingerprintSuffixLen = len(fingerprintSuffix)

	if aKeyLen == 0 && fingerprintPrefixLen == 0 && fingerprintSuffixLen == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// fingerprint is the base64 encoding of the result of sha256, which is 32 bytes, so 1 padding is required.
	// the last 2 bits in 6 bits will be 00, so it is limited to the following characters.
	if fingerprintSuffixLen > 0 && !bytes.Contains([]byte("AEIMQUYcgkosw048"), fingerprintSuffix[fingerprintSuffixLen-1:]) {
		log.Fatal("the last character of fingerprint suffix must be one of \"AEIMQUYcgkosw048\"")
	}

	log.Println("start")

	privateKeyChan := make(chan ed25519.PrivateKey)
	for i := 0; i < runtime.NumCPU(); i++ {
		if aKeyLen > 0 && (fingerprintPrefixLen > 0 || fingerprintSuffixLen > 0) {
			go bruteCombined(privateKeyChan)
		} else if aKeyLen > 0 {
			go bruteAuthorizedKey(privateKeyChan)
		} else if fingerprintPrefixLen > 0 || fingerprintSuffixLen > 0 {
			go bruteFingerprint(privateKeyChan)
		}
	}

	privateKey := <-privateKeyChan

	log.Println("found")

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(pemBlock)
	signer, _ := ssh.NewSignerFromSigner(privateKey)
	authorizedKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	_ = os.WriteFile("out", privateKeyPem, 0600)
	_ = os.WriteFile("out.pub", authorizedKey, 0644)
}
