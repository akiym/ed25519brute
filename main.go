package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

const ChildEnvName = "BRUTE_SSH_KEY_CHILD"

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

func bruteAuthorizedKey() ed25519.PrivateKey {
	var seed [ed25519.SeedSize]byte
	var encodedPublicKey [encodedPublicKeyLen]byte
	for {
		if _, err := crand.Read(seed[:]); err != nil {
			panic(err)
		}

		for i := 0; i < 0x10000; i++ {
			seed[0] = byte(i)
			seed[1] = byte(i >> 8)
			privateKey := ed25519.NewKeyFromSeed(seed[:])

			// the process itself is the same as the end of ssh.MarshalAuthorizedKeys.
			// the public key is included after the private key, so encode it with a shift of 1 character to consider
			// padding.
			base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

			if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
				return privateKey
			}
		}
	}
}

func bruteFingerprint() ed25519.PrivateKey {
	var seed [ed25519.SeedSize]byte
	var fingerprint [fingerprintLen]byte
	d := sha256.New()
	for {
		if _, err := crand.Read(seed[:]); err != nil {
			panic(err)
		}

		for i := 0; i < 0x10000; i++ {
			seed[0] = byte(i)
			seed[1] = byte(i >> 8)
			privateKey := ed25519.NewKeyFromSeed(seed[:])

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
				return privateKey
			}
		}
	}
}

func bruteCombined() ed25519.PrivateKey {
	var seed [ed25519.SeedSize]byte
	var encodedPublicKey [encodedPublicKeyLen]byte
	var fingerprint [fingerprintLen]byte
	d := sha256.New()
	for {
		if _, err := crand.Read(seed[:]); err != nil {
			panic(err)
		}

		for i := 0; i < 0x10000; i++ {
			seed[0] = byte(i)
			seed[1] = byte(i >> 8)
			privateKey := ed25519.NewKeyFromSeed(seed[:])
			base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

			if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
				d.Reset()
				d.Write([]byte{0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20})
				d.Write(privateKey[32:])
				sha256sum := d.Sum(nil)
				base64.RawStdEncoding.Encode(fingerprint[:], sha256sum[:])

				if (fingerprintPrefixLen == 0 || bytes.Equal(fingerprint[:fingerprintPrefixLen], fingerprintPrefix)) &&
					(fingerprintSuffixLen == 0 || bytes.Equal(fingerprint[fingerprintLen-fingerprintSuffixLen:], fingerprintSuffix)) {
					return privateKey
				}
			}
		}
	}
}

func childProcess() {
	var privateKey ed25519.PrivateKey
	if aKeyLen > 0 && (fingerprintPrefixLen > 0 || fingerprintSuffixLen > 0) {
		privateKey = bruteCombined()
	} else if aKeyLen > 0 {
		privateKey = bruteAuthorizedKey()
	} else if fingerprintPrefixLen > 0 || fingerprintSuffixLen > 0 {
		privateKey = bruteFingerprint()
	}

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	pem.Encode(os.Stdout, pemBlock)
}

func child(ctx context.Context, privateKeyChan chan<- ed25519.PrivateKey) {
	cmd := exec.CommandContext(ctx, os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), ChildEnvName+"=1")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return
	}

	privateKey, err := pemutil.ParseOpenSSHPrivateKey(buf.Bytes())
	if err != nil {
		panic(err)
	}
	privateKeyChan <- privateKey.(ed25519.PrivateKey)
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

	if os.Getenv(ChildEnvName) != "" {
		childProcess()
		return
	}

	log.Println("start")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privateKeyChan := make(chan ed25519.PrivateKey, runtime.NumCPU())
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child(ctx, privateKeyChan)
		}()
	}

	privateKey := <-privateKeyChan
	cancel()
	wg.Wait()

	log.Println("found")

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(pemBlock)
	signer, _ := ssh.NewSignerFromSigner(privateKey)
	authorizedKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	_ = os.WriteFile("out", privateKeyPem, 0600)
	_ = os.WriteFile("out.pub", authorizedKey, 0644)
}
