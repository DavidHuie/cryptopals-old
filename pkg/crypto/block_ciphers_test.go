package crypto_test

import (
	"bytes"
	"fmt"
	"testing"

	"crypto/rand"

	"crypto/aes"

	"encoding/base64"
	"io/ioutil"

	"github.com/DavidHuie/cryptopals/pkg/crypto"
)

func TestPadWithPKCS7(t *testing.T) {
	str := "YELLOW SUBMARINE"
	padded := crypto.PadWithPKCS7([]byte(str), 20)
	if fmt.Sprintf("%x", padded) != "59454c4c4f57205355424d4152494e4504040404" {
		t.Fatal("invalid pad")
	}
}

func TestCBCEncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	t.Logf("IV: %x", iv)

	plaintext := "this is so fun!"
	ptBytes := crypto.PadWithPKCS7([]byte(plaintext), 16)
	t.Logf("original plaintext: %x", ptBytes)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypter := crypto.NewCBCEncrypter(cipher, iv)

	ct := make([]byte, 16)
	encrypter.CryptBlocks(ct, ptBytes)

	t.Logf("ciphertext: %x", ct)

	pt := make([]byte, 16)
	decrypter := crypto.NewCBCDecrypter(cipher, iv)
	decrypter.CryptBlocks(pt, ct)

	t.Logf("plaintext: %x", pt)
	t.Logf("plaintext: %s", string(pt))

	if bytes.Compare(pt, ptBytes) != 0 {
		t.Fatal("output should match")
	}
}

func TestChallenge10(t *testing.T) {
	f, err := ioutil.ReadFile("examples/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	ct, err := base64.StdEncoding.DecodeString(string(f))
	if err != nil {
		t.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	mode := crypto.NewCBCDecrypter(cipher, iv)
	out := crypto.CBCProcess(ct, mode)
	a
	t.Logf("out: %s", string(out))
}
