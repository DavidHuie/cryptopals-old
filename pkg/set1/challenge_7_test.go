package set1

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestChallenge7(t *testing.T) {
	f, err := os.Open("7.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	reader := base64.NewDecoder(base64.StdEncoding, f)
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var pt []byte

	for i := 0; i < len(bytes); i += 16 {
		portion := make([]byte, 16)
		cipher.Decrypt(portion, bytes[i:i+16])
		pt = append(pt, portion...)
	}

	fmt.Println(string(pt))
}
