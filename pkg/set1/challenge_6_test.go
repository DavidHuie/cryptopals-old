package set1

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
)

func TestChallenge6(t *testing.T) {
	f, err := os.Open("6.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	reader := base64.NewDecoder(base64.StdEncoding, f)
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	size := DetectKeySize(bytes, 40)
	blocks := make([][]byte, size)

	for i, b := range bytes {
		blocks[i%size] = append(blocks[i%size], b)
	}

	var key []byte

	for _, block := range blocks {
		var winner byte
		var highScore int
		// var plaintext []byte

		for i := 0; i <= 255; i++ {
			candidateByte := i
			var candidate []byte
			for j := 0; j < len(block); j++ {
				candidate = append(candidate, byte(candidateByte))
			}

			pt := new(big.Int).Xor(
				new(big.Int).SetBytes(block),
				new(big.Int).SetBytes(candidate),
			).Bytes()

			score := AlphabetFrequencyScore(string(pt))
			if score >= highScore {
				// plaintext = pt
				winner = byte(candidateByte)
				highScore = score
			}
		}

		key = append(key, winner)
	}

	fmt.Println("key:", string(key))
	fmt.Println(string(EncryptWithRepeatingXOR(string(bytes), string(key))))
}
