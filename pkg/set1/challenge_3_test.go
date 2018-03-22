package set1

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestChallenge3(t *testing.T) {
	c := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	cBytes, err := hex.DecodeString(c)
	if err != nil {
		t.Fatal(err)
	}

	var winner string
	var highScore int

	for i := 0; i <= 255; i++ {
		candidateByte := i
		var candidate []byte
		for j := 0; j < len(cBytes); j++ {
			candidate = append(candidate, byte(candidateByte))
		}

		pt := new(big.Int).Xor(
			new(big.Int).SetBytes(cBytes),
			new(big.Int).SetBytes(candidate),
		).Bytes()

		score := VowelFrequencyScore(string(pt))
		if score > highScore {
			winner = string(pt)
			highScore = score
		}
	}

	fmt.Println(winner)
}
