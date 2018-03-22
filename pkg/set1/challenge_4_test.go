package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"
)

func TestChallenge4(t *testing.T) {
	f, err := os.Open("4.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var winner string
	var highScore int

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		bytes, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i <= 255; i++ {
			candidateByte := i
			var candidate []byte
			for j := 0; j < len(bytes); j++ {
				candidate = append(candidate, byte(candidateByte))
			}

			pt := new(big.Int).Xor(
				new(big.Int).SetBytes(bytes),
				new(big.Int).SetBytes(candidate),
			).Bytes()

			score := AlphabetFrequencyScore(string(pt))
			if score >= highScore {
				winner = string(pt)
				highScore = score
			}
		}
	}

	fmt.Printf("%d: %s", highScore, winner)
}
