package set1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

func HexToBase64(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

func XORHex(s1, s2 string) string {
	s1Bytes, err := hex.DecodeString(s1)
	if err != nil {
		panic(err)
	}

	s2Bytes, err := hex.DecodeString(s2)
	if err != nil {
		panic(err)
	}

	s1Big := new(big.Int).SetBytes(s1Bytes)
	s2Big := new(big.Int).SetBytes(s2Bytes)

	xored := new(big.Int).Xor(s1Big, s2Big)
	xoredBytes := xored.Bytes()

	return hex.EncodeToString(xoredBytes)
}

func VowelFrequencyScore(s string) int {
	vowels := map[rune]bool{
		'a': true,
		'e': true,
		'i': true,
		'o': true,
		'u': true,
	}

	var score int
	for _, v := range s {
		if _, ok := vowels[v]; ok {
			score++
		}
	}

	return score
}

func AlphabetFrequencyScore(s string) int {
	allowed := make(map[rune]bool)
	for i := int('a'); i < 'a'+26; i++ {
		allowed[rune(i)] = true
	}
	for i := int('A'); i < 'A'+26; i++ {
		allowed[rune(i)] = true
	}
	for i := int('1'); i < '1'+10; i++ {
		allowed[rune(i)] = true
	}

	allowed[' '] = true

	var score int
	for _, v := range s {
		if _, ok := allowed[v]; ok {
			score++
		}
	}

	return score
}

func EncryptWithRepeatingXOR(s, key string) []byte {
	bytes := []byte(s)
	var ciphertext []byte

	for i, b := range bytes {
		v := b ^ (key[i%len(key)])
		ciphertext = append(ciphertext, v)
	}

	return ciphertext
}

func HammingDistance(b1, b2 []byte) int {
	if len(b1) != len(b2) {
		panic("lengths must match")
	}

	var distance int
	for i, b := range b1 {
		for j := uint(0); j < 8; j++ {
			v1 := (b >> j) & 1
			v2 := (b2[i] >> j) & 1
			if v1 != v2 {
				distance++
			}
		}
	}

	return distance
}

func DetectKeySize(ct []byte, keysizes int) int {
	var winner int
	highScore := float64(8)
	for size := 4; size <= keysizes; size++ {
		block1 := ct[:size]
		block2 := ct[size : 2*size]
		block3 := ct[2*size : 3*size]
		block4 := ct[3*size : 4*size]

		distance := HammingDistance(block1, block2) +
			HammingDistance(block2, block3) +
			HammingDistance(block3, block4)
		normalized := float64(distance) / (3 * float64(size))

		if normalized < highScore {
			highScore = normalized
			winner = size
		}
	}

	fmt.Println(highScore)
	fmt.Println(winner)

	return winner
}
