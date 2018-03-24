package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func blockCounts(b []byte) map[string]int {
	blocks := make(map[string]int)
	for i := 0; i < len(b); i += 16 {
		block := b[i : i+16]
		blockStr := fmt.Sprintf("%x", block)

		if _, ok := blocks[blockStr]; ok {
			continue
		}

		for j := 0; j < len(b); j += 16 {
			candidate := b[j : j+16]
			if blockStr == fmt.Sprintf("%x", candidate) {
				blocks[blockStr]++
			}
		}
	}

	for k, v := range blocks {
		if v == 1 {
			delete(blocks, k)
		}
	}

	return blocks
}

func TestChallenge8(t *testing.T) {
	f, err := os.Open("8.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		bytes, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}

		blockMap := blockCounts(bytes)
		if len(blockMap) > 0 {
			fmt.Printf("line: %x\n", bytes)
			for block, count := range blockMap {
				fmt.Printf("block repeated %d times: %s\n", count, block)
			}
		}
	}
}
