package set1

import "testing"

func TestHammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	distance := HammingDistance([]byte(s1), []byte(s2))

	if distance != 37 {
		t.Fatalf("invalid hamming distance: %d", distance)
	}
}
