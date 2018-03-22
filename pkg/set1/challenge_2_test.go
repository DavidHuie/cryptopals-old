package set1

import "testing"

func TestChallenge2(t *testing.T) {
	value := XORHex("1c0111001f010100061a024b53535009181c",
		"686974207468652062756c6c277320657965")

	if value != "746865206b696420646f6e277420706c6179" {
		t.Fatalf("invalid value: %s", value)
	}
}
