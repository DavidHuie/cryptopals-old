package set1

import "testing"

func TestChallenge1(t *testing.T) {
	str := `49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`
	b64 := HexToBase64(str)
	if b64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Fatalf("wrong string: %s", b64)
	}
}
