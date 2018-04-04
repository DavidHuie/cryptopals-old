package crypto

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
