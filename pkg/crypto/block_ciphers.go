package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

func PadWithPKCS7(buf []byte, size int) []byte {
	padSize := size - len(buf)
	for i := 0; i < padSize; i++ {
		buf = append(buf, byte(padSize))
	}
	return buf
}

func CBCProcess(data []byte, mode cipher.BlockMode) []byte {
	var out []byte
	buf := make([]byte, mode.BlockSize())
	for i := 0; i < len(data); i += 16 {
		mode.CryptBlocks(buf, data[i:i+16])
		out = append(out, buf...)
	}
	return out
}

func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcEncrypter{
		block: block,
		iv:    new(big.Int).SetBytes(iv),
	}
}

type cbcEncrypter struct {
	block cipher.Block
	iv    *big.Int
}

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(dst) != len(src) {
		panic("lengths don't match")
	}

	pt := new(big.Int).SetBytes(src)
	pt.Xor(pt, c.iv)
	ptBytes := pt.Bytes()

	if len(ptBytes) != len(src) {
		prefix := make([]byte, len(src)-len(ptBytes))
		ptBytes = append(prefix, ptBytes...)
	}

	c.block.Encrypt(dst, ptBytes)
	c.iv = new(big.Int).SetBytes(dst)
}

func (c *cbcEncrypter) BlockSize() int {
	return c.block.BlockSize()
}

func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcDecrypter{
		block: block,
		iv:    new(big.Int).SetBytes(iv),
	}
}

type cbcDecrypter struct {
	block cipher.Block
	iv    *big.Int
}

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) != len(src) {
		panic("lengths don't match")
	}

	buf := make([]byte, len(src))
	c.block.Decrypt(buf, src)

	pt := new(big.Int).Xor(c.iv, new(big.Int).SetBytes(buf))
	for i, b := range pt.Bytes() {
		dst[i] = b
	}

	c.iv = new(big.Int).SetBytes(src)
}

func (c *cbcDecrypter) BlockSize() int {
	return c.block.BlockSize()
}

func ECBEncrypt(ct []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(cipher)
	}
	if len(ct)%16 != 0 {
		ct = PadWithPKCS7(ct, len(ct)+(16-len(ct)/16))
	}

	var out []byte
	for i := 0; i < len(ct); i += 16 {
		block := make([]byte, 16)
		cipher.Encrypt(block, ct[i:i+16])
		out = append(out, block...)
	}

	return out
}

func ECBDecrypt(ct []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(cipher)
	}

	var out []byte
	for i := 0; i < len(ct); i += 16 {
		block := make([]byte, 16)
		cipher.Decrypt(block, ct[i:i+16])
		out = append(out, block...)
	}

	return out
}

func GetRandBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func GetRandInt(max int) int {
	rint, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(rint.Int64())
}

func GetRepeatedChar(s rune, num int) []byte {
	var b []byte
	for i := 0; i < num; i++ {
		b = append(b, byte(s))
	}
	return b
}

func CBCECBEncryptionOracle(pt []byte) ([]byte, string) {
	useCBC := false
	if GetRandInt(2) == 0 {
		useCBC = true
	}

	prefix := GetRandBytes(5 + GetRandInt(5))
	suffix := GetRandBytes(5 + GetRandInt(5))
	changed := append(prefix, pt...)
	changed = append(changed, suffix...)

	numBlocks := len(changed) / 16
	if len(changed)%16 > 0 {
		changed = PadWithPKCS7(changed, (numBlocks+1)*16)
	}

	if useCBC {
		cipher, err := aes.NewCipher(GetRandBytes(16))
		if err != nil {
			panic(err)
		}
		encrypter := NewCBCEncrypter(cipher, GetRandBytes(16))
		return CBCProcess(changed, encrypter), "cbc"
	}

	return ECBEncrypt(changed, GetRandBytes(16)), "ecb"
}

func DetectEncryptionMode(ct []byte) string {
	blocks := len(ct) / 16
	for i := 0; i < blocks-1; i++ {
		dist := HammingDistance(ct[i:i+16], ct[i+16:i+32])
		if dist == 0 {
			return "ecb"
		}
	}

	return "cbc"
}

var challenge12Key []byte

func Challenge12EncryptionOracle(pt []byte) []byte {
	if len(challenge12Key) == 0 {
		challenge12Key = GetRandBytes(16)
	}

	s := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return ECBEncrypt(append(pt, b...), challenge12Key)
}

func ByteAtATimeECBDecrypt() (pt []byte) {
	size := len(Challenge12EncryptionOracle(nil))

	for i := 0; i < size; i++ {
		tester := GetRepeatedChar('a', size-1-i)
		prefix := append(tester, pt...)
		dict := make(map[string]byte)

		for i := 0; i < 256; i++ {
			buf := append(prefix, byte(i))
			ct := Challenge12EncryptionOracle(buf)
			block := ct[size-16 : size]
			dict[fmt.Sprintf("%x", block)] = byte(i)
		}

		ct := Challenge12EncryptionOracle(tester)
		block := ct[size-16 : size]
		b := dict[fmt.Sprintf("%x", block)]
		pt = append(pt, b)

	}

	return
}
