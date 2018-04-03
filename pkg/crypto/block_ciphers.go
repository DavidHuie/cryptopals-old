package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

func CBCECBEncryptionOracle(pt []byte) []byte {
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
		return CBCProcess(changed, encrypter)
	}

	return ECBEncrypt(changed, GetRandBytes(16))
}
