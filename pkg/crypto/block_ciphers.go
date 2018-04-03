package crypto

import (
	"crypto/cipher"
	"math/big"
)

func PadWithPKCS7(buf []byte, size int) []byte {
	padSize := size - len(buf)
	for i := 0; i < padSize; i++ {
		buf = append(buf, byte(padSize))
	}
	return buf
}

func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcEncrypter{
		block: block,
		iv:    new(big.Int).SetBytes(iv),
	}
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

	c.block.Encrypt(dst, pt.Bytes())
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
