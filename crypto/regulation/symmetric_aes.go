package regulation

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

var CommonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

type AesCipher struct{}

func (a AesCipher) Encrypt(plainText []byte, secret []byte) (cipherText []byte, err error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	encrypter := cipher.NewCBCEncrypter(c, CommonIV)
	paddedText := PKCS5Padding(plainText, encrypter.BlockSize())
	cipherText = make([]byte, len(paddedText))
	encrypter.CryptBlocks(cipherText, paddedText)
	return cipherText, nil
}

func (a AesCipher) Decrypt(cipherText []byte, secret []byte) (plainText []byte, err error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	decrypter := cipher.NewCBCDecrypter(c, CommonIV)
	paddedText := make([]byte, len(cipherText))
	decrypter.CryptBlocks(paddedText, cipherText)
	return PKCS5UnPadding(paddedText)
}

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number > length {
		return nil, fmt.Errorf("padding length is wrong")
	}
	return plainText[:length-number], nil
}
