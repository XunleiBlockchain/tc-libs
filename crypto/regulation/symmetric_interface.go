package regulation

type SymmetricCipher interface {
	Encrypt(plainText []byte, secret []byte) (cipherText []byte, err error)
	Decrypt(cipherText []byte, secret []byte) (plainText []byte, err error)
}
