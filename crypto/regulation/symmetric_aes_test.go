package regulation

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAesCipher_Decrypt(t *testing.T) {
	var aesCipher AesCipher
	for i := 0; i <= 128; i++ {
		key := make([]byte, 32)
		data := make([]byte, i)
		_, _ = rand.Read(key)
		_, _ = rand.Read(data)
		cipherText, err := aesCipher.Encrypt(data, key)
		if err != nil {
			t.Fatalf(err.Error())
		}
		plainText, err := aesCipher.Decrypt(cipherText, key)
		if err != nil {
			t.Fatalf(err.Error())
		}
		if !bytes.Equal(data, plainText) {
			t.Fatalf("decrypted data is wrong")
		}
	}
}
