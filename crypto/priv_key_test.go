package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/XunleiBlockchain/tc-libs/common"
	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivKey(t *testing.T) {
	testPriv, err := GenPrivKeyEd25519()
	if err != nil {
		t.Fatalf("GenPrivKeyEd25519 fail: %s", err)
	}
	testGenerate := testPriv.Generate(1)
	signBytes := []byte("something to sign")
	pub := testGenerate.PubKey()
	sig, err := testGenerate.Sign(signBytes)
	assert.NoError(t, err)
	assert.True(t, pub.VerifyBytes(signBytes, sig))
}

func TestGenPrivKeyEd25519FromSecret(t *testing.T) {
	secret := []byte("hello")
	privBytes := common.FromHex("9e5e70a1b9af8fb8402cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824d16198cd553243dae7d8e421107d9887e270eb1cc6e4c072adea0f0442b65ace")
	expectPriv, err := PrivKeyFromBytes(privBytes)
	assert.Nil(t, err)

	pubBytes := common.FromHex("724c2517228e6aa0d16198cd553243dae7d8e421107d9887e270eb1cc6e4c072adea0f0442b65ace")
	expectPub, err := PubKeyFromBytes(pubBytes)
	assert.Nil(t, err)

	priv, err := GenPrivKeyEd25519FromSecret(secret)
	if err != nil {
		t.Fatalf("GenPrivKeyEd25519FromSecret fail: %s", err)
	}
	assert.True(t, priv.Equals(expectPriv))
	assert.True(t, priv.PubKey().Equals(expectPub))

	expectSig := common.FromHex("c2ecc12ed3ead6b840966ce54dfa5d3de320a1cc0af59655e49fe52674b74e33b31a8d8289bd300bb63486ee4a86164f25e388c1f496a75c4f101bc67bd81c70a1f2553a20ee68be07")
	sig, err := priv.Sign(secret)
	assert.Nil(t, err)
	assert.Equal(t, expectSig, sig.Bytes())

	assert.True(t, expectPub.VerifyBytes(secret, sig))
}

func TestGenPrivKeyGM(t *testing.T) {
	privKey, err := GenPrivKeyGM()
	if err != nil {
		t.Fatalf("GenPrivKeyGM fail: %s", err)
	}

	privKey2, err := GenPrivKeyGMFromSecret(privKey.Raw())
	if err != nil {
		t.Fatalf("GenPrivKeyGMFromSecret fail: %s", err)
	}
	assert.Equal(t, privKey.pk, privKey2.pk, "")

	msg := []byte("hello world")
	hash := Keccak256(msg)
	sig, err := privKey.Sign(hash)
	if err != nil {
		t.Fatalf("Sign fail: %s", err)
	}

	pubKey := privKey.PubKey()
	addr := PubkeyToAddress(pubKey)
	t.Logf("pubKey: raw=%s, bytes=%s, address=%s",
		hex.EncodeToString(pubKey.Raw()),
		hex.EncodeToString(pubKey.Bytes()),
		PubkeyToAddress(pubKey).String())

	ok := pubKey.VerifyBytes(hash, sig)
	assert.Equal(t, ok, true)

	sender, err := Sender(hash, sig.Raw())
	if err != nil {
		t.Fatalf("Sender fail: %s", err)
	}
	t.Logf("sender: %s", sender.String())
	assert.Equal(t, sender, addr, "")
}

func TestGenPrivKeySecp256k1(t *testing.T) {
	privKey, err := GenPrivKeySecp256k1()
	if err != nil {
		t.Fatalf("GenPrivKeySecp256k1 fail: %s", err)
	}

	privKey2, err := GenPrivKeySecp256k1FromSecret(privKey.Raw())
	if err != nil {
		t.Fatalf("GenPrivKeySecp256k1FromSecret fail: %s", err)
	}
	assert.Equal(t, privKey.pk, privKey2.pk, "ecdsa.PrivateKey Equal")

	msg := []byte("hello world")
	hash := Keccak256(msg)
	sig, err := privKey.Sign(hash)
	if err != nil {
		t.Fatalf("Sign fail: %s", err)
	}

	sig2, err := privKey2.Sign(hash)
	if err != nil {
		t.Fatalf("Sign fail: %s", err)
	}

	assert.Equal(t, sig, sig2, "Signature Equal")
}

func TestSecp256k1(t *testing.T) {
	privKey, err := GenPrivKeySecp256k1()
	if err != nil {
		t.Fatalf("GenPrivKeySecp256k1 fail: %s", err)
	}

	pubKey := privKey.PubKey()

	msg := []byte("hello world")
	hash := Keccak256(msg)
	sig, err := privKey.Sign(hash)
	if err != nil {
		t.Fatalf("Sign fail: %s", err)
	}

	ok := pubKey.VerifyBytes(hash, sig)
	if !ok {
		t.Fatalf("VerifyBytes fail")
	}

	recoverData, err := Ecrecover(hash, sig.Raw())
	if err != nil {
		t.Fatalf("Ecrecover fail: %s", err)
	}
	t.Logf("Ecrecover: %s", hex.EncodeToString(recoverData))

	sender, err := Sender(hash, sig.Raw())
	if err != nil {
		t.Fatalf("Sender fail: %s", err)
	}
	// assert.Equal(t, sender.String(), PubkeyToAddress(pubKey).String())
	assert.Equal(t, sender, PubkeyToAddress(pubKey), "Address Equal")
}

func BenchmarkEd25519VerifyBytes(b *testing.B) {
	secret := []byte("hello")
	priv, err := GenPrivKeyEd25519FromSecret(secret)
	if err != nil {
		b.Fatalf("GenPrivKeyEd25519FromSecret fail: %s", err)
	}
	sig, _ := priv.Sign(secret)
	pub := priv.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.VerifyBytes(secret, sig)
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	secret := []byte("hello")
	priv, err := GenPrivKeyEd25519FromSecret(secret)
	if err != nil {
		b.Fatalf("GenPrivKeyEd25519FromSecret fail: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priv.Sign(secret)
	}
}
