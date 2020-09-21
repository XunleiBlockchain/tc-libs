package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyData struct {
	priv string
	pub  string
	addr string
}

var secpDataTable = []keyData{
	{
		priv: "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:  "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr: "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
	},
}

func TestPubKeyInvalidDataProperReturnsEmpty(t *testing.T) {
	pk, err := PubKeyFromBytes([]byte("foo"))
	require.NotNil(t, err, "expecting a non-nil error")
	require.Nil(t, pk, "expecting an empty public key on error")
}

func TestPubKeySecp256k1(t *testing.T) {
	privKey, err := GenPrivKeySecp256k1()
	if err != nil {
		t.Fatalf("GenPrivKeySecp256k1 fail: %s", err)
	}

	pubKey := privKey.PubKey().(*PubKeySecp256k1)
	pubKey2 := PubKeySecp256k1FromBytes(pubKey.Raw())
	assert.Equal(t, pubKey.pk, pubKey2.pk, "PubKeySecp256K1 Equal")
}
