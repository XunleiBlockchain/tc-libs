package crypto

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/XunleiBlockchain/tc-libs/common"
	"github.com/XunleiBlockchain/tc-libs/crypto/secp256k1"
)

const (
	CryptoTypeGM        = "gm"
	CryptoTypeEd25519   = "ed25519"
	CryptoTypeSecp256K1 = "secp256k1"
)

var (
	// localCryptoType  = CryptoTypeGM
	// default crypto type
	localAccountType = CryptoTypeSecp256K1
	localNodeType    = CryptoTypeEd25519
)

// --------------------------------------------------------

var (
	// ErrInvalidCryptoType --
	ErrInvalidCryptoType = errors.New("Invalid Crypto Type")
)

// SetLocalAccountType --
func SetLocalAccountType(t string) {
	if t == CryptoTypeGM || t == CryptoTypeSecp256K1 {
		localAccountType = t
		return
	}
	panic(fmt.Sprintf("Invalid CryptoType: %s", t))
}

// LocalAccountType --
func LocalAccountType() string { return localAccountType }

// SetLocalNodeType --
func SetLocalNodeType(t string) {
	if t == CryptoTypeEd25519 {
		localNodeType = t
		return
	}
	panic(fmt.Sprintf("Invalid CryptoType: %s", t))
}

func LocalNodeType() string {
	return localNodeType
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// GenerateAccountKey --
func GenerateAccountKey() (PrivKey, error) {
	plugin := cryptos[LocalAccountType()]
	if plugin == nil {
		return nil, ErrInvalidCryptoType
	}

	return plugin.GenerateKey()
}

// GenerateNodeKey --
func GenerateNodeKey() (PrivKey, error) {
	plugin := cryptos[LocalNodeType()]
	if plugin == nil {
		return nil, ErrInvalidCryptoType
	}

	return plugin.GenerateKey()
}

// PubkeyToAddress --
func PubkeyToAddress(pubKey PubKey) common.Address {
	return common.BytesToAddress(pubKey.Address())
}

// GeneratePrivKeyFromSecret --
func GeneratePrivKeyFromSecret(secret []byte, t string) (PrivKey, error) {
	plugin := cryptos[t]
	if plugin == nil {
		return nil, ErrInvalidCryptoType
	}
	return plugin.GenerateKeyFromSecret(secret)
}

// VerifySignature checks that the given pubkey created signature over message.
// The signature should be in [R || S || V] format.
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) == 65 {
		v := signature[64]
		if v == 0 || v == 1 {
			// The signature should be in [R || S] format.
			return secp256k1.VerifySignature(pubkey, hash, signature[:64])
		}

		if v == SM2Magic || v == SM2Magic+1 {
			pk := PubKeyGMFromBytes(pubkey)
			sig, ok := NewSignatureGM(signature)
			if !ok {
				return false
			}
			return pk.VerifyBytes(hash, sig)
		}
		return false
	}

	sig := NewSignatureEd25519(signature)
	pk := PubKeyEd25519{}
	copy(pk[:], pubkey)
	return pk.VerifyBytes(hash, sig)
}

// Ecrecover returns the uncompressed public key that created the given signature.
func Ecrecover(hash, sig []byte) ([]byte, error) {
	pubKey, err := ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}
	return pubKey.Raw(), nil
}

// Sender : Ecrecover sender's Address
func Sender(hash, sig []byte) (common.Address, error) {
	pubKey, err := ecrecover(hash, sig)
	if err != nil {
		return common.EmptyAddress, err
	}
	return PubkeyToAddress(pubKey), nil
}

// ------------------------------------------------

func ecrecover(hash, sig []byte) (PubKey, error) {
	// For GM
	if sig[64] == SM2Magic || sig[64] == SM2Magic+1 {
		r, s, v, ok := ParseSignatureGM(sig)
		if !ok {
			return nil, fmt.Errorf("ParseSignatureGM fail")
		}
		pk, ok := sm2.Ecrecover(hash, r, s, v)
		if !ok {
			return nil, fmt.Errorf("sm2.Recover fail")
		}

		pubKey := makePubKeyGM(pk)
		return pubKey, nil
	}

	// For secp256k1
	if sig[64] == 0 || sig[64] == 1 {
		raw, err := secp256k1.RecoverPubkey(hash, sig)
		if err != nil {
			return nil, err
		}
		return &PubKeySecp256k1{Data: raw}, nil
	}

	panic(fmt.Sprintf("Unknow V=%d, sig=%X", sig[64], sig))
}
