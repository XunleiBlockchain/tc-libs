package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/XunleiBlockchain/tc-libs/bal"
	"github.com/XunleiBlockchain/tc-libs/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/tjfoc/gmsm/sm2"
	"golang.org/x/crypto/ed25519"
)

func PrivKeyFromBytes(privKeyBytes []byte) (privKey PrivKey, err error) {
	err = bal.DecodeBytesWithType(privKeyBytes, &privKey)
	return
}

//----------------------------------------

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) (Signature, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Reset()
	Raw() []byte
	Type() string
}

//-------------------------------------

var _ PrivKey = PrivKeyEd25519{}

// Implements PrivKey
type PrivKeyEd25519 [64]byte

func (privKey PrivKeyEd25519) Type() string {
	return CryptoTypeEd25519
}

func (privKey PrivKeyEd25519) Bytes() []byte {
	return bal.MustEncodeToBytesWithType(privKey)
}

// Raw --
func (privKey PrivKeyEd25519) Raw() []byte {
	return privKey[:]
}

func (privKey PrivKeyEd25519) Sign(msg []byte) (Signature, error) {
	privKeyBytes := privKey[:]
	sigBytes := ed25519.Sign(privKeyBytes, msg)
	signatureBytes := new([SignatureEd25519Size]byte)
	copy(signatureBytes[:SignatureEd25519Size], sigBytes)
	return SignatureEd25519(*signatureBytes), nil
}

func (privKey PrivKeyEd25519) PubKey() PubKey {
	privKeyBytes := [64]byte(privKey)
	pub, _, err := ed25519.GenerateKey(bytes.NewReader(privKeyBytes[:]))
	if err != nil {
		panic(err)
	}
	newKey := new([PubKeyEd25519Size]byte)
	copy(newKey[:PubKeyEd25519Size], pub)
	return PubKeyEd25519(*newKey)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeyEd25519) Equals(other PrivKey) bool {
	if otherEd, ok := other.(PrivKeyEd25519); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}
	return false
}

// Reset --
func (privKey PrivKeyEd25519) Reset() {
	for i := 0; i < 64; i++ {
		privKey[i] = 0
	}
}

// Deterministically generates new priv-key bytes from key.
func (privKey PrivKeyEd25519) Generate(index int) PrivKeyEd25519 {
	bz, err := bal.EncodeToBytes(struct {
		PrivKey [64]byte
		Index   int
	}{privKey, index})
	if err != nil {
		panic(err)
	}
	newBytes := Sha256(bz)
	newKey := new([64]byte)
	copy(newKey[:32], newBytes)
	_, priv, err := ed25519.GenerateKey(bytes.NewReader(newKey[:]))
	if err != nil {
		panic(err)
	}
	copy(newKey[:64], priv)
	return PrivKeyEd25519(*newKey)
}

func (privKey PrivKeyEd25519) MarshalJSON() ([]byte, error) {
	return serEncodeFroJSON(privKey)
}

func (privKey *PrivKeyEd25519) UnmarshalJSON(input []byte) error {
	return serDecodeForJSON(privKey, input)
}

func GenPrivKeyEd25519() (PrivKeyEd25519, error) {
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], CRandBytes(32))
	_, priv, err := ed25519.GenerateKey(bytes.NewReader(privKeyBytes[:]))
	if err != nil {
		return PrivKeyEd25519{}, err
	}
	copy(privKeyBytes[:64], priv)
	return PrivKeyEd25519(*privKeyBytes), nil
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyEd25519FromSecret(secret []byte) (PrivKeyEd25519, error) {
	privKey32 := Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], privKey32)
	_, priv, err := ed25519.GenerateKey(bytes.NewReader(privKeyBytes[:]))
	if err != nil {
		return PrivKeyEd25519{}, err
	}
	copy(privKeyBytes[:64], priv)
	return PrivKeyEd25519(*privKeyBytes), err
}

//-------------------------------------

var _ PrivKey = &PrivKeySecp256k1{}

type PrivKeySecp256k1 struct {
	pk   *ecdsa.PrivateKey
	Data []byte
}

func (privKey *PrivKeySecp256k1) toECDSA() *ecdsa.PrivateKey {
	if privKey.pk == nil {
		privKey.fromRaw()
	}
	return privKey.pk
}

func (privKey *PrivKeySecp256k1) fromRaw() error {
	if privKey.pk == nil {
		priv := new(ecdsa.PrivateKey)
		priv.PublicKey.Curve = S256()
		if 8*len(privKey.Raw()) != priv.Params().BitSize {
			return fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
		}

		priv.D = new(big.Int).SetBytes(privKey.Raw())
		// The priv.D must < N
		if priv.D.Cmp(secp256k1N) >= 0 {
			return fmt.Errorf("invalid private key, >=N")
		}
		// The priv.D must not be zero or negative.
		if priv.D.Sign() <= 0 {
			return fmt.Errorf("invalid private key, zero or negative")
		}

		priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(privKey.Raw())
		if priv.PublicKey.X == nil {
			return errors.New("invalid private key")
		}

		privKey.pk = priv
	}
	return nil
}

// Type --
func (privKey *PrivKeySecp256k1) Type() string {
	return CryptoTypeSecp256K1
}

// Bytes --
func (privKey *PrivKeySecp256k1) Bytes() []byte {
	return bal.MustEncodeToBytesWithType(privKey)
}

// Raw --
func (privKey *PrivKeySecp256k1) Raw() []byte {
	return privKey.Data
}

// Sign calculates an ECDSA signature.
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given hash cannot be chosen by an adversery. Common
// solution is to hash any input before calculating the signature.
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
func (privKey *PrivKeySecp256k1) Sign(hash []byte) (Signature, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	seckey := privKey.Raw()
	b, err := secp256k1.Sign(hash, seckey)
	if err != nil {
		return nil, err
	}

	return NewSignatureSecp256k1(b), nil
}

// PubKey --
func (privKey *PrivKeySecp256k1) PubKey() PubKey {
	return makePubKeySecp256k1(&privKey.toECDSA().PublicKey)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey *PrivKeySecp256k1) Equals(other PrivKey) bool {
	if otherSecp, ok := other.(*PrivKeySecp256k1); ok {
		return subtle.ConstantTimeCompare(privKey.Data, otherSecp.Data) == 1
	}
	return false
}

// Reset --
func (privKey *PrivKeySecp256k1) Reset() {
	for i := 0; i < len(privKey.Data); i++ {
		privKey.Data[i] = 0
	}
}

/*
// Deterministically generates new priv-key bytes from key.
func (key PrivKeySecp256k1) Generate(index int) PrivKeySecp256k1 {
	newBytes := cdc.BinarySha256(struct {
		PrivKey [64]byte
		Index   int
	}{key, index})
	var newKey [64]byte
	copy(newKey[:], newBytes)
	return PrivKeySecp256k1(newKey)
}
*/

func GenPrivKeySecp256k1() (*PrivKeySecp256k1, error) {
	pk, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &PrivKeySecp256k1{
		pk:   pk,
		Data: math.PaddedBigBytes(pk.D, pk.Params().BitSize/8),
	}, nil
}

// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeySecp256k1FromSecret(secret []byte) (*PrivKeySecp256k1, error) {
	privKey := PrivKeySecp256k1{
		Data: secret,
	}
	err := privKey.fromRaw()
	return &privKey, err

}

// -----------------------------------

// PrivKeyGM --
type PrivKeyGM struct {
	pk *sm2.PrivateKey
	Db []byte
}

func (privKey *PrivKeyGM) key() *sm2.PrivateKey {
	if privKey.pk == nil {
		if err := privKey.fromRaw(); err != nil {
			panic(err)
		}
	}
	return privKey.pk
}

func (privKey *PrivKeyGM) fromRaw() error {
	if privKey.pk == nil {
		pk := new(sm2.PrivateKey)
		pk.D = new(big.Int).SetBytes(privKey.Raw())
		c := sm2.P256Sm2()
		pk.PublicKey.Curve = c
		pk.PublicKey.X, pk.PublicKey.Y = c.ScalarBaseMult(privKey.Raw())
		if pk.PublicKey.X == nil {
			return errors.New("invalid private key")
		}

		privKey.pk = pk
	}

	return nil
}

// Type --
func (privKey *PrivKeyGM) Type() string {
	return CryptoTypeGM
}

// Bytes --
func (privKey *PrivKeyGM) Bytes() []byte {
	return bal.MustEncodeToBytesWithType(privKey)
}

// Raw --
func (privKey *PrivKeyGM) Raw() []byte {
	return privKey.Db
}

// Sign --
func (privKey *PrivKeyGM) Sign(msg []byte) (Signature, error) {
	r, s, v, err := sm2.SignExt(privKey.key(), msg)
	if err != nil {
		return nil, err
	}
	return makeSignatureGM(r, s, v), nil
}

// PubKey --
func (privKey *PrivKeyGM) PubKey() PubKey {
	return makePubKeyGM(&privKey.key().PublicKey)
}

// Equals --
func (privKey *PrivKeyGM) Equals(other PrivKey) bool {
	if otherGM, ok := other.(*PrivKeyGM); ok {
		return bytes.Equal(privKey.Raw(), otherGM.Raw())
	}
	return false
}

// Reset --
func (privKey *PrivKeyGM) Reset() {
	for i := 0; i < len(privKey.Raw()); i++ {
		privKey.Db[i] = 0
	}
}

// GenPrivKeyGM --
func GenPrivKeyGM() (*PrivKeyGM, error) {
	pk, err := sm2.GenerateKey()
	if err != nil {
		return nil, err
	}

	privKey := PrivKeyGM{
		pk: pk,
		Db: pk.D.Bytes(),
	}
	return &privKey, nil
}

// GenPrivKeyGMFromSecret --
func GenPrivKeyGMFromSecret(secret []byte) (*PrivKeyGM, error) {
	privKey := PrivKeyGM{
		Db: secret,
	}
	if err := privKey.fromRaw(); err != nil {
		return nil, err
	}
	return &privKey, nil
}
