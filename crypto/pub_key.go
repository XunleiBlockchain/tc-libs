package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"

	"github.com/XunleiBlockchain/tc-libs/bal"
	cmn "github.com/XunleiBlockchain/tc-libs/common"
	"github.com/XunleiBlockchain/tc-libs/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/tjfoc/gmsm/sm2"
	"golang.org/x/crypto/ed25519"
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = cmn.HexBytes

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = bal.DecodeBytesWithType(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
	Raw() []byte
}

//-------------------------------------

var _ PubKey = PubKeyEd25519{}

const PubKeyEd25519Size = 32

// Implements PubKeyInner
type PubKeyEd25519 [PubKeyEd25519Size]byte

// Address is the Ripemd160 of the raw pubkey bytes.
func (pubKey PubKeyEd25519) Address() Address {
	return Address(Ripemd160(pubKey[:]))
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	bz, err := bal.EncodeToBytesWithType(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

// Raw --
func (pubKey PubKeyEd25519) Raw() []byte {
	return pubKey[:]
}

func serEncodeFroJSON(v interface{}) ([]byte, error) {
	b, err := bal.EncodeToBytesWithType(v)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(b)*2+4)
	copy(enc, `"0x`)
	hex.Encode(enc[3:], b)
	enc[len(enc)-1] = '"'
	return enc, err
}

func serDecodeForJSON(v interface{}, input []byte) error {
	if len(input) < 4 {
		return fmt.Errorf("%s is not a hex string", input)
	}
	input = input[3 : len(input)-1]
	dec := make([]byte, len(input)/2)
	if _, err := hex.Decode(dec, input); err != nil {
		return err
	}
	return bal.DecodeBytesWithType(dec, v)
}

func (pubKey PubKeyEd25519) MarshalJSON() ([]byte, error) {
	return serEncodeFroJSON(pubKey)
}

func (pubKey *PubKeyEd25519) UnmarshalJSON(input []byte) error {
	return serDecodeForJSON(pubKey, input)
}

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool {
	// make sure we use the same algorithm to sign
	sig, ok := sig_.(SignatureEd25519)
	if !ok {
		return false
	}
	pubKeyBytes := [PubKeyEd25519Size]byte(pubKey)
	sigBytes := [SignatureEd25519Size]byte(sig)
	return ed25519.Verify(pubKeyBytes[:], msg, sigBytes[:])
}

func (pubKey PubKeyEd25519) String() string {
	return fmt.Sprintf("PubKeyEd25519{%v}", hexutil.Encode(pubKey.Bytes()))
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}
	return false
}

//-------------------------------------

var _ PubKey = &PubKeySecp256k1{}

// const PubKeySecp256k1Size = 33

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
// type PubKeySecp256k1 [PubKeySecp256k1Size]byte
type PubKeySecp256k1 struct {
	pk   *ecdsa.PublicKey
	Data []byte
}

func (pubKey *PubKeySecp256k1) toECDSA() *ecdsa.PublicKey {
	if pubKey.pk == nil {
		pubKey.fromRaw()
	}
	return pubKey.pk
}

func (pubKey *PubKeySecp256k1) fromRaw() {
	if pubKey.pk == nil {
		if len(pubKey.Data) == 0 {
			panic("")
		}
		x, y := elliptic.Unmarshal(S256(), pubKey.Raw())
		pubKey.pk = &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}
	}
}

// Address --
func (pubKey *PubKeySecp256k1) Address() Address {
	pubBytes := pubKey.Raw()
	return Address(Keccak256(pubBytes[1:])[12:])
}

// Bytes --
func (pubKey *PubKeySecp256k1) Bytes() []byte {
	bz, err := bal.EncodeToBytesWithType(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

// Raw --
func (pubKey *PubKeySecp256k1) Raw() []byte {
	return pubKey.Data
}

// VerifyBytes --
// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func (pubKey *PubKeySecp256k1) VerifyBytes(msg []byte, sig Signature) bool {
	return secp256k1.VerifySignature(pubKey.Raw(), msg, sig.Raw()[:64])
}

func (pubKey *PubKeySecp256k1) String() string {
	return fmt.Sprintf("PubKeySecp256k1{%X}", pubKey.Data)
}

// Equals --
func (pubKey *PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.(*PubKeySecp256k1); ok {
		return bytes.Equal(pubKey.Data, otherSecp.Data)
	}
	return false
}

func makePubKeySecp256k1(pk *ecdsa.PublicKey) *PubKeySecp256k1 {
	return &PubKeySecp256k1{
		pk:   pk,
		Data: elliptic.Marshal(S256(), pk.X, pk.Y), //FromECDSAPub(pk),
	}
}

// PubKeySecp256k1FromBytes --
func PubKeySecp256k1FromBytes(raw []byte) *PubKeySecp256k1 {
	pubKey := PubKeySecp256k1{
		Data: raw,
	}
	pubKey.fromRaw()
	return &pubKey
}

// -----------------------------------

// PubKeyGM --
type PubKeyGM struct {
	Data []byte
	pk   *sm2.PublicKey
}

// Address --
func (pubKey *PubKeyGM) Address() Address {
	pubBytes := pubKey.Raw()
	return Address(Keccak256(pubBytes[1:])[12:])
}

// Bytes --
func (pubKey *PubKeyGM) Bytes() []byte {
	return bal.MustEncodeToBytesWithType(pubKey)
}

// Raw --
func (pubKey *PubKeyGM) Raw() []byte {
	return pubKey.Data[:]
}

// VerifyBytes --
func (pubKey *PubKeyGM) VerifyBytes(msg []byte, sig Signature) bool {
	r, s, v, ok := ParseSignatureGM(sig.Raw())
	if !ok {
		return false
	}
	return sm2.VerifyExt(pubKey.key(), msg, r, s, v)
}

// Equals --
func (pubKey *PubKeyGM) Equals(other PubKey) bool {
	if otherGM, ok := other.(*PubKeyGM); ok {
		return bytes.Equal(pubKey.Raw(), otherGM.Raw())
	}
	return false
}

func (pubKey *PubKeyGM) key() *sm2.PublicKey {
	if pubKey.pk == nil {
		pubKey.fromRaw()
	}
	return pubKey.pk
}

func (pubKey *PubKeyGM) fromRaw() {
	if pubKey.pk == nil {
		if len(pubKey.Data) == 0 {
			panic("")
		}
		x, y := elliptic.Unmarshal(sm2.P256Sm2(), pubKey.Raw())
		pubKey.pk = &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}
	}
}

func makePubKeyGM(pk *sm2.PublicKey) *PubKeyGM {
	return &PubKeyGM{
		pk:   pk,
		Data: elliptic.Marshal(sm2.P256Sm2(), pk.X, pk.Y),
	}
}

// PubKeyGMFromBytes --
func PubKeyGMFromBytes(data []byte) *PubKeyGM {
	pubKey := PubKeyGM{
		Data: data,
	}
	pubKey.fromRaw()
	return &pubKey
}
