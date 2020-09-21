package crypto

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/XunleiBlockchain/tc-libs/bal"
	"github.com/XunleiBlockchain/tc-libs/common"
)

func SignatureFromBytes(signBytes []byte) (sign Signature, err error) {
	err = bal.DecodeBytesWithType(signBytes, &sign)
	return
}

//----------------------------------------

type Signature interface {
	Bytes() []byte
	IsZero() bool
	Equals(Signature) bool
	Raw() []byte
}

//-------------------------------------

var _ Signature = SignatureEd25519{}

const SignatureEd25519Size = 64

// Implements Signature
type SignatureEd25519 [SignatureEd25519Size]byte

func (sig SignatureEd25519) Bytes() []byte {
	bz, err := bal.EncodeToBytesWithType(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

// Raw --
func (sig SignatureEd25519) Raw() []byte {
	return sig[:]
}

func (sig SignatureEd25519) IsZero() bool { return len(sig) == 0 }

func (sig SignatureEd25519) String() string {
	return fmt.Sprintf("/%X.../", common.Fingerprint(sig[:]))
}

func (sig SignatureEd25519) Equals(other Signature) bool {
	if otherEd, ok := other.(SignatureEd25519); ok {
		return subtle.ConstantTimeCompare(sig[:], otherEd[:]) == 1
	}
	return false
}

func NewSignatureEd25519(data []byte) Signature {
	var sig SignatureEd25519
	copy(sig[:], data)
	return sig
}

//-------------------------------------

var _ Signature = SignatureSecp256k1{}

// Implements Signature
type SignatureSecp256k1 []byte

func (sig SignatureSecp256k1) Bytes() []byte {
	bz, err := bal.EncodeToBytesWithType(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

// Raw --
func (sig SignatureSecp256k1) Raw() []byte {
	return sig
}

func (sig SignatureSecp256k1) IsZero() bool { return len(sig) == 0 }

func (sig SignatureSecp256k1) String() string {
	return fmt.Sprintf("/%X.../", common.Fingerprint(sig[:]))
}

func (sig SignatureSecp256k1) Equals(other Signature) bool {
	if otherSecp, ok := other.(SignatureSecp256k1); ok {
		return subtle.ConstantTimeCompare(sig[:], otherSecp[:]) == 1
	}
	return false
}

func NewSignatureSecp256k1(data []byte) Signature {
	sig := make(SignatureSecp256k1, len(data))
	copy(sig[:], data)
	return sig
}

// ------------------------------

const SignatureGMSize = 65
const SM2Magic = 0x8

// SignatureGM --
type SignatureGM [SignatureGMSize]byte

// Bytes --
func (sig SignatureGM) Bytes() []byte {
	return bal.MustEncodeToBytesWithType(sig)
}

// Raw --
func (sig SignatureGM) Raw() []byte {
	return sig[:]
}

// IsZero --
func (sig SignatureGM) IsZero() bool {
	return len(sig) == 0
}

// Equals --
func (sig SignatureGM) Equals(other Signature) bool {
	if otherSig, ok := other.(SignatureGM); ok {
		return bytes.Equal(sig[:], otherSig[:])
	}
	return false
}

func makeSignatureGM(r, s, v *big.Int) Signature {
	var ss SignatureGM
	rb := r.Bytes()
	sb := s.Bytes()

	copy(ss[32-len(rb):32], rb)
	copy(ss[64-len(sb):64], sb)
	ss[64] = SM2Magic + byte(v.Uint64())
	return ss
}

// ParseSignatureGM --
func ParseSignatureGM(sig []byte) (r, s, v *big.Int, ok bool) {
	if len(sig) != SignatureGMSize {
		return nil, nil, nil, false
	}

	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = big.NewInt(int64(sig[64] - byte(SM2Magic)))
	return r, s, v, true
}

// NewSignatureGM --
func NewSignatureGM(data []byte) (Signature, bool) {
	if len(data) != SignatureGMSize {
		return SignatureGM{}, false
	}
	var sig SignatureGM
	copy(sig[:], data[:SignatureGMSize])
	return sig, true
}
