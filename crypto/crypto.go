package crypto

import (
	"errors"
	"math/big"

	"github.com/XunleiBlockchain/tc-libs/bal"
	"github.com/XunleiBlockchain/tc-libs/common"
	"golang.org/x/crypto/sha3"
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64, payload []byte) common.Address {
	data, _ := bal.EncodeToBytes([]interface{}{b, nonce, payload})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// CreateAddress2 creates an ethereum address given the address bytes, initial
// contract code hash and a salt.
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak256([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// CreateContractAddress creates an ethereum address given the bytes and the nonce and the random number
func CreateContractAddress(b common.Address, nonce uint64, payload []byte, rand int) common.Address {
	data, _ := bal.EncodeToBytes([]interface{}{b, nonce, payload, rand})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}

	if v == 0 || v == 1 {
		// reject upper range of s values (ECDSA malleability)
		// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
		if homestead && s.Cmp(secp256k1halfN) > 0 {
			return false
		}
		// Frontier: allow s to be in full N range
		return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
	}

	return (v == SM2Magic || v == SM2Magic+1)
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
