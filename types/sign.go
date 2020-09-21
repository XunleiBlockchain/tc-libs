package types

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/XunleiBlockchain/tc-libs/bal"
	"github.com/XunleiBlockchain/tc-libs/common"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidSignParam is returned if the transaction signed with error param.
	ErrInvalidSignParam = errors.New("invalid sign param for signer")
)

type SignerData interface {
	Recover(hash common.Hash, signParamMul *big.Int, homestead bool) (common.Address, error)
	SignParam() *big.Int
	Protected() bool
	SignFields() []interface{}
	From() *atomic.Value
}

// STDSigner encapsulates signdata signature handling. Note that this interface is not a
// stable API and may change at any time to accommodate new protocol rules.
type STDSigner interface {
	// Sender returns the sender address of the signdata.
	Sender(data SignerData) (common.Address, error)
	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed.
	Hash(data SignerData) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(STDSigner) bool
	// SignParam return the field signParam
	SignParam() *big.Int
}

var big8 = big.NewInt(8)

func BalHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	bal.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

// STDEIP155Signer implements STDSigner using the EIP155 rules.
type STDEIP155Signer struct {
	signParam, signParamMul *big.Int
}

// NewSTDEIP155Signer return a STDEIP155Signer
func NewSTDEIP155Signer(signParam *big.Int) STDEIP155Signer {
	if signParam == nil {
		signParam = new(big.Int)
	}
	return STDEIP155Signer{
		signParam:    signParam,
		signParamMul: new(big.Int).Mul(signParam, big.NewInt(2)),
	}
}

// SignParam return the field signParam
func (s STDEIP155Signer) SignParam() *big.Int {
	return s.signParam
}

// Equal returns true if the given signer is the same as the receiver.
func (s STDEIP155Signer) Equal(s2 STDSigner) bool {
	eip155, ok := s2.(STDEIP155Signer)
	return ok && eip155.signParam.Cmp(s.signParam) == 0
}

// Sender returns the sender address of the signdata.
func (s STDEIP155Signer) Sender(data SignerData) (common.Address, error) {
	if !data.Protected() {
		return STDHomesteadSigner{}.Sender(data)
	}

	signParam := data.SignParam()
	if signParam.Cmp(s.signParam) != 0 {
		signParam = signParam.Sub(signParam, big.NewInt(4))
		if signParam.Cmp(s.signParam) != 0 {
			return common.EmptyAddress, ErrInvalidSignParam
		}
	}
	return data.Recover(s.Hash(data), s.signParamMul, true)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s STDEIP155Signer) SignatureValues(sig []byte) (R, S, V *big.Int, err error) {
	R, S, V, err = STDHomesteadSigner{}.SignatureValues(sig)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.signParam.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.signParamMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the signdata.
func (s STDEIP155Signer) Hash(data SignerData) common.Hash {
	h := data.SignFields()
	h = append(h, s.signParam, uint(0), uint(0))
	return BalHash(h)
}

// STDHomesteadSigner implements TransactionInterface using the homestead rules.
type STDHomesteadSigner struct{ STDFrontierSigner }

// SignParam return the field signParam
func (s STDHomesteadSigner) SignParam() *big.Int {
	return nil
}

// Equal returns true if the given signer is the same as the receiver.
func (s STDHomesteadSigner) Equal(s2 STDSigner) bool {
	_, ok := s2.(STDHomesteadSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s STDHomesteadSigner) SignatureValues(sig []byte) (*big.Int, *big.Int, *big.Int, error) {
	return s.STDFrontierSigner.SignatureValues(sig)
}

// Sender returns the sender address of the signdata.
func (s STDHomesteadSigner) Sender(data SignerData) (common.Address, error) {
	return data.Recover(s.Hash(data), nil, true)
}

// STDFrontierSigner implements TransactionInterface using the homestead rules.
type STDFrontierSigner struct{}

// SignParam return the field signParam
func (s STDFrontierSigner) SignParam() *big.Int {
	return nil
}

// Equal returns true if the given signer is the same as the receiver.
func (s STDFrontierSigner) Equal(s2 STDSigner) bool {
	_, ok := s2.(STDFrontierSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s STDFrontierSigner) SignatureValues(sig []byte) (R, S, V *big.Int, err error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	R = new(big.Int).SetBytes(sig[:32])
	S = new(big.Int).SetBytes(sig[32:64])
	V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s STDFrontierSigner) Hash(data SignerData) common.Hash {
	return BalHash(data.SignFields())
}

// Sender returns the sender address of the signdata.
func (s STDFrontierSigner) Sender(data SignerData) (common.Address, error) {
	return data.Recover(s.Hash(data), nil, false)
}
