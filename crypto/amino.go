package crypto

import (
	"github.com/XunleiBlockchain/tc-libs/bal"
)

func init() {
	// NOTE: It's important that there be no conflicts here,
	// as that would change the canonical representations,
	// and therefore change the address.
	// TODO: Add feature to go-amino to ensure that there
	// are no conflicts.
	RegisterAmino()
}

// RegisterAmino registers all crypto related types in the given (amino) codec.
func RegisterAmino() {
	bal.RegisterInterface((*PubKey)(nil), nil)
	bal.RegisterConcrete(PubKeyEd25519{}, "PubKeyEd25519", nil)
	bal.RegisterConcrete(&PubKeySecp256k1{}, "PubKeySecp256k1", nil)
	bal.RegisterConcrete(&PubKeyGM{}, "PubKeyGM", nil)

	bal.RegisterInterface((*PrivKey)(nil), nil)
	bal.RegisterConcrete(PrivKeyEd25519{}, "PrivKeyEd25519", nil)
	bal.RegisterConcrete(&PrivKeySecp256k1{}, "PrivKeySecp256k1", nil)
	bal.RegisterConcrete(&PrivKeyGM{}, "PrivKeyGM", nil)

	bal.RegisterInterface((*Signature)(nil), nil)
	bal.RegisterConcrete(SignatureEd25519{}, "SignEd25519", nil)
	bal.RegisterConcrete(SignatureSecp256k1{}, "SignSecp256k1", nil)
	bal.RegisterConcrete(SignatureGM{}, "SignGM", nil)
}
