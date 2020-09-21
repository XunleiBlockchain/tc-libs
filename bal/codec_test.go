package bal_test

import (
	"testing"

	"github.com/XunleiBlockchain/tc-libs/bal"

	"github.com/stretchr/testify/assert"
)

func TestCodecSeal(t *testing.T) {

	type Foo interface{}
	type Bar interface{}

	cdc := bal.NewCodec()
	cdc.RegisterInterface((*Foo)(nil), nil)
	cdc.Seal()

	assert.Panics(t, func() { cdc.RegisterInterface((*Bar)(nil), nil) })
	assert.Panics(t, func() { cdc.RegisterConcrete(int(0), "int", nil) })
}
