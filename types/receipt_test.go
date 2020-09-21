package types

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"testing"
	"time"

	"github.com/XunleiBlockchain/tc-libs/bal"
	"github.com/XunleiBlockchain/tc-libs/common"
)

func TestReceiptEncode(t *testing.T) {
	log := &Log{
		Address:     common.HexToAddress("0x01"),
		Topics:      []common.Hash{common.HexToHash("0x02")},
		Data:        []byte("data"),
		BlockNumber: 3,
		TxHash:      common.HexToHash("0x4"),
		TxIndex:     5,
		BlockHash:   common.HexToHash("0x6"),
		Index:       7,
		BlockTime:   uint64(time.Now().Unix()),
	}
	receipt := &Receipt{
		PostState:         common.HexToHash("0x01").Bytes(),
		Status:            2,
		VMErr:             "vmerr",
		CumulativeGasUsed: 3e10,
		TxHash:            common.HexToHash("0x4"),
		GasUsed:           5e10,
		ContractAddress:   common.HexToAddress("0x06"),
		Logs:              []*Log{log},
		ZoneID:            7,
	}
	receipt.Bloom = CreateBloom(Receipts{-1: ReceiptList{receipt}})

	receipts := make(ReceiptList, 0)
	for i := 0; i < 1; i++ {
		receipts = append(receipts, receipt)
	}

	bs, err := bal.EncodeToBytes(receipts)
	if err != nil {
		t.Fatalf("bal.EncodeToBytes err:%v", err)
	}

	receipts2 := make(ReceiptList, 0)
	if err := bal.DecodeBytes(bs, &receipts2); err != nil {
		t.Fatalf("bal.DecodeBytes err:%v", err)
	}

	bf := new(bytes.Buffer)
	enc := gob.NewEncoder(bf)
	if err := enc.Encode(receipts); err != nil {
		t.Fatalf("gob.Encode err:%v", err)
	}

	rBytes := bf.Bytes()

	bf.Reset()
	enc = gob.NewEncoder(bf)
	if err := enc.Encode(receipts2); err != nil {
		t.Fatalf("gob.Encode err:%v", err)
	}
	if fmt.Sprintf("%x", rBytes) != fmt.Sprintf("%x", bf.Bytes()) {
		t.Fatalf("ReceiptList encode error")
	}
	fmt.Println(receipts.Hash().Hex())
	fmt.Println(receipts2.Hash().Hex())
	receipts2[0].Status = 3332
	fmt.Println(receipts2.Hash().Hex())
}

func BenchmarkReceiptHashBybal(b *testing.B) {
	log := &Log{
		Address:     common.HexToAddress("0x01"),
		Topics:      []common.Hash{common.HexToHash("0x02")},
		Data:        []byte("data"),
		BlockNumber: 3,
		TxHash:      common.HexToHash("0x4"),
		TxIndex:     5,
		BlockHash:   common.HexToHash("0x6"),
		Index:       7,
		BlockTime:   uint64(time.Now().Unix()),
	}
	receipt := &Receipt{
		PostState:         common.HexToHash("0x01").Bytes(),
		Status:            2,
		VMErr:             "vmerr",
		CumulativeGasUsed: 3e10,
		TxHash:            common.HexToHash("0x4"),
		GasUsed:           5e10,
		ContractAddress:   common.HexToAddress("0x06"),
		Logs:              []*Log{log},
		ZoneID:            7,
	}
	receipt.Bloom = CreateBloom(Receipts{-1: ReceiptList{receipt}})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		receipt.Hash()
	}
}
