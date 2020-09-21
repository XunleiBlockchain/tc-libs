// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"math/big"
	"sort"
	"unsafe"

	"github.com/XunleiBlockchain/tc-libs/bloombits"
	"github.com/XunleiBlockchain/tc-libs/common"
	"github.com/XunleiBlockchain/tc-libs/crypto/merkle"
)

//go:generate gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	receiptStatusFailedbal     = []byte{}
	receiptStatusSuccessfulbal = []byte{0x01}
)

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields
	PostState         []byte          `json:"root"`
	Status            uint64          `json:"status"`
	VMErr             string          `json:"vmErr"`
	CumulativeGasUsed uint64          `json:"cumulativeGasUsed" gencodec:"required"`
	Bloom             bloombits.Bloom `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log          `json:"logs"              gencodec:"required"`

	// Implementation fields (don't reorder!)
	TxHash          common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress common.Address `json:"contractAddress"`
	GasUsed         uint64         `json:"gasUsed" gencodec:"required"`
	ZoneID          int            `json:"zoneid"`
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
func NewReceipt(root []byte, vmerr error, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{PostState: common.CopyBytes(root), CumulativeGasUsed: cumulativeGasUsed}
	if vmerr != nil {
		r.Status = ReceiptStatusFailed
		r.VMErr = vmerr.Error()
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (r *Receipt) Size() common.StorageSize {
	size := common.StorageSize(unsafe.Sizeof(*r)) + common.StorageSize(len(r.PostState))

	size += common.StorageSize(len(r.Logs)) * common.StorageSize(unsafe.Sizeof(Log{}))
	for _, log := range r.Logs {
		size += common.StorageSize(len(log.Topics)*common.HashLength + len(log.Data))
	}
	return size
}

func (r *Receipt) Hash() common.Hash {
	return BalHash(r)
}

// Receipts is a wrapper around a Receipt array to implement DerivableList.
type ReceiptList []*Receipt

func CreateBloom(mreceipts Receipts) bloombits.Bloom {
	bin := new(big.Int)
	for _, receipts := range mreceipts {
		for _, receipt := range receipts {
			bin.Or(bin, LogsBloom(receipt.Logs))
		}
	}

	return bloombits.BytesToBloom(bin.Bytes())
}

func (r ReceiptList) Hash() common.Hash {
	switch len(r) {
	case 0:
		return common.EmptyHash
	case 1:
		return r[0].Hash()
	default:
		left := ReceiptList(r[:(len(r)+1)/2]).Hash().Bytes()
		right := ReceiptList(r[(len(r)+1)/2:]).Hash().Bytes()
		hash := merkle.SimpleHashFromTwoHashes(left, right)
		return common.BytesToHash(hash)
	}
}

type HashList []common.Hash

func (hl HashList) Hash() common.Hash {
	switch len(hl) {
	case 0:
		return common.EmptyHash
	case 1:
		return hl[0]
	default:
		left := HashList(hl[:(len(hl)+1)/2]).Hash().Bytes()
		right := HashList(hl[(len(hl)+1)/2:]).Hash().Bytes()
		hash := merkle.SimpleHashFromTwoHashes(left, right)
		return common.BytesToHash(hash)
	}
}

type Receipts map[int]ReceiptList

func (r Receipts) Hash() common.Hash {
	zoneids := make([]int, 0, len(r))
	hashs := make(HashList, 0, len(r))
	for zoneid, _ := range r {
		zoneids = append(zoneids, zoneid)
	}
	sort.Ints(zoneids)
	for _, zoneid := range zoneids {
		hashs = append(hashs, r[zoneid].Hash())
	}
	return hashs.Hash()

}

// Len returns the number of receipts in this list.
/*
func (r Receipts) Len() int { return len(r) }

// Getbal returns the bal encoding of one receipt from the list.
func (r Receipts) Getbal(i int) []byte {
	bytes, err := bal.EncodeToBytes(r[i])
	if err != nil {
		panic(err)
	}
	return bytes
}
*/

func (r Receipts) GetReceipt(zoneid int, index uint64) *Receipt {
	receipts, has := r[zoneid]
	if !has {
		return nil
	}
	if index >= uint64(len(receipts)) {
		return nil
	}
	return receipts[index]
}
