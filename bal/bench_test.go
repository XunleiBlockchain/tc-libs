package bal

import (
	"bytes"
	"testing"
)

func init() {
	RegisterInterface((*human)(nil), nil)
	RegisterConcrete(&girl{}, "bal/girl", nil)
}

func BenchmarkbalEncode(b *testing.B) {
	b.StopTimer()
	gl := &girl{
		Age:   18,
		Name:  "LiLi",
		Hobby: "song",
	}
	fa := &father{
		Kid:  gl,
		Age:  40,
		Name: "Jack",
	}
	var buf = new(bytes.Buffer)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		err := Encode(buf, fa)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkbalDecode(b *testing.B) {
	b.StopTimer()
	gl := &girl{
		Age:   18,
		Name:  "LiLi",
		Hobby: "song",
	}
	fa := &father{
		Kid:  gl,
		Age:  40,
		Name: "Jack",
	}
	var buf = new(bytes.Buffer)
	Encode(buf, fa)
	var h1 father
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		err := DecodeBytes(buf.Bytes(), &h1)
		if err != nil {
			panic(err)
		}
	}
}
