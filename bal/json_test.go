package bal

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestMapJson(t *testing.T) {
	m1 := map[int]string{
		1: "1",
		2: "2",
	}

	m2 := map[string]string{
		"1": "1",
		"2": "2",
	}

	jsonstr, err := json.Marshal(m1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Marshal: %s\n", jsonstr)

	var v1 map[int]string
	err = json.Unmarshal(jsonstr, &v1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Unmarshal: %v\n", v1)

	jsonstr, err = json.Marshal(m2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Marshal: %s\n", jsonstr)

	var v2 map[string]string
	err = json.Unmarshal(jsonstr, &v2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Unmarshal: %v\n", v2)

	jsonstr, err = MarshalJSON(m1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.MarshalJSON: %s\n", jsonstr)

	var v3 map[int]string
	err = UnmarshalJSON(jsonstr, &v3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.UnmarshalJson: %v\n", v3)

	jsonstr, err = MarshalJSON(m2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.MarshalJSON: %s\n", jsonstr)

	var v4 map[string]string
	err = UnmarshalJSON(jsonstr, &v4)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.UnmarshalJson: %v\n", v4)

	type mapTest struct {
		ID       int
		Name     string
		Rel      map[int]string
		U8       uint8
		U16      uint16
		U64      uint64
		SSlice   []string
		U8Slice  []uint8
		U64Slice []uint64
	}

	t1 := mapTest{
		ID:       1,
		Name:     "jack",
		Rel:      map[int]string{2: "friend", 3: "worker"},
		U8:       8,
		U16:      16,
		U64:      64,
		SSlice:   []string{"123", "455"},
		U8Slice:  []uint8{1, 2, 3},
		U64Slice: []uint64{1, 2, 3},
	}
	jsonstr, err = json.Marshal(t1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Marshal: %s\n", jsonstr)

	var rt1 mapTest
	err = json.Unmarshal(jsonstr, &rt1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("json.Unmarshal: %v\n", rt1)

	jsonstr, err = MarshalJSON(t1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.MarshalJSON: %s\n", jsonstr)

	var rt2 mapTest
	err = UnmarshalJSON(jsonstr, &rt2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bal.UnmarshalJson: %v\n", rt2)
}
