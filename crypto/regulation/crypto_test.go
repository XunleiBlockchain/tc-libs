package regulation

import (
	"testing"
)

func TestRegulationCrypto(t *testing.T) {
	x, Y := GenerateRegulationKey()

	k, C1, C2, symk, err := GenerateAndEncryptSymmetricKey(Y)
	if err != nil {
		t.Fatalf(err.Error())
	}

	symk1, err := GetSymmetricKeyWithK(C2, Y, k)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if *symk1 != *symk {
		t.Fatalf("GetSymmetricKeyWithK returned a wrong symk")
	}

	symk2, err := GetSymmetricKeyWithX(C1, C2, x)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if *symk2 != *symk {
		t.Fatalf("GetSymmetricKeyWithX returned a wrong symk")
	}
}
