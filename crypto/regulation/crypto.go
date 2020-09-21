package regulation

import (
	"fmt"
	"github.com/bwesterb/go-ristretto"
)

// generate x and Y. Y = x * G
func GenerateRegulationKey() (privateKey *[32]byte, publicKey *[32]byte) {
	var privateKeyScalar ristretto.Scalar
	privateKeyScalar.Rand()
	privateKey = new([32]byte)
	privateKeyScalar.BytesInto(privateKey)
	var publicKeyPoint ristretto.Point
	publicKeyPoint.PublicScalarMultBase(&privateKeyScalar)
	publicKey = new([32]byte)
	publicKeyPoint.BytesInto(publicKey)
	return
}

// Y is regulator's public key
func GenerateAndEncryptSymmetricKey(Y *[32]byte) (k *[32]byte, C1 *[32]byte, C2 *[32]byte, symk *[32]byte, err error) {
	// generate a random point M in the curve, and use its compressed form as symmetric key
	var seed ristretto.Scalar
	seed.Rand()
	var M ristretto.Point
	M.PublicScalarMultBase(&seed)
	symk = new([32]byte)
	M.BytesInto(symk)

	// generate a random scalar k
	var kScalar ristretto.Scalar
	kScalar.Rand()
	k = new([32]byte)
	kScalar.BytesInto(k)

	// C1 = k * G
	var C1Point ristretto.Point
	C1Point.PublicScalarMultBase(&kScalar)
	C1 = new([32]byte)
	C1Point.BytesInto(C1)

	// C2 = M + k * Y
	var kY ristretto.Point
	var YPoint ristretto.Point
	if !YPoint.SetBytes(Y) {
		err = fmt.Errorf("Y is not a valid public key. ")
		return
	}
	kY.PublicScalarMult(&YPoint, &kScalar)
	var C2Point ristretto.Point
	C2Point.Add(&M, &kY)
	C2 = new([32]byte)
	C2Point.BytesInto(C2)

	return
}

func GetSymmetricKeyWithK(C2 *[32]byte, Y *[32]byte, k *[32]byte) (symk *[32]byte, err error) {
	var C2Point ristretto.Point
	if !C2Point.SetBytes(C2) {
		err = fmt.Errorf("C2 is not a valid point in the curve. ")
		return
	}

	var kY ristretto.Point
	var YPoint ristretto.Point
	if !YPoint.SetBytes(Y) {
		err = fmt.Errorf("Y is not a valid public key. ")
		return
	}
	var kScalar ristretto.Scalar
	kScalar.SetBytes(k)
	kY.PublicScalarMult(&YPoint, &kScalar)

	var M ristretto.Point
	M.Sub(&C2Point, &kY)
	symk = new([32]byte)
	M.BytesInto(symk)
	return
}

// x is the regulator's private key
func GetSymmetricKeyWithX(C1 *[32]byte, C2 *[32]byte, x *[32]byte) (symk *[32]byte, err error) {
	var C1Point ristretto.Point
	if !C1Point.SetBytes(C1) {
		err = fmt.Errorf("C1 is not a valid point in the curve. ")
		return
	}

	var C2Point ristretto.Point
	if !C2Point.SetBytes(C2) {
		err = fmt.Errorf("C2 is not a valid point in the curve. ")
		return
	}

	var xScalar ristretto.Scalar
	xScalar.SetBytes(x)
	var xC1 ristretto.Point
	xC1.PublicScalarMult(&C1Point, &xScalar)

	var M ristretto.Point
	M.Sub(&C2Point, &xC1)
	symk = new([32]byte)
	M.BytesInto(symk)
	return
}

func GetSymmetricCipher() SymmetricCipher {
	return AesCipher{}
}
