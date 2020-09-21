package ristretto_test

import (
	"bytes"
	"fmt"
)

func Example() {
	// Generate an El'Gamal keypair
	var secretKey Scalar
	var publicKey Point

	secretKey.Rand()                     // generate a new secret key
	publicKey.ScalarMultBase(&secretKey) // compute public key

	// El'Gamal encrypt a random curve point p into a ciphertext-pair (c1,c2)
	var p Point
	var r Scalar
	var c1 Point
	var c2 Point
	p.Rand()
	r.Rand()
	c2.ScalarMultBase(&r)
	c1.PublicScalarMult(&publicKey, &r)
	c1.Add(&c1, &p)

	// Decrypt (c1,c2) back to p
	var blinding, p2 Point
	blinding.ScalarMult(&c2, &secretKey)
	p2.Sub(&c1, &blinding)

	fmt.Printf("%v", bytes.Equal(p.Bytes(), p2.Bytes()))
	// Output:
	// true
}
