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

/*
Package RLP implements the bal serialization format and support interface.

The purpose of RLP (Recursive Linear Prefix) is to encode arbitrarily
nested arrays of binary data, and bal is the main encoding method used
to serialize objects in Ethereum. The only purpose of bal is to encode
structure; encoding specific atomic data types (eg. strings, ints,
floats) is left up to higher-order protocols; in Ethereum integers
must be represented in big endian binary form with no leading zeroes
(thus making the integer value zero equivalent to the empty byte
array).

bal values are distinguished by a type tag. The type tag precedes the
value in the input stream and defines the size and kind of the bytes
that follow.

Amino is an encoding library that can handle interfaces (like protobuf "oneof")
well.  This is achieved by prefixing bytes before each "concrete type".
A concrete type is some non-interface value (generally a struct) which
implements the interface to be (de)serialized. Not all structures need to be
registered as concrete types -- only when they will be stored in interface type
fields (or interface type slices) do they need to be registered.
Registering types
*/
package bal
