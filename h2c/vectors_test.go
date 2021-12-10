// Copyright (c) 2021 Oasis Labs Inc. All rights reserved.
// Copyright (c) 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package h2c

import (
	"bytes"
	"compress/gzip"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

func (v *montgomeryPoint) Equal(other *montgomeryPoint) bool {
	return v.u.Equal(other.u) == 1 && v.v.Equal(other.v) == 1
}

func (v *montgomeryPoint) Bytes() []byte {
	return v.u.Bytes()
}

type suiteTestDef struct {
	n    string
	file string
	fn   func([]byte, []byte) (*edwards25519.Point, error)
	fn2  func([]byte, []byte) (*field.Element, *field.Element, error)
}

type expandTestDef struct {
	n    string
	file string
	h    crypto.Hash
	xof  sha3.ShakeHash
}

func TestVectors(t *testing.T) {
	for _, expandTest := range []expandTestDef{
		{
			n:    "SHA256",
			file: "testdata/expand_message_xmd_SHA256_38.json.gz",
			h:    crypto.SHA256,
		},
		{
			n:    "SHA256-LongDST",
			file: "testdata/expand_message_xmd_SHA256_256.json.gz",
			h:    crypto.SHA256,
		},
		{
			n:    "SHA512",
			file: "testdata/expand_message_xmd_SHA512_38.json.gz",
			h:    crypto.SHA512,
		},
		{
			n:    "SHAKE128",
			file: "testdata/expand_message_xof_SHAKE128_36.json.gz",
			xof:  sha3.NewShake128(),
		},
		{
			n:    "SHAKE128-LongDST",
			file: "testdata/expand_message_xof_SHAKE128_256.json.gz",
			xof:  sha3.NewShake128(),
		},
		{
			n:    "SHAKE256",
			file: "testdata/expand_message_xof_SHAKE256_36.json.gz",
			xof:  sha3.NewShake256(),
		},
	} {
		t.Run(expandTest.n, func(t *testing.T) {
			testExpand(t, &expandTest)
		})
	}

	for _, suiteTest := range []suiteTestDef{
		{
			n:    "edwards25519_XMD:SHA-512_ELL2_RO_",
			file: "testdata/edwards25519_XMD:SHA-512_ELL2_RO_.json.gz",
			fn:   Edwards25519_XMD_SHA512_ELL2_RO,
		},
		{
			n:    "edwards25519_XMD:SHA-512_ELL2_NU_",
			file: "testdata/edwards25519_XMD:SHA-512_ELL2_NU_.json.gz",
			fn:   Edwards25519_XMD_SHA512_ELL2_NU,
		},
		{
			n:    "curve25519_XMD:SHA-512_ELL2_RO_",
			file: "testdata/curve25519_XMD_SHA-512_ELL2_RO_.json.gz",
			fn2:  Curve25519_XMD_SHA512_ELL2_RO,
		},
		{
			n:    "curve25519_XMD:SHA-512_ELL2_NU_",
			file: "testdata/curve25519_XMD_SHA-512_ELL2_NU_.json.gz",
			fn2:  Curve25519_XMD_SHA512_ELL2_NU,
		},
	} {
		t.Run(suiteTest.n, func(t *testing.T) {
			testSuite(t, &suiteTest)
		})
	}
}

type suiteTestVectors struct {
	DST     string            `json:"DST"`
	Vectors []suiteTestVector `json:"vectors"`
}

type suiteTestVector struct {
	P   suiteTestPoint
	Msg string `json:"msg"`
}

type suiteTestPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func (pt *suiteTestPoint) ToCoordinates(t *testing.T) (*field.Element, *field.Element, error) {
	x := mustUnhex(t, trimOhEcks(pt.X))
	y := mustUnhex(t, trimOhEcks(pt.Y))

	// The IETF test vectors provide all coordinates in big-endian byte order.
	x = reversedByteSlice(x)
	y = reversedByteSlice(y)

	// Generate a point from the test vector x and y-coordinates.
	var feX, feY field.Element
	if _, err := feX.SetBytes(x); err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize x: %w", err)
	}
	if _, err := feY.SetBytes(y); err != nil {
		return nil, nil, fmt.Errorf("h2c: failed to deserialize y: %w", err)
	}

	return &feX, &feY, nil
}

func (pt *suiteTestPoint) ToEdwardsPoint(t *testing.T) (*edwards25519.Point, error) {
	feX, feY, err := pt.ToCoordinates(t)
	if err != nil {
		return nil, err
	}
	return newEdwardsFromXY(feX, feY), nil
}

func (pt *suiteTestPoint) ToMontgomeryPoint(t *testing.T) (*montgomeryPoint, error) {
	feX, feY, err := pt.ToCoordinates(t)
	return &montgomeryPoint{feX, feY}, err
}

func testSuite(t *testing.T, def *suiteTestDef) {
	f, err := os.Open(def.file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	var testVectors suiteTestVectors

	dec := json.NewDecoder(rd)
	if err = dec.Decode(&testVectors); err != nil {
		t.Fatal(err)
	}

	for i, vec := range testVectors.Vectors {
		t.Run(fmt.Sprintf("TestCase/%d", i), func(t *testing.T) {
			switch {
			case def.fn != nil:
				expectedP, err := vec.P.ToEdwardsPoint(t)
				if err != nil {
					t.Fatalf("failed to deserialized result: %v", err)
				}

				p, err := def.fn([]byte(testVectors.DST), []byte(vec.Msg))
				if err != nil {
					t.Fatalf("hash to curve failed: %v", err)
				}

				if expectedP.Equal(p) != 1 {
					t.Fatalf("h2c: point mismatch (Got: '%x')", p.Bytes())
				}
			case def.fn2 != nil:
				expectedP, err := vec.P.ToMontgomeryPoint(t)
				if err != nil {
					t.Fatalf("failed to deserialized result: %v", err)
				}

				u, v, err := def.fn2([]byte(testVectors.DST), []byte(vec.Msg))
				if err != nil {
					t.Fatalf("hash to curve failed: %v", err)
				}
				p := &montgomeryPoint{u, v}

				if !expectedP.Equal(p) {
					t.Fatalf("h2c: point mismatch (Got: '%x')", p.Bytes())
				}
			default:
				t.Fatalf("h2c: no suite function defined")
			}
		})
	}
}

type expandTestVectors struct {
	DST   string             `json:"DST"`
	Tests []expandTestVector `json:"tests"`
}

type expandTestVector struct {
	Msg          string `json:"msg"`
	UniformBytes string `json:"uniform_bytes"`
}

func testExpand(t *testing.T, def *expandTestDef) {
	f, err := os.Open(def.file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	var testVectors expandTestVectors

	dec := json.NewDecoder(rd)
	if err = dec.Decode(&testVectors); err != nil {
		t.Fatal(err)
	}

	for i, vec := range testVectors.Tests {
		t.Run(fmt.Sprintf("TestCase/%d", i), func(t *testing.T) {
			expectedU := mustUnhex(t, vec.UniformBytes)
			out := make([]byte, len(expectedU))

			var err error
			switch {
			case def.h != 0:
				err = ExpandMessageXMD(out, def.h, []byte(testVectors.DST), []byte(vec.Msg))
			case def.xof != nil:
				err = ExpandMessageXOF(out, def.xof, []byte(testVectors.DST), []byte(vec.Msg))
			default:
				t.Fatalf("malformed test vector, unknown hash/XOF")
			}
			if err != nil {
				t.Fatalf("failed ExpandMessage(out, h, dst, msg): %v", err)
			}

			if !bytes.Equal(expectedU, out) {
				t.Fatalf("output mismatch: got '%x'", out)
			}
		})
	}
}

func trimOhEcks(s string) string {
	return strings.TrimPrefix(s, "0x")
}
