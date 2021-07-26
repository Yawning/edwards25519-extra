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
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

func (v *montgomeryPoint) Equal(other *montgomeryPoint) bool {
	return v.u.Equal(other.u) == 1 && v.v.Equal(other.v) == 1
}

func (v *montgomeryPoint) Bytes() []byte {
	return v.u.Bytes()
}

type hashToCurveTestVector struct {
	msg  string
	x, y string
}

func (vec *hashToCurveTestVector) ToCoordinates(t *testing.T) (*field.Element, *field.Element) {
	// Generate a point from the test vector x and y-coordinates.
	feX := mustUnhexElementIETF(t, vec.x)
	feY := mustUnhexElementIETF(t, vec.y)

	return feX, feY
}

func (vec *hashToCurveTestVector) ToEdwardsPoint(t *testing.T) *edwards25519.Point {
	feX, feY := vec.ToCoordinates(t)
	return newEdwardsFromXY(feX, feY)
}

func (vec *hashToCurveTestVector) ToMontgomeryPoint(t *testing.T) *montgomeryPoint {
	feX, feY := vec.ToCoordinates(t)
	return &montgomeryPoint{feX, feY}
}

func TestHashToCurve(t *testing.T) {
	t.Run("edwards25519", func(t *testing.T) {
		checkEdwards := func(t *testing.T, dst []byte, vecs []hashToCurveTestVector, isRO bool) {
			for i, vec := range vecs {
				expected := vec.ToEdwardsPoint(t)

				var (
					p   *edwards25519.Point
					err error
				)
				if isRO {
					p, err = Edwards25519_XMD_SHA512_ELL2_RO(dst, []byte(vec.msg))
				} else {
					p, err = Edwards25519_XMD_SHA512_ELL2_NU(dst, []byte(vec.msg))
				}
				if err != nil {
					t.Fatalf("h2c: failed to generate point[%d]: %v", i, err)
				}

				if expected.Equal(p) != 1 {
					t.Fatalf("h2c: point[%d] mismatch (Got: '%x')", i, p.Bytes())
				}
			}
		}

		t.Run("XMD:SHA512_ELL2_RO_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6",
					y:   "09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",
				},
				{
					msg: "abc",
					x:   "608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad",
					y:   "1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",
				},
				{
					msg: "abcdef0123456789",
					x:   "6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472",
					y:   "53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "5fb0b92acedd16f3bcb0ef83f5c7b7a9466b5f1e0d8d217421878ea3686f8524",
					y:   "2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "0efcfde5898a839b00997fbe40d2ebe950bc81181afbd5cd6b9618aa336c1e8c",
					y:   "6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995",
				},
			}

			checkEdwards(t, dst, vecs, true)
		})
		t.Run("XMD:SHA512_ELL2_NU_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "1ff2b70ecf862799e11b7ae744e3489aa058ce805dd323a936375a84695e76da",
					y:   "222e314d04a4d5725e9f2aff9fb2a6b69ef375a1214eb19021ceab2d687f0f9b",
				},

				{
					msg: "abc",
					x:   "5f13cc69c891d86927eb37bd4afc6672360007c63f68a33ab423a3aa040fd2a8",
					y:   "67732d50f9a26f73111dd1ed5dba225614e538599db58ba30aaea1f5c827fa42",
				},
				{
					msg: "abcdef0123456789",
					x:   "1dd2fefce934ecfd7aae6ec998de088d7dd03316aa1847198aecf699ba6613f1",
					y:   "2f8a6c24dd1adde73909cada6a4a137577b0f179d336685c4a955a0a8e1a86fb",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "35fbdc5143e8a97afd3096f2b843e07df72e15bfca2eaf6879bf97c5d3362f73",
					y:   "2af6ff6ef5ebba128b0774f4296cb4c2279a074658b083b8dcca91f57a603450",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "6e5e1f37e99345887fc12111575fc1c3e36df4b289b8759d23af14d774b66bff",
					y:   "2c90c3d39eb18ff291d33441b35f3262cdd307162cc97c31bfcc7a4245891a37",
				},
			}

			checkEdwards(t, dst, vecs, false)
		})
	})

	t.Run("curve25519", func(t *testing.T) {
		checkMontgomery := func(t *testing.T, dst []byte, vecs []hashToCurveTestVector, isRO bool) {
			for i, vec := range vecs {
				expected := vec.ToMontgomeryPoint(t)

				var (
					u, v *field.Element
					err  error
				)
				if isRO {
					u, v, err = Curve25519_XMD_SHA512_ELL2_RO(dst, []byte(vec.msg))
				} else {
					u, v, err = Curve25519_XMD_SHA512_ELL2_NU(dst, []byte(vec.msg))
				}
				if err != nil {
					t.Fatalf("h2c: failed to generate point[%d]: %v", i, err)
				}
				p := &montgomeryPoint{u, v}

				if !expected.Equal(p) {
					t.Logf("u: %x", p.u.Bytes())
					t.Logf("v: %x", p.v.Bytes())
					t.Fatalf("h2c: point[%d] mismatch (Got: '%x')", i, p.Bytes())
				}
			}
		}

		t.Run("XMD:SHA512_ELL2_RO_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "2de3780abb67e861289f5749d16d3e217ffa722192d16bbd9d1bfb9d112b98c0",
					y:   "3b5dc2a498941a1033d176567d457845637554a2fe7a3507d21abd1c1bd6e878",
				},
				{
					msg: "abc",
					x:   "2b4419f1f2d48f5872de692b0aca72cc7b0a60915dd70bde432e826b6abc526d",
					y:   "1b8235f255a268f0a6fa8763e97eb3d22d149343d495da1160eff9703f2d07dd",
				},
				{
					msg: "abcdef0123456789",
					x:   "68ca1ea5a6acf4e9956daa101709b1eee6c1bb0df1de3b90d4602382a104c036",
					y:   "2a375b656207123d10766e68b938b1812a4a6625ff83cb8d5e86f58a4be08353",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "096e9c8bae6c06b554c1ee69383bb0e82267e064236b3a30608d4ed20b73ac5a",
					y:   "1eb5a62612cafb32b16c3329794645b5b948d9f8ffe501d4e26b073fef6de355",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "1bc61845a138e912f047b5e70ba9606ba2a447a4dade024c8ef3dd42b7bbc5fe",
					y:   "623d05e47b70e25f7f1d51dda6d7c23c9a18ce015fe3548df596ea9e38c69bf1",
				},
			}

			checkMontgomery(t, dst, vecs, true)
		})
		t.Run("XMD:SHA512_ELL2_NU_", func(t *testing.T) {
			dst := []byte("QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_NU_")
			vecs := []hashToCurveTestVector{
				{
					msg: "",
					x:   "1bb913f0c9daefa0b3375378ffa534bda5526c97391952a7789eb976edfe4d08",
					y:   "4548368f4f983243e747b62a600840ae7c1dab5c723991f85d3a9768479f3ec4",
				},

				{
					msg: "abc",
					x:   "7c22950b7d900fa866334262fcaea47a441a578df43b894b4625c9b450f9a026",
					y:   "5547bc00e4c09685dcbc6cb6765288b386d8bdcb595fa5a6e3969e08097f0541",
				},
				{
					msg: "abcdef0123456789",
					x:   "31ad08a8b0deeb2a4d8b0206ca25f567ab4e042746f792f4b7973f3ae2096c52",
					y:   "405070c28e78b4fa269427c82827261991b9718bd6c6e95d627d701a53c30db1",
				},
				{
					msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					x:   "027877759d155b1997d0d84683a313eb78bdb493271d935b622900459d52ceaa",
					y:   "54d691731a53baa30707f4a87121d5169fb5d587d70fb0292b5830dedbec4c18",
				},
				{
					msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					x:   "5fd892c0958d1a75f54c3182a18d286efab784e774d1e017ba2fb252998b5dc1",
					y:   "750af3c66101737423a4519ac792fb93337bd74ee751f19da4cf1e94f4d6d0b8",
				},
			}

			checkMontgomery(t, dst, vecs, false)
		})
	})
}

func mustUnhexElementIETF(t *testing.T, x string) *field.Element {
	b := mustUnhex(t, x)

	// The IETF test vectors provide all coordinates in big-endian byte order.
	b = reversedByteSlice(b)

	fe, err := new(field.Element).SetBytes(b)
	if err != nil {
		t.Fatalf("failed to parse fe hex: %v", err)
	}

	return fe
}
