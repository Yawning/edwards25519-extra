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

package montgomery

import (
	"testing"

	"filippo.io/edwards25519/field"
)

func TestMontgomery(t *testing.T) {
	t.Run("Elligator2Constants", testElligator2Constants)
}

func testElligator2Constants(t *testing.T) {
	t.Run("NegA", func(t *testing.T) {
		expected := new(field.Element).Negate(NEG_A)

		if expected.Equal(A) != 1 {
			t.Fatalf("invalid value for -A: %x", NEG_A.Bytes())
		}
	})

	t.Run("SqrtNegAPlusTwo", func(t *testing.T) {
		expected := new(field.Element).Subtract(NEG_A, TWO)
		expected.Invert(expected)
		expected.SqrtRatio(ONE, expected)

		if expected.Equal(SQRT_NEG_A_PLUS_TWO) != 1 {
			t.Fatalf("invalid value for sqrt(-(A+2): %x", SQRT_NEG_A_PLUS_TWO.Bytes())
		}
	})

	t.Run("UFactor", func(t *testing.T) {
		expected := new(field.Element).Negate(TWO)
		expected.Multiply(expected, SQRT_M1)

		if expected.Equal(U_FACTOR) != 1 {
			t.Fatalf("invalid value for u_factor: %x", U_FACTOR.Bytes())
		}
	})

	t.Run("VFactor", func(t *testing.T) {
		expected := new(field.Element).Invert(U_FACTOR)
		expected.SqrtRatio(ONE, expected)

		if expected.Equal(V_FACTOR) != 1 {
			t.Fatalf("invalid value for v_factor: %x", V_FACTOR.Bytes())
		}
	})
}
