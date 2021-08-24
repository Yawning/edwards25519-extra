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
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

type montgomeryPoint struct {
	u, v *field.Element
}

func newMontgomeryPointFromEdwards(p *edwards25519.Point) *montgomeryPoint {
	xExt, yExt, zExt, _ := p.ExtendedCoordinates()

	// Convert from extended (x, y, z, t) coordiantes to x, y.
	zInv := new(field.Element).Invert(zExt)
	x := new(field.Element).Multiply(xExt, zInv)
	y := new(field.Element).Multiply(yExt, zInv)

	// Per RFC 7748: (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)

	onePlusY := new(field.Element).Add(constOne, y)
	oneMinusY := new(field.Element).Subtract(constOne, y)
	u := new(field.Element).Invert(oneMinusY)
	u.Multiply(onePlusY, u)

	v := new(field.Element).Invert(x)
	v.Multiply(v, constMONTGOMERY_SQRT_NEG_A_PLUS_TWO)
	v.Multiply(v, u)

	// If y == 1, 1/(1-y) = 0, (u, v) = (0, 0) (No adjustment needed)
	// If x == 0, sqrt(-486664)*u/x = 0, (u, v) = (u, 0)
	u.Select(constZero, u, feIsZero(x))

	return &montgomeryPoint{u, v}
}

func (v *montgomeryPoint) ToEdwardsPoint() *edwards25519.Point {
	// Per RFC 7748: (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))

	x := new(field.Element).Invert(v.v)
	x.Multiply(x, v.u)
	x.Multiply(x, constMONTGOMERY_SQRT_NEG_A_PLUS_TWO)

	uMinusOne := new(field.Element).Subtract(v.u, constOne)
	uPlusOne := new(field.Element).Add(v.u, constOne)
	uPlusOneIsZero := feIsZero(uPlusOne)

	uPlusOne.Invert(uPlusOne)
	y := new(field.Element).Multiply(uMinusOne, uPlusOne)

	// This mapping is undefined when t == 0 or s == -1, i.e., when the
	// denominator of either of the above rational functions is zero.
	// Implementations MUST detect exceptional cases and return the value
	// (v, w) = (0, 1), which is the identity point on all twisted Edwards
	// curves.
	resultUndefined := feIsZero(v.v) | uPlusOneIsZero
	x.Select(constZero, x, resultUndefined)
	y.Select(constOne, y, resultUndefined)

	// Convert from Edwards (x, y) to extended (x, y, z, t) coordinates.
	return newEdwardsFromXY(x, y)
}
