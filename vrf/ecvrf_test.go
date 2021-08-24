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

package vrf

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestECVRF(t *testing.T) {
	t.Run("TestVectors", testIETFVectors)
}

func testIETFVectors(t *testing.T) {
	testVectors := []struct {
		sk    []byte
		pk    []byte
		alpha []byte
		pi    []byte
		beta  []byte
	}{
		{
			sk:    mustUnhex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
			pk:    mustUnhex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
			alpha: []byte{},
			pi:    mustUnhex(t, "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f25898f6bd7d4ed4c75f0282b0f7bb9d0e61b387b76db60b3cbf34bf09109ccb33fab742a8bddc0c8ba3caf5c0b75bb04"),
			beta:  mustUnhex(t, "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"),
		},
		{
			sk:    mustUnhex(t, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
			pk:    mustUnhex(t, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
			alpha: []byte{0x72},
			pi:    mustUnhex(t, "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef9bf1a234f833f72d8fff36075fd9b836da28b5569e74caa418bae7ef521f2ddd35f5727d271ecc70b4a83c1fc8ebc40c"),
			beta:  mustUnhex(t, "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"),
		},
		{
			sk:    mustUnhex(t, "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
			pk:    mustUnhex(t, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
			alpha: []byte{0xaf, 0x82},
			pi:    mustUnhex(t, "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce6187befa109606682503b3a1424f0f729ca0418099fbd86a48093e6a8de26307b8d93e02da927e6dd5b73c8f119aee0f"),
			beta:  mustUnhex(t, "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"),
		},
	}
	for i, vec := range testVectors {
		sk := ed25519.NewKeyFromSeed(vec.sk)
		pk := sk.Public().(ed25519.PublicKey)

		pi := Prove(sk, vec.alpha)
		if !bytes.Equal(vec.pi, pi) {
			t.Fatalf("[%d] pi mismatch (Got: %x)", i, pi)
		}

		ok, beta := Verify(pk, pi, vec.alpha)
		if !ok {
			t.Fatalf("[%d] Verify() failed", i)
		}
		if !bytes.Equal(vec.beta, beta) {
			t.Fatalf("[%d] beta mismatch (Got: %x)", i, beta)
		}

		pi[0] ^= 0xa5
		ok, _ = Verify(pk, pi, vec.alpha)
		if ok {
			t.Fatalf("[%d] bad pi, Verify() passed", i)
		}
	}
}

func BenchmarkECVRF(b *testing.B) {
	b.Run("Prove", benchProve)
	b.Run("ProofToHash", benchProofToHash)
	b.Run("Verify", benchVerify)
}

func benchProve(b *testing.B) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Prove(sk, []byte("test-alpha-pls-ignore"))
	}
}

func benchProofToHash(b *testing.B) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	pi := Prove(sk, []byte("test-alpha-pls-ignore"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProofToHash(pi)
		if err != nil {
			b.Fatalf("ProofToHash: %v", err)
		}
	}
}

func benchVerify(b *testing.B) {
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	alpha := []byte("test-alpha-pls-ignore")
	pi := Prove(sk, alpha)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, _ := Verify(pk, pi, alpha)
		if !ok {
			b.Fatalf("Verify() failed")
		}
	}
}

func mustUnhex(t *testing.T, x string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(x, " ", ""))
	if err != nil {
		t.Fatalf("failed to parse hex: %v", err)
	}

	return b
}
