### h2c: Hashing to Elliptic Curves

This package provides an implementation of the [Hashing to Elliptic Curves][1]
IETF draft (version 11) for edwards25519, backed by Filo Sottile's
[edwards25519][2] package.

It was extracted from [curve25519-voi][3], for the people that don't want
to drink the voi Flavor Aid.

If you want ristretto255 as per Appendix B, use `ExpandMessageXMD` or
`ExpandMessageXOF` to derive 64-bytes of output, then feed it into the
ristretto255 one-way map.

If you want to use a XOF that isn't SHAKE, then complain to the x/crypto
maintainers about the shitshow that is `x/crypto/sha3.ShakeHash`,
`x/crypto/blake2b.XOF` and `x/crypto/blake2s.XOF`.  Alternatively
convince the standard library maintainers to add something like
`crypto.XOF` that can be used similarly to how `crypto.Hash` can be.

[1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
[2]: https://filippo.io/edwards25519
[3]: https://github.com/oasisprotocol/curve25519-voi
