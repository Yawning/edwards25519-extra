### edwards25519-extra

This package provides extensions to the Go standard library's Ed25519 and
curve25519 implementations, primarily extracted from [curve25519-voi][1].
This package is intended for interoperability with the standard library
and the [edwards25519][2] package as much as possible.

 * h2c: [Hashing to Elliptic Curves (version 16)][3]
 * vrf: [Verifiable Random Functions (version 10)][4]

Note: It is the author's biased opinion that using curve25519-voi is
objectively superior to using the standard library along with this
package.

[1]: https://github.com/oasisprotocol/curve25519-voi
[2]: https://filippo.io/edwards25519
[3]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
[4]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/
