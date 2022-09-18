## vrf-mod

`vrf-mod` is an open source implementation of Verifiable Random Functions (VRFs) and Elliptical Curve VRFs written in Rust.
This library follows algorithms described in:

* [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
* [RFC6979](https://tools.ietf.org/html/rfc6979)

_Disclaimer: Experimental

## VRF

This module uses the OpenSSL library for big number cryptographic arithmetic.

Supported cipher suites include:

* `PKI_MGF_MGF1_SHA1`: mask generation algorithm utilizing `SHA1`.
* `PKI_MGF_MGF1_SHA256`: mask generation algorithm utilizing `SHA256`.

## Elliptical Curve VRF

This module also uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.

Supported cipher suites include:

* `P256_SHA256_TAI`: algorithms with `SHA256` and the `secp256r1` curve (aka `NIST P-256`).
* `SECP256K1_SHA256_TAI`: algorithms with `SHA256` and the `secp256k1` curve.

## License

`vrf-mod` is published under the [MIT license](https://github.com/th3outcast/vrf-mod/blob/main/LICENSE).