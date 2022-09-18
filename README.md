## vrf-mod

`vrf-mod` is an open source implementation of Verifiable Random Functions (VRFs) and Elliptical Curve VRFs written in Rust.
This library follows algorithms described in:

* [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
* [RFC6979](https://tools.ietf.org/html/rfc6979)

_Disclaimer: Experimental_

## VRF

This module uses the OpenSSL library for big number cryptographic arithmetic.

Supported cipher suites include:

* `PKI_MGF_MGF1_SHA1`: mask generation algorithm utilizing `SHA1`.
* `PKI_MGF_MGF1_SHA256`: mask generation algorithm utilizing `SHA256`.

```rust
use vrf_mod::vrf::{VRFCipherSuite, VRF};
use vrf_mod::VRF as VRF_trait;
use openssl::rsa::Rsa;

fn main() {
    // Initialization of VRF context
    let mut vrf = VRF::from_suite(VRFCipherSuite::PKI_MGF_MGF1_SHA256).unwrap();
    // Load private key from a file
    let pkey = include_bytes!("../link_to_file/rsa.pem");
    let private_key = Rsa::private_key_from_pem(pkey).unwrap();
    // Load public key from a file
    let key = include_bytes!("../link_to_file/rsa.pem.pub");
    let public_key = Rsa::public_key_from_pem(key).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let message: &[u8] = b"sample";
    
    // VRF proof and hash output
    let pi = vrf.prove(&private_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &message, &pi);
}
```

## Adding unsupported cipher suites

This library also defines a `VRF` trait which can be extended.

```rust
use openssl::{
    rsa::Rsa,
    pkey::{Public, Private}.
};

pub trait VRF {
    type Error;

    fn prove(&mut self, pkey: &Rsa<Private>, alpha_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn proof_to_hash(&mut self, pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(&mut self, public_key: &Rsa<Public>, alpha_string: &[u8], pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
```

## Elliptical Curve VRF

This module also uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.

Supported cipher suites include:

* `P256_SHA256_TAI`: algorithms with `SHA256` and the `secp256r1` curve (aka `NIST P-256`).
* `SECP256K1_SHA256_TAI`: algorithms with `SHA256` and the `secp256k1` curve.

```rust
use vrf_mod::ecvrf::{CipherSuite, ECVRF};
use vrf_mod::ECVRF as ECVRF_trait;

fn main() {
    // Initialization of VRF context by providing a curve
    let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
    // Private Key, Public Key (derived) & message
    let private_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = ecvrf.derive_public_key(&private_key).unwrap();
    let message: &[u8] = b"sample";
    
    // ECVRF proof and hash output
    let pi = ecvrf.prove(&private_key, &message).unwrap();
    let hash = ecvrf.proof_to_hash(&pi).unwrap();

    // ECVRF proof verification (returns ECVRF hash output)
    let beta = ecvrf.verify(&public_key, &message, &pi);
}
```

## Adding unsupported cipher suites

This library defines a `ECVRF` trait which can be extended in order to use different curves and algorithms.

```rust
pub trait ECVRF<PrivateKey, PublicKey> {
    type Error;

    fn prove(&mut self, pkey: PrivateKey, alpha_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn proof_to_hash(&mut self, pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(&mut self, public_key: PublicKey, alpha_string: &[u8], pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
```

## License

`vrf-mod` is published under the [MIT license](https://github.com/th3outcast/vrf-mod/blob/main/LICENSE).