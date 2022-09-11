//! Module using the OpenSSL library to offer Elliptical Curve Verfiable Random Function (ECVRF) functionality
//!
//! ## References
//!
//! * [RFC6969](https://www.rfc-editor.org/rfc/rfc6979)
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//!
//! ECVRF is a VRF that satisfies the trusted uniqueness, trusted collision resistance and full pseudorandomness
//!
//! ## Features
//!
//! * Compute VRF proof
//! * Verify VRF proof
//!
use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
    ec::{EcGroup, EcPoint},
};
use thiserror::Error;
use crate::VRF;

mod primitives;

// Cipher suite types for different curves
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum CipherSuite {
    // `NIST P-256` with `SHA256`
    P256_SHA256_TAI,
    // `SECP256k1` with `SHA256`
    SECP256k1_SHA256_TAI,
}

// Elliptical Curve VRF
pub struct ECVRF {
    // BigNum arithmetic context
    bn_ctx: BigNumContext,
    // Ciphersuite identity
    cipher_suite: CipherSuite,
    // Hasher structure
    hasher: Hasher, 
    // Length in bytes of hash function output
    hlen: usize,
    // Finite field
    field:
    // Length in octets of a field element in F, rounded up to nearest integer
    len:
    // Elliptical Curve defined over the finite field
    ec:
    // Subgroup of `ec` of large prime order
    subgroup:
    // Prime order of group G
    q: 
    // Length of q in octets i.e smallest integer such that 2^(8*qlen)>q
    qlen:
    // Number of points on `ec` divided by q
    cofactor:
    // Generator of group G
    gen: 
}

impl ECVRF {
    /// Associated function to initialize a ECVRF structure with an initialized context for the given cipher suite.
    ///
    /// # Arguments:
    ///
    /// *    `suite`: Identifying ciphersuite
    ///
    /// # returns a ECVRF struct if successful
    ///
    pub fn from_suite(
        suite: CipherSuite
    ) -> Result<Self, Error> {
        // Context for BigNum algebra
        let mut bn_ctx = BigNumContext::new()?;

        let (group, cofactor) = match suite {
            CipherSuite::P256_SHA256_TAI => (EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?, 0x01),
            CipherSuite::SECP256k1_SHA256_TAI => (EcGroup::from_curve_name(Nid::SECP256K1)?, 0x01),
        };
    }

    /// ECVRF_hash_to_curve implementation as specified in [Section 5.4.1.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// 
    /// # Arguments
    ///
    /// * `public_key`: an Elliptical Curve point
    /// * `alpha_string`: value to be hashed, an octet string
    ///
    /// # returns a finite EC point in G
    ///
    pub fn hash_to_try_and_increment(
        &mut self,
        public_key: &EcPoint,
        alpha_string: &[u8],
    ) -> Result<EcPoint, Error> {
        
    }
}