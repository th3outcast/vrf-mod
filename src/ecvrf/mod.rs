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
    ec::{EcGroup, EcPoint, PointConversionForm},
};
use thiserror::Error;
use std::{
    os::raw::c_ulong,
};
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

impl CipherSuite {
    fn suite_string(&self) -> u8 {
        match *self {
            CipherSuite::P256_SHA256_TAI => 0x01,
            CipherSuite::SECP256k1_SHA256_TAI => 0xFE,
        }
    }
}

/// Error types that can be raised
#[derive(Error, Debug)]
pub enum Error {
    /// Error raised from `openssl::error::ErrorStack` with a specific code
    #[error("Error with code: {code:?}")]
    CodedError { code: c_ulong },
    /// `hash_to_point()` function could not find a valid point
    #[error("Hash to point function could not find a valid point")]
    HashToPointError,
    /// Unknown error
    #[error("Unknown error")]
    Unknown,
}

impl From<ErrorStack> for Error {
    /// Transform error from `openssl::error::ErrorStack` to `Error::CodedError` or `Error::Unknown`
    fn from(error: ErrorStack) -> Self {
        match error.errors().get(0).map(openssl::error::Error::code) {
            Some(code) => Error::CodedError { code },
            _ => Error::Unknown {},
        }
    }
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
    // Elliptical Curve group
    group: EcGroup,
    // Finite field
    field:
    // Length in octets of a field element in F, rounded up to nearest integer
    len:
    // Elliptical Curve defined over the finite field
    group:
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
        let mut counter = 0..255;
        let pk_string = public_key.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;
        // Hash(suite_string || one_string || pk_string || alpha_string || ctr_string)
        let mut cipher = [self.cipher_suite.suite_string(), 0x01, &pk_string, alpha_string, 0x00].concat();
        let last = cipher.len() - 1;
        let mut point = counter.find_map(|ctr| {
            cipher[last] = ctr;
            self.hasher.update(&cipher).unwrap();
            let hash_attempt = self.hasher.finish().unwrap().to_vec();
            let h = self.arbitrary_string_to_point();
            // Check the validity of 'H'
            match h {
                Ok(hash_point) => Some(hash_point),
                _ => None,
            }
        });
        // Set H = cofactor * H
        if let Some(pt) = point.as_mut() {
            let mut new_point = EcPoint::new(&self.group)?;
            new_point.mul(
                &self.group,
                pt,
                &BigNum::from_slice(&[self.cofactor])?,
                &self.bn_ctx,
            )?;
            *pt = new_point;
        };
        // Convert point or error if no valid point found
        point.ok_or(Error::HashToPointError)
    }

    /// Converts an arbitrary string to a point in the curve as specified in [Section 5.5 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// 
    /// # Arguments
    /// 
    /// * `data`: a 32 octet string to be converted to a point
    ///
    /// # returns an `EcPoint` representing the converted point if successful
    ///
    pub fn arbitrary_string_to_point(
        &mut self,
        data: &[u8],
    ) -> Result<EcPoint, Error> {
        let mut v = [0x02, data].concat();
        let point = EcPoint::from_bytes(&self.group, &v, &mut self.bn_ctx)?;
        Ok(point)
    }
}