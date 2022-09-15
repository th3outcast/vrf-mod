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
use hmac_sha256::HMAC;
use crate::VRF;

mod primitives;
use primitives::{
    bits2ints,
    bits2octets,
    append_zeroes,
};

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
    // Prime order of `group`
    order:
    // Length of `order` in octets i.e smallest integer such that 2^(8*qlen)>order
    qlen:
    // 2n - length in octets of a field element in bits, rounded up to the nearest even integer
    n:

    /*
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
    // Number of points on `ec` divided by q
    cofactor:
    // Generator of group G
    gen:
    */ 
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

    /// Generates a nonce deterministically from the algorithm specified in [Section 3.2 RFC6979](https://tools.ietf.org/html/rfc6979)
    ///
    /// # Arguments
    ///
    /// * `secret key`: a BigNum representing the secret key.
    /// * `data`: a slice of octets representing the message
    ///
    /// # returns a `BigNum` representing the nonce.
    ///
    pub fn generate_nonce(
        &mut self,
        secret_key: &BigNum,
        data: &[u8]
    ) -> Result<BigNum, Error> {
        // h1 = H(m)
        self.hasher.update(data).unwrap();
        let h1 = self.hasher.finish().unwrap().to_vec();

        // Initialize `V` and `K`
        let mut v = [0x01; 32];
        let mut k = [0x00; 32];

        // private key in the [1, qlen -1] range, should be a multiple of 8; left pad with zeroes (if neccessary)
        // ints2octets(private_key)
        let padded_secret_key = append_zeroes(&secret_key.to_vec(), self.qlen);

        // bits2octets(h1)
        let data = bits2octets(
            &h1, self.qlen, &self.order, &mut self.bn_ctx,
        )?;
        let padded_data = append_zeroes(&data, self.qlen);

        // 2 rounds of hashing as specified
        for prefix in 0..2u8 {
            k = HMAC::mac(
                [
                    &v[..],
                    &[prefix],
                    &padded_secret_key.as_slice(),
                    &padded_data.as_slice(),
                ]
                .concat(),
                &k,
            );
            v = HMAC::mac(&v, &k);
        }

        // Loop until a valid `BigNum` nonce is found in `V`
        loop {
            v = HMAC::mac(&v, &k);

            let nonce = bits2ints(&v)?;

            if nonce > BigNum::from_u32(0)? && nonce < self.order {
                return Ok(nonce);
            }

            k = HMAC::mac(
                [
                    &v,
                    &[0x00],
                ]
                .concat(),
                &k,
            );
            v = HMAC::mac(&v, &k);
        }
    }

    /// Hashes a slice of EC points to a `BigNum` integer as specified in [Section 5.4.3 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    /// # Arguments
    ///
    /// * `points`: a slice of points that need to be hashed
    ///
    /// # returns a `BigNum` integer (0 < x < 2^(8n) - 1) representing the hash of points truncated to length `n`, if successful.
    ///
    pub fn hash_points(
        points: &[EcPoint],
    ) -> Result<BigNum, Error> {
        let concatenate_points: <Vec<u8> = points.iter().try_fold(
            vec![self.cipher_suite.suite_string(), 0x02],
            |mut acc, point| {
                let sequence: Vec<u8> = point.to_bytes(
                    &self.group,
                    PointConversionForm::COMPRESSED,
                    &mut self.bn_ctx,
                )?;

                acc.extend(sequence);
                Ok(acc)
            }
        )?;

        self.hasher.update(&concatenate_points.as_slice()).unwrap();
        let hash_string = self.hasher.finish().unwrap().to_vec();

        let truncated_hash_string = hash_string[0..self.n / 8];
        let result = BigNum::from_slice(truncated_hash_string)?;

        Ok(result)
    }

    /// Function to derive public key given a private key point.
    ///
    /// # Arguments
    ///
    /// * `private_key`: a `BigNum` representing the private key
    ///
    /// # returns an `EcPoint` representing the public key, if successful
    ///
    pub fn derive_public_key_point(
        &mut self, 
        private_key: &BigNum
    ) -> Result<EcPoint, Error> {
        let mut point = EcPoint::new(&self.group)?;
        // public_key = private_key * generator
        point.mul_generator(&self.group, private_key, &self.bn_ctx)?;
        Ok(point)
    }
}

impl ECVRF_trait<&[u8], &[u8]> for ECVRF {
    type Error = Error;

    /// Generates proof from a private key and a message as specified in [Section 5.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) 
    ///
    /// # Arguments:
    ///
    /// *    `pkey`: a private key
    /// *    `alpha_string`: octet string message represented by a slice
    ///
    /// # returns if successful, a vector of octets representing the proof `pi_string`
    ///
    fn prove(
        &mut self, 
        pkey: &[u8], 
        alpha_string: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // 1. Derive public key Y
        // Y = x * B
        let private_key = BigNum::from_slice(pkey)?;
        let public_key = self.derive_public_key_point(&private_key)?;

        // 2. H = hash_to_curve(suite_string, public_key, alpha_string)
        let h = self.hash_to_try_and_increment(&public_key, alpha_string)?;

        // 3. h_string = point_to_string(H)
        let h_string = h.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut bn_ctx,
        )?;

        // 4. Gamma = x * H
        let mut gamma = EcPoint::new(&self.group)?;
        gamma.mul(&self.group, &h, &private_key, self.bn_ctx)?;

        // 5. nonce_generation(private_key, h_string)
        let nonce = self.generate_nonce(&private_key, &h_string)?;

        // 6. c = hash_points(H, Gamma, k*B, k*H)
        let mut kb = EcPoint::new(&self.group)?;
        kb.mul_generator(&self.group, &nonce, &self.bn_ctx)?;
        let mut kh = EcPoint::new(&self.group)?;
        kh.mul(&self.group, &h, &nonce, &self.bn_ctx)?;
        let c = self.hash_points(&[&h, &gamma, &kb, &kh])?;

        // 7. s = (k + c*x) mod q
        let s = &(&nonce + &c * &private_key) % &self.order;

        // 8. pi_string = point_to_string(gamma) || int_to_string(c, n) || int_to_string(s, qlen)
        let gamma_string = gamma.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut bn_ctx,
        )?;
        let c_string = append_zeroes(&c.to_vec(), self.n)?;
        let s_string = append_zeroes(&s.to_vec(), self.qlen)?;
        let pi_string = [&gamma_string.as_slice(), c_string.as_slice(), s_string.as_slice()].concat()

        // 9. Output pi_string
        Ok(pi_string)
    }

    /// Generates VRF hash output from the provided proof
    ///
    /// # Arguments:
    ///
    /// *    `pi_string`: generated VRF proof
    ///
    /// # returns the VRF hash output
    ///
    fn proof_to_hash(&mut self, pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output
    ///
    /// # Arguments:
    ///
    /// *    `public_key`: a public key
    /// *    `alpha_string`: VRF hash input, an octet string
    /// *    `pi_string`: proof to be verified, an octet string
    /// 
    /// # returns if successful, a vector of octets with the VRF hash output
    ///
    fn verify(&mut self, public_key: PublicKey, alpha_string: &[u8], pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;
}