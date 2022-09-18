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
    nid::Nid,
    hash::{Hasher, MessageDigest},
};
use thiserror::Error;
use std::{
    os::raw::c_ulong,
};
use hmac_sha256::HMAC;
use crate::ECVRF as ECVRF_trait;

pub mod primitives;
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
    /// Invalid pi length
    #[error("Proof(pi) length is invalid")]
    InvalidPiLength,
    /// Invalid proof
    #[error("Proof(pi) is invalid")]
    InvalidProof,
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
    // Elliptical Curve group
    group: EcGroup,
    // Prime order of `group`
    order: BigNum,
    // Length of `order` in octets i.e smallest integer such that 2^(8*qlen)>order
    qlen: usize,
    // 2n - length in octets of a field element in bits, rounded up to the nearest even integer
    n: usize,
    // Number of points on the elliptical curve divided by `order`
    cofactor: u8,
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

        let mut p = BigNum::new()?;
        let mut a = BigNum::new()?;
        let mut b = BigNum::new()?;
        group.components_gfp(&mut p, &mut a, &mut b, &mut bn_ctx)?;

        let mut order = BigNum::new()?;
        group.order(&mut order, &mut bn_ctx)?;

        let n = ((p.num_bits() + (p.num_bits() % 2)) / 2) as usize;
        let qlen = order.num_bits() as usize;

        // Digest type - `sha256`
        let hasher = Hasher::new(MessageDigest::sha256())?;

        Ok(
            ECVRF {
                bn_ctx,
                cipher_suite: suite,
                hasher,
                group,
                order,
                qlen,
                n,
                cofactor,
            }
        )
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
        let mut cipher = [&[self.cipher_suite.suite_string()], &[0x01], pk_string.as_slice(), alpha_string, &[0x00]].concat();
        let last = cipher.len() - 1;
        let mut point = counter.find_map(|ctr| {
            cipher[last] = ctr;
            self.hasher.update(&cipher).unwrap();
            let hash_attempt = self.hasher.finish().unwrap().to_vec();
            let h = self.arbitrary_string_to_point(&hash_attempt);
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
                BigNum::from_slice(&[self.cofactor])?.as_ref(),
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
        let v = [&[0x02], data].concat();
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

            let nonce = bits2ints(&v, self.qlen)?;

            if nonce > BigNum::from_u32(0)? && nonce < self.order {
                return Ok(nonce);
            }

            k = HMAC::mac(
                [
                    &v[..],
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
        &mut self,
        points: &[&EcPoint],
    ) -> Result<BigNum, Error> {
        let concatenate_points: Result<Vec<u8>, Error> = points.iter().try_fold(
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
        );

        self.hasher.update(&concatenate_points?.as_slice()).unwrap();
        let mut hash_string = self.hasher.finish().unwrap().to_vec();
        hash_string.truncate(self.n / 8);

        let result = BigNum::from_slice(hash_string.as_slice())?;

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

    /// Function to decode a proof `pi_string` produced by `EC_prove`, to (`gamma`, `c`, `s`) as specified in
    /// [Section 5.4.4 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    /// # Arguments
    ///
    /// * `pi_string`: a slice of octets representing the generated proof
    ///
    /// # Returns 
    ///
    /// * `gamma`: an `EcPoint`
    /// * `c`: integer between 0 and 2 ^ (8n) - 1
    /// * `s`: integer between 0 and 2 ^ (8qlen) - 1
    ///
    pub fn decode_proof(
        &mut self,
        pi_string: &[u8],
    ) -> Result<(EcPoint, BigNum, BigNum), Error> {
        let pt_len = if self.qlen % 8 > 0 {
            self.qlen / 8 + 2
        } else {
            self.qlen / 8 + 1
        };
        let c_len = if self.n % 8 > 0 {
            self.n / 8 + 1
        } else {
            self.n / 8
        };

        // Expected length of proof: len(pi_string) == len(gamma) + len(c) + len(s)
        // len(s) == 2 * len(c), so len(pi) == len(gamma) + len(c) * 3
        if pi_string.len() != pt_len + c_len * 3 {
            return Err(Error::InvalidPiLength);
        }

        let gamma = EcPoint::from_bytes(
            &self.group,
            &pi_string[0..pt_len],
            &mut self.bn_ctx,
        )?;
        let c = BigNum::from_slice(&pi_string[pt_len..pt_len + c_len])?;
        let s = BigNum::from_slice(&pi_string[pt_len + c_len..])?;
        Ok((gamma, c, s))
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
    ) -> Result<Vec<u8>, Error> {
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
            &mut self.bn_ctx,
        )?;

        // 4. Gamma = x * H
        let mut gamma = EcPoint::new(&self.group)?;
        gamma.mul(&self.group, &h, &private_key, &self.bn_ctx)?;

        // 5. nonce_generation(private_key, h_string)
        let nonce = self.generate_nonce(&private_key, &h_string)?;

        // 6. c = hash_points(H, Gamma, k*B, k*H)
        let mut kb = EcPoint::new(&self.group)?;
        kb.mul_generator(&self.group, &nonce, &self.bn_ctx)?;
        let mut kh = EcPoint::new(&self.group)?;
        kh.mul(&self.group, &h, &nonce, &self.bn_ctx)?;
        let c = self.hash_points(&[&h, &gamma, &kb, &kh])?;

        // 7. s = (k + c*x) mod q
        let s = &(&nonce + &(&c * &private_key)) % &self.order;

        // 8. pi_string = point_to_string(gamma) || int_to_string(c, n) || int_to_string(s, qlen)
        let gamma_string = gamma.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;
        let c_string = append_zeroes(&c.to_vec(), self.n);
        let s_string = append_zeroes(&s.to_vec(), self.qlen);
        let pi_string = [&gamma_string.as_slice(), c_string.as_slice(), s_string.as_slice()].concat();

        // 9. Output pi_string
        Ok(pi_string)
    }

    /// Generates ECVRF hash output from the provided proof
    ///
    /// # Arguments:
    ///
    /// *    `pi_string`: generated ECVRF proof
    ///
    /// # Returns 
    ///
    /// * `beta_string`: the ECVRF hash output
    ///
    fn proof_to_hash(
        &mut self, 
        pi_string: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let (gamma, _, _) = self.decode_proof(pi_string)?;

        // cofactor * Gamma
        let mut gamma_ = EcPoint::new(&self.group)?;
        gamma_.mul(
            &self.group,
            &gamma,
            BigNum::from_slice(&[self.cofactor])?.as_ref(),
            &self.bn_ctx,
        )?;

        let gamma_bytes = gamma_.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;

        let cipher = [
            &[self.cipher_suite.suite_string()],
            &[0x03],
            gamma_bytes.as_slice(),
        ].concat();

        self.hasher.update(&cipher).unwrap();
        let beta_string = self.hasher.finish().unwrap().to_vec();

        Ok(beta_string)
    }

    /// Verifies the provided VRF proof and computes the VRF hash output
    ///
    /// # Arguments:
    ///
    /// *    `public_key`: a slice representing the public key in octets
    /// *    `alpha_string`: VRF hash input, an octet string
    /// *    `pi_string`: proof to be verified, an octet string
    /// 
    /// # returns if successful, a vector of octets with the VRF hash output
    ///
    fn verify(
        &mut self, 
        public_key: &[u8], 
        alpha_string: &[u8], 
        pi_string: &[u8]
    ) -> Result<Vec<u8>, Error> {
        // 1. Decode proof
        let (gamma, c, s) = self.decode_proof(pi_string)?;

        let public_key_point = EcPoint::from_bytes(
            &self.group,
            public_key,
            &mut self.bn_ctx,
        )?;

        // 2. ECVRF_hash_to_curve(suite_string, y, alpha_string)
        let hash_point = self.hash_to_try_and_increment(
            &public_key_point,
            alpha_string,
        )?;

        // 3. U = s*B - c*Y
        let mut sb = EcPoint::new(&self.group)?;
        sb.mul_generator(
            &self.group,
            &s,
            &self.bn_ctx,
        )?;
        let mut cy = EcPoint::new(&self.group)?;
        cy.mul(
            &self.group,
            &public_key_point,
            &c,
            &self.bn_ctx,
        )?;
        cy.invert(&self.group, &self.bn_ctx)?;
        let mut u_point = EcPoint::new(&self.group)?;
        u_point.add(
            &self.group,
            &sb,
            &cy,
            &mut self.bn_ctx,
        )?;

        // 4. V = s*H - c*Gamma
        let mut sh = EcPoint::new(&self.group)?;
        sh.mul(
            &self.group,
            &hash_point,
            &s,
            &self.bn_ctx,
        )?;
        let mut c_gamma = EcPoint::new(&self.group)?;
        c_gamma.mul(
            &self.group,
            &gamma,
            &c,
            &self.bn_ctx,
        )?;
        c_gamma.invert(&self.group, &self.bn_ctx)?;
        let mut v_point = EcPoint::new(&self.group)?;
        v_point.add(
            &self.group,
            &sh,
            &c_gamma,
            &mut self.bn_ctx,
        )?;

        // 5. c' = ECVRF_hash_points(H, Gamma, U, V)
        let derived_c = self.hash_points(
            &[
                &hash_point, 
                &gamma, 
                &u_point, 
                &v_point,
            ]
        )?;

        // 6. Validity check
        if c == derived_c {
            Ok(self.proof_to_hash(pi_string)?)
        } else {
            return Err(Error::InvalidProof);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector for `P256-SHA256-TAI` cipher suite as specified in
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    #[test]
    fn test_hash_to_try_and_increment_1() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        // hex encoded -> 'sample'
        let alpha = hex::decode("73616d706c65").unwrap();

        let hex_public_key = hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6").unwrap();
        let public_key = EcPoint::from_bytes(
            &ecvrf.group, &hex_public_key, &mut ecvrf.bn_ctx
        ).unwrap();

        let result = ecvrf.hash_to_try_and_increment(&public_key, &alpha).unwrap();
        let result_bytes = result.to_bytes(
            &ecvrf.group,
            PointConversionForm::COMPRESSED,
            &mut ecvrf.bn_ctx,
        ).unwrap();

        let expected_result = hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e").unwrap();

        assert_eq!(result_bytes, expected_result);
    }

    /// Test vector for `P256-SHA256-TAI` cipher suite as specified in
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    #[test]
    fn test_hash_to_try_and_increment_2() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        // hex encoded -> 'test'
        let alpha = hex::decode("74657374").unwrap();

        let hex_public_key = hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6").unwrap();
        let public_key = EcPoint::from_bytes(
            &ecvrf.group, &hex_public_key, &mut ecvrf.bn_ctx
        ).unwrap();

        let result = ecvrf.hash_to_try_and_increment(&public_key, &alpha).unwrap();
        let result_bytes = result.to_bytes(
            &ecvrf.group,
            PointConversionForm::COMPRESSED,
            &mut ecvrf.bn_ctx,
        ).unwrap();

        let expected_result = hex::decode("02ca565721155f9fd596f1c529c7af15dad671ab30c76713889e3d45b767ff6433").unwrap();

        assert_eq!(result_bytes, expected_result);
    }

    /// Test vector for `P256-SHA256-TAI` cipher suite as specified in
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    #[test]
    fn test_hash_to_try_and_increment_3() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        // hex encoded -> 'test'
        let alpha = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();

        let hex_public_key = hex::decode("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d").unwrap();
        let public_key = EcPoint::from_bytes(
            &ecvrf.group, &hex_public_key, &mut ecvrf.bn_ctx
        ).unwrap();

        let result = ecvrf.hash_to_try_and_increment(&public_key, &alpha).unwrap();
        let result_bytes = result.to_bytes(
            &ecvrf.group,
            PointConversionForm::COMPRESSED,
            &mut ecvrf.bn_ctx,
        ).unwrap();

        let expected_result = hex::decode("02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d").unwrap();

        assert_eq!(result_bytes, expected_result);
    }
}