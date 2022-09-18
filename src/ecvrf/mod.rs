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
    /// # Returns:
    ///
    /// *    a ECVRF struct if successful
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
    /// # Returns:
    ///
    /// * a finite EC point in G
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
    /// # Returns:
    ///
    /// * a `BigNum` representing the nonce.
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
    /// # Returns:
    ///
    /// * a `BigNum` integer (0 < x < 2^(8n) - 1) representing the hash of points truncated to length `n`, if successful.
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
    /// # Returns:
    ///
    /// *    if successful, a vector of octets representing the proof `pi_string`
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
    /// # Returns:
    ///
    /// *    if successful, a vector of octets with the VRF hash output
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
        )?;println!("{:?}, {:?}", c, derived_c);

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

        // hex encoded -> 'Example of ECDSA with ansip256r1 and SHA-256'
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

    /// Test vector for `P-256` curve with `SHA-256` as specified in
    /// [Section A.2.5 \[RFC6979\]](https://tools.ietf.org/html/rfc6979)
    ///
    #[test]
    fn test_generate_nonce_p256_1() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let mut ord = BigNum::new().unwrap();
        ecvrf.group.order(&mut ord, &mut ecvrf.bn_ctx).unwrap();

        let hex_private_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let private_key = BigNum::from_slice(&hex_private_key).unwrap();

        // hex encoded -> 'sample'
        let alpha = hex::decode("73616d706c65").unwrap();

        let result_nonce = ecvrf.generate_nonce(&private_key, &alpha).unwrap();

        let expected_result = hex::decode("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60").unwrap();
        
        assert_eq!(result_nonce.to_vec(), expected_result);
    }

    /// Test vector for `P-256` curve with `SHA-256` as specified in
    /// [Section A.2.5 \[RFC6979\]](https://tools.ietf.org/html/rfc6979)
    ///
    #[test]
    fn test_generate_nonce_p256_2() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let mut ord = BigNum::new().unwrap();
        ecvrf.group.order(&mut ord, &mut ecvrf.bn_ctx).unwrap();

        let hex_private_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let private_key = BigNum::from_slice(&hex_private_key).unwrap();

        // hex encoded -> 'test'
        let alpha = hex::decode("74657374").unwrap();

        let result_nonce = ecvrf.generate_nonce(&private_key, &alpha).unwrap();

        let expected_result = hex::decode("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0").unwrap();
        
        assert_eq!(result_nonce.to_vec(), expected_result);
    }

    /// Test vector for hash points with `P256-SHA256-TAI` cipher suite
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    #[test]
    fn test_hash_points() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        // Test data
        let hash_hex = hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e").unwrap();
        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb61b201059f89186e7175af796d65e7").unwrap();
        
        // Compute all required points (gamma, u, v)
        let hash_point = EcPoint::from_bytes(&ecvrf.group, &hash_hex, &mut ecvrf.bn_ctx).unwrap();
        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);
        let gamma_point = EcPoint::from_bytes(&ecvrf.group, &gamma_hex, &mut ecvrf.bn_ctx).unwrap();
        let u_hex = hex::decode("030286d82c95d54feef4d39c000f8659a5ce00a5f71d3a888bd1b8e8bf07449a50").unwrap();
        let u_point = EcPoint::from_bytes(&ecvrf.group, &u_hex, &mut ecvrf.bn_ctx).unwrap();
        let v_hex = hex::decode("03e4258b4a5f772ed29830050712fa09ea8840715493f78e5aaaf7b27248efc216").unwrap();
        let v_point = EcPoint::from_bytes(&ecvrf.group, &v_hex, &mut ecvrf.bn_ctx).unwrap();

        let computed_c = ecvrf.hash_points(
            &[
                &hash_point, 
                &gamma_point, 
                &u_point, 
                &v_point
            ]
        ).unwrap();

        let mut expected_c = c_s_hex.clone();
        
        expected_c.truncate(16);
        
        assert_eq!(computed_c.to_vec(), expected_c);
    }

    /// Test decode_proof vector for `P256-SHA256-TAI` cipher suite as specified in
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    #[test]
    fn test_decode_proof() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb61b201059f89186e7175af796d65e7").unwrap();
        let (derived_gamma, derived_c, _) = ecvrf.decode_proof(&pi_hex).unwrap();

        // Expected values
        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);
        let mut c_hex = c_s_hex.clone();
        c_hex.truncate(16);
        let expected_gamma = EcPoint::from_bytes(&ecvrf.group, &gamma_hex, &mut ecvrf.bn_ctx).unwrap();
        let expected_c = BigNum::from_slice(c_hex.as_slice()).unwrap();

        assert!(derived_c.eq(&expected_c));
        assert!(expected_gamma.eq(&ecvrf.group, &derived_gamma, &mut ecvrf.bn_ctx).unwrap());
    }

    /// Test prove for `P256-SHA256-TAI` cipher suite
    /// 
    #[test]
    fn test_prove_p256_sha256_tai() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        // private key
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        
        let alpha = hex::decode("73616d706c65").unwrap();

        let pi = ecvrf.prove(&x, &alpha).unwrap();
        let expected_pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb61b201059f89186e7175af796d65e7").unwrap();
        
        assert_eq!(pi, expected_pi);
    }

    /// Test prove for `SECP256K1-SHA256-TAI` cipher suite
    /// 
    #[test]
    fn test_prove_secp256k1_sha256_tai() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::SECP256k1_SHA256_TAI).unwrap();
        // private key
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        // hex -> 'sample'
        let alpha = hex::decode("73616d706c65").unwrap();

        let pi = ecvrf.prove(&x, &alpha).unwrap();
        
        let expected_pi = hex::decode("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9").unwrap();
        
        assert_eq!(pi, expected_pi);
    }

    /// Test verify for `P256-SHA256-TAI` cipher suite as specified in
    /// [Section A.1 \[VRF-draft-05\]](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// 
    #[test]
    fn test_verify_p256_sha256_tai() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        // Public Key
        let public_key = hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6").unwrap();
        // hex -> 'sample'
        let alpha = hex::decode("73616d706c65").unwrap();
        // ecvrf proof
        let pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb61b201059f89186e7175af796d65e7").unwrap();

        let beta = ecvrf.verify(&public_key, &alpha, &pi).unwrap();
        let expected_beta = hex::decode("59ca3801ad3e981a88e36880a3aee1df38a0472d5be52d6e39663ea0314e594c").unwrap();
        
        assert_eq!(beta, expected_beta);
    }

    /// Test verify for `SECP256K1-SHA256-TAI` cipher suite
    /// 
    #[test]
    fn test_verify_secp256k1_sha256_tai() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::SECP256k1_SHA256_TAI).unwrap();
        // Public Key
        let public_key = hex::decode("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645").unwrap();
        // hex -> 'sample'
        let alpha = hex::decode("73616d706c65").unwrap();
        // ecvrf proof
        let pi = hex::decode("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f").unwrap();

        let beta = ecvrf.verify(&public_key, &alpha, &pi).unwrap();
        let expected_beta = hex::decode("612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81").unwrap();
        
        assert_eq!(beta, expected_beta);
    }
}