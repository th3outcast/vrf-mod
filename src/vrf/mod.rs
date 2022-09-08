//! Module using the OpenSSL library to offer Verfiable Random Function (VRF) functionality
//!
//! ## References
//!
//! * [RFC6969](https://www.rfc-editor.org/rfc/rfc6979)
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//!
//! sk: the private key for the vrf
//! pk: the public key for the vrf
//! alpha: the input to be hashed by the vrf
//! beta: the vrf hash output; 
//!         beta = VRF_hash(sk, alpha)
//! pi: the vrf proof; 
//!         pi = VRF_prove(sk, alpha)
//! prover: the prover holds the private vrf key 'sk' and public vrf key 'pk'
//! verifier: the verifier holds the public vrf key 'pk'
//!
//! The prover generates beta and pi.
//! 
//! To deterministically obtain the vrf hash output beta directly from the proof pi:
//! 
//! beta = VRF_proof_to_hash(pi)
//! 
//! VRF_hash(sk, alpha) = VRF_proof_to_hash(VRF_prove(sk, alpha))
//!
//! pi allows a verifier holding the public key pk to verify the correctness of beta as the vrf hash of the input alpha under key pk
//! 
//! Verfication:
//!     VRF_verfify(pk, alpha, pi)
//! Output if valid:
//!     (valid, beta = VRF_proof_to_hash(pi)) 
//!
//! ## Features
//!
//! * Compute VRF proof
//! * Verify VRF proof
use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
    //rsa::Rsa,
    //pkey::{Private, Public},
    hash::{Hasher, MessageDigest},
    rsa::Rsa,
    pkey::{Private, Public}
};
use bytes::BytesMut;
use thiserror::Error;
use std::{
    os::raw::c_ulong,
};
use crate::VRF as VRF_trait;

mod primitives;

use primitives::{
    i20sp,
    os2ip,
};

/// Cipher suites for VRF
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum VRFCipherSuite {
    /// Set MGF hash function as SHA-1
    PKI_MGF_MGF1_SHA1,
    /// Set MGF hash function as SHA-256
    PKI_MGF_MGF1_SHA256
}

/// Error types that can be raised
#[derive(Error, Debug)]
pub enum Error {
    /// Error raised from `openssl::error::ErrorStack` with a specific code
    #[error("Error with code: {code:?}")]
    CodedError { code: c_ulong },
    /// The mask length is invalid
    #[error("Invalid mask length")]
    InvalidMaskLength,
    /// The modulus length is invalid
    #[error("Invalid modulus `n` length")]
    InvalidModulusLength,
    /// The modulus length is invalid
    #[error("Invalid message `m` length")]
    InvalidMessageLength,
    /// The proof is invalid
    #[error("Invalid proof")]
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

pub struct VRF {
    // BigNum arithmetic context
    bn_ctx: BigNumContext,
    // Ciphersuite identity
    cipher_suite: VRFCipherSuite,
    // Hasher structure
    hasher: Hasher, 
    // Length in bytes of hash function output
    hlen: usize,
}

impl VRF {
    /// Associated function to initialize a VRF structure with an initialized context for the given cipher suite.
    ///
    /// @arguments:
    ///     suite: Identifying ciphersuite
    ///
    /// @returns a VRF struct if successful
    ///
    pub fn from_suite(
        suite: VRFCipherSuite
    ) -> Result<Self, Error> {
        // Context for BigNum algebra
        let bn_ctx = BigNumContext::new()?;

        // Set digest type
        let digest_type = match suite {
            VRFCipherSuite::PKI_MGF_MGF1_SHA1 => MessageDigest::sha1(),
            VRFCipherSuite::PKI_MGF_MGF1_SHA256 => MessageDigest::sha256(),
        };

        // Length in bytes of hash function output
        let hlen = digest_type.size();

        let hasher = Hasher::new(digest_type)?;

        Ok(VRF {
            bn_ctx,
            cipher_suite: suite,
            hasher,
            hlen,
        })
    }

    /// RSASP1 signature primitive defined in
    /// (Section 5.2.1 of [RFC8017])[https://datatracker.ietf.org/doc/pdf/rfc8017#section-5.2.1]
    ///
    /// @arguments: 
    ///     secret_key: Rsa private key
    ///     message: BigNum message representation
    ///
    /// @returns a signature representative
    ///
    pub fn rsasp1(&mut self, 
        secret_key: &Rsa<Private>, 
        message: &BigNum
    ) -> Result<BigNum, Error> {
        let n = secret_key.n();
        let d = secret_key.d();
        let mut signature = BigNum::new()?;

        if *message > (n - &BigNum::from_u32(1)?) && !message.is_negative() {
            return Err(Error::InvalidMessageLength);
        }

        signature.mod_exp(&message, d, n, &mut self.bn_ctx)?;
        Ok(signature)
    }

    /// RSAVP1 verification primitive defined in
    /// (Section 5.2.2 of [RFC8017])[https://datatracker.ietf.org/doc/pdf/rfc8017#section-5.2.2]
    /// 
    /// @arguments:
    ///     public_key: Rsa public key
    ///     signature: signed message to extract
    ///
    /// @returns a BigNum representing the message extracted from the signature
    ///
    pub fn rsavp1(&mut self, 
        public_key: &Rsa<Public>, 
        signature: &BigNum
    ) -> Result<BigNum, Error> {
        let n = public_key.n();
        let e = public_key.e();
        let mut message = BigNum::new()?;

        if *signature > (n - &BigNum::from_u32(1)?) && !signature.is_negative() {
            return Err(Error::InvalidMessageLength);
        }

        message.mod_exp(&signature, e, n, &mut self.bn_ctx)?;
        Ok(message)
    }

    /// MGF1 mask generation function based on the hash function hash as defined
    /// in (Section B.2.1 of [RFC8017])[https://datatracker.ietf.org/doc/pdf/rfc8017]
    ///
    /// @arguments:
    ///     mgf_seed: seed from which mask is generated, an octet string
    ///     mask_len: intended length in octets of the mask; max length 2 ^ 32
    ///
    /// @returns an octet string of length mask_len
    ///
    pub fn mgf1(&mut self, 
        mgf_seed: &[u8], 
        mask_len: usize
    ) -> Result<Vec<u8>, Error> {
        let max_len: usize = u32::MAX.try_into().unwrap();
        if mask_len > max_len + 1 {
            return Err(Error::InvalidMaskLength);
        }
        
        let mut octet = BytesMut::with_capacity(mask_len);
        
        // ceil (maskLen / hlen) -> (maskLen + hlen - 1) / hlen
        let iterations = (mask_len + &self.hlen - 1) / &self.hlen ;
    
        for counter in 0..iterations {
            let mut num = BigNum::from_u32(counter as u32)?;
            let c = i20sp(&mut num, 4).unwrap();
            
            // Load the seed into the hash buffer
            //  Hash(mgf_seed || c)
            self.hasher.update(&mgf_seed).unwrap();
            self.hasher.update(c.as_slice()).unwrap();
            // Digest hash
            let digest = self.hasher.finish().unwrap().to_vec();
            octet.extend_from_slice(digest.as_slice());
        }
        // Output the leading octets
        Ok(octet[0..mask_len].to_vec())
    }
}

impl VRF_trait for VRF {
    type Error = Error;

    /// RSA-FDH-VRF prooving algorithm as defined
    /// in Section 4.1 of [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    /// @arguments:
    ///     secret_key: RSA private key
    ///     alpha_string: VRF hash input, an octet string
    ///
    /// @returns pi_string: proof, an octet string of length k
    ///
    fn prove(
        &mut self, 
        secret_key: &Rsa<Private>, 
        alpha_string: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let one_string: u8 = 0x01;
        let mut n = secret_key.n().to_owned().unwrap();

        let k = &n.to_vec().len();
        if !(*k < 4_294_967_296usize) {
            return Err(Error::InvalidModulusLength);
        }
        
        // mgf1(one_string || i20sp(k, 4) || i20sp(n, k) || alpha_string, k - 1)
        // create a mutable byte sequence to concatenate entries
        let mut sequence = BytesMut::new();
        sequence.extend_from_slice(&[one_string]);

        let mut num = BigNum::from_u32(*k as u32)?;
        let i2 = i20sp(&mut num, 4).unwrap();
        sequence.extend_from_slice(i2.as_slice());

        let i3 = i20sp(&mut n, *k).unwrap();
        sequence.extend_from_slice(i3.as_slice());

        sequence.extend_from_slice(alpha_string);

        let em = self.mgf1(&sequence, k - 1).unwrap();
        let m = os2ip(&em.as_slice()).unwrap();
        let mut s = self.rsasp1(secret_key, &m).unwrap();
        let pi_string = i20sp(&mut s, *k).unwrap();

        Ok(pi_string)
    }

    /// RSA-FDH-VRF proof to hash algorithm as defined
    /// in Section 4.2 of [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// 
    /// @arguments:
    ///     pi_string: proof, an octet string of length k
    ///
    /// @returns beta_string: VRF hash output, an octet string of length hLen
    ///
    fn proof_to_hash(
        &mut self, 
        pi_string: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let two_string: u8 = 0x02;
        self.hasher.update(&[two_string]).unwrap();
        self.hasher.update(pi_string).unwrap();
        let beta_string = self.hasher.finish().unwrap().to_vec();

        Ok(beta_string)
    }

    /// RSA-FDH-VRF verifying algorithm as defined
    /// in Section 4.3 of [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    ///
    /// @arguments:
    ///     public_key: RSA public key
    ///     alpha_string: VRF hash input, an octet string
    ///     pi_string: proof to be verified, an octet string of length n
    ///
    /// @returns beta_string: VRF hash output, an octet string of length hLen
    ///
    fn verify(
        &mut self, 
        public_key: &Rsa<Public>, 
        alpha_string: &[u8], 
        pi_string: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let s = os2ip(pi_string).unwrap();
        let mut m = self.rsavp1(public_key, &s).unwrap();
        
        let mut n = public_key.n().to_owned().unwrap();
        let k = &n.to_vec().len();

        let em = i20sp(&mut m, *k - 1).unwrap();
        let one_string: u8 = 0x01;

        let mut sequence = BytesMut::new();
        sequence.extend_from_slice(&[one_string]);

        let mut num = BigNum::from_u32(*k as u32)?;
        let i2 = i20sp(&mut num, 4).unwrap();
        sequence.extend_from_slice(i2.as_slice());

        let i3 = i20sp(&mut n, *k).unwrap();
        sequence.extend_from_slice(i3.as_slice());

        sequence.extend_from_slice(alpha_string);

        let em_ = self.mgf1(&sequence, k - 1).unwrap();

        if em == em_ {
            Ok(self.proof_to_hash(pi_string).unwrap())
        } else {
            return Err(Error::InvalidProof);
        }
    } 
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsasp1() {
        let mut vrf = VRF::from_suite(VRFCipherSuite::PKI_MGF_MGF1_SHA256).unwrap();

        let pkey = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(pkey).unwrap();

        // hex encoded -> 'this is a sample message'
        let alpha = BigNum::from_hex_str("7468697320697320612073616d706c65206d657373616765").unwrap();
        // signature -> an integer between 0 < n - 1
        let signature = vrf.rsasp1(&private_key, &alpha).unwrap();
        
        let expected_signature = BigNum::from_dec_str("\
            1776277981368162742811103276847038001291908781090057338317637858700131454\
            3368853810456104465225789241093347677520344819844115213079786239362994134\
            5965350441718127796651075868428100553726539595770065215247642182314807705\
            5539991297172940996514772987752142846280297196586316332720263746969001076\
            9732878056030898069509511139305651648477603830169517327114345051395234682\
            9733897544214649098209309949711422768149757935850125331268865861756758528\
            2933996843972618288453248328023531638084508626181473370553595306726617362\
            0383437871866902044174482588333308357293433575058467801404176149537871016\
            058216362423935315679183767657269\
        ").unwrap();
        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn test_rsavp1() {
        let mut vrf = VRF::from_suite(VRFCipherSuite::PKI_MGF_MGF1_SHA256).unwrap();

        let key = include_bytes!("../test/rsa.pem.pub");
        let public_key = Rsa::public_key_from_pem(key).unwrap();

        let signature = BigNum::from_dec_str("\
            1776277981368162742811103276847038001291908781090057338317637858700131454\
            3368853810456104465225789241093347677520344819844115213079786239362994134\
            5965350441718127796651075868428100553726539595770065215247642182314807705\
            5539991297172940996514772987752142846280297196586316332720263746969001076\
            9732878056030898069509511139305651648477603830169517327114345051395234682\
            9733897544214649098209309949711422768149757935850125331268865861756758528\
            2933996843972618288453248328023531638084508626181473370553595306726617362\
            0383437871866902044174482588333308357293433575058467801404176149537871016\
            058216362423935315679183767657269\
        ").unwrap();

        let message = vrf.rsavp1(&public_key, &signature).unwrap();
        let expected_message = BigNum::from_hex_str("7468697320697320612073616d706c65206d657373616765").unwrap();
    
        assert_eq!(message, expected_message);
    }

    #[test]
    fn test_mgf1() {
        let mut vrf = VRF::from_suite(VRFCipherSuite::PKI_MGF_MGF1_SHA256).unwrap();
        let seed: &[u8; 32] = &[
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
        ];
        let mask_len: usize = 32;

        let mask = vrf.mgf1(seed, mask_len).unwrap();
        let expected_mask = vec![
            63, 108, 39, 36, 162, 26, 59, 41, 
            239, 136, 106, 82, 170, 65, 75, 236, 
            150, 196, 111, 122, 241, 55, 198, 54, 
            6, 82, 9, 255, 137, 44, 238, 108
        ];

        assert_eq!(mask, expected_mask);
    }
}