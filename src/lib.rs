//! Implementation of a Verfiable Random Function (VRF)
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
};
use bytes::BytesMut;

mod primitives;

use primitives::i20sp;

/// Cipher suites for VRF
#[derive(Debug)]
pub enum VRFCipherSuite {
    /// Set MGF hash function as SHA-1
    PKI_MGF_MGF1SHA1,
    /// Set MGF hash function as SHA-256
    PKI_MGF_MGF1SHA256
}

pub struct VRF {
    // BigNum arithmetic context
    bn_ctx: BigNumContext,
    // Ciphersuite identity
    cipher_suite: VRFCipherSuite,
    // Hasher structure
    hasher: Hasher, //MessageDigest,
}

impl VRF {
    /// Associated function to initialize a VRF structure with an initialized context for the given cipher suite.
    ///
    /// @arguments:
    ///     suite: Identifying ciphersuite
    ///
    /// @returns a VRF struct if successful
    ///
    pub fn from_suite(suite: VRFCipherSuite) -> Result<Self, ErrorStack> {
        // Context for BigNum algebra
        let mut bn_ctx = BigNumContext::new()?;

        // Hasher digest
        let hasher = match suite {
            VRFCipherSuite::PKI_MGF_MGF1SHA1 => Hasher::new(MessageDigest::sha1())?,
            VRFCipherSuite::PKI_MGF_MGF1SHA256 => Hasher::new(MessageDigest::sha256())?,
        };

        Ok(VRF {
            bn_ctx,
            cipher_suite: suite,
            hasher,
        })
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
    pub fn mgf1(&mut self, mgf_seed: &[u8], mask_len: usize, hLen: Option<usize>) -> Result<Vec<u8>, ErrorStack> {
        let max_len: usize = u32::MAX.try_into().unwrap();
        if mask_len > max_len + 1 {
            panic!()
        }
        
        let mut octet = BytesMut::with_capacity(mask_len);
        let mut iterations = mask_len;
        
        // If hLen specified, shadow iterations
        if let Some(s) = hLen {
            iterations = &iterations / s;
        }
    
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
        Ok(octet.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}