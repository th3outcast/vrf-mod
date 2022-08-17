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

pub struct VRF {

}

impl VRF {
    
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
