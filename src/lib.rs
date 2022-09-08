//! # Verifiable Random Function
//!
//! This crate defines a trait that must be implemented by VRFs.
//!
use openssl::{
    rsa::Rsa,
    pkey::{Public, Private}
};

pub mod vrf;

/// A trait containing the common capabilities for VRF implementations
///
pub trait VRF {
    type Error;

    /// Generates proof from a private key and a message
    ///
    /// @arguments:
    ///     pkey: a private key
    ///     alpha_string: octet string message represented by a slice
    ///
    /// @returns if successful, a vector of octets representing the VRF proof
    ///
    fn prove(&mut self, pkey: &Rsa<Private>, alpha_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Generates VRF hash output from the provided proof
    ///
    /// @arguments:
    ///     pi_string: generated VRF proof
    ///
    /// @returns the VRF hash output
    ///
    fn proof_to_hash(&mut self, pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output
    ///
    /// @arguments:
    ///     public_key: a public key
    ///     alpha_string: VRF hash input, an octet string
    ///     pi_string: proof to be verified, an octet string
    /// 
    /// @returns if successful, a vector of octets with the VRF hash output
    fn verify(&mut self, public_key: &Rsa<Public>, alpha_string: &[u8], pi_string: &[u8]) -> Result<Vec<u8>, Self::Error>;
}