//! Data conversion primitives
//!

use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

/// Converts an octet string to a non-negative integer a