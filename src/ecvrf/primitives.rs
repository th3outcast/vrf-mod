//! Data conversion primitives
//!

use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

/// Converts a sequence of blen bits to a non-negative integer that is less than 2^qlen as specified in
/// [Section 2.3.2 of \[RFC6979\]](https://www.rfc-editor.org/rfc/rfc6979#section-2.3.2)
///
/// # Arguments
///
/// * `num`: an octet slice representing the number to be converted
/// * `qlen`: the length of the output `BigNum`
///
/// # returns
///
pub fn bits2ints(
    num: &[u8],
    qlen: usize,
) -> Result<BigNum, ErrorStack> {
    let vlen = num.len() * 8;
    let result = BigNum::from_slice(num)?;

    if vlen > qlen {
        let mut truncated = BigNum::new()?;
        truncated.rshift(&result, (vlen - qlen) as i32)?;
        
        Ok(truncated)
    } else {
        Ok(result)
    }
}

/// Converts a sequence of blen bits to an output of rlen bits as specified in
/// [Section 2.3.4 of \[RFC6979\]](https://www.rfc-editor.org/rfc/rfc6979#section-2.3.4)
///
/// # Arguments
///
/// * ``:
/// * ``:
///
/// # returns
///
pub fn bits2octets(

) -> Result<> {

}