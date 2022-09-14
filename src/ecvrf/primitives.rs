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
/// # returns a `BigNum` representing the conversion.
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
/// * `num`: an octet slice
/// * `length`: transform input `num` to a sequence of `length`
/// * `order`: right output boundary non-inclusive, output lies in range = (0, order)
/// * `bn_ctx`: `BigNumContext` for arithmetic
///
/// # returns a vector of octets
///
pub fn bits2octets(
    num: &[u8],
    length: usize,
    order: &BigNum,
    bn_ctx: &mut BigNumContext,
) -> Result<Vec<u8>, ErrorStack> {
    let z1 = bits2ints(num, length);
    let mut z2 = BigNum::new().and_then(|mut result| {
        result.nnmod(&z1, order, bn_ctx)?;
        Ok(result.to_vec()) 
    })?;
}

/// Appends zeroes if provided slice is smaller than given length in bits
///
/// # Arguments
/// 
/// * `data`: octet slice
/// * `length`: size in bits after appending zeroes
///
/// # returns a vector of octets with leading zeroes (if necessary) 
///
pub fn append_zeroes(
    data: &[u8],
    length: usize,
) -> Vec<u8> {
    // Check if data length does not exceed provided transform length
    if data.len() * 8 > length {
        return data.to_vec();
    }

    let zeroes = if length % 8 > 0 {
        vec![0; length / 8 - data.len() + 1]
    } else {
        vec![0; length / 8 - data.len()]
    };

    [&zeroes.as_slice(), data].concat()
}