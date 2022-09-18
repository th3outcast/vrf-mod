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
/// # Returns:
///
/// * a `BigNum` representing the conversion.
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
/// # Returns:
///
/// * a vector of octets
///
pub fn bits2octets(
    num: &[u8],
    length: usize,
    order: &BigNum,
    bn_ctx: &mut BigNumContext,
) -> Result<Vec<u8>, ErrorStack> {
    let z1 = bits2ints(num, length)?;
    let z2 = BigNum::new().and_then(|mut result| {
        result.nnmod(&z1, order, bn_ctx)?;
        Ok(result.to_vec()) 
    })?;
    Ok(z2)
}

/// Appends zeroes if provided slice is smaller than given length in bits
///
/// # Arguments
/// 
/// * `data`: octet slice
/// * `length`: size in bits after appending zeroes
///
/// # Returns: 
///
/// * a vector of octets with leading zeroes (if necessary) 
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bits2ints() {
        let octets = &[0x01; 33];
        let data = BigNum::from_slice(octets).unwrap();
    
        let result = bits2ints(octets, 256).unwrap();
        let mut expected_result = BigNum::new().unwrap();
        expected_result.rshift(&data, 8).unwrap();

        assert_eq!(result.to_vec(), expected_result.to_vec());
    }

    #[test]
    fn test_bits2octets() {
        // hex-encoded -> 'this is a sample string'
        let data = hex::decode("7468697320697320612073616d706c65206d657373616765")
            .unwrap();
        let order_ = hex::decode("020000000000000000000b2e3b3a5f7182d417ceba").unwrap();
        let order = BigNum::from_slice(&order_.as_slice()).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let result = bits2octets(
            &data.as_slice(),
            order.num_bits() as usize,
            &order,
            &mut bn_ctx,
        )
        .unwrap();

        let expected_result = [
            1, 209, 161, 165, 204, 129, 165, 204, 129, 132, 
            129, 205, 133, 181, 193, 177, 148, 129, 181, 149, 205
        ];

        assert_eq!(result, expected_result);
    }
}