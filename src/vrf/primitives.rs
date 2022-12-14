//! Data conversion primitives
//!

use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

/// Converts a non-negative BigNum integer to an octet string of specified length as 
/// defined in [Section 4.1 of RFC8017](https://datatracker.ietf.org/doc/pdf/rfc8017#section-4.1)
/// 
/// # Arguments:
///
/// *    num: unsigned BigNum integer to be converted
/// *    xlen: length of octet string to return
///
/// # Returns: 
///
/// *   a vector representing the octet string in big-endian
///
pub fn i20sp(num: &mut BigNum, xlen: usize) -> Result<Vec<u8>, ErrorStack> {
    // Set base 256
    let base = BigNum::from_u32(256)?;
    let mut bn_ctx = BigNumContext::new()?;
    let mut limit = BigNum::new()?;
    limit.exp(&base, &BigNum::from_u32(xlen as u32).unwrap(), &mut bn_ctx)?;

    // Check limit bound
    if num >= &mut limit {
        panic!("Above limit");
    }

    let mut octet: Vec<u8> = Vec::with_capacity(xlen);
    let mut rem = BigNum::new()?;

    for _ in 0..xlen {
        let mut div = BigNum::new()?;
        div.div_rem(&mut rem, num, &base, &mut bn_ctx)?;
        *num = div;
        let r: u8 = rem.to_dec_str()?.parse().unwrap();
        octet.push(r); 
    }

    // Reverse vector to big-endian
    octet.reverse();
    Ok(octet)
}

/// Converts an octet string to a non-negative BigNum integer as 
/// defined in [Section 4.2 of RFC8017](https://datatracker.ietf.org/doc/pdf/rfc8017#section-4.2)
/// 
/// # Arguments:
///
/// *    `octet`: slice representing octet string to be converted to a BigNum integer
/// 
/// # Returns:
///
/// *    a non-negative BigNum integer
///
pub fn os2ip(octet: &[u8]) -> Result<BigNum, ErrorStack> {
    let base = BigNum::from_u32(256)?;
    let mut bn_ctx = BigNumContext::new()?;

    let length = octet.len();
    let mut sum = BigNum::new()?;
    let mut step = BigNum::new()?;
    let mut mul = BigNum::new()?;
    //let mut dup = BigNum::new()?;
    for (index, num) in octet.iter().enumerate() {
        let mut dup = BigNum::new()?;
        let num = BigNum::from_u32(*num as u32).unwrap();
        let pow = BigNum::from_u32((&length - 1 - index) as u32)?;

        step.exp(&base, &pow, &mut bn_ctx)?;
        mul.checked_mul(&num, &step, &mut bn_ctx)?;
        dup.checked_add(&sum, &mul)?;
        sum = dup;
    }

    Ok(sum)
} 

#[cfg(test)]
mod tests {
    use super::*; 

    #[test]
    fn i20sp_test() {
        let mut result = BigNum::from_dec_str("234567817231231").unwrap();
        let result = i20sp(&mut result, 6).unwrap();

        let expected_result = vec![213, 86, 147, 107, 251, 127];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn os2ip_test() {
        let octets = vec![213, 86, 147, 107, 251, 127];
        let result = os2ip(&octets).unwrap();

        let expected_result = BigNum::from_dec_str("234567817231231").unwrap();
        assert_eq!(result, expected_result);
    }
}