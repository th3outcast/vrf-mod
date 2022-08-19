//! Data conversion primitives
//!

use openssl::{
    bn::{BigNum},
    error::ErrorStack,
};

/// Converts a non-negative BigNum integer to an octet string of specified length as 
/// defined in [Section 4.1 of RFC8017](https://datatracker.ietf.org/doc/pdf/rfc8017#section-4.1)
/// 
/// Arguments:
///     x: unsigned BigNum integer to be converted
///     xlen: length of octet string to return
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
    //let mut div = BigNum::new()?;
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

#[cfg(test)]
mod tests {
    #[test]
    fn i20sp_test() {
        let result = BigNum::from_hex_string("0123456789abcde");
        let result = i20sp(result, 8);
        print!(result);
        assert_eq!(result, 5);
    }
}