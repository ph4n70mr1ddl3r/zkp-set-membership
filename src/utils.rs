//! Utility functions for hex validation and formatting.

use anyhow::Result;
use halo2_gadgets::poseidon::primitives::{
    self as poseidon, ConstantLength, P128Pow5T3 as PoseidonSpec,
};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;

fn is_valid_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn strip_hex_prefix(input: &str) -> &str {
    input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or_else(|| input.trim())
}

/// Validates and strips hex prefix from a string.
///
/// # Arguments
///
/// * `input` - The hex string to validate (may include "0x" or "0X" prefix)
/// * `expected_len` - Expected length of the hex string after stripping prefix
///
/// # Returns
///
/// The stripped hex string if valid, or an error if validation fails.
///
/// # Errors
/// Returns an error if:
/// - The hex string has incorrect length
/// - The hex string contains non-hex characters
///
/// # Examples
///
/// ```
/// use zkp_set_membership::utils::validate_and_strip_hex;
///
/// let result = validate_and_strip_hex("0x1234abcd", 8).unwrap();
/// assert_eq!(result, "1234abcd");
/// ```
pub fn validate_and_strip_hex(input: &str, expected_len: usize) -> Result<String> {
    let stripped = strip_hex_prefix(input);

    if stripped.len() != expected_len {
        return Err(anyhow::anyhow!(
            "Invalid hex string: must be {} characters (got {})",
            expected_len,
            stripped.len()
        ));
    }

    if !is_valid_hex_string(stripped) {
        return Err(anyhow::anyhow!(
            "Invalid hex string: contains non-hex characters"
        ));
    }

    Ok(stripped.to_string())
}

/// Validates that a string contains only hex digits.
///
/// # Errors
/// Returns an error if:
/// - The string is empty
/// - The string contains non-hex characters
#[must_use]
pub fn validate_hex_string(input: &str) -> bool {
    let stripped = strip_hex_prefix(input);

    if stripped.is_empty() {
        return false;
    }

    is_valid_hex_string(stripped)
}

const BASE_U64: u64 = 256;

/// Converts 32 bytes to a field element in the Pallas curve.
///
/// Uses base-256 encoding for deterministic conversion between bytes and field elements.
///
/// # Arguments
///
/// * `bytes` - 32-byte array to convert
///
/// # Returns
///
/// Field element in the Pallas curve
#[inline]
#[must_use]
pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    let mut value = pallas::Base::zero();
    let base = pallas::Base::from(BASE_U64);

    for &byte in bytes.iter() {
        value = value * base + pallas::Base::from(byte as u64);
    }

    value
}

/// Converts a field element to 32 bytes.
///
/// # Arguments
///
/// * `field` - Field element to convert
///
/// # Returns
///
/// 32-byte array representation of the field element
#[inline]
#[must_use]
pub fn field_to_bytes(field: pallas::Base) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let repr = field.to_repr();
    bytes.copy_from_slice(repr.as_ref());
    bytes
}

/// Poseidon hash of two field elements using `P128Pow5T3` specification.
///
/// This is the optimized Poseidon hash for in-circuit use with 3 full rounds,
/// 2 partial rounds, and constant length 2.
///
/// # Arguments
///
/// * `left` - First field element to hash
/// * `right` - Second field element to hash
///
/// # Returns
///
/// The Poseidon hash of the two field elements
///
/// # Example
///
/// ```
/// use zkp_set_membership::utils::poseidon_hash;
/// use pasta_curves::pallas;
///
/// let left = pallas::Base::from(1);
/// let right = pallas::Base::from(2);
/// let hash = poseidon_hash(left, right);
/// ```
#[inline]
#[must_use]
pub fn poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    let inputs = [left, right];
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<2>, 3, 2>::init().hash(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_and_strip_hex_valid() {
        let result = validate_and_strip_hex("0x1234abcd", 8);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234abcd");
    }

    #[test]
    fn test_validate_and_strip_hex_uppercase_prefix() {
        let result = validate_and_strip_hex("0X1234ABCD", 8);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234ABCD");
    }

    #[test]
    fn test_validate_and_strip_hex_no_prefix() {
        let result = validate_and_strip_hex("1234abcd", 8);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234abcd");
    }

    #[test]
    fn test_validate_and_strip_hex_with_whitespace() {
        let result = validate_and_strip_hex("  0x1234abcd  ", 8);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234abcd");
    }

    #[test]
    fn test_validate_and_strip_hex_wrong_length() {
        let result = validate_and_strip_hex("0x1234abcd", 10);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be 10 characters"));
    }

    #[test]
    fn test_validate_and_strip_hex_invalid_characters() {
        let result = validate_and_strip_hex("0x1234xyzw", 8);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("non-hex characters"));
    }

    #[test]
    fn test_validate_hex_string_valid() {
        assert!(validate_hex_string("0x1234abcd"));
    }

    #[test]
    fn test_validate_hex_string_valid_no_prefix() {
        assert!(validate_hex_string("1234abcd"));
    }

    #[test]
    fn test_validate_hex_string_invalid() {
        assert!(!validate_hex_string("0x1234xyzw"));
    }

    #[test]
    fn test_validate_hex_string_empty() {
        assert!(!validate_hex_string(""));
    }

    #[test]
    fn test_validate_and_strip_hex_full_ethereum_address() {
        let result = validate_and_strip_hex("0x1234567890123456789012345678901234567890", 40);
        assert!(result.is_ok());
    }
}
