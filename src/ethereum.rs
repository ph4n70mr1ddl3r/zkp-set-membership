//! Ethereum address validation and normalization utilities.
//!
//! This module provides functions for validating and normalizing Ethereum addresses
//! to ensure consistency across the codebase.

use crate::utils::validate_and_strip_hex;
use anyhow::{Context, Result};

/// Expected length of an Ethereum address in hex characters (excluding 0x prefix)
/// Ethereum addresses are 20 bytes = 40 hex characters
pub const ADDRESS_HEX_LENGTH: usize = 40;

/// Expected length of an Ethereum private key in hex characters (excluding 0x prefix)
/// Ethereum private keys are 32 bytes = 64 hex characters
pub const PRIVATE_KEY_HEX_LENGTH: usize = 64;

/// Validates and normalizes a single Ethereum address.
///
/// Returns a lowercase hex string without the 0x prefix.
///
/// # Arguments
///
/// * `address` - The Ethereum address to validate and normalize
///
/// # Returns
///
/// A normalized address as a lowercase hex string without 0x prefix
///
/// # Errors
///
/// Returns an error if:
/// - The address is not exactly 40 hex characters (excluding 0x prefix)
/// - The address contains non-hex characters
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::normalize_address;
///
/// let normalized = normalize_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").unwrap();
/// assert_eq!(normalized, "742d35cc6634c0532925a3b844bc454e4438f44e");
/// ```
pub fn normalize_address(address: &str) -> Result<String> {
    validate_and_strip_hex(address, ADDRESS_HEX_LENGTH).map(|s| s.to_lowercase())
}

/// Validates a batch of Ethereum addresses in one pass.
/// More efficient than processing individually.
///
/// # Arguments
///
/// * `addresses` - Slice of Ethereum address strings to validate and normalize
///
/// # Returns
///
/// A vector of normalized addresses as lowercase hex strings without 0x prefix
///
/// # Errors
///
/// Returns an error if any address is invalid, with context indicating which address failed
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::normalize_addresses_batch;
///
/// let addresses = vec![
///     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
///     "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
/// ];
/// let normalized = normalize_addresses_batch(&addresses).unwrap();
/// assert_eq!(normalized.len(), 2);
/// ```
pub fn normalize_addresses_batch(addresses: &[String]) -> Result<Vec<String>> {
    addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            normalize_address(addr).with_context(|| {
                format!("Failed to validate address at line {}: '{}'", i + 1, addr)
            })
        })
        .collect()
}

/// Validates a single Ethereum address.
///
/// Returns true if the address is valid, false otherwise.
///
/// An address is considered valid if:
/// - It is exactly 42 characters (including 0x prefix)
/// - It starts with "0x"
/// - All remaining characters are valid hex digits
/// - It is not the zero address (all zeros)
///
/// # Arguments
///
/// * `address` - The Ethereum address to validate
///
/// # Returns
///
/// `true` if the address is valid, `false` otherwise
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::validate_address;
///
/// assert!(validate_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"));
/// assert!(!validate_address("0x0000000000000000000000000000000000000000"));
/// assert!(!validate_address("invalid"));
/// ```
#[must_use]
pub fn validate_address(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address[2..].chars().all(|c| c.is_ascii_hexdigit())
        && !address[2..].chars().all(|c| c == '0')
}

/// Validates a batch of Ethereum addresses.
///
/// Returns true if all addresses are valid, false otherwise.
///
/// # Arguments
///
/// * `addresses` - Slice of Ethereum address strings to validate
///
/// # Returns
///
/// `true` if all addresses are valid, `false` otherwise
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::validate_addresses_batch;
///
/// let addresses = vec![
///     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
///     "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
/// ];
/// assert!(validate_addresses_batch(&addresses));
/// ```
#[must_use]
pub fn validate_addresses_batch(addresses: &[String]) -> bool {
    addresses.iter().all(|addr| validate_address(addr))
}

/// Validates an Ethereum private key.
///
/// # Arguments
///
/// * `private_key` - The private key as a hex string (with or without 0x prefix)
///
/// # Returns
///
/// Ok(()) if the private key is valid, Err otherwise
///
/// # Errors
///
/// Returns an error if:
/// - The private key is not exactly 64 hex characters (excluding 0x prefix)
/// - The private key contains non-hex characters
/// - The private key is all zeros
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::validate_private_key;
///
/// // Valid private key (not a real key)
/// assert!(validate_private_key("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").is_ok());
///
/// // All zeros is invalid
/// assert!(validate_private_key("0x0000000000000000000000000000000000000000000000000000000000000000").is_err());
/// ```
pub fn validate_private_key(private_key: &str) -> Result<()> {
    let stripped = validate_and_strip_hex(private_key, PRIVATE_KEY_HEX_LENGTH)?;

    if stripped.chars().all(|c| c == '0') {
        return Err(anyhow::anyhow!(
            "Private key cannot be all zeros. Please provide a valid private key."
        ));
    }

    Ok(())
}

/// Converts a normalized Ethereum address to a 32-byte array.
///
/// Ethereum addresses are 20 bytes, so this pads with 12 zero bytes at the beginning
/// to match the 32-byte field element size used in the circuit.
///
/// # Arguments
///
/// * `normalized_address` - A normalized Ethereum address (40 hex characters, no 0x prefix)
///
/// # Returns
///
/// A 32-byte array with the 20-byte address right-aligned and zero-padded on the left
///
/// # Errors
///
/// Returns an error if the address cannot be decoded from hex
///
/// # Examples
///
/// ```
/// use zkp_set_membership::ethereum::address_to_bytes_normalized;
///
/// let normalized = "742d35cc6634c0532925a3b844bc454e4438f44e";
/// let bytes = address_to_bytes_normalized(normalized).unwrap();
/// assert_eq!(bytes.len(), 32);
/// assert!(bytes[12..].iter().any(|&b| b != 0));  // Last 20 bytes contain address
/// ```
pub fn address_to_bytes_normalized(
    normalized_address: &str,
) -> Result<[u8; crate::types::HASH_SIZE]> {
    let bytes = hex::decode(normalized_address).context("Failed to decode address from hex")?;

    if bytes.len() != 20 {
        return Err(anyhow::anyhow!("Address bytes length mismatch"));
    }

    let mut full_bytes = [0u8; crate::types::HASH_SIZE];
    full_bytes[crate::types::HASH_SIZE - 20..crate::types::HASH_SIZE].copy_from_slice(&bytes);
    Ok(full_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_address_valid() {
        let result = normalize_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "742d35cc6634c0532925a3b844bc454e4438f44e");
    }

    #[test]
    fn test_normalize_address_no_prefix() {
        let result = normalize_address("742d35Cc6634C0532925a3b844Bc454e4438f44e");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "742d35cc6634c0532925a3b844bc454e4438f44e");
    }

    #[test]
    fn test_normalize_address_invalid_length() {
        let result = normalize_address("0x742d35Cc6634C0532925a3b844Bc454e4438");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_address_invalid_hex() {
        let result = normalize_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44g");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_valid() {
        assert!(validate_address(
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        ));
        assert!(validate_address(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
    }

    #[test]
    fn test_validate_address_invalid_length() {
        assert!(!validate_address("0x123456"));
    }

    #[test]
    fn test_validate_address_invalid_prefix() {
        assert!(!validate_address(
            "1234567890123456789012345678901234567890"
        ));
    }

    #[test]
    fn test_validate_address_invalid_hex() {
        assert!(!validate_address(
            "0x123456789012345678901234567890123456789z"
        ));
    }

    #[test]
    fn test_validate_address_all_zero() {
        assert!(!validate_address(
            "0x0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_validate_private_key_valid() {
        assert!(validate_private_key(
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        )
        .is_ok());
    }

    #[test]
    fn test_validate_private_key_all_zeros() {
        assert!(validate_private_key(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
    }

    #[test]
    fn test_validate_private_key_invalid_hex() {
        assert!(validate_private_key(
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_err());
    }

    #[test]
    fn test_address_to_bytes_normalized() {
        let normalized = "742d35cc6634c0532925a3b844bc454e4438f44e";
        let bytes = address_to_bytes_normalized(normalized).unwrap();
        assert_eq!(bytes.len(), crate::types::HASH_SIZE);
        assert_eq!(
            bytes[0..crate::types::HASH_SIZE - 20],
            [0u8; crate::types::HASH_SIZE - 20]
        );
    }

    #[test]
    fn test_normalize_addresses_batch() {
        let addresses = vec![
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
        ];
        let result = normalize_addresses_batch(&addresses);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_addresses_batch() {
        let addresses = vec![
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
        ];
        assert!(validate_addresses_batch(&addresses));
    }
}
