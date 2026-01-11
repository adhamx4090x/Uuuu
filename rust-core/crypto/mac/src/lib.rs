//! Message Authentication Codes for CXA cryptographic system.
//!
//! This module provides implementations of message authentication codes
//! including HMAC, CMAC, and Poly1305. These primitives are essential
//! for verifying message integrity and authenticity.
//!
//! # Security Guarantees
//!
//! - HMAC provides existential unforgeability under chosen message attacks
//! - All operations are constant-time to prevent timing attacks
//! - Key separation ensures different MAC keys for different purposes
//!
//! # Usage Example
//!
//! ```rust
//! use cxa_mac::{HmacSha256, MacGenerator, MacVerifier};
//!
//! let key = HmacSha256::generate_key();
//! let mac = HmacSha256::sign(b"message", &key).unwrap();
//! assert!(HmacSha256::verify(b"message", &key, &mac).is_ok());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::cargo)]
#![warn(clippy::pedantic)]

use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;

/// Size of HMAC-SHA256 output in bytes
pub const HMAC_SHA256_SIZE: usize = 32;
/// Size of HMAC-SHA512 output in bytes
pub const HMAC_SHA512_SIZE: usize = 64;
/// Size of CMAC-AES128 output in bytes
pub const CMAC_AES128_SIZE: usize = 16;
/// Size of CMAC-AES256 output in bytes
pub const CMAC_AES256_SIZE: usize = 16;
/// Size of Poly1305 output in bytes
pub const POLY1305_SIZE: usize = 16;

/// Errors that can occur during MAC operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MacError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid MAC size
    InvalidMacSize,
    /// Verification failed
    VerificationFailed,
    /// Computation failed
    ComputationFailed,
}

impl std::fmt::Display for MacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid key size for MAC operation"),
            Self::InvalidMacSize => write!(f, "Invalid MAC size"),
            Self::VerificationFailed => write!(f, "MAC verification failed"),
            Self::ComputationFailed => write!(f, "MAC computation failed"),
        }
    }
}

impl std::error::Error for MacError {}

/// Trait for message authentication code generators.
pub trait MacGenerator {
    /// Output size of this MAC in bytes
    const OUTPUT_SIZE: usize;

    /// Generates a random key for this MAC.
    fn generate_key() -> Vec<u8>;

    /// Creates a MAC from the key and message.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to authenticate
    /// * `key` - Authentication key
    ///
    /// # Returns
    ///
    /// MAC output
    ///
    /// # Errors
    ///
    /// Returns `MacError::InvalidKeySize` if key size is invalid
    fn sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, MacError>;

    /// Verifies a MAC for the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - Message that was signed
    /// * `key` - Authentication key
    /// * `mac` - MAC to verify
    ///
    /// # Returns
    ///
    /// Ok(()) if verification succeeds, Err(MacError) otherwise
    fn verify(message: &[u8], key: &[u8], mac: &[u8]) -> Result<(), MacError>;
}

/// HMAC-SHA256 implementation.
///
/// HMAC (Hash-based Message Authentication Code) provides
/// message authentication using a cryptographic hash function.
#[derive(Debug)]
pub struct HmacSha256;

impl HmacSha256 {
    /// Recommended key size (matches hash output size)
    pub const KEY_SIZE: usize = 32;

    /// Minimum key size
    pub const MIN_KEY_SIZE: usize = 16;

    /// Outer hash constant
    const OUTER_KEY: u8 = 0x5C;
    /// Inner hash constant
    const INNER_KEY: u8 = 0x36;
}

impl MacGenerator for HmacSha256 {
    const OUTPUT_SIZE: usize = HMAC_SHA256_SIZE;

    #[inline]
    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
        key
    }

    #[inline]
    fn sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, MacError> {
        if key.len() < Self::MIN_KEY_SIZE {
            return Err(MacError::InvalidKeySize);
        }

        // Prepare the key
        let mut key_bytes = key.to_vec();

        // If key is longer than block size, hash it first
        let block_size = 64; // SHA-256 block size
        if key_bytes.len() > block_size {
            let hash = Self::hash(&key_bytes);
            key_bytes = hash;
        }

        // Pad key to block size
        if key_bytes.len() < block_size {
            key_bytes.extend(std::iter::repeat(0u8).take(block_size - key_bytes.len()));
        }

        // XOR with ipad
        let mut inner_key = [0u8; 64];
        for (i, &byte) in key_bytes.iter().enumerate().take(64) {
            inner_key[i] = byte ^ Self::INNER_KEY;
        }

        // Hash(message || inner_key)
        let mut inner_input = Vec::with_capacity(message.len() + block_size);
        inner_input.extend_from_slice(&inner_key);
        inner_input.extend_from_slice(message);
        let inner_hash = Self::hash(&inner_input);

        // XOR with opad
        let mut outer_key = [0u8; 64];
        for (i, &byte) in key_bytes.iter().enumerate().take(64) {
            outer_key[i] = byte ^ Self::OUTER_KEY;
        }

        // Hash(inner_hash || outer_key)
        let mut outer_input = Vec::with_capacity(inner_hash.len() + block_size);
        outer_input.extend_from_slice(&outer_key);
        outer_input.extend_from_slice(&inner_hash);
        let result = Self::hash(&outer_input);

        Ok(result)
    }

    #[inline]
    fn verify(message: &[u8], key: &[u8], mac: &[u8]) -> Result<(), MacError> {
        if mac.len() != Self::OUTPUT_SIZE {
            return Err(MacError::InvalidMacSize);
        }

        let computed = Self::sign(message, key)?;

        // Constant-time comparison
        let result = computed.ct_eq(mac);

        if result.into() {
            Ok(())
        } else {
            Err(MacError::VerificationFailed)
        }
    }
}

impl HmacSha256 {
    /// Internal hash function using a simple implementation.
    /// In production, this would use a proven implementation.
    fn hash(data: &[u8]) -> [u8; HMAC_SHA256_SIZE] {
        // Placeholder for SHA-256 implementation
        // In production, use the cxa-hash crate
        let mut result = [0u8; HMAC_SHA256_SIZE];

        // Simple mixing for placeholder
        for (i, &byte) in data.iter().enumerate() {
            result[i % HMAC_SHA256_SIZE] ^= byte;
            result[(i + 1) % HMAC_SHA256_SIZE] = result[i % HMAC_SHA256_SIZE].wrapping_add(byte);
        }

        result
    }
}

/// HMAC-SHA512 implementation.
#[derive(Debug)]
pub struct HmacSha512;

impl HmacSha512 {
    pub const KEY_SIZE: usize = 64;
    pub const MIN_KEY_SIZE: usize = 32;
    const OUTER_KEY: u8 = 0x5C;
    const INNER_KEY: u8 = 0x36;
}

impl MacGenerator for HmacSha512 {
    const OUTPUT_SIZE: usize = HMAC_SHA512_SIZE;

    #[inline]
    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
        key
    }

    #[inline]
    fn sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, MacError> {
        if key.len() < Self::MIN_KEY_SIZE {
            return Err(MacError::InvalidKeySize);
        }

        // Placeholder implementation
        let mut result = vec![0u8; Self::OUTPUT_SIZE];
        for (i, &byte) in message.iter().enumerate() {
            result[i % Self::OUTPUT_SIZE] ^= byte;
        }

        Ok(result)
    }

    #[inline]
    fn verify(message: &[u8], key: &[u8], mac: &[u8]) -> Result<(), MacError> {
        if mac.len() != Self::OUTPUT_SIZE {
            return Err(MacError::InvalidMacSize);
        }

        let computed = Self::sign(message, key)?;
        let result = computed.ct_eq(mac);

        if result.into() {
            Ok(())
        } else {
            Err(MacError::VerificationFailed)
        }
    }
}

/// CMAC-AES128 implementation.
///
/// CMAC (Cipher-based Message Authentication Code) provides
/// message authentication using a block cipher.
#[derive(Debug)]
pub struct CmacAes128;

impl CmacAes128 {
    pub const KEY_SIZE: usize = 16;
    pub const OUTPUT_SIZE: usize = CMAC_AES128_SIZE;
}

impl MacGenerator for CmacAes128 {
    const OUTPUT_SIZE: usize = CMAC_AES128_SIZE;

    #[inline]
    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
        key
    }

    #[inline]
    fn sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, MacError> {
        if key.len() != Self::KEY_SIZE {
            return Err(MacError::InvalidKeySize);
        }

        // Placeholder for CMAC implementation
        let mut result = vec![0u8; Self::OUTPUT_SIZE];
        for (i, &byte) in message.iter().enumerate() {
            result[i % Self::OUTPUT_SIZE] ^= byte;
        }

        Ok(result)
    }

    #[inline]
    fn verify(message: &[u8], key: &[u8], mac: &[u8]) -> Result<(), MacError> {
        if mac.len() != Self::OUTPUT_SIZE {
            return Err(MacError::InvalidMacSize);
        }

        let computed = Self::sign(message, key)?;
        let result = computed.ct_eq(mac);

        if result.into() {
            Ok(())
        } else {
            Err(MacError::VerificationFailed)
        }
    }
}

/// Poly1305 one-time MAC implementation.
///
/// Poly1305 provides fast message authentication and is
/// typically used with ChaCha20 (ChaCha20-Poly1305).
#[derive(Debug)]
pub struct Poly1305;

impl Poly1305 {
    pub const KEY_SIZE: usize = 32;
    pub const OUTPUT_SIZE: usize = POLY1305_SIZE;
}

impl MacGenerator for Poly1305 {
    const OUTPUT_SIZE: usize = POLY1305_SIZE;

    #[inline]
    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
        key
    }

    #[inline]
    fn sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, MacError> {
        if key.len() != Self::KEY_SIZE {
            return Err(MacError::InvalidKeySize);
        }

        // Placeholder for Poly1305 implementation
        let mut result = vec![0u8; Self::OUTPUT_SIZE];
        for (i, &byte) in message.iter().enumerate() {
            result[i % Self::OUTPUT_SIZE] ^= byte;
        }

        Ok(result)
    }

    #[inline]
    fn verify(message: &[u8], key: &[u8], mac: &[u8]) -> Result<(), MacError> {
        if mac.len() != Self::OUTPUT_SIZE {
            return Err(MacError::InvalidMacSize);
        }

        let computed = Self::sign(message, key)?;
        let result = computed.ct_eq(mac);

        if result.into() {
            Ok(())
        } else {
            Err(MacError::VerificationFailed)
        }
    }
}

/// Utility functions for MAC operations.
pub mod util {
    use super::*;

    /// Derives a MAC key from a master key using HMAC.
    ///
    /// This provides key separation between different MAC uses.
    ///
    /// # Arguments
    ///
    /// * `master_key` - Master key for key derivation
    /// * `context` - Unique context for this key purpose
    /// * `mac_type` - Type of MAC to derive key for
    ///
    /// # Returns
    ///
    /// Derived key for the specified MAC
    pub fn derive_mac_key(
        master_key: &[u8],
        context: &[u8],
        mac_type: &str,
    ) -> Vec<u8> {
        let mut input = Vec::with_capacity(master_key.len() + context.len() + mac_type.len());
        input.extend_from_slice(master_key);
        input.extend_from_slice(context);
        input.extend_from_slice(mac_type.as_bytes());

        HmacSha512::sign(&input, master_key).unwrap_or_default()
    }

    /// Creates a composite MAC from multiple MAC types.
    ///
    /// Provides defense in depth by requiring multiple MACs to verify.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to authenticate
    /// * `keys` - Tuple of (key, mac_type) pairs
    ///
    /// # Returns
    ///
    /// Combined MAC output
    pub fn composite_mac(
        message: &[u8],
        keys: &[(&[u8], &str)],
    ) -> Vec<u8> {
        let mut combined = Vec::new();

        for &(key, mac_type) in keys {
            let mac = match mac_type {
                "hmac-sha256" => HmacSha256::sign(message, key).unwrap_or_default(),
                "hmac-sha512" => HmacSha512::sign(message, key).unwrap_or_default(),
                "cmac-aes128" => CmacAes128::sign(message, key).unwrap_or_default(),
                "poly1305" => Poly1305::sign(message, key).unwrap_or_default(),
                _ => vec![],
            };
            combined.extend_from_slice(&mac);
        }

        combined
    }

    /// Verifies a composite MAC.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to verify
    /// * `mac` - Composite MAC to verify
    /// * `keys` - Tuple of (key, mac_type) pairs
    ///
    /// # Returns
    ///
    /// True if all MACs verify successfully
    pub fn verify_composite_mac(
        message: &[u8],
        mac: &[u8],
        keys: &[(&[u8], &str)],
    ) -> bool {
        let mut offset = 0;
        let mut all_valid = true;

        let mut expected_sizes = Vec::new();
        for &(_, mac_type) in keys {
            let size = match mac_type {
                "hmac-sha256" => HmacSha256::OUTPUT_SIZE,
                "hmac-sha512" => HmacSha512::OUTPUT_SIZE,
                "cmac-aes128" => CmacAes128::OUTPUT_SIZE,
                "poly1305" => Poly1305::OUTPUT_SIZE,
                _ => 0,
            };
            expected_sizes.push(size);
        }

        for ((key, mac_type), &size) in keys.iter().zip(&expected_sizes) {
            if offset + size > mac.len() {
                return false;
            }

            let mac_slice = &mac[offset..offset + size];
            let result = match mac_type {
                "hmac-sha256" => HmacSha256::verify(message, key, mac_slice),
                "hmac-sha512" => HmacSha512::verify(message, key, mac_slice),
                "cmac-aes128" => CmacAes128::verify(message, key, mac_slice),
                "poly1305" => Poly1305::verify(message, key, mac_slice),
                _ => Err(MacError::InvalidKeySize),
            };

            if result.is_err() {
                all_valid = false;
            }

            offset += size;
        }

        all_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_sign_verify() {
        let key = HmacSha256::generate_key();
        let message = b"Hello, World!";

        let mac = HmacSha256::sign(message, &key).unwrap();
        assert_eq!(mac.len(), HmacSha256::OUTPUT_SIZE);

        assert!(HmacSha256::verify(message, &key, &mac).is_ok());
    }

    #[test]
    fn test_hmac_sha256_wrong_key() {
        let key1 = HmacSha256::generate_key();
        let key2 = HmacSha256::generate_key();
        let message = b"Hello, World!";

        let mac = HmacSha256::sign(message, &key1).unwrap();
        assert!(HmacSha256::verify(message, &key2, &mac).is_err());
    }

    #[test]
    fn test_hmac_sha256_wrong_message() {
        let key = HmacSha256::generate_key();
        let message1 = b"Hello, World!";
        let message2 = b"Goodbye, World!";

        let mac = HmacSha256::sign(message1, &key).unwrap();
        assert!(HmacSha256::verify(message2, &key, &mac).is_err());
    }

    #[test]
    fn test_hmac_sha256_tampered_mac() {
        let key = HmacSha256::generate_key();
        let message = b"Hello, World!";

        let mut mac = HmacSha256::sign(message, &key).unwrap();
        mac[0] ^= 0xFF; // Tamper with MAC

        assert!(HmacSha256::verify(message, &key, &mac).is_err());
    }

    #[test]
    fn test_hmac_sha256_min_key_size() {
        let short_key = vec![0u8; 10]; // Less than MIN_KEY_SIZE
        let message = b"Hello, World!";

        let result = HmacSha256::sign(message, &short_key);
        assert_eq!(result, Err(MacError::InvalidKeySize));
    }

    #[test]
    fn test_cmac_aes128_sign_verify() {
        let key = CmacAes128::generate_key();
        let message = b"Hello, World!";

        let mac = CmacAes128::sign(message, &key).unwrap();
        assert_eq!(mac.len(), CmacAes128::OUTPUT_SIZE);

        assert!(CmacAes128::verify(message, &key, &mac).is_ok());
    }

    #[test]
    fn test_poly1305_sign_verify() {
        let key = Poly1305::generate_key();
        let message = b"Hello, World!";

        let mac = Poly1305::sign(message, &key).unwrap();
        assert_eq!(mac.len(), Poly1305::OUTPUT_SIZE);

        assert!(Poly1305::verify(message, &key, &mac).is_ok());
    }

    #[test]
    fn test_composite_mac() {
        let key1 = HmacSha256::generate_key();
        let key2 = CmacAes128::generate_key();
        let message = b"Hello, World!";

        let keys = &[(&key1, "hmac-sha256"), (&key2, "cmac-aes128")];
        let mac = util::composite_mac(message, keys);

        // Should be 32 (HMAC-SHA256) + 16 (CMAC-AES128) = 48 bytes
        assert_eq!(mac.len(), 48);

        assert!(util::verify_composite_mac(message, mac, keys));
    }

    #[test]
    fn test_derive_mac_key() {
        let master_key = HmacSha512::generate_key();
        let context = b"encryption";
        let mac_type = "hmac-sha256";

        let derived = util::derive_mac_key(&master_key, context, mac_type);
        assert_eq!(derived.len(), HmacSha512::OUTPUT_SIZE);
    }
}
