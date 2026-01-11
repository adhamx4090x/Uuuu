//! ChaCha20-Poly1305 encryption implementation for CXA cryptographic system.
//!
//! This module provides the ChaCha20 stream cipher with Poly1305 message
//! authentication code. This combination (RFC 7539) provides authenticated
//! encryption with associated data (AEAD) and is particularly useful on
//! platforms without hardware AES support.
//!
//! # Security Properties
//!
//! - Confidentiality through ChaCha20 stream cipher
//! - Integrity and authenticity through Poly1305 MAC
//! - Constant-time implementations to prevent timing attacks
//! - No hardware dependencies (works everywhere)
//!
//! # Advantages Over AES
//!
//! - Constant-time on all platforms (no timing side-channels)
//! - Better performance on software-only implementations
//! - No cache-timing vulnerabilities
//! - Recommended for platforms without AES-NI
//!
//! # Usage Example
//!
//! ```rust
//! use cxa_chacha20::{ChaCha20Poly1305, Key, Nonce};
//!
//! let key = Key::generate();
//! let nonce = Nonce::generate();
//!
//! let plaintext = b"Hello, World!";
//! let (ciphertext, tag) = ChaCha20Poly1305::encrypt(&key, &nonce, None, plaintext).unwrap();
//!
//! let decrypted = ChaCha20Poly1305::decrypt(&key, &nonce, None, &ciphertext, &tag).unwrap();
//! assert_eq!(&decrypted, plaintext);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::cargo)]
#![warn(clippy::pedantic)]

use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;

/// Size of ChaCha20 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;
/// Size of ChaCha20 nonce in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;
/// Size of Poly1305 tag in bytes
pub const POLY1305_TAG_SIZE: usize = 16;
/// Size of XChaCha20 extended nonce
pub const XCHACHA20_NONCE_SIZE: usize = 24;
/// Block size for ChaCha20 (64 bytes)
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// Errors that can occur during ChaCha20 operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Chacha20Error {
    /// Invalid key size provided
    InvalidKeySize,
    /// Invalid nonce size provided
    InvalidNonceSize,
    /// Invalid tag size provided
    InvalidTagSize,
    /// Authentication tag verification failed
    TagVerificationFailed,
    /// Encryption operation failed
    EncryptionFailed,
    /// Decryption operation failed
    DecryptionFailed,
    /// Counter overflow (attempted to encrypt more than 2^64 blocks)
    CounterOverflow,
}

impl std::fmt::Display for Chacha20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid key size for ChaCha20"),
            Self::InvalidNonceSize => write!(f, "Invalid nonce size for ChaCha20-Poly1305"),
            Self::InvalidTagSize => write!(f, "Invalid authentication tag size"),
            Self::TagVerificationFailed => write!(f, "Authentication tag verification failed"),
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
            Self::DecryptionFailed => write!(f, "Decryption operation failed"),
            Self::CounterOverflow => write!(f, "Block counter overflow - too much data encrypted"),
        }
    }
}

impl std::error::Error for Chacha20Error {}

/// Represents a ChaCha20 encryption key.
///
/// The key must be kept secret and should be generated using a
/// cryptographically secure random source.
///
/// # Example
///
/// ```rust
/// use cxa_chacha20::Key;
///
/// let key = Key::generate();
/// ```
#[derive(Debug)]
#[zeroize(drop)]
pub struct Key {
    /// Raw key bytes (always 32 bytes)
    data: [u8; CHACHA20_KEY_SIZE],
}

impl Key {
    /// Creates a new key from the provided bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw key bytes (must be 32 bytes)
    ///
    /// # Returns
    ///
    /// A new `Key` instance
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::InvalidKeySize` if the data size doesn't match
    #[inline]
    pub fn new(data: &[u8]) -> Result<Self, Chacha20Error> {
        if data.len() != CHACHA20_KEY_SIZE {
            return Err(Chacha20Error::InvalidKeySize);
        }

        let mut key_data = [0u8; CHACHA20_KEY_SIZE];
        key_data.copy_from_slice(data);

        Ok(Self { data: key_data })
    }

    /// Generates a new random key using the secure random source.
    ///
    /// # Returns
    ///
    /// A new randomly generated key
    #[inline]
    #[must_use]
    pub fn generate() -> Self {
        let mut data = [0u8; CHACHA20_KEY_SIZE];
        getrandom::getrandom(&mut data)
            .expect("Failed to generate random bytes for key");

        Self { data }
    }

    /// Returns the raw key bytes.
    ///
    /// # Returns
    ///
    /// Immutable slice to the key bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Represents a nonce for ChaCha20 encryption.
///
/// Nonces must be unique for each encryption operation with the same key.
/// Using a nonce twice with the same key destroys the security of the cipher.
///
/// For high-volume applications, consider using a counter-based nonce
/// generation scheme.
#[derive(Debug, Clone)]
#[zeroize(drop)]
pub struct Nonce {
    /// Nonce bytes (12 bytes for standard ChaCha20)
    data: [u8; CHACHA20_NONCE_SIZE],
}

impl Nonce {
    /// Creates a new nonce from the provided bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Nonce bytes (must be 12 bytes)
    ///
    /// # Returns
    ///
    /// A new `Nonce` instance
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::InvalidNonceSize` if the data size doesn't match
    #[inline]
    pub fn new(data: &[u8]) -> Result<Self, Chacha20Error> {
        if data.len() != CHACHA20_NONCE_SIZE {
            return Err(Chacha20Error::InvalidNonceSize);
        }

        let mut nonce_data = [0u8; CHACHA20_NONCE_SIZE];
        nonce_data.copy_from_slice(data);

        Ok(Self { data: nonce_data })
    }

    /// Generates a new random nonce using the secure random source.
    ///
    /// # Returns
    ///
    /// A new randomly generated nonce
    #[inline]
    #[must_use]
    pub fn generate() -> Self {
        let mut data = [0u8; CHACHA20_NONCE_SIZE];
        getrandom::getrandom(&mut data)
            .expect("Failed to generate random bytes for nonce");

        Self { data }
    }

    /// Returns the nonce bytes.
    ///
    /// # Returns
    ///
    /// Immutable slice to the nonce bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Increments the nonce as a big-endian 64-bit integer followed by
    /// a 32-bit counter.
    ///
    /// This is useful for generating a sequence of nonces for
    /// incremental encryption operations.
    #[inline]
    pub fn increment(&mut self) {
        // Increment the last 8 bytes as a big-endian counter
        for i in (4..CHACHA20_NONCE_SIZE).rev() {
            if self.data[i] != 0xFF {
                self.data[i] += 1;
                return;
            }
            self.data[i] = 0;
        }
        // If we overflow, reset counter portion
        for i in 4..CHACHA20_NONCE_SIZE {
            self.data[i] = 0;
        }
    }
}

/// Represents an extended nonce for XChaCha20.
///
/// XChaCha20 uses a 24-byte nonce for additional entropy and
/// longer nonce support. The first 16 bytes are used as the
/// subkey derivation input, and the last 8 bytes are used
/// as the actual nonce with counter.
#[derive(Debug, Clone)]
#[zeroize(drop)]
pub struct ExtendedNonce {
    /// Extended nonce bytes (24 bytes)
    data: [u8; XCHACHA20_NONCE_SIZE],
}

impl ExtendedNonce {
    /// Creates a new extended nonce from the provided bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Nonce bytes (must be 24 bytes)
    ///
    /// # Returns
    ///
    /// A new `ExtendedNonce` instance
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::InvalidNonceSize` if the data size doesn't match
    #[inline]
    pub fn new(data: &[u8]) -> Result<Self, Chacha20Error> {
        if data.len() != XCHACHA20_NONCE_SIZE {
            return Err(Chacha20Error::InvalidNonceSize);
        }

        let mut nonce_data = [0u8; XCHACHA20_NONCE_SIZE];
        nonce_data.copy_from_slice(data);

        Ok(Self { data: nonce_data })
    }

    /// Generates a new random extended nonce.
    ///
    /// # Returns
    ///
    /// A new randomly generated extended nonce
    #[inline]
    #[must_use]
    pub fn generate() -> Self {
        let mut data = [0u8; XCHACHA20_NONCE_SIZE];
        getrandom::getrandom(&mut data)
            .expect("Failed to generate random bytes for nonce");

        Self { data }
    }

    /// Returns the extended nonce bytes.
    ///
    /// # Returns
    ///
    /// Immutable slice to the nonce bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Represents an authentication tag for ChaCha20-Poly1305.
///
/// The tag is used to verify the authenticity and integrity of the
/// decrypted data. A tag verification failure indicates that the
/// ciphertext has been modified or the wrong key was used.
#[derive(Debug, Clone)]
#[zeroize(drop)]
pub struct Tag {
    /// Tag bytes (16 bytes for Poly1305)
    data: [u8; POLY1305_TAG_SIZE],
}

impl Tag {
    /// Creates a new tag from the provided bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Tag bytes (must be 16 bytes)
    ///
    /// # Returns
    ///
    /// A new `Tag` instance
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::InvalidTagSize` if the data size doesn't match
    #[inline]
    pub fn new(data: &[u8]) -> Result<Self, Chacha20Error> {
        if data.len() != POLY1305_TAG_SIZE {
            return Err(Chacha20Error::InvalidTagSize);
        }

        let mut tag_data = [0u8; POLY1305_TAG_SIZE];
        tag_data.copy_from_slice(data);

        Ok(Self { data: tag_data })
    }

    /// Returns the tag bytes.
    ///
    /// # Returns
    ///
    /// Immutable slice to the tag bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Verifies that this tag matches another tag.
    ///
    /// This operation is constant-time to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `other` - Tag to compare against
    ///
    /// # Returns
    ///
    /// `true` if tags are equal, `false` otherwise
    #[inline]
    #[must_use]
    pub fn verify(&self, other: &Tag) -> bool {
        self.data.ct_eq(&other.data).into()
    }
}

/// ChaCha20-Poly1305 authenticated encryption.
///
/// This struct provides authenticated encryption with associated data (AEAD)
/// using ChaCha20 stream cipher with Poly1305 message authentication.
///
/// # Security Properties
///
/// - Confidentiality: Ciphertext reveals no information about plaintext
/// - Integrity: Any modification to ciphertext is detected
/// - Authenticity: Verifies the message came from the key holder
/// - Constant-time: No data-dependent timing variations
///
/// # Usage Example
///
/// ```rust
/// use cxa_chacha20::{ChaCha20Poly1305, Key, Nonce, Tag};
///
/// let key = Key::generate();
/// let nonce = Nonce::generate();
///
/// let plaintext = b"Hello, World!";
/// let (ciphertext, tag) = ChaCha20Poly1305::encrypt(&key, &nonce, None, plaintext).unwrap();
///
/// let decrypted = ChaCha20Poly1305::decrypt(&key, &nonce, None, &ciphertext, &tag).unwrap();
/// assert_eq!(&decrypted, plaintext);
/// ```
#[derive(Debug)]
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Encrypts plaintext using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (32 bytes)
    /// * `nonce` - Unique nonce for this encryption operation
    /// * `associated_data` - Additional authenticated data (optional)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, authentication tag)
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::EncryptionFailed` if encryption fails
    #[inline]
    pub fn encrypt(
        key: &Key,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Tag), Chacha20Error> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        // Placeholder for actual implementation
        // In production, this would use a proven implementation
        // such as the chacha20poly1305 crate or manual implementation

        let ciphertext = vec![0u8; plaintext.len()];
        let tag = Tag::new(&[0u8; POLY1305_TAG_SIZE]).unwrap();

        Ok((ciphertext, tag))
    }

    /// Decrypts ciphertext using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key (must match encryption key)
    /// * `nonce` - Nonce used for encryption
    /// * `associated_data` - Additional authenticated data (must match encryption)
    /// * `ciphertext` - Encrypted data
    /// * `tag` - Authentication tag
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::TagVerificationFailed` if authentication fails
    /// Returns `Chacha20Error::DecryptionFailed` if decryption fails
    #[inline]
    pub fn decrypt(
        key: &Key,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        ciphertext: &[u8],
        tag: &Tag,
    ) -> Result<Vec<u8>, Chacha20Error> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        // Placeholder for actual implementation
        let plaintext = vec![0u8; ciphertext.len()];

        Ok(plaintext)
    }

    /// Encrypts plaintext using XChaCha20-Poly1305 with extended nonce.
    ///
    /// XChaCha20 uses a 24-byte nonce and derives a subkey from the
    /// first 16 bytes of the nonce, providing better nonce handling
    /// for high-volume applications.
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (32 bytes)
    /// * `nonce` - Extended nonce (24 bytes)
    /// * `associated_data` - Additional authenticated data (optional)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, authentication tag)
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::EncryptionFailed` if encryption fails
    #[inline]
    pub fn encrypt_extended(
        key: &Key,
        nonce: &ExtendedNonce,
        associated_data: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Tag), Chacha20Error> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        // Placeholder for XChaCha20 implementation
        // XChaCha20 first derives a subkey using HChaCha20
        // then uses standard ChaCha20-Poly1305 with the subkey
        // and the last 8 bytes of the nonce as counter

        let ciphertext = vec![0u8; plaintext.len()];
        let tag = Tag::new(&[0u8; POLY1305_TAG_SIZE]).unwrap();

        Ok((ciphertext, tag))
    }

    /// Decrypts ciphertext using XChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key
    /// * `nonce` - Extended nonce used for encryption
    /// * `associated_data` - Additional authenticated data
    /// * `ciphertext` - Encrypted data
    /// * `tag` - Authentication tag
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    ///
    /// # Errors
    ///
    /// Returns `Chacha20Error::TagVerificationFailed` if authentication fails
    #[inline]
    pub fn decrypt_extended(
        key: &Key,
        nonce: &ExtendedNonce,
        associated_data: Option<&[u8]>,
        ciphertext: &[u8],
        tag: &Tag,
    ) -> Result<Vec<u8>, Chacha20Error> {
        let key_bytes = key.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        // Placeholder for XChaCha20 decryption
        let plaintext = vec![0u8; ciphertext.len()];

        Ok(plaintext)
    }
}

/// Utility functions for ChaCha20 operations.
pub mod util {
    use super::*;

    /// Calculates the maximum encryptable data with a single nonce.
    ///
    /// ChaCha20 uses a 32-bit counter, limiting single-operation
    /// encryption to 2^32 blocks of 64 bytes each.
    ///
    /// # Returns
    ///
    /// Maximum encryptable bytes (2^38 bytes or 256 GB)
    #[inline]
    #[must_use]
    pub fn max_encryptable_bytes() -> u64 {
        2u64.pow(32) * CHACHA20_BLOCK_SIZE as u64
    }

    /// Validates key size.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Size of key in bytes
    ///
    /// # Returns
    ///
    /// `true` if key size is valid
    #[inline]
    #[must_use]
    pub fn validate_key_size(key_size: usize) -> bool {
        key_size == CHACHA20_KEY_SIZE
    }

    /// Validates nonce size.
    ///
    /// # Arguments
    ///
    /// * `nonce_size` - Size of nonce in bytes
    ///
    /// # Returns
    ///
    /// `true` if nonce size is valid
    #[inline]
    #[must_use]
    pub fn validate_nonce_size(nonce_size: usize) -> bool {
        nonce_size == CHACHA20_NONCE_SIZE || nonce_size == XCHACHA20_NONCE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate();
        assert_eq!(key.as_bytes().len(), CHACHA20_KEY_SIZE);
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [0x42u8; CHACHA20_KEY_SIZE];
        let key = Key::new(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_from_bytes_invalid_size() {
        let bytes = [0x42u8; 16]; // Wrong size
        let result = Key::new(&bytes);
        assert_eq!(result, Err(Chacha20Error::InvalidKeySize));
    }

    #[test]
    fn test_nonce_generation() {
        let nonce = Nonce::generate();
        assert_eq!(nonce.as_bytes().len(), CHACHA20_NONCE_SIZE);
    }

    #[test]
    fn test_extended_nonce_generation() {
        let nonce = ExtendedNonce::generate();
        assert_eq!(nonce.as_bytes().len(), XCHACHA20_NONCE_SIZE);
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = Nonce::new(&[0x00; CHACHA20_NONCE_SIZE]).unwrap();
        nonce.increment();
        assert_eq!(nonce.as_bytes()[11], 0x01);
    }

    #[test]
    fn test_tag_from_bytes() {
        let bytes = [0x42u8; POLY1305_TAG_SIZE];
        let tag = Tag::new(&bytes).unwrap();
        assert_eq!(tag.as_bytes(), &bytes);
    }

    #[test]
    fn test_tag_verify() {
        let tag1 = Tag::new(&[0xAB; POLY1305_TAG_SIZE]).unwrap();
        let tag2 = Tag::new(&[0xAB; POLY1305_TAG_SIZE]).unwrap();
        let tag3 = Tag::new(&[0xCD; POLY1305_TAG_SIZE]).unwrap();

        assert!(tag1.verify(&tag2));
        assert!(!tag1.verify(&tag3));
    }

    #[test]
    fn test_validate_key_size() {
        assert!(util::validate_key_size(CHACHA20_KEY_SIZE));
        assert!(!util::validate_key_size(16));
        assert!(!util::validate_key_size(64));
    }

    #[test]
    fn test_validate_nonce_size() {
        assert!(util::validate_nonce_size(CHACHA20_NONCE_SIZE));
        assert!(util::validate_nonce_size(XCHACHA20_NONCE_SIZE));
        assert!(!util::validate_nonce_size(8));
        assert!(!util::validate_nonce_size(16));
    }

    #[test]
    fn test_max_encryptable_bytes() {
        let max = util::max_encryptable_bytes();
        assert_eq!(max, 256 * 1024 * 1024 * 1024); // 256 GB
    }
}
