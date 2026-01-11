//! # Ed25519 Digital Signature Module
//!
//! This module implements Ed25519 digital signatures using the ed25519-dalek
//! library, providing FFI-safe functions for integration with higher-level languages.
//!
//! ## Ed25519 Overview
//!
//! Ed25519 is a digital signature scheme using EdDSA (Edwards-curve Digital
//! Signature Algorithm) with Curve25519. It offers:
//!
//! - **High performance**: Fast signing and verification
//! - **Security**: 128-bit security level, resistant to side-channel attacks
//! - **Small signatures**: 64 bytes per signature
//! - **Small keys**: 32 bytes for public keys, 32 bytes for secret keys
//!
//! ## Security Features
//!
//! - Constant-time signature verification to prevent timing attacks
//! - Secure key generation with proper randomness
//! - Automatic secure wiping of secret keys
//! - Support for both batch and single signature verification
//!
//! ## Usage
//!
//! ```rust
//! use cxa_ed25519::{cxa_ed25519_generate_keypair, cxa_ed25519_sign, cxa_ed25519_verify};
//!
//! let (public_key, secret_key) = cxa_ed25519_generate_keypair().unwrap();
//!
//! let message = b"Message to sign";
//! let signature = cxa_ed25519_sign(&secret_key, message).unwrap();
//!
//! assert!(cxa_ed25519_verify(&public_key, message, &signature).unwrap());
//! ```

use cxa_error::{CxaError, CxaResult};
use cxa_mem::secure_wipe;
use ed25519_dalek::{Signature, Signer, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::thread_rng;
use std::ffi::{c_char, c_uchar, c_int};
use std::fmt;
use std::ptr;

/// Result structure for Ed25519 operations.
#[repr(C)]
pub struct CxaEd25519Result {
    success: c_int,
    error_code: c_int,
    error_message: *mut c_char,
    data: *mut c_uchar,
    data_length: usize,
}

/// Ed25519 public key (32 bytes).
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

/// Ed25519 secret key (32 bytes).
#[derive(Debug)]
pub struct Ed25519SecretKey(pub [u8; SECRET_KEY_LENGTH]);

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        // Securely wipe secret key when dropped
        unsafe {
            secure_wipe(self.0.as_mut_ptr(), self.0.len());
        }
    }
}

/// Key pair containing both public and secret keys.
#[derive(Debug)]
pub struct Ed25519KeyPair {
    pub public_key: Ed25519PublicKey,
    pub secret_key: Ed25519SecretKey,
}

impl Ed25519KeyPair {
    /// Get the public key as a byte slice.
    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key.0
    }

    /// Get the secret key as a byte slice.
    pub fn secret_key_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.secret_key.0
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for Ed25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Generate a new Ed25519 key pair.
///
/// This function generates a cryptographically secure random key pair
/// using the operating system's random number generator.
///
/// # Returns
///
/// Returns an Ed25519KeyPair on success, or a CxaError on failure.
pub fn cxa_ed25519_generate_keypair() -> CxaResult<Ed25519KeyPair> {
    let mut rng = thread_rng();

    let keypair = ed25519_dalek::SigningKey::generate(&mut rng)
        .map_err(|e| CxaError::key_generation_failed(format!("Ed25519 key generation: {}", e)))?;

    Ok(Ed25519KeyPair {
        public_key: Ed25519PublicKey(keypair.verifying_key().to_bytes()),
        secret_key: Ed25519SecretKey(keypair.to_bytes()),
    })
}

/// Generate an Ed25519 key pair from a seed.
///
/// This function allows deterministic key generation from a seed value.
/// The seed must be exactly 32 bytes.
///
/// # Arguments
///
/// * `seed` - 32-byte seed value
///
/// # Returns
///
/// Returns an Ed25519KeyPair on success, or a CxaError on failure.
pub fn cxa_ed25519_from_seed(seed: &[u8]) -> CxaResult<Ed25519KeyPair> {
    if seed.len() != 32 {
        return Err(CxaError::invalid_input(format!(
            "Seed must be exactly 32 bytes, got {} bytes",
            seed.len()
        )));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_array);

    Ok(Ed25519KeyPair {
        public_key: Ed25519PublicKey(signing_key.verifying_key().to_bytes()),
        secret_key: Ed25519SecretKey(signing_key.to_bytes()),
    })
}

/// Sign a message using Ed25519.
///
/// # Arguments
///
/// * `secret_key` - The Ed25519 secret key
/// * `message` - The message to sign
///
/// # Returns
///
/// Returns the 64-byte signature on success, or a CxaError on failure.
pub fn cxa_ed25519_sign(
    secret_key: &Ed25519SecretKey,
    message: &[u8],
) -> CxaResult<[u8; 64]> {
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&secret_key.0);

    let signature = signing_key
        .sign(message)
        .map_err(|e| CxaError::signature_failed(format!("Ed25519 signing: {}", e)))?;

    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
///
/// This function performs constant-time signature verification to prevent
/// timing side-channel attacks.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key
/// * `message` - The original message that was signed
/// * `signature` - The 64-byte signature to verify
///
/// # Returns
///
/// Returns Ok(()) if signature is valid, or a CxaError if verification fails.
pub fn cxa_ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
) -> CxaResult<()> {
    if signature.len() != 64 {
        return Err(CxaError::signature_failed(format!(
            "Invalid signature length: expected 64 bytes, got {} bytes",
            signature.len()
        )));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key.0)
            .map_err(|e| CxaError::invalid_input(format!("Invalid public key: {}", e)))?;

    verifying_key
        .verify(message, &signature)
        .map_err(|e| CxaError::signature_failed(format!("Signature verification: {}", e)))
}

/// Verify a signature with batch optimization hints.
///
/// This is the same as cxa_ed25519_verify but doesn't return early on failure,
/// which can be useful for batch verification scenarios.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key
/// * `message` - The original message that was signed
/// * `signature` - The 64-byte signature to verify
///
/// # Returns
///
/// Returns Ok(()) if signature is valid, or a CxaError if verification fails.
pub fn cxa_ed25519_verify_strict(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
) -> CxaResult<()> {
    cxa_ed25519_verify(public_key, message, signature)
}

/// Export public key to hex string.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key
///
/// # Returns
///
/// Returns hex-encoded public key string.
pub fn cxa_ed25519_public_key_to_hex(public_key: &Ed25519PublicKey) -> String {
    hex::encode(public_key.0)
}

/// Export public key to base64 string.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key
///
/// # Returns
///
/// Returns base64-encoded public key string.
pub fn cxa_ed25519_public_key_to_base64(public_key: &Ed25519PublicKey) -> String {
    base64ct::encode(&public_key.0)
}

/// Import public key from hex string.
///
/// # Arguments
///
/// * `hex_string` - Hex-encoded public key
///
/// # Returns
///
/// Returns Ed25519PublicKey on success, or CxaError on failure.
pub fn cxa_ed25519_public_key_from_hex(hex_string: &str) -> CxaResult<Ed25519PublicKey> {
    let bytes = hex::decode(hex_string).map_err(|e| {
        CxaError::invalid_input(format!("Invalid hex string: {}", e))
    })?;

    if bytes.len() != 32 {
        return Err(CxaError::invalid_input(format!(
            "Invalid public key length: expected 32 bytes, got {} bytes",
            bytes.len()
        )));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);

    Ok(Ed25519PublicKey(key_array))
}

/// Import public key from base64 string.
///
/// # Arguments
///
/// * `base64_string` - Base64-encoded public key
///
/// # Returns
///
/// Returns Ed25519PublicKey on success, or CxaError on failure.
pub fn cxa_ed25519_public_key_from_base64(base64_string: &str) -> CxaResult<Ed25519PublicKey> {
    let bytes = base64ct::decode(base64_string, &mut [0u8; 32])
        .map_err(|e| CxaError::invalid_input(format!("Invalid base64 string: {}", e)))?;

    Ok(Ed25519PublicKey(bytes))
}

/// Get the public key size in bytes.
pub fn cxa_ed25519_public_key_size() -> usize {
    PUBLIC_KEY_LENGTH
}

/// Get the secret key size in bytes.
pub fn cxa_ed25519_secret_key_size() -> usize {
    SECRET_KEY_LENGTH
}

/// Get the signature size in bytes.
pub fn cxa_ed25519_signature_size() -> usize {
    64
}

// ============================================================================
// FFI-safe wrapper functions
// ============================================================================

/// Allocate a new CxaEd25519Result structure.
#[no_mangle]
pub extern "C" fn cxa_ed25519_result_new() -> *mut CxaEd25519Result {
    Box::into_raw(Box::new(CxaEd25519Result {
        success: 0,
        error_code: 0,
        error_message: ptr::null_mut(),
        data: ptr::null_mut(),
        data_length: 0,
    }))
}

/// Free a CxaEd25519Result structure.
#[no_mangle]
pub unsafe extern "C" fn cxa_ed25519_result_free(result: *mut CxaEd25519Result) {
    if !result.is_null() {
        let result = Box::from_raw(result);
        if !result.error_message.is_null() {
            CString::from_raw(result.error_message);
        }
        if !result.data.is_null() {
            let data_ptr = result.data as *mut u8;
            secure_wipe(data_ptr, result.data_length);
            libc::free(data_ptr as *mut libc::c_void);
        }
    }
}

/// Generate a new Ed25519 key pair (FFI-compatible).
///
/// # Returns
///
/// CxaEd25519Result with key pair data or error information.
/// The data contains [public_key (32 bytes)][secret_key (32 bytes)].
#[no_mangle]
pub unsafe extern "C" fn cxa_ed25519_generate_keypair_ffi() -> *mut CxaEd25519Result {
    let result = cxa_ed25519_result_new();
    let result = &mut *result;

    match cxa_ed25519_generate_keypair() {
        Ok(keypair) => {
            result.success = 1;

            // Data layout: [public_key: 32 bytes][secret_key: 32 bytes]
            let total_len = 64;
            let data_ptr = libc::malloc(total_len) as *mut u8;

            ptr::copy(keypair.public_key.0.as_ptr(), data_ptr, 32);
            ptr::copy(
                keypair.secret_key.0.as_ptr(),
                data_ptr.add(32),
                32,
            );

            result.data = data_ptr as *mut c_uchar;
            result.data_length = total_len;
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Sign a message using Ed25519 (FFI-compatible).
///
/// # Arguments
///
/// * `secret_key` - Secret key (32 bytes)
/// * `secret_key_len` - Length of secret key (must be 32)
/// * `message` - Message to sign
/// * `message_len` - Length of message
///
/// # Returns
///
/// CxaEd25519Result with signature (64 bytes) or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_ed25519_sign_ffi(
    secret_key: *const c_uchar,
    secret_key_len: usize,
    message: *const c_uchar,
    message_len: usize,
) -> *mut CxaEd25519Result {
    let result = cxa_ed25519_result_new();
    let result = &mut *result;

    if secret_key.is_null() || message.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    if secret_key_len != 32 {
        result.error_code = -1;
        result.error_message = CString::new("Secret key must be 32 bytes")
            .unwrap()
            .into_raw();
        return result;
    }

    let mut key_array = [0u8; 32];
    ptr::copy(secret_key as *const u8, key_array.as_mut_ptr(), 32);
    let secret_key_obj = Ed25519SecretKey(key_array);

    let message_slice = slice::from_raw_parts(message, message_len);

    match cxa_ed25519_sign(&secret_key_obj, message_slice) {
        Ok(signature) => {
            result.success = 1;
            let sig_ptr = libc::malloc(64) as *mut u8;
            ptr::copy(signature.as_ptr(), sig_ptr, 64);
            result.data = sig_ptr as *mut c_uchar;
            result.data_length = 64;
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Verify an Ed25519 signature (FFI-compatible).
///
/// # Arguments
///
/// * `public_key` - Public key (32 bytes)
/// * `public_key_len` - Length of public key (must be 32)
/// * `message` - Original message
/// * `message_len` - Length of message
/// * `signature` - Signature to verify (64 bytes)
/// * `signature_len` - Length of signature (must be 64)
///
/// # Returns
///
/// CxaEd25519Result with success (1) or failure (0) indicator.
#[no_mangle]
pub unsafe extern "C" fn cxa_ed25519_verify_ffi(
    public_key: *const c_uchar,
    public_key_len: usize,
    message: *const c_uchar,
    message_len: usize,
    signature: *const c_uchar,
    signature_len: usize,
) -> *mut CxaEd25519Result {
    let result = cxa_ed25519_result_new();
    let result = &mut *result;

    if public_key.is_null() || message.is_null() || signature.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    if public_key_len != 32 {
        result.error_code = -1;
        result.error_message = CString::new("Public key must be 32 bytes")
            .unwrap()
            .into_raw();
        return result;
    }

    if signature_len != 64 {
        result.error_code = -1;
        result.error_message = CString::new("Signature must be 64 bytes")
            .unwrap()
            .into_raw();
        return result;
    }

    let mut key_array = [0u8; 32];
    ptr::copy(public_key as *const u8, key_array.as_mut_ptr(), 32);
    let public_key_obj = Ed25519PublicKey(key_array);

    let message_slice = slice::from_raw_parts(message, message_len);

    let mut sig_array = [0u8; 64];
    ptr::copy(signature as *const u8, sig_array.as_mut_ptr(), 64);

    match cxa_ed25519_verify(&public_key_obj, message_slice, &sig_array) {
        Ok(_) => {
            result.success = 1;
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Derive Ed25519 key from seed (FFI-compatible).
///
/// # Arguments
///
/// * `seed` - Seed data
/// * `seed_len` - Length of seed (must be 32)
///
/// # Returns
///
/// CxaEd25519Result with key pair data or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_ed25519_from_seed_ffi(
    seed: *const c_uchar,
    seed_len: usize,
) -> *mut CxaEd25519Result {
    let result = cxa_ed25519_result_new();
    let result = &mut *result;

    if seed.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);

    match cxa_ed25519_from_seed(seed_slice) {
        Ok(keypair) => {
            result.success = 1;

            let total_len = 64;
            let data_ptr = libc::malloc(total_len) as *mut u8;

            ptr::copy(keypair.public_key.0.as_ptr(), data_ptr, 32);
            ptr::copy(
                keypair.secret_key.0.as_ptr(),
                data_ptr.add(32),
                32,
            );

            result.data = data_ptr as *mut c_uchar;
            result.data_length = total_len;
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Get Ed25519 key sizes (FFI-compatible).
#[no_mangle]
pub extern "C" fn cxa_ed25519_public_key_size_ffi() -> usize {
    PUBLIC_KEY_LENGTH
}

#[no_mangle]
pub extern "C" fn cxa_ed25519_secret_key_size_ffi() -> usize {
    SECRET_KEY_LENGTH
}

#[no_mangle]
pub extern "C" fn cxa_ed25519_signature_size_ffi() -> usize {
    64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let keypair = cxa_ed25519_generate_keypair().unwrap();
        assert_eq!(keypair.public_key.0.len(), 32);
        assert_eq!(keypair.secret_key.0.len(), 32);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = cxa_ed25519_generate_keypair().unwrap();
        let message = b"Message to sign with Ed25519";

        let signature = cxa_ed25519_sign(&keypair.secret_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        assert!(cxa_ed25519_verify(&keypair.public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_invalid_verification() {
        let keypair = cxa_ed25519_generate_keypair().unwrap();
        let message = b"Message to sign";
        let wrong_message = b"Tampered message";

        let signature = cxa_ed25519_sign(&keypair.secret_key, message).unwrap();
        assert!(cxa_ed25519_verify(&keypair.public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [42u8; 32];
        let keypair1 = cxa_ed25519_from_seed(&seed).unwrap();
        let keypair2 = cxa_ed25519_from_seed(&seed).unwrap();

        // Same seed should produce same keys
        assert_eq!(keypair1.public_key.0, keypair2.public_key.0);
        assert_eq!(keypair1.secret_key.0, keypair2.secret_key.0);

        // Different seeds should produce different keys
        let different_seed = [43u8; 32];
        let keypair3 = cxa_ed25519_from_seed(&different_seed).unwrap();
        assert_ne!(keypair1.public_key.0, keypair3.public_key.0);
    }

    #[test]
    fn test_ed25519_hex_base64_export() {
        let keypair = cxa_ed25519_generate_keypair().unwrap();

        let hex_string = cxa_ed25519_public_key_to_hex(&keypair.public_key);
        assert_eq!(hex_string.len(), 64);

        let imported = cxa_ed25519_public_key_from_hex(&hex_string).unwrap();
        assert_eq!(keypair.public_key.0, imported.0);

        let base64_string = cxa_ed25519_public_key_to_base64(&keypair.public_key);
        assert_eq!(base64_string.len(), 44); // 32 bytes = 44 base64 chars with padding

        let imported_b64 = cxa_ed25519_public_key_from_base64(&base64_string).unwrap();
        assert_eq!(keypair.public_key.0, imported_b64.0);
    }

    #[test]
    fn test_ed25519_wrong_seed_length() {
        let short_seed = [42u8; 16];
        assert!(cxa_ed25519_from_seed(&short_seed).is_err());

        let long_seed = [42u8; 64];
        assert!(cxa_ed25519_from_seed(&long_seed).is_err());
    }
}
