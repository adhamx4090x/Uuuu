//! # RSA Cryptographic Module
//!
//! This module implements RSA encryption and decryption operations using
//! OAEP (Optimal Asymmetric Encryption Padding) for secure key encapsulation.
//! It provides FFI-safe functions for integration with higher-level languages.
//!
//! ## Security Features
//!
//! - OAEP padding with SHA-256/384/512 hash functions
//! - Constant-time operations where possible
//! - Secure key generation with proper randomness
//! - Support for multiple key sizes (2048, 3072, 4096 bits)
//!
//! ## Usage
//!
//! ```rust
//! use cxa_rsa::{cxa_rsa_encrypt, cxa_rsa_decrypt, RsaKeySize};
//!
//! let key_size = RsaKeySize::Bits2048;
//! let (public_key, private_key) = cxa_rsa_generate_keypair(key_size).unwrap();
//!
//! let plaintext = b"Secret message for RSA encryption";
//! let ciphertext = cxa_rsa_encrypt(&public_key, plaintext).unwrap();
//! let decrypted = cxa_rsa_decrypt(&private_key, &ciphertext).unwrap();
//! ```

use cxa_error::{CxaError, CxaResult};
use cxa_mem::secure_wipe;
use num_bigint::BigUint;
use num_traits::Zero;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::DecodePrivateKey,
    PublicKey as RsaPublicKey,
};
use std::ffi::{c_char, c_uchar, c_int, c_ulong, CString};
use std::mem;
use std::ptr;
use std::slice;

/// Represents supported RSA key sizes in bits.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096,
}

impl RsaKeySize {
    /// Convert to rsa::pkcs1::RsaKeySize
    fn to_rsa_key_size(self) -> rsa::pkcs1::RsaKeySize {
        match self {
            RsaKeySize::Bits2048 => rsa::pkcs1::RsaKeySize::rsa2048,
            RsaKeySize::Bits3072 => rsa::pkcs1::RsaKeySize::rsa3072,
            RsaKeySize::Bits4096 => rsa::pkcs1::RsaKeySize::rsa4096,
        }
    }
}

/// Internal RSA public key representation for FFI.
#[repr(C)]
pub struct CxaRsaPublicKey {
    data: *mut u8,
    length: usize,
    _phantom: std::marker::PhantomData<()>,
}

/// Internal RSA private key representation for FFI.
#[repr(C)]
pub struct CxaRsaPrivateKey {
    data: *mut u8,
    length: usize,
    _phantom: std::marker::PhantomData<()>,
}

/// Result structure for RSA operations.
#[repr(C)]
pub struct CxaRsaResult {
    success: c_int,
    error_code: c_int,
    error_message: *mut c_char,
    data: *mut c_uchar,
    data_length: usize,
}

/// Represents an RSA public key with its DER encoding.
#[derive(Debug, Clone)]
pub struct RsaPublicKeyData {
    pub der: Vec<u8>,
}

/// Represents an RSA private key with its DER encoding.
#[derive(Debug, Clone)]
pub struct RsaPrivateKeyData {
    pub der: Vec<u8>,
    // Note: We don't store the actual key object to allow secure wiping
}

impl Drop for RsaPrivateKeyData {
    fn drop(&mut self) {
        // Securely wipe private key data when dropped
        unsafe {
            secure_wipe(self.der.as_mut_ptr(), self.der.len());
        }
    }
}

/// Generate a new RSA key pair with the specified key size.
///
/// # Arguments
///
/// * `key_size` - The desired key size in bits
///
/// # Returns
///
/// Returns a tuple of (public_key, private_key) on success, or a CxaError on failure.
pub fn cxa_rsa_generate_keypair(
    key_size: RsaKeySize,
) -> CxaResult<(RsaPublicKeyData, RsaPrivateKeyData)> {
    let mut rng = rand::thread_rng();
    let rsa_key_size = key_size.to_rsa_key_size();

    let private_key = rsa::RsaPrivateKey::new(&mut rng, rsa_key_size.num_bits())
        .map_err(|e| CxaError::key_generation_failed(format!("RSA key generation: {}", e)))?;

    let public_key = private_key.to_public_key();

    // Export keys to DER format
    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|e| CxaError::key_generation_failed(format!("Private key export: {}", e)))?;

    let public_der = public_key
        .to_public_key_der()
        .map_err(|e| CxaError::key_generation_failed(format!("Public key export: {}", e)))?;

    Ok((
        RsaPublicKeyData {
            der: public_der.as_bytes().to_vec(),
        },
        RsaPrivateKeyData {
            der: private_der.as_bytes().to_vec(),
        },
    ))
}

/// Encrypt data using RSA with OAEP-SHA256 padding.
///
/// This function encrypts plaintext using the provided RSA public key.
/// The plaintext must be shorter than the key size minus the OAEP padding overhead.
///
/// # Arguments
///
/// * `public_key` - The RSA public key data (DER format)
/// * `plaintext` - The data to encrypt
///
/// # Returns
///
/// Returns encrypted ciphertext on success, or a CxaError on failure.
pub fn cxa_rsa_encrypt(
    public_key: &RsaPublicKeyData,
    plaintext: &[u8],
) -> CxaResult<Vec<u8>> {
    let public_key = rsa::RsaPublicKey::from_public_key_der(&public_key.der)
        .map_err(|e| CxaError::encryption_failed(format!("Invalid public key: {}", e)))?;

    // Use OAEP-SHA256 for padding
    let padding = rsa::Oaep::new::<sha2::Sha256>();

    // Check plaintext size against key size
    let max_plaintext_size = (public_key.size() - 2 * 32 - 2) as usize;
    if plaintext.len() > max_plaintext_size {
        return Err(CxaError::encryption_failed(format!(
            "Plaintext too long. Maximum size: {} bytes, got: {} bytes",
            max_plaintext_size,
            plaintext.len()
        )));
    }

    let ciphertext = public_key
        .encrypt(&mut rand::thread_rng(), padding, plaintext)
        .map_err(|e| CxaError::encryption_failed(format!("RSA encryption: {}", e)))?;

    Ok(ciphertext)
}

/// Decrypt data using RSA with OAEP-SHA256 padding.
///
/// # Arguments
///
/// * `private_key` - The RSA private key data (DER format)
/// * `ciphertext` - The encrypted data to decrypt
///
/// # Returns
///
/// Returns decrypted plaintext on success, or a CxaError on failure.
pub fn cxa_rsa_decrypt(
    private_key: &RsaPrivateKeyData,
    ciphertext: &[u8],
) -> CxaResult<Vec<u8>> {
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.der)
        .map_err(|e| CxaError::decryption_failed(format!("Invalid private key: {}", e)))?;

    let public_key = private_key.to_public_key();

    // Validate ciphertext size
    if ciphertext.len() != public_key.size() as usize {
        return Err(CxaError::decryption_failed(format!(
            "Invalid ciphertext length. Expected: {} bytes, got: {} bytes",
            public_key.size(),
            ciphertext.len()
        )));
    }

    // Use OAEP-SHA256 for padding (same as encryption)
    let padding = rsa::Oaep::new::<sha2::Sha256>();

    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|e| CxaError::decryption_failed(format!("RSA decryption: {}", e)))?;

    Ok(plaintext)
}

/// Sign data using RSA with PSS-SHA256 padding.
///
/// This function creates a digital signature for the provided data.
///
/// # Arguments
///
/// * `private_key` - The RSA private key data (DER format)
/// * `data` - The data to sign
///
/// # Returns
///
/// Returns the digital signature on success, or a CxaError on failure.
pub fn cxa_rsa_sign(
    private_key: &RsaPrivateKeyData,
    data: &[u8],
) -> CxaResult<Vec<u8>> {
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.der)
        .map_err(|e| CxaError::signature_failed(format!("Invalid private key: {}", e)))?;

    let padding = rsa::pss::Pss::new::<sha2::Sha256>();
    let signature = private_key
        .sign(&mut rand::thread_rng(), padding, data)
        .map_err(|e| CxaError::signature_failed(format!("RSA signing: {}", e)))?;

    Ok(signature)
}

/// Verify an RSA digital signature.
///
/// # Arguments
///
/// * `public_key` - The RSA public key data (DER format)
/// * `data` - The original signed data
/// * `signature` - The signature to verify
///
/// # Returns
///
/// Returns Ok(()) if signature is valid, or a CxaError if verification fails.
pub fn cxa_rsa_verify(
    public_key: &RsaPublicKeyData,
    data: &[u8],
    signature: &[u8],
) -> CxaResult<()> {
    let public_key = rsa::RsaPublicKey::from_public_key_der(&public_key.der)
        .map_err(|e| CxaError::signature_failed(format!("Invalid public key: {}", e)))?;

    let padding = rsa::pss::Pss::new::<sha2::Sha256>();

    public_key
        .verify(padding, data, signature)
        .map_err(|e| CxaError::signature_failed(format!("Signature verification: {}", e)))
}

/// Export public key to PEM format.
///
/// # Arguments
///
/// * `public_key` - The RSA public key data
///
/// # Returns
///
/// Returns PEM-formatted public key string.
pub fn cxa_rsa_public_key_to_pem(public_key: &RsaPublicKeyData) -> CxaResult<String> {
    let public_key = rsa::RsaPublicKey::from_public_key_der(&public_key.der)
        .map_err(|e| CxaError::key_operation_failed(format!("Invalid public key: {}", e)))?;

    let pem = public_key
        .to_pem(rsa::pkcs1::LineEnding::LF)
        .ok_or_else(|| CxaError::key_operation_failed("Failed to export public key to PEM".into()))?;

    Ok(pem)
}

/// Export private key to PEM format.
///
/// # Arguments
///
/// * `private_key` - The RSA private key data
///
/// # Returns
///
/// Returns PEM-formatted private key string.
pub fn cxa_rsa_private_key_to_pem(private_key: &RsaPrivateKeyData) -> CxaResult<String> {
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.der)
        .map_err(|e| CxaError::key_operation_failed(format!("Invalid private key: {}", e)))?;

    let pem = private_key
        .to_pem(rsa::pkcs1::LineEnding::LF)
        .ok_or_else(|| CxaError::key_operation_failed("Failed to export private key to PEM".into()))?;

    Ok(pem)
}

// ============================================================================
// FFI-safe wrapper functions
// ============================================================================

/// Allocate a new CxaRsaResult structure.
#[no_mangle]
pub extern "C" fn cxa_rsa_result_new() -> *mut CxaRsaResult {
    Box::into_raw(Box::new(CxaRsaResult {
        success: 0,
        error_code: 0,
        error_message: ptr::null_mut(),
        data: ptr::null_mut(),
        data_length: 0,
    }))
}

/// Free a CxaRsaResult structure.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_result_free(result: *mut CxaRsaResult) {
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

/// Generate a new RSA key pair (FFI-compatible).
///
/// # Arguments
///
/// * `key_size` - The key size (2048, 3072, or 4096)
/// * `out_public_key` - Output pointer for public key
/// * `out_private_key` - Output pointer for private key
///
/// # Returns
///
/// CxaRsaResult with key data or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_generate_keypair_ffi(
    key_size: c_int,
) -> *mut CxaRsaResult {
    let result = cxa_rsa_result_new();
    let result = &mut *result;

    let key_size = match key_size {
        2048 => RsaKeySize::Bits2048,
        3072 => RsaKeySize::Bits3072,
        4096 => RsaKeySize::Bits4096,
        _ => {
            result.error_code = -1;
            result.error_message = CString::new("Invalid key size. Use 2048, 3072, or 4096.")
                .unwrap()
                .into_raw();
            return result;
        }
    };

    match cxa_rsa_generate_keypair(key_size) {
        Ok((public_key, private_key)) => {
            result.success = 1;

            // Copy public key data
            let pub_len = public_key.der.len();
            let pub_ptr = libc::malloc(pub_len) as *mut u8;
            ptr::copy(public_key.der.as_ptr(), pub_ptr, pub_len);

            // Copy private key data
            let priv_len = private_key.der.len();
            let priv_ptr = libc::malloc(priv_len) as *mut u8;
            ptr::copy(private_key.der.as_ptr(), priv_ptr, priv_len);

            // Store as single buffer: [pub_len: 4 bytes][pub_data][priv_len: 4 bytes][priv_data]
            let total_len = 4 + pub_len + 4 + priv_len;
            let total_ptr = libc::malloc(total_len) as *mut u8;

            total_ptr.write(pub_len as u32);
            ptr::copy(pub_ptr, total_ptr.add(4), pub_len);
            (total_ptr.add(4 + pub_len) as *mut u32).write(priv_len as u32);
            ptr::copy(priv_ptr, total_ptr.add(4 + pub_len + 4), priv_len);

            libc::free(pub_ptr as *mut libc::c_void);
            libc::free(priv_ptr as *mut libc::c_void);

            result.data = total_ptr as *mut c_uchar;
            result.data_length = total_len;
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Encrypt data using RSA (FFI-compatible).
///
/// # Arguments
///
/// * `public_key_data` - Public key data buffer
/// * `public_key_len` - Length of public key data
/// * `plaintext` - Plaintext data to encrypt
/// * `plaintext_len` - Length of plaintext
/// * `out_ciphertext` - Output buffer for ciphertext
/// * `out_ciphertext_len` - Pointer to store ciphertext length
///
/// # Returns
///
/// CxaRsaResult with ciphertext or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_encrypt_ffi(
    public_key_data: *const c_uchar,
    public_key_len: usize,
    plaintext: *const c_uchar,
    plaintext_len: usize,
) -> *mut CxaRsaResult {
    let result = cxa_rsa_result_new();
    let result = &mut *result;

    if public_key_data.is_null() || plaintext.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let key_data = slice::from_raw_parts(public_key_data, public_key_len);
    let plain_data = slice::from_raw_parts(plaintext, plaintext_len);

    let public_key = RsaPublicKeyData {
        der: key_data.to_vec(),
    };

    match cxa_rsa_encrypt(&public_key, plain_data) {
        Ok(ciphertext) => {
            result.success = 1;
            let cipher_ptr = libc::malloc(ciphertext.len()) as *mut u8;
            ptr::copy(ciphertext.as_ptr(), cipher_ptr, ciphertext.len());
            result.data = cipher_ptr as *mut c_uchar;
            result.data_length = ciphertext.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Decrypt data using RSA (FFI-compatible).
///
/// # Arguments
///
/// * `private_key_data` - Private key data buffer
/// * `private_key_len` - Length of private key data
/// * `ciphertext` - Ciphertext data to decrypt
/// * `ciphertext_len` - Length of ciphertext
///
/// # Returns
///
/// CxaRsaResult with plaintext or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_decrypt_ffi(
    private_key_data: *const c_uchar,
    private_key_len: usize,
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
) -> *mut CxaRsaResult {
    let result = cxa_rsa_result_new();
    let result = &mut *result;

    if private_key_data.is_null() || ciphertext.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let key_data = slice::from_raw_parts(private_key_data, private_key_len);
    let cipher_data = slice::from_raw_parts(ciphertext, ciphertext_len);

    let private_key = RsaPrivateKeyData {
        der: key_data.to_vec(),
    };

    match cxa_rsa_decrypt(&private_key, cipher_data) {
        Ok(plaintext) => {
            result.success = 1;
            let plain_ptr = libc::malloc(plaintext.len()) as *mut u8;
            ptr::copy(plaintext.as_ptr(), plain_ptr, plaintext.len());
            result.data = plain_ptr as *mut c_uchar;
            result.data_length = plaintext.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Sign data using RSA (FFI-compatible).
///
/// # Arguments
///
/// * `private_key_data` - Private key data buffer
/// * `private_key_len` - Length of private key data
/// * `data` - Data to sign
/// * `data_len` - Length of data
///
/// # Returns
///
/// CxaRsaResult with signature or error information.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_sign_ffi(
    private_key_data: *const c_uchar,
    private_key_len: usize,
    data: *const c_uchar,
    data_len: usize,
) -> *mut CxaRsaResult {
    let result = cxa_rsa_result_new();
    let result = &mut *result;

    if private_key_data.is_null() || data.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let key_data = slice::from_raw_parts(private_key_data, private_key_len);
    let data_slice = slice::from_raw_parts(data, data_len);

    let private_key = RsaPrivateKeyData {
        der: key_data.to_vec(),
    };

    match cxa_rsa_sign(&private_key, data_slice) {
        Ok(signature) => {
            result.success = 1;
            let sig_ptr = libc::malloc(signature.len()) as *mut u8;
            ptr::copy(signature.as_ptr(), sig_ptr, signature.len());
            result.data = sig_ptr as *mut c_uchar;
            result.data_length = signature.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Verify RSA signature (FFI-compatible).
///
/// # Arguments
///
/// * `public_key_data` - Public key data buffer
/// * `public_key_len` - Length of public key data
/// * `data` - Original signed data
/// * `data_len` - Length of data
/// * `signature` - Signature to verify
/// * `signature_len` - Length of signature
///
/// # Returns
///
/// CxaRsaResult with success (1) or failure (0) indicator.
#[no_mangle]
pub unsafe extern "C" fn cxa_rsa_verify_ffi(
    public_key_data: *const c_uchar,
    public_key_len: usize,
    data: *const c_uchar,
    data_len: usize,
    signature: *const c_uchar,
    signature_len: usize,
) -> *mut CxaRsaResult {
    let result = cxa_rsa_result_new();
    let result = &mut *result;

    if public_key_data.is_null() || data.is_null() || signature.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let key_data = slice::from_raw_parts(public_key_data, public_key_len);
    let data_slice = slice::from_raw_parts(data, data_len);
    let sig_slice = slice::from_raw_parts(signature, signature_len);

    let public_key = RsaPublicKeyData {
        der: key_data.to_vec(),
    };

    match cxa_rsa_verify(&public_key, data_slice, sig_slice) {
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

/// Get the RSA key size in bytes (for encryption buffer allocation).
///
/// # Arguments
///
/// * `key_size` - Key size in bits (2048, 3072, 4096)
///
/// # Returns
///
/// Size of encrypted data in bytes.
#[no_mangle]
pub extern "C" fn cxa_rsa_ciphertext_size(key_size: c_int) -> c_ulong {
    match key_size {
        2048 => 256,
        3072 => 384,
        4096 => 512,
        _ => 0,
    }
}

/// Get the RSA signature size for a given key size.
///
/// # Arguments
///
/// * `key_size` - Key size in bits (2048, 3072, 4096)
///
/// # Returns
///
/// Size of signature in bytes.
#[no_mangle]
pub extern "C" fn cxa_rsa_signature_size(key_size: c_int) -> c_ulong {
    cxa_rsa_ciphertext_size(key_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let (public_key, private_key) = cxa_rsa_generate_keypair(RsaKeySize::Bits2048).unwrap();
        assert!(!public_key.der.is_empty());
        assert!(!private_key.der.is_empty());
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let (_, private_key) = cxa_rsa_generate_keypair(RsaKeySize::Bits2048).unwrap();
        let public_key = RsaPublicKeyData {
            der: vec![], // Will be extracted from private key for test
        };

        // Extract public key from private key for testing
        let rsa_private = rsa::RsaPrivateKey::from_pkcs8_der(&private_key.der).unwrap();
        let public_der = rsa_private.to_public_key().to_public_key_der().unwrap();
        let public_key = RsaPublicKeyData {
            der: public_der.as_bytes().to_vec(),
        };

        let plaintext = b"Hello, RSA encryption!";
        let ciphertext = cxa_rsa_encrypt(&public_key, plaintext).unwrap();
        let decrypted = cxa_rsa_decrypt(&private_key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_rsa_sign_verify() {
        let (public_key, private_key) = cxa_rsa_generate_keypair(RsaKeySize::Bits2048).unwrap();
        let data = b"Data to sign";

        let signature = cxa_rsa_sign(&private_key, data).unwrap();
        assert!(cxa_rsa_verify(&public_key, data, &signature).is_ok());
    }

    #[test]
    fn test_rsa_invalid_verification() {
        let (public_key, private_key) = cxa_rsa_generate_keypair(RsaKeySize::Bits2048).unwrap();
        let data = b"Data to sign";
        let wrong_data = b"Tampered data";

        let signature = cxa_rsa_sign(&private_key, data).unwrap();
        assert!(cxa_rsa_verify(&public_key, wrong_data, &signature).is_err());
    }

    #[test]
    fn test_rsa_pem_export() {
        let (public_key, private_key) = cxa_rsa_generate_keypair(RsaKeySize::Bits2048).unwrap();

        let public_pem = cxa_rsa_public_key_to_pem(&public_key).unwrap();
        assert!(public_pem.contains("-----BEGIN RSA PUBLIC KEY-----"));

        let private_pem = cxa_rsa_private_key_to_pem(&private_key).unwrap();
        assert!(private_pem.contains("-----BEGIN RSA PRIVATE KEY-----"));
    }
}
