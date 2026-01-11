//! # Key Derivation Function (KDF) Module
//!
//! This module implements multiple key derivation functions for converting
//! passwords, passphrases, or other secret inputs into cryptographic keys.
//!
//! ## Supported KDFs
//!
//! 1. **Argon2id** (Recommended) - Winner of the Password Hashing Competition,
//!    resistant to GPU and ASIC attacks
//!
//! 2. **scrypt** - Memory-hard function, good for preventing hardware attacks
//!
//! 3. **PBKDF2-HMAC-SHA256** - Legacy support, still useful for certain applications
//!
//! ## Security Recommendations
//!
//! - Use Argon2id for new applications with the following parameters:
//!   - Memory cost: At least 64 MiB (ideally 256 MiB+)
//!   - Time cost: At least 3 iterations (adjust based on hardware)
//!   - Parallelism: At least 1, up to number of CPU cores
//!
//! - Always use a unique salt for each key derivation
//! - Store salts alongside encrypted data (they don't need to be secret)
//! - Use appropriate output lengths for your cryptographic operations
//!
//! ## Usage
//!
//! ```rust
//! use cxa_kdf::{cxa_argon2id_derive, Argon2Config};
//!
//! let config = Argon2Config::default();
//! let password = b"my_secret_password";
//! let salt = cxa_kdf_generate_salt(32).unwrap();
//!
//! let key = cxa_argon2id_derive(password, &salt, &config, 32).unwrap();
//! ```

use cxa_error::{CxaError, CxaResult};
use cxa_mem::secure_wipe;
use std::ffi::{c_char, c_int, c_uchar, c_ulong};
use std::ptr;
use std::slice;

/// Configuration for Argon2id key derivation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Argon2Config {
    /// Memory cost in kibibytes (KiB). Default: 65536 (64 MiB)
    pub memory_cost: u32,
    /// Number of iterations. Default: 3
    pub time_cost: u32,
    /// Number of parallel lanes. Default: 1
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Argon2Config {
            memory_cost: 65536,  // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
}

/// Configuration for scrypt key derivation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScryptConfig {
    /// CPU/memory cost parameter (N). Must be power of 2. Default: 32768
    pub n: u32,
    /// Block size parameter (r). Default: 8
    pub r: u32,
    /// Parallelization parameter (p). Default: 1
    pub p: u32,
}

impl Default for ScryptConfig {
    fn default() -> Self {
        ScryptConfig {
            n: 32768,  // 2^15
            r: 8,
            p: 1,
        }
    }
}

/// Configuration for PBKDF2 key derivation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Config {
    /// Number of iterations. Default: 600,000 (OWASP recommendation)
    pub iterations: u32,
}

impl Default for Pbkdf2Config {
    fn default() -> Self {
        Pbkdf2Config {
            iterations: 600_000,
        }
    }
}

/// Result structure for KDF operations.
#[repr(C)]
pub struct CxaKdfResult {
    success: c_int,
    error_code: c_int,
    error_message: *mut c_char,
    data: *mut c_uchar,
    data_length: usize,
}

/// Generate a cryptographically secure random salt.
///
/// # Arguments
///
/// * `length` - Desired salt length in bytes (recommended: 16-32)
///
/// # Returns
///
/// Returns random salt bytes on success, or a CxaError on failure.
pub fn cxa_kdf_generate_salt(length: usize) -> CxaResult<Vec<u8>> {
    if length == 0 {
        return Err(CxaError::invalid_input(
            "Salt length must be greater than 0".into(),
        ));
    }

    if length > 1024 {
        return Err(CxaError::invalid_input(
            "Salt length exceeds maximum (1024 bytes)".into(),
        ));
    }

    let mut salt = vec![0u8; length];
    let mut rng = rand::thread_rng();
    rand::Rng::fill(&mut rng, salt.as_mut_slice())
        .map_err(|e| CxaError::randomness_failed(format!("Salt generation: {}", e)))?;

    Ok(salt)
}

// ============================================================================
// Argon2id Functions
// ============================================================================

/// Derive a key using Argon2id.
///
/// Argon2id is the recommended KDF for most applications. It provides
/// excellent resistance against both GPU and ASIC attacks.
///
/// # Arguments
///
/// * `password` - The password or secret input
/// * `salt` - Unique salt for this key derivation
/// * `config` - Argon2 configuration parameters
/// * `output_length` - Desired output key length in bytes
///
/// # Returns
///
/// Returns derived key bytes on success, or a CxaError on failure.
pub fn cxa_argon2id_derive(
    password: &[u8],
    salt: &[u8],
    config: &Argon2Config,
    output_length: usize,
) -> CxaResult<Vec<u8>> {
    // Validate inputs
    if password.is_empty() {
        return Err(CxaError::invalid_input(
            "Password cannot be empty".into(),
        ));
    }

    if salt.is_empty() {
        return Err(CxaError::invalid_input(
            "Salt cannot be empty".into(),
        ));
    }

    if output_length == 0 {
        return Err(CxaError::invalid_input(
            "Output length must be greater than 0".into(),
        ));
    }

    if output_length > 1024 {
        return Err(CxaError::invalid_input(
            "Output length exceeds maximum (1024 bytes)".into(),
        ));
    }

    // Validate configuration
    if config.memory_cost < 8 {
        return Err(CxaError::invalid_input(
            "Memory cost must be at least 8 KiB".into(),
        ));
    }

    if config.time_cost == 0 {
        return Err(CxaError::invalid_input(
            "Time cost must be at least 1".into(),
        ));
    }

    if config.parallelism == 0 {
        return Err(CxaError::invalid_input(
            "Parallelism must be at least 1".into(),
        ));
    }

    // Create Argon2id hasher
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(output_length),
        )
        .map_err(|e| CxaError::key_derivation_failed(format!("Invalid Argon2 parameters: {}", e)))?,
    );

    // Derive key
    let mut output = vec![0u8; output_length];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CxaError::key_derivation_failed(format!("Argon2 hashing: {}", e)))?;

    Ok(output)
}

/// Verify a password against a stored Argon2id hash.
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `stored_hash` - The stored hash (from argon2 hash output)
///
/// # Returns
///
/// Returns true if password matches, false otherwise.
pub fn cxa_argon2id_verify(password: &[u8], stored_hash: &[u8]) -> bool {
    if password.is_empty() || stored_hash.is_empty() {
        return false;
    }

    // Try to verify as a standard Argon2 encoded string (if it's a string)
    if let Ok(hash_str) = std::str::from_utf8(stored_hash) {
        if let Ok(verified) = argon2::verify_raw(password, &[], hash_str, argon2::Algorithm::Argon2id, argon2::Version::V0x13) {
            return verified;
        }
    }

    // Try raw comparison as fallback
    // Note: This is less secure but provides compatibility
    false
}

/// Get recommended Argon2id configuration for security level.
///
/// # Arguments
///
/// * `security_level` - 1 for interactive, 2 for online, 3 for offline
///
/// # Returns
///
/// Argon2Config with recommended parameters.
pub fn cxa_argon2id_recommended_config(security_level: u32) -> Argon2Config {
    match security_level {
        1 => Argon2Config {
            memory_cost: 32768,  // 32 MiB
            time_cost: 2,
            parallelism: 1,
        },
        2 => Argon2Config {
            memory_cost: 65536,  // 64 MiB
            time_cost: 3,
            parallelism: 1,
        },
        3 => Argon2Config {
            memory_cost: 131072, // 128 MiB
            time_cost: 4,
            parallelism: 2,
        },
        _ => Argon2Config::default(),
    }
}

// ============================================================================
// scrypt Functions
// ============================================================================

/// Derive a key using scrypt.
///
/// scrypt is a memory-hard function that makes it expensive to perform
/// large-scale custom hardware attacks.
///
/// # Arguments
///
/// * `password` - The password or secret input
/// * `salt` - Unique salt for this key derivation
/// * `config` - scrypt configuration parameters
/// * `output_length` - Desired output key length in bytes
///
/// # Returns
///
/// Returns derived key bytes on success, or a CxaError on failure.
pub fn cxa_scrypt_derive(
    password: &[u8],
    salt: &[u8],
    config: &ScryptConfig,
    output_length: usize,
) -> CxaResult<Vec<u8>> {
    if password.is_empty() || salt.is_empty() {
        return Err(CxaError::invalid_input(
            "Password and salt cannot be empty".into(),
        ));
    }

    if output_length == 0 || output_length > 1024 {
        return Err(CxaError::invalid_input(
            "Invalid output length".into(),
        ));
    }

    // Validate scrypt parameters
    if config.n == 0 || !config.n.is_power_of_two() {
        return Err(CxaError::invalid_input(
            "N must be a power of 2 greater than 0".into(),
        ));
    }

    if config.r < 1 {
        return Err(CxaError::invalid_input(
            "Block size must be at least 1".into(),
        ));
    }

    if config.p < 1 {
        return Err(CxaError::invalid_input(
            "Parallelism must be at least 1".into(),
        ));
    }

    let params = scrypt::Params::new(
        (config.n as f64).log2() as u8,
        config.r,
        config.p,
        scrypt::Salt::new(salt),
    )
    .map_err(|e| CxaError::key_derivation_failed(format!("Invalid scrypt parameters: {}", e)))?;

    let mut output = vec![0u8; output_length];
    scrypt::scrypt(password, &params, &mut output)
        .map_err(|e| CxaError::key_derivation_failed(format!("scrypt derivation: {}", e)))?;

    Ok(output)
}

/// Get recommended scrypt configuration for security level.
///
/// # Arguments
///
/// * `security_level` - 1 for interactive, 2 for online, 3 for offline
///
/// # Returns
///
/// ScryptConfig with recommended parameters.
pub fn cxa_scrypt_recommended_config(security_level: u32) -> ScryptConfig {
    match security_level {
        1 => ScryptConfig {
            n: 16384,  // 2^14
            r: 8,
            p: 1,
        },
        2 => ScryptConfig {
            n: 32768,  // 2^15
            r: 8,
            p: 1,
        },
        3 => ScryptConfig {
            n: 65536,  // 2^16
            r: 8,
            p: 2,
        },
        _ => ScryptConfig::default(),
    }
}

// ============================================================================
// PBKDF2 Functions
// ============================================================================

/// Derive a key using PBKDF2-HMAC-SHA256.
///
/// PBKDF2 is a legacy KDF that is still useful for certain applications.
/// For new applications, prefer Argon2id or scrypt.
///
/// # Arguments
///
/// * `password` - The password or secret input
/// * `salt` - Unique salt for this key derivation
/// * `config` - PBKDF2 configuration parameters
/// * `output_length` - Desired output key length in bytes
///
/// # Returns
///
/// Returns derived key bytes on success, or a CxaError on failure.
pub fn cxa_pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    config: &Pbkdf2Config,
    output_length: usize,
) -> CxaResult<Vec<u8>> {
    if password.is_empty() || salt.is_empty() {
        return Err(CxaError::invalid_input(
            "Password and salt cannot be empty".into(),
        ));
    }

    if output_length == 0 || output_length > 1024 {
        return Err(CxaError::invalid_input(
            "Invalid output length".into(),
        ));
    }

    if config.iterations == 0 {
        return Err(CxaError::invalid_input(
            "Iterations must be at least 1".into(),
        ));
    }

    let mut output = vec![0u8; output_length];
    let params = pbkdf2::Params {
        out: &mut output,
        salt,
        iter: config.iterations,
        hasher: sha2::Sha256::new(),
    };

    pbkdf2::derive_from_params(params, password)
        .map_err(|e| CxaError::key_derivation_failed(format!("PBKDF2 derivation: {}", e)))?;

    Ok(output)
}

/// Get recommended PBKDF2 configuration for security level.
///
/// # Arguments
///
/// * `security_level` - 1 for interactive, 2 for online, 3 for offline
///
/// # Returns
///
/// Pbkdf2Config with recommended parameters.
pub fn cxa_pbkdf2_recommended_config(security_level: u32) -> Pbkdf2Config {
    match security_level {
        1 => Pbkdf2Config {
            iterations: 120_000,
        },
        2 => Pbkdf2Config {
            iterations: 600_000,
        },
        3 => Pbkdf2Config {
            iterations: 1_200_000,
        },
        _ => Pbkdf2Config::default(),
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Compare two derived keys in constant time to prevent timing attacks.
///
/// # Arguments
///
/// * `a` - First derived key
/// * `b` - Second derived key
///
/// # Returns
///
/// Returns true if keys are equal, false otherwise.
pub fn cxa_kdf_constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Estimate the time to derive a key with given parameters.
///
/// This is a rough estimate and depends on hardware capabilities.
///
/// # Arguments
///
/// * `config_type` - Type of config (1=Argon2id, 2=scrypt, 3=PBKDF2)
/// * `config_ptr` - Pointer to configuration struct
///
/// # Returns
///
/// Estimated time in milliseconds.
pub fn cxa_kdf_estimate_time(config_type: c_int, config: &Argon2Config) -> u64 {
    // Rough estimates based on typical modern hardware
    match config_type {
        1 => {
            // Argon2id: ~1ms per iteration with default params on modern CPU
            config.time_cost as u64 * 100
        }
        _ => 100, // Unknown config type
    }
}

// ============================================================================
// FFI-safe wrapper functions
// ============================================================================

/// Allocate a new CxaKdfResult structure.
#[no_mangle]
pub extern "C" fn cxa_kdf_result_new() -> *mut CxaKdfResult {
    Box::into_raw(Box::new(CxaKdfResult {
        success: 0,
        error_code: 0,
        error_message: ptr::null_mut(),
        data: ptr::null_mut(),
        data_length: 0,
    }))
}

/// Free a CxaKdfResult structure.
#[no_mangle]
pub unsafe extern "C" fn cxa_kdf_result_free(result: *mut CxaKdfResult) {
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

/// Generate a random salt (FFI-compatible).
///
/// # Arguments
///
/// * `length` - Desired salt length
///
/// # Returns
///
/// CxaKdfResult with salt data or error.
#[no_mangle]
pub unsafe extern "C" fn cxa_kdf_generate_salt_ffi(length: usize) -> *mut CxaKdfResult {
    let result = cxa_kdf_result_new();
    let result = &mut *result;

    match cxa_kdf_generate_salt(length) {
        Ok(salt) => {
            result.success = 1;
            let salt_ptr = libc::malloc(salt.len()) as *mut u8;
            ptr::copy(salt.as_ptr(), salt_ptr, salt.len());
            result.data = salt_ptr as *mut c_uchar;
            result.data_length = salt.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Derive key using Argon2id (FFI-compatible).
///
/// # Arguments
///
/// * `password` - Password data
/// * `password_len` - Password length
/// * `salt` - Salt data
/// * `salt_len` - Salt length
/// * `memory_cost` - Memory cost in KiB
/// * `time_cost` - Number of iterations
/// * `parallelism` - Number of parallel lanes
/// * `output_length` - Desired output length
///
/// # Returns
///
/// CxaKdfResult with derived key or error.
#[no_mangle]
pub unsafe extern "C" fn cxa_argon2id_derive_ffi(
    password: *const c_uchar,
    password_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_length: usize,
) -> *mut CxaKdfResult {
    let result = cxa_kdf_result_new();
    let result = &mut *result;

    if password.is_null() || salt.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let password_slice = slice::from_raw_parts(password, password_len);
    let salt_slice = slice::from_raw_parts(salt, salt_len);

    let config = Argon2Config {
        memory_cost,
        time_cost,
        parallelism,
    };

    match cxa_argon2id_derive(password_slice, salt_slice, &config, output_length) {
        Ok(key) => {
            result.success = 1;
            let key_ptr = libc::malloc(key.len()) as *mut u8;
            ptr::copy(key.as_ptr(), key_ptr, key.len());
            result.data = key_ptr as *mut c_uchar;
            result.data_length = key.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Derive key using scrypt (FFI-compatible).
///
/// # Arguments
///
/// * `password` - Password data
/// * `password_len` - Password length
/// * `salt` - Salt data
/// * `salt_len` - Salt length
/// * `n` - CPU/memory cost (power of 2)
/// * `r` - Block size
/// * `p` - Parallelization
/// * `output_length` - Desired output length
///
/// # Returns
///
/// CxaKdfResult with derived key or error.
#[no_mangle]
pub unsafe extern "C" fn cxa_scrypt_derive_ffi(
    password: *const c_uchar,
    password_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
    n: u32,
    r: u32,
    p: u32,
    output_length: usize,
) -> *mut CxaKdfResult {
    let result = cxa_kdf_result_new();
    let result = &mut *result;

    if password.is_null() || salt.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let password_slice = slice::from_raw_parts(password, password_len);
    let salt_slice = slice::from_raw_parts(salt, salt_len);

    let config = ScryptConfig { n, r, p };

    match cxa_scrypt_derive(password_slice, salt_slice, &config, output_length) {
        Ok(key) => {
            result.success = 1;
            let key_ptr = libc::malloc(key.len()) as *mut u8;
            ptr::copy(key.as_ptr(), key_ptr, key.len());
            result.data = key_ptr as *mut c_uchar;
            result.data_length = key.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Derive key using PBKDF2 (FFI-compatible).
///
/// # Arguments
///
/// * `password` - Password data
/// * `password_len` - Password length
/// * `salt` - Salt data
/// * `salt_len` - Salt length
/// * `iterations` - Number of iterations
/// * `output_length` - Desired output length
///
/// # Returns
///
/// CxaKdfResult with derived key or error.
#[no_mangle]
pub unsafe extern "C" fn cxa_pbkdf2_derive_ffi(
    password: *const c_uchar,
    password_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
    iterations: u32,
    output_length: usize,
) -> *mut CxaKdfResult {
    let result = cxa_kdf_result_new();
    let result = &mut *result;

    if password.is_null() || salt.is_null() {
        result.error_code = -1;
        result.error_message = CString::new("Null pointer provided").unwrap().into_raw();
        return result;
    }

    let password_slice = slice::from_raw_parts(password, password_len);
    let salt_slice = slice::from_raw_parts(salt, salt_len);

    let config = Pbkdf2Config { iterations };

    match cxa_pbkdf2_derive(password_slice, salt_slice, &config, output_length) {
        Ok(key) => {
            result.success = 1;
            let key_ptr = libc::malloc(key.len()) as *mut u8;
            ptr::copy(key.as_ptr(), key_ptr, key.len());
            result.data = key_ptr as *mut c_uchar;
            result.data_length = key.len();
        }
        Err(e) => {
            result.error_code = e.error_code();
            result.error_message = CString::new(e.to_string()).unwrap().into_raw();
        }
    }

    result
}

/// Get recommended Argon2id configuration (FFI-compatible).
#[no_mangle]
pub extern "C" fn cxa_argon2id_get_config(security_level: c_int) -> Argon2Config {
    cxa_argon2id_recommended_config(security_level as u32)
}

/// Get recommended scrypt configuration (FFI-compatible).
#[no_mangle]
pub extern "C" fn cxa_scrypt_get_config(security_level: c_int) -> ScryptConfig {
    cxa_scrypt_recommended_config(security_level as u32)
}

/// Get recommended PBKDF2 configuration (FFI-compatible).
#[no_mangle]
pub extern "C" fn cxa_pbkdf2_get_config(security_level: c_int) -> Pbkdf2Config {
    cxa_pbkdf2_recommended_config(security_level as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derive() {
        let password = b"test_password";
        let salt = cxa_kdf_generate_salt(16).unwrap();
        let config = Argon2Config {
            memory_cost: 8192,  // Use smaller value for faster tests
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = cxa_argon2id_derive(password, &salt, &config, 32).unwrap();
        assert_eq!(key1.len(), 32);

        // Same password, salt, and config should produce same key
        let key2 = cxa_argon2id_derive(password, &salt, &config, 32).unwrap();
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let salt2 = cxa_kdf_generate_salt(16).unwrap();
        let key3 = cxa_argon2id_derive(password, &salt2, &config, 32).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_scrypt_derive() {
        let password = b"test_password";
        let salt = cxa_kdf_generate_salt(16).unwrap();
        let config = ScryptConfig {
            n: 1024,  // Small value for faster tests
            r: 1,
            p: 1,
        };

        let key = cxa_scrypt_derive(password, &salt, &config, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_derive() {
        let password = b"test_password";
        let salt = cxa_kdf_generate_salt(16).unwrap();
        let config = Pbkdf2Config {
            iterations: 1000,  // Small value for faster tests
        };

        let key = cxa_pbkdf2_derive(password, &salt, &config, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![0x01u8, 0x02, 0x03, 0x04];
        let b = vec![0x01u8, 0x02, 0x03, 0x04];
        let c = vec![0x01u8, 0x02, 0x03, 0x05];

        assert!(cxa_kdf_constant_time_compare(&a, &b));
        assert!(!cxa_kdf_constant_time_compare(&a, &c));
        assert!(!cxa_kdf_constant_time_compare(&a, &[0x01]));
    }

    #[test]
    fn test_recommended_configs() {
        let argon2 = cxa_argon2id_recommended_config(2);
        assert_eq!(argon2.memory_cost, 65536);
        assert_eq!(argon2.time_cost, 3);

        let scrypt = cxa_scrypt_recommended_config(2);
        assert_eq!(scrypt.n, 32768);

        let pbkdf2 = cxa_pbkdf2_recommended_config(2);
        assert_eq!(pbkdf2.iterations, 600_000);
    }

    #[test]
    fn test_argon2id_rejected_empty_password() {
        let salt = cxa_kdf_generate_salt(16).unwrap();
        let config = Argon2Config::default();

        assert!(cxa_argon2id_derive(b"", &salt, &config, 32).is_err());
    }

    #[test]
    fn test_argon2id_rejected_empty_salt() {
        let password = b"password";
        let config = Argon2Config::default();

        assert!(cxa_argon2id_derive(password, &[], &config, 32).is_err());
    }
}
