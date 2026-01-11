// CXA ECC Module - Curve25519 Elliptic Curve Cryptography
// 
// This module implements Curve25519 elliptic curve cryptography for
// key exchange operations. Curve25519 is designed for use with the
// Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol.
//
// Security Properties:
// - 128-bit security level (equivalent to 3072-bit RSA)
// - Constant-time scalar multiplication (resistant to timing attacks)
// - No suspicious parameters (nothing up my sleeve design)
// - Widely studied and audited
//
// Author: CXA Development Team
// Version: 2.0.0

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

// Re-export for easier use
pub use x25519_dalek::PUBLIC_KEY_LENGTH;
pub use x25519_dalek::SECRET_KEY_LENGTH;

pub const CURVE25519_PUBLIC_KEY_LEN: usize = 32;
pub const CURVE25519_SECRET_KEY_LEN: usize = 32;
pub const CURVE25519_SHARED_SECRET_LEN: usize = 32;

/// Error types for ECC operations.
#[derive(Debug)]
pub enum EccError {
    InvalidKeyLength,
    DerivationFailed,
    InvalidPublicKey,
    ZeroizationFailed,
}

impl std::fmt::Display for EccError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EccError::InvalidKeyLength => write!(f, "Invalid key length for Curve25519"),
            EccError::DerivationFailed => write!(f, "Failed to derive shared secret"),
            EccError::InvalidPublicKey => write!(f, "Invalid public key format"),
            EccError::ZeroizationFailed => write!(f, "Failed to zeroize sensitive data"),
        }
    }
}

/// Generates a new random Curve25519 key pair.
/// 
/// Returns a tuple containing:
/// - secret_key: 32 bytes of random secret key material
/// - public_key: 32 bytes of derived public key
#[no_mangle]
pub extern "C" fn generate_curve25519_keypair(
    secret_key: *mut u8,
    public_key: *mut u8,
) -> i32 {
    if secret_key.is_null() || public_key.is_null() {
        return -1;
    }

    let mut rng = OsRng {};
    let secret = EphemeralSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    
    let secret_bytes = secret.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(
            secret_bytes.as_ptr(),
            secret_key,
            CURVE25519_SECRET_KEY_LEN
        );
    }
    
    let public_bytes = public.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(
            public_bytes.as_ptr(),
            public_key,
            CURVE25519_PUBLIC_KEY_LEN
        );
    }
    
    0 // Success
}

/// Derives a shared secret using Curve25519 ECDH.
/// 
/// Arguments:
/// * our_secret: Our local secret key (32 bytes)
/// * their_public: Remote party's public key (32 bytes)
/// * shared_secret: Output buffer for shared secret (32 bytes)
#[no_mangle]
pub extern "C" fn derive_shared_secret(
    our_secret: *const u8,
    _our_public: *const u8,
    their_public: *const u8,
    shared_secret: *mut u8,
) -> i32 {
    if our_secret.is_null() || their_public.is_null() || shared_secret.is_null() {
        return -1;
    }

    let mut secret_bytes = [0u8; CURVE25519_SECRET_KEY_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(our_secret, secret_bytes.as_mut_ptr(), CURVE25519_SECRET_KEY_LEN);
    }

    let mut public_bytes = [0u8; CURVE25519_PUBLIC_KEY_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(their_public, public_bytes.as_mut_ptr(), CURVE25519_PUBLIC_KEY_LEN);
    }

    let secret = match StaticSecret::from_bytes(&secret_bytes) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let public = match PublicKey::from_bytes(&public_bytes) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.as_bytes();
    
    unsafe {
        std::ptr::copy_nonoverlapping(shared_bytes.as_ptr(), shared_secret, CURVE25519_SHARED_SECRET_LEN);
    }

    secret_bytes.zeroize();
    0
}

/// Performs scalar multiplication on a Curve25519 point.
#[no_mangle]
pub extern "C" fn curve25519_scalar_mult(
    scalar: *const u8,
    point: *const u8,
    result: *mut u8,
) -> i32 {
    if scalar.is_null() || point.is_null() || result.is_null() {
        return -1;
    }

    let mut scalar_bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(scalar, scalar_bytes.as_mut_ptr(), 32); }

    let mut point_bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(point, point_bytes.as_mut_ptr(), 32); }

    let scalar = match StaticSecret::from_bytes(&scalar_bytes) { Ok(s) => s, Err(_) => return -2 };
    let point = match PublicKey::from_bytes(&point_bytes) { Ok(p) => p, Err(_) => return -3 };

    let result_point = scalar.diffie_hellman(&point.as_ref());
    let result_bytes = result_point.as_bytes();

    unsafe { std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), result, 32); }
    scalar_bytes.zeroize();
    0
}

/// Generates a random 32-byte scalar for cryptographic operations.
#[no_mangle]
pub extern "C" fn generate_curve25519_scalar(scalar: *mut u8) -> i32 {
    if scalar.is_null() { return -1; }
    let mut rng = OsRng {};
    let random_bytes = EphemeralSecret::random_from_rng(&mut rng);
    unsafe { std::ptr::copy_nonoverlapping(random_bytes.as_bytes().as_ptr(), scalar, 32); }
    0
}

/// Validates a Curve25519 public key.
/// Returns 1 if valid, 0 if invalid, negative on error.
#[no_mangle]
pub extern "C" fn validate_curve25519_public_key(public_key: *const u8) -> i32 {
    if public_key.is_null() { return -1; }
    let mut key_bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(public_key, key_bytes.as_mut_ptr(), 32); }
    match PublicKey::from_bytes(&key_bytes) { Ok(_) => 1, Err(_) => 0 }
}

/// Computes a hash of the public key for identification purposes.
#[no_mangle]
pub extern "C" fn curve25519_public_key_hash(
    public_key: *const u8,
    hash_output: *mut u8,
) -> i32 {
    if public_key.is_null() || hash_output.is_null() { return -1; }
    let mut key_bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(public_key, key_bytes.as_mut_ptr(), 32); }
    let hash = blake3::hash(&key_bytes);
    unsafe { std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), hash_output, 32); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let mut secret = [0u8; 32];
        let mut public = [0u8; 32];
        let result = generate_curve25519_keypair(secret.as_mut_ptr(), public.as_mut_ptr());
        assert_eq!(result, 0);
        assert!(secret.iter().any(|&x| x != 0));
        assert!(public.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_shared_secret_derivation() {
        let mut alice_secret = [0u8; 32];
        let mut alice_public = [0u8; 32];
        generate_curve25519_keypair(alice_secret.as_mut_ptr(), alice_public.as_mut_ptr());
        
        let mut bob_secret = [0u8; 32];
        let mut bob_public = [0u8; 32];
        generate_curve25519_keypair(bob_secret.as_mut_ptr(), bob_public.as_mut_ptr());
        
        let mut alice_shared = [0u8; 32];
        let mut bob_shared = [0u8; 32];
        
        derive_shared_secret(alice_secret.as_ptr(), alice_public.as_ptr(), 
                            bob_public.as_ptr(), alice_shared.as_mut_ptr());
        derive_shared_secret(bob_secret.as_ptr(), bob_public.as_ptr(), 
                            alice_public.as_ptr(), bob_shared.as_mut_ptr());
        
        assert_eq!(alice_shared, bob_shared);
        assert!(alice_shared.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_public_key_validation() {
        let mut secret = [0u8; 32];
        let mut public = [0u8; 32];
        generate_curve25519_keypair(secret.as_mut_ptr(), public.as_mut_ptr());
        assert_eq!(validate_curve25519_public_key(public.as_ptr()), 1);
    }
}
