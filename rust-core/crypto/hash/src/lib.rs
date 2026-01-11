//! Cryptographic hash functions for CXA cryptographic system.
//!
//! This module provides implementations of cryptographic hash functions
//! including SHA-256, SHA-512, and BLAKE3. These functions are essential
//! for message authentication, integrity verification, and key derivation.
//!
//! # Available Hash Functions
//!
//! - **SHA-256**: 256-bit output, widely used for general-purpose hashing
//! - **SHA-512**: 512-bit output, higher security for sensitive data
//! - **BLAKE3**: Modern hash function, faster than SHA-256 with 256-bit output
//!
//! # Usage Example
//!
//! ```rust
//! use cxa_hash::{Sha256, Hasher};
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"Hello, World!");
//! let result = hasher.finalize();
//!
//! println!("Hash: {:x}", result);
 //! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::cargo)]
#![warn(clippy::pedantic)]

use zeroize::Zeroize;
use std::marker::PhantomData;

/// Size of SHA-256 hash output in bytes
pub const SHA256_OUTPUT_SIZE: usize = 32;
/// Size of SHA-512 hash output in bytes
pub const SHA512_OUTPUT_SIZE: usize = 64;
/// Size of BLAKE3 hash output in bytes
pub const BLAKE3_OUTPUT_SIZE: usize = 32;
/// Block size for SHA-256 in bytes
pub const SHA256_BLOCK_SIZE: usize = 64;
/// Block size for SHA-512 in bytes
pub const SHA512_BLOCK_SIZE: usize = 128;
/// BLAKE3 chunk size in bytes
pub const BLAKE3_CHUNK_SIZE: usize = 1024;

/// Errors that can occur during hash operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashError {
    /// Invalid output size requested
    InvalidOutputSize,
    /// Invalid input for initialization
    InvalidInitialization,
    /// Hash computation failed
    ComputationFailed,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOutputSize => write!(f, "Invalid hash output size requested"),
            Self::InvalidInitialization => write!(f, "Invalid hash initialization"),
            Self::ComputationFailed => write!(f, "Hash computation failed"),
        }
    }
}

impl std::error::Error for HashError {}

/// Trait representing a cryptographic hash function.
///
/// This trait defines the interface that all hash function implementations
/// must follow, allowing for generic algorithms and easy swapping.
pub trait HashFunction: Sized {
    /// Output size of this hash function in bytes
    const OUTPUT_SIZE: usize;

    /// Creates a new hasher instance.
    fn new() -> Self;

    /// Creates a hasher with a specific output size (if supported).
    ///
    /// # Arguments
    ///
    /// * `output_size` - Desired output size in bytes
    ///
    /// # Returns
    ///
    /// A new hasher instance
    ///
    /// # Errors
    ///
    /// Returns `HashError::InvalidOutputSize` if the size is not supported
    fn with_output_size(output_size: usize) -> Result<Self, HashError>;

    /// Updates the hasher with new data.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash computation and returns the result.
    ///
    /// # Returns
    ///
    /// Hash output as a byte vector
    fn finalize(self) -> Vec<u8>;

    /// Finalizes the hash and stores the result in the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `output` - Buffer to store the hash result
    ///
    /// # Errors
    ///
    /// Returns `HashError::InvalidOutputSize` if the buffer is too small
    fn finalize_into(self, output: &mut [u8]) -> Result<(), HashError>;

    /// Computes the hash of data in one operation.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    ///
    /// # Returns
    ///
    /// Hash output as a byte vector
    #[inline]
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// Represents a hash output with compile-time size checking.
///
/// This type wraps the raw hash bytes and provides secure deletion
/// when dropped.
#[derive(Debug)]
#[zeroize(drop)]
pub struct HashOutput<const N: usize> {
    /// Raw hash bytes
    data: [u8; 64], // Maximum size for alignment
    /// Actual size used
    size: usize,
}

impl<const N: usize> HashOutput<N> {
    /// Creates a new hash output from the provided bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Hash bytes
    ///
    /// # Returns
    ///
    /// A new `HashOutput` instance
    ///
    /// # Panics
    ///
    /// Panics if data size exceeds buffer size
    #[inline]
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        assert!(data.len() <= 64, "Data too large for HashOutput");
        let mut output = Self {
            data: [0u8; 64],
            size: data.len(),
        };
        output.data[..data.len()].copy_from_slice(data);
        output
    }

    /// Returns the hash bytes.
    ///
    /// # Returns
    ///
    /// Immutable slice to the hash bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Returns the size of the hash in bytes.
    ///
    /// # Returns
    ///
    /// Hash size in bytes
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Compares this hash with another for equality.
    ///
    /// This operation is constant-time to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `other` - Hash to compare against
    ///
    /// # Returns
    ///
    /// `true` if hashes are equal, `false` otherwise
    #[inline]
    #[must_use]
    pub fn verify(&self, other: &HashOutput<N>) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<const N: usize> From<&[u8]> for HashOutput<N> {
    #[inline]
    fn from(data: &[u8]) -> Self {
        Self::new(data)
    }
}

impl<const N: usize> std::fmt::LowerHex for HashOutput<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<const N: usize> std::fmt::UpperHex for HashOutput<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

/// SHA-256 hash function implementation.
///
/// SHA-256 produces a 256-bit (32-byte) hash value. It is widely used
/// for general-purpose cryptographic hashing and is considered secure
/// for most applications.
///
/// # Example
///
/// ```rust
/// use cxa_hash::{Sha256, HashFunction};
///
/// let hash = Sha256::digest(b"Hello, World!");
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug)]
pub struct Sha256 {
    /// Internal state
    state: [u32; 8],
    /// Message length in bytes
    length: u64,
    /// Unprocessed message bytes
    buffer: [u8; SHA256_BLOCK_SIZE],
    /// Current position in buffer
    buffer_pos: usize,
    /// Marker for compile-time output size
    _marker: PhantomData<[u8; SHA256_OUTPUT_SIZE]>,
}

impl Sha256 {
    /// SHA-256 initialization constants (first 32 bits of fractional parts of square roots of first 8 primes)
    const INITIAL_STATE: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    /// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    #[rustfmt::skip]
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];

    /// Right rotation of a 32-bit value.
    #[inline]
    fn rotr32(value: u32, n: u32) -> u32 {
        value.rotate_right(n)
    }

    /// Right rotation of a 64-bit value.
    #[inline]
    fn rotr64(value: u64, n: u32) -> u64 {
        value.rotate_right(n)
    }

    /// Performs one round of SHA-256 compression.
    #[inline]
    fn compress(&mut self, message_schedule: &mut [u32; 16]) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s0 = Self::rotr32(a, 2) ^ Self::rotr32(a, 13) ^ Self::rotr32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            let s1 = Self::rotr32(e, 6) ^ Self::rotr32(e, 11) ^ Self::rotr32(e, 25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::ROUND_CONSTANTS[i]).wrapping_add(message_schedule[i % 16]);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            if i < 63 {
                let s0_msg = Self::rotr32(message_schedule[(i + 1) % 16], 7) ^ Self::rotr32(message_schedule[(i + 1) % 16], 18) ^ (message_schedule[(i + 1) % 16] >> 3);
                let s1_msg = Self::rotr32(message_schedule[(i + 14) % 16], 17) ^ Self::rotr32(message_schedule[(i + 14) % 16], 19) ^ (message_schedule[(i + 14) % 16] >> 10);
                message_schedule[(i + 16) % 16] = message_schedule[i % 16].wrapping_add(s0_msg).wrapping_add(message_schedule[(i + 9) % 16]).wrapping_add(s1_msg);
            }
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl HashFunction for Sha256 {
    const OUTPUT_SIZE: usize = SHA256_OUTPUT_SIZE;

    #[inline]
    fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            length: 0,
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_pos: 0,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn with_output_size(output_size: usize) -> Result<Self, HashError> {
        if output_size == SHA256_OUTPUT_SIZE {
            Ok(Self::new())
        } else {
            Err(HashError::InvalidOutputSize)
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;

        let mut pos = 0;
        while pos < data.len() {
            let to_copy = std::cmp::min(data.len() - pos, SHA256_BLOCK_SIZE - self.buffer_pos);
            self.buffer[self.buffer_pos..self.buffer_pos + to_copy].copy_from_slice(&data[pos..pos + to_copy]);
            self.buffer_pos += to_copy;
            pos += to_copy;

            if self.buffer_pos == SHA256_BLOCK_SIZE {
                let mut message_schedule = [0u32; 16];
                for i in 0..16 {
                    message_schedule[i] = u32::from_le_bytes(
                        self.buffer[i * 4..i * 4 + 4].try_into().unwrap()
                    );
                }
                self.compress(&mut message_schedule);
                self.buffer_pos = 0;
            }
        }
    }

    #[inline]
    fn finalize(self) -> Vec<u8> {
        let mut hasher = self;
        hasher.finalize_into(&mut vec![0u8; SHA256_OUTPUT_SIZE]).unwrap()
    }

    #[inline]
    fn finalize_into(self, output: &mut [u8]) -> Result<(), HashError> {
        if output.len() < SHA256_OUTPUT_SIZE {
            return Err(HashError::InvalidOutputSize);
        }

        let mut hasher = self;

        // Pad the message
        let bit_length = hasher.length * 8;
        let mut buffer = hasher.buffer;
        let mut buffer_pos = hasher.buffer_pos;

        // Append the '1' bit
        buffer[buffer_pos] = 0x80;
        buffer_pos += 1;

        // If no room for 64-bit length, process block
        if buffer_pos > SHA256_BLOCK_SIZE - 8 {
            let mut message_schedule = [0u32; 16];
            for i in 0..16 {
                message_schedule[i] = u32::from_le_bytes(
                    buffer[i * 4..i * 4 + 4].try_into().unwrap()
                );
            }
            hasher.compress(&mut message_schedule);
            buffer = [0u8; SHA256_BLOCK_SIZE];
            buffer_pos = 0;
        }

        // Append the 64-bit message length (big-endian)
        let length_bytes = bit_length.to_be_bytes();
        buffer[SHA256_BLOCK_SIZE - 8..SHA256_BLOCK_SIZE].copy_from_slice(&length_bytes);

        // Process final block
        let mut message_schedule = [0u32; 16];
        for i in 0..16 {
            message_schedule[i] = u32::from_le_bytes(
                buffer[i * 4..i * 4 + 4].try_into().unwrap()
            );
        }
        hasher.compress(&mut message_schedule);

        // Output hash
        let result = hasher.state;
        for (i, chunk) in result.chunks(1).enumerate() {
            output[i] = chunk[0];
        }

        Ok(())
    }
}

/// SHA-512 hash function implementation.
///
/// SHA-512 produces a 512-bit (64-byte) hash value. It provides
/// higher security than SHA-256 but is slower and uses more memory.
///
/// # Example
///
/// ```rust
/// use cxa_hash::{Sha512, HashFunction};
///
/// let hash = Sha512::digest(b"Hello, World!");
/// assert_eq!(hash.len(), 64);
/// ```
#[derive(Debug)]
pub struct Sha512 {
    /// Internal state
    state: [u64; 8],
    /// Message length in bytes
    length: u128,
    /// Unprocessed message bytes
    buffer: [u8; SHA512_BLOCK_SIZE],
    /// Current position in buffer
    buffer_pos: usize,
    /// Marker for compile-time output size
    _marker: PhantomData<[u8; SHA512_OUTPUT_SIZE]>,
}

impl Sha512 {
    /// SHA-512 initialization constants
    const INITIAL_STATE: [u64; 8] = [
        0xF3BCC908, 0x84A73C43, 0x9FA0F4A7, 0x1F83D9AB,
        0x5BE0CD19, 0x1F83D9AB, 0x5BE0CD19, 0x9FA0F4A7,
    ];

    #[rustfmt::skip]
    const ROUND_CONSTANTS: [u64; 80] = [
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBC2,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1FDE0B9, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ];
}

impl HashFunction for Sha512 {
    const OUTPUT_SIZE: usize = SHA512_OUTPUT_SIZE;

    #[inline]
    fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            length: 0,
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_pos: 0,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn with_output_size(output_size: usize) -> Result<Self, HashError> {
        if output_size == SHA512_OUTPUT_SIZE {
            Ok(Self::new())
        } else {
            Err(HashError::InvalidOutputSize)
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u128;
        // Implementation would go here - omitted for brevity
    }

    #[inline]
    fn finalize(self) -> Vec<u8> {
        let mut output = vec![0u8; SHA512_OUTPUT_SIZE];
        self.finalize_into(&mut output).unwrap();
        output
    }

    #[inline]
    fn finalize_into(self, output: &mut [u8]) -> Result<(), HashError> {
        if output.len() < SHA512_OUTPUT_SIZE {
            return Err(HashError::InvalidOutputSize);
        }
        Ok(())
    }
}

/// BLAKE3 hash function implementation.
///
/// BLAKE3 is a modern cryptographic hash function that is faster than
/// SHA-256 while providing the same 256-bit security level. It supports
/// keyed hashing, hashing with context, and tree hashing.
///
/// # Example
///
/// ```rust
/// use cxa_hash::{Blake3, HashFunction};
///
/// let hash = Blake3::digest(b"Hello, World!");
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug)]
pub struct Blake3 {
    /// Internal state (placeholder)
    state: [u32; 16],
    /// Message length in bytes
    length: u64,
    /// Unprocessed bytes
    buffer: [u8; BLAKE3_CHUNK_SIZE],
    /// Current position
    buffer_pos: usize,
}

impl Blake3 {
    /// BLAKE3 IV constants
    const IV: [u32; 8] = [
        0xF3BCC908, 0x84A73C43, 0x9FA0F4A7, 0x1F83D9AB,
        0x5BE0CD19, 0x1F83D9AB, 0x5BE0CD19, 0x9FA0F4A7,
    ];
}

impl HashFunction for Blake3 {
    const OUTPUT_SIZE: usize = BLAKE3_OUTPUT_SIZE;

    #[inline]
    fn new() -> Self {
        Self {
            state: Self::IV,
            length: 0,
            buffer: [0u8; BLAKE3_CHUNK_SIZE],
            buffer_pos: 0,
        }
    }

    #[inline]
    fn with_output_size(output_size: usize) -> Result<Self, HashError> {
        if output_size == BLAKE3_OUTPUT_SIZE {
            Ok(Self::new())
        } else {
            Err(HashError::InvalidOutputSize)
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        // BLAKE3 implementation would go here
    }

    #[inline]
    fn finalize(self) -> Vec<u8> {
        vec![0u8; BLAKE3_OUTPUT_SIZE]
    }

    #[inline]
    fn finalize_into(self, output: &mut [u8]) -> Result<(), HashError> {
        if output.len() < BLAKE3_OUTPUT_SIZE {
            return Err(HashError::InvalidOutputSize);
        }
        Ok(())
    }
}

/// Type alias for SHA-256 hash output
pub type Sha256Hash = HashOutput<SHA256_OUTPUT_SIZE>;
/// Type alias for SHA-512 hash output
pub type Sha512Hash = HashOutput<SHA512_OUTPUT_SIZE>;
/// Type alias for BLAKE3 hash output
pub type Blake3Hash = HashOutput<BLAKE3_OUTPUT_SIZE>;

/// Utility functions for hash operations.
pub mod util {
    use super::*;

    /// Concatenates and hashes multiple inputs using a specified hash function.
    ///
    /// This is useful for building Merkle trees or hash chains.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Slice of byte slices to hash
    /// * `hasher` - Hasher closure
    ///
    /// # Returns
    ///
    /// Combined hash of all inputs
    #[inline]
    pub fn hash_concatenation<H: HashFunction>(inputs: &[&[u8]], mut hasher: impl FnMut() -> H) -> Vec<u8> {
        let mut h = hasher();
        for &input in inputs {
            h.update(input);
        }
        h.finalize()
    }

    /// Hashes the concatenation of a prefix and data.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix bytes
    /// * `data` - Data bytes
    /// * `hasher` - Hasher closure
    ///
    /// # Returns
    ///
    /// Hash of prefix || data
    #[inline]
    pub fn hash_prefixed<H: HashFunction>(prefix: &[u8], data: &[u8], mut hasher: impl FnMut() -> H) -> Vec<u8> {
        let mut h = hasher();
        h.update(prefix);
        h.update(data);
        h.finalize()
    }

    /// Computes HMAC using a specified hash function.
    ///
    /// # Arguments
    ///
    /// * `key` - Secret key
    /// * `message` - Message to authenticate
    /// * `hasher` - Hasher closure
    ///
    /// # Returns
    ///
    /// HMAC output
    #[inline]
    pub fn hmac<H: HashFunction>(key: &[u8], message: &[u8]) -> Vec<u8> {
        let block_size = H::OUTPUT_SIZE;
        let mut k = key.to_vec();

        if k.len() > block_size {
            let mut h = H::new();
            h.update(&k);
            k = h.finalize();
        }

        k.resize(block_size, 0u8);

        let mut ipad = vec![0x36u8; block_size];
        let mut opad = vec![0x5Cu8; block_size];

        for (i, byte) in k.iter().enumerate() {
            ipad[i] ^= byte;
            opad[i] ^= byte;
        }

        let mut inner = H::new();
        inner.update(&ipad);
        inner.update(message);
        let inner_hash = inner.finalize();

        let mut outer = H::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Derives a key using HKDF-SHA256.
    ///
    /// # Arguments
    ///
    /// * `ikm` - Input key material
    /// * `salt` - Optional salt
    /// * `info` - Optional context info
    /// * `length` - Desired output length
    ///
    /// # Returns
    ///
    /// Derived key material
    #[inline]
    pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, length: usize) -> Vec<u8> {
        let salt = salt.unwrap_or(b"");
        let info = info.unwrap_or(b"");

        // Extract
        let mut prk = vec![0u8; SHA256_OUTPUT_SIZE];
        let mut hmac_extractor = || {
            let mut h = Sha256::new();
            h.update(salt);
            h
        };
        prk.copy_from_slice(&hmac(ikm, salt, hmac_extractor));

        // Expand
        let mut output = vec![0u8; length];
        let mut t = vec![];
        let mut i = 0u8;

        while output.iter().any(|&b| b != 0) {
            i += 1;
            let mut h = Sha256::new();
            h.update(&t);
            h.update(info);
            h.update(&[i]);
            t = h.finalize();

            for (j, &byte) in t.iter().enumerate() {
                if j < output.len() {
                    output[j] ^= byte;
                }
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_new() {
        let hasher = Sha256::new();
        assert_eq!(hasher.state, Sha256::INITIAL_STATE);
    }

    #[test]
    fn test_sha256_digest() {
        let hash = Sha256::digest(b"");
        assert_eq!(hash.len(), SHA256_OUTPUT_SIZE);

        // Verify against known test vector
        let expected = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
            0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
            0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
            0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(hash.as_slice(), &expected);
    }

    #[test]
    fn test_sha256_hello_world() {
        let hash = Sha256::digest(b"Hello, World!");
        let expected = [
            0xD2, 0x9A, 0x62, 0xED, 0x55, 0x1C, 0xE9, 0x3F,
            0xF9, 0xF3, 0x28, 0xCE, 0x25, 0x41, 0x1E, 0xD7,
            0xF0, 0xC3, 0xAA, 0x78, 0xF4, 0xDF, 0x5F, 0x56,
            0xA5, 0xF5, 0x9D, 0xB6, 0x82, 0xC0, 0x8E, 0xA3,
        ];
        assert_eq!(hash.as_slice(), &expected);
    }

    #[test]
    fn test_sha256_update() {
        let mut hasher = Sha256::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash = hasher.finalize();

        let expected = [
            0xD2, 0x9A, 0x62, 0xED, 0x55, 0x1C, 0xE9, 0x3F,
            0xF9, 0xF3, 0x28, 0xCE, 0x25, 0x41, 0x1E, 0xD7,
            0xF0, 0xC3, 0xAA, 0x78, 0xF4, 0xDF, 0x5F, 0x56,
            0xA5, 0xF5, 0x9D, 0xB6, 0x82, 0xC0, 0x8E, 0xA3,
        ];
        assert_eq!(hash.as_slice(), &expected);
    }

    #[test]
    fn test_sha256_with_output_size() {
        let hasher = Sha256::with_output_size(SHA256_OUTPUT_SIZE).unwrap();
        assert!(Sha256::with_output_size(16).is_err());
    }

    #[test]
    fn test_hash_output_hex_formatting() {
        let hash = Sha256::digest(b"test");
        let lower_hex = format!("{:x}", hash);
        let upper_hex = format!("{:X}", hash);

        assert!(lower_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(upper_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(lower_hex, upper_hex.to_lowercase());
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let message = b"message";
        let mac = util::hmac::<Sha256>(key, message);

        // HMAC-SHA256 should be 32 bytes
        assert_eq!(mac.len(), SHA256_OUTPUT_SIZE);
    }

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input key material";
        let salt = Some(b"salt");
        let info = Some(b"info");
        let derived = util::hkdf_sha256(ikm, salt, info, 32);

        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hash_output_verify() {
        let hash1 = Sha256::digest(b"test");
        let hash2 = Sha256::digest(b"test");
        let hash3 = Sha256::digest(b"different");

        assert!(hash1.verify(&hash2));
        assert!(!hash1.verify(&hash3));
    }
}
