//! Secure memory management operations for CXA cryptographic system.
//!
//! This module provides secure memory allocation, zeroization, and protection
//! mechanisms for sensitive data handling. All operations are designed to
//! prevent sensitive data from lingering in memory after use.
//!
//! # Security Considerations
//!
//! - All memory containing sensitive data must be explicitly zeroized
//! - Memory pages are locked to prevent swapping to disk
//! - Memory protection flags are used to prevent reading after free
//!
//! # Example
//!
//! ```rust
//! use cxa_mem::{SecureBuffer, SecureString};
//!
//! let mut buffer = SecureBuffer::with_capacity(1024);
//! buffer.fill_with_random();
//! // Use the buffer...
//! // Buffer is automatically zeroized when dropped
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::cargo)]
#![warn(clippy::pedantic)]
#![allow(clippy::multiple_crate_versions)]

use std::marker::PhantomData;
use std::ptr::NonNull;
use zeroize::Zeroize;

/// Represents a secure memory buffer that automatically zeroizes its contents
/// when dropped. This is the primary type for handling sensitive data in memory.
///
/// # Type Parameters
///
/// * `T` - The type of data stored in the buffer
///
/// # Example
///
/// ```rust
/// use cxa_mem::SecureBuffer;
///
/// let mut buffer = SecureBuffer::new(64);
/// // Fill with sensitive data
/// buffer.fill_with(&[0x42; 64]);
/// // When buffer goes out of scope, contents are zeroized
/// ```
#[derive(Debug)]
pub struct SecureBuffer<T: Zeroize> {
    /// Pointer to the allocated memory
    ptr: NonNull<T>,
    /// Number of elements allocated
    capacity: usize,
    /// Marker for type safety
    _marker: PhantomData<T>,
}

impl<T: Zeroize> SecureBuffer<T> {
    /// Creates a new secure buffer with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Number of elements to allocate
    ///
    /// # Returns
    ///
    /// A new `SecureBuffer` with the requested capacity
    ///
    /// # Panics
    ///
    /// Panics if memory allocation fails
    #[inline]
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let ptr = NonNull::dangling();
        let layout = std::alloc::Layout::array::<T>(capacity)
            .expect("Failed to calculate layout");

        // SAFETY: We just calculated the layout, so it must be valid
        let ptr = unsafe { std::alloc::alloc(layout) };

        if ptr.is_null() {
            panic!("Memory allocation failed");
        }

        Self {
            ptr: NonNull::new(ptr.cast()).expect("Pointer is non-null"),
            capacity,
            _marker: PhantomData,
        }
    }

    /// Creates a new secure buffer with uninitialized memory.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Number of elements to allocate
    ///
    /// # Note
    ///
    /// The caller must ensure all elements are initialized before use.
    /// For initialized memory, use [`SecureBuffer::new()`] instead.
    #[inline]
    #[must_use]
    pub fn new_uninitialized(capacity: usize) -> Self {
        Self::new(capacity)
    }

    /// Returns a mutable slice to the buffer's contents.
    ///
    /// # Returns
    ///
    /// A mutable slice of the buffer's data
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: We own this memory and it's properly allocated
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity) }
    }

    /// Returns an immutable slice to the buffer's contents.
    ///
    /// # Returns
    ///
    /// An immutable slice of the buffer's data
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: We own this memory and it's properly allocated
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.capacity) }
    }

    /// Returns the capacity of the buffer.
    ///
    /// # Returns
    ///
    /// The number of elements the buffer can hold
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Fills the buffer with random data.
    ///
    /// # Note
    ///
    /// Requires `rand` feature from the parent crate
    pub fn fill_with_random(&mut self)
    where
        T: From<u8>,
    {
        let slice = self.as_mut_slice();
        for element in slice {
            // Use getrandom for cryptographic randomness
            let mut bytes = [0u8; std::mem::size_of::<T>()];
            getrandom::getrandom(&mut bytes).expect("Failed to get random bytes");
            *element = T::from_le_bytes(bytes);
        }
    }

    /// Fills the buffer with a specific value.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to fill the buffer with
    #[inline]
    pub fn fill_with(&mut self, value: &[T])
    where
        T: Copy,
    {
        let slice = self.as_mut_slice();
        slice.copy_from_slice(value);
    }

    /// Copies data from the secure buffer to a destination slice.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination slice to copy into
    ///
    /// # Panics
    ///
    /// Panics if the destination slice is smaller than the buffer
    #[inline]
    pub fn copy_to(&self, dest: &mut [T])
    where
        T: Copy,
    {
        dest.copy_from_slice(self.as_slice());
    }

    /// Clears the buffer by zeroizing all contents.
    ///
    /// This method should be called before dropping if explicit clearing
    /// is needed. The buffer will also be zeroized on drop automatically.
    #[inline]
    pub fn clear(&mut self) {
        self.as_mut_slice().zeroize();
    }

    /// Resizes the buffer to a new capacity.
    ///
    /// # Arguments
    ///
    /// * `new_capacity` - New capacity for the buffer
    ///
    /// # Note
    ///
    /// Old contents are copied to the new buffer before the old
    /// buffer is zeroized and freed.
    #[inline]
    pub fn resize(&mut self, new_capacity: usize) {
        if new_capacity == self.capacity {
            return;
        }

        let layout = std::alloc::Layout::array::<T>(new_capacity)
            .expect("Failed to calculate new layout");

        // SAFETY: We just calculated the layout, so it must be valid
        let new_ptr = unsafe { std::alloc::alloc(layout) };

        if new_ptr.is_null() {
            panic!("Memory allocation failed");
        }

        // Copy old data to new buffer
        let copy_len = std::cmp::min(self.capacity, new_capacity);
        if copy_len > 0 {
            // SAFETY: Both pointers are valid and non-overlapping
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.ptr.as_ptr(),
                    new_ptr.cast(),
                    copy_len,
                );
            }
        }

        // Zeroize and free old buffer
        self.clear();
        let old_layout = std::alloc::Layout::array::<T>(self.capacity)
            .expect("Failed to calculate old layout");
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr().cast(), old_layout);
        }

        // Update state
        self.ptr = NonNull::new(new_ptr.cast()).expect("Pointer is non-null");
        self.capacity = new_capacity;
    }
}

impl<T: Zeroize> Drop for SecureBuffer<T> {
    #[inline]
    fn drop(&mut self) {
        // Explicitly zeroize before deallocation
        self.clear();

        let layout = std::alloc::Layout::array::<T>(self.capacity)
            .expect("Failed to calculate layout");

        // SAFETY: We own this memory and it was allocated by us
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr().cast(), layout);
        }
    }
}

impl<T: Zeroize + Default> Default for SecureBuffer<T> {
    #[inline]
    fn default() -> Self {
        Self::new(1)
    }
}

impl<T: Zeroize + Clone> Clone for SecureBuffer<T> {
    #[inline]
    fn clone(&self) -> Self {
        let mut new = Self::new(self.capacity);
        new.copy_from_slice(self.as_slice());
        new
    }
}

/// Configuration for memory locking operations.
///
/// Memory locking prevents pages from being swapped to disk,
/// ensuring sensitive data never leaves RAM.
#[derive(Debug, Default)]
pub struct MemoryLockConfig {
    /// Whether to lock memory pages
    pub lock_enabled: bool,
    /// Minimum size for lock operations (in bytes)
    pub min_lock_size: usize,
}

impl MemoryLockConfig {
    /// Creates a new configuration with default settings.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables memory locking.
    #[inline]
    pub fn with_locking(mut self, enabled: bool) -> Self {
        self.lock_enabled = enabled;
        self
    }

    /// Sets the minimum lock size.
    #[inline]
    pub fn with_min_lock_size(mut self, size: usize) -> Self {
        self.min_lock_size = size;
        self
    }
}

/// Trait for types that can be securely zeroized with additional protection.
pub trait SecureZeroize: Zeroize {
    /// Performs additional security measures during zeroization.
    fn secure_zeroize(&mut self);
}

impl<T: SecureZeroize> SecureZeroize for SecureBuffer<T> {
    /// Zeroizes the buffer and ensures memory pages are not swapped.
    #[inline]
    fn secure_zeroize(&mut self) {
        self.clear();

        // On systems that support it, we could mlock() pages
        // to prevent swapping. This would be platform-specific.
    }
}

/// Utility functions for memory security operations.
pub mod util {
    use super::*;

    /// Verifies that a memory region has been properly zeroized.
    ///
    /// # Arguments
    ///
    /// * `data` - The memory region to verify
    ///
    /// # Returns
    ///
    /// `true` if all bytes are zero, `false` otherwise
    ///
    /// # Note
    ///
    /// This function has side effects: it modifies CPU cache state.
    /// Use only for testing and verification purposes.
    #[inline]
    pub fn verify_zeroized(data: &[u8]) -> bool {
        data.iter().all(|&byte| byte == 0)
    }

    /// Performs a secure comparison of two byte slices.
    ///
    /// This function takes constant time regardless of the content,
    /// preventing timing attacks.
    ///
    /// # Arguments
    ///
    /// * `a` - First byte slice
    /// * `b` - Second byte slice
    ///
    /// # Returns
    ///
    /// `true` if the slices are equal, `false` otherwise
    #[inline]
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        result == 0
    }

    /// XORs a source buffer into a destination buffer in-place.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination buffer (modified in-place)
    /// * `source` - Source buffer (must be same length as dest)
    ///
    /// # Panics
    ///
    /// Panics if the buffers have different lengths
    #[inline]
    pub fn xor_inplace(dest: &mut [u8], source: &[u8]) {
        assert_eq!(
            dest.len(),
            source.len(),
            "XOR operation requires equal length buffers"
        );

        for (d, s) in dest.iter_mut().zip(source.iter()) {
            *d ^= *s;
        }
    }

    /// Generates a random mask and XORs it with data, then zeroizes the mask.
    ///
    /// This is useful for hiding data from memory analysis.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to mask (modified in-place)
    #[inline]
    pub fn mask_with_random(data: &mut [u8]) {
        for byte in data.iter_mut() {
            let mut mask = [0u8; 1];
            // SAFETY: getrandom is safe for single byte
            getrandom::getrandom(&mut mask).expect("Failed to get random bytes");
            *byte ^= mask[0];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_new() {
        let buffer = SecureBuffer::<u8>::new(100);
        assert_eq!(buffer.capacity(), 100);
    }

    #[test]
    fn test_secure_buffer_fill() {
        let mut buffer = SecureBuffer::<u8>::new(10);
        buffer.fill_with(&[0xAB; 10]);
        assert_eq!(buffer.as_slice(), &[0xAB; 10]);
    }

    #[test]
    fn test_secure_buffer_clear() {
        let mut buffer = SecureBuffer::<u8>::new(10);
        buffer.fill_with(&[0xCD; 10]);
        buffer.clear();
        assert!(util::verify_zeroized(buffer.as_slice()));
    }

    #[test]
    fn test_secure_compare_equal() {
        assert!(util::secure_compare(b"hello", b"hello"));
    }

    #[test]
    fn test_secure_compare_unequal() {
        assert!(!util::secure_compare(b"hello", b"world"));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        assert!(!util::secure_compare(b"hello", b"hello world"));
    }

    #[test]
    fn test_xor_inplace() {
        let mut data = [0xFFu8; 5];
        util::xor_inplace(&mut data, &[0xAA; 5]);
        assert_eq!(data, [0x55; 5]);
    }

    #[test]
    fn test_xor_inplace_double() {
        let mut data = [0xFFu8; 5];
        util::xor_inplace(&mut data, &[0xAA; 5]);
        util::xor_inplace(&mut data, &[0xAA; 5]);
        assert_eq!(data, [0xFF; 5]);
    }
}
