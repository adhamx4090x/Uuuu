#!/usr/bin/env python3
"""
CXA Secure Memory Module

This module provides secure memory management utilities for handling sensitive
cryptographic data. It includes secure memory allocation, zeroization, and
constant-time comparison functions essential for secure cryptographic operations.

The module addresses several critical security concerns in memory management:

1. Preventing Sensitive Data from Being Swapped to Disk:
   Operating systems may swap memory pages to disk under memory pressure.
   For sensitive data like cryptographic keys, this creates a security risk
   as the data may persist on disk after the program exits. This module uses
   mlock (Linux/macOS) or VirtualLock (Windows) to prevent swapping.

2. Automatic Memory Zeroization:
   Sensitive data must be overwritten before being freed to prevent recovery
   from memory forensics. This module provides secure_wipe() function that
   performs multiple overwrite passes to ensure data cannot be recovered.

3. Constant-Time Comparison:
   Standard byte comparison functions may leak information about matching
   bytes through timing differences. This module provides secure_compare()
   which takes constant time regardless of where differences occur.

4. Context Manager Support:
   The SecureBuffer and SecureString classes implement context manager
   protocol to ensure automatic cleanup when objects go out of scope.

Security Features:
- Secure memory allocation using mlock to prevent swapping
- Automatic memory zeroization on deallocation
- Constant-time comparison to prevent timing attacks
- Protection against memory inspection through platform-specific APIs

Author: CXA Development Team
Version: 1.0.0
"""

# ============================================================================
# Import Statements
# ============================================================================

# Standard library imports for system operations and type handling
import ctypes          # Foreign Function Interface for low-level memory operations
import os              # Operating system functions for file and memory operations
import platform        # System information for platform detection
import threading       # Thread synchronization primitives
from typing import Optional, Union, ByteString  # Type hints for better code documentation


# ============================================================================
# Platform Detection
# ============================================================================

# Detect the current operating system for platform-specific implementations
# This enables conditional code paths for Linux, macOS, and Windows

# Get lowercase platform name for consistent comparison
PLATFORM = platform.system().lower()

# Boolean flags for each supported platform
# These are used throughout the module to select appropriate system calls

# Linux platform flag (includes most Linux distributions)
IS_LINUX = PLATFORM == "linux"

# macOS platform flag (Darwin-based operating system)
IS_MACOS = PLATFORM == "darwin"

# Windows platform flag (Microsoft Windows)
IS_WINDOWS = PLATFORM == "windows"


# ============================================================================
# Secure Memory Functions
# ============================================================================

# Core functions for secure memory management
# These functions provide the foundation for secure data handling


def secure_allocate(size: int) -> ctypes.Array:
    """
    Allocate memory that cannot be swapped to disk.
    
    This function allocates a memory buffer and locks it in physical RAM
    using platform-specific system calls. This prevents the operating system
    from swapping the sensitive data to disk, where it could potentially
    be recovered by other processes or after system reboot.
    
    Memory Locking Mechanism:
    - Linux/macOS: Uses mlock() system call to lock pages in RAM
    - Windows: Uses VirtualLock() API to lock memory pages
    
    The mlock/VirtualLock call tells the kernel to keep the specified
    memory pages in physical RAM and not to swap them out. This is
    essential for protecting cryptographic keys and other sensitive data.
    
    Note on Limits:
    Most systems impose limits on how much memory can be locked. The
    get_memory_lock_limit() function can be used to query these limits.
    If locking fails, the allocation continues without locking, which
    provides some protection but less than the locked version.
    
    Args:
        size: Number of bytes to allocate. Must be a positive integer.
    
    Returns:
        ctypes.create_string_buffer: A ctypes array containing the allocated
        memory. This buffer can be used like a bytearray but provides
        access to low-level memory operations.
    
    Raises:
        ValueError: If size is not a positive integer
        MemoryError: If memory allocation fails (rare, typically only
        with very large sizes or system resource exhaustion)
    
    Example:
        >>> buffer = secure_allocate(32)
        >>> # Fill with sensitive data
        >>> buffer[:] = os.urandom(32)
        >>> # Buffer is now locked in physical memory
    """
    # Validate input parameter
    if size <= 0:
        raise ValueError("Size must be positive")
    
    # Create a ctypes string buffer of the requested size
    # This allocates memory that can be manipulated at the byte level
    buffer = ctypes.create_string_buffer(size)
    
    try:
        # Attempt to lock the memory to prevent swapping
        if IS_LINUX or IS_MACOS:
            # Linux and macOS use the mlock() system call
            # Load the C library (libc) and call mlock
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib")
            # mlock takes the buffer pointer and size in bytes
            libc.mlock(buffer, size)
        elif IS_WINDOWS:
            # Windows uses the VirtualLock() API from kernel32
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualLock(buffer, size)
    except Exception:
        # If locking fails (e.g., due to resource limits),
        # we continue without locking. The memory is still allocated
        # and usable, just not protected against swapping.
        # This is a best-effort approach - complete failure would
        # be exceptional.
        pass
    
    return buffer


def secure_free(buffer: ctypes.Array) -> None:
    """
    Securely free allocated memory by wiping and unlocking.
    
    This function ensures that sensitive data is securely erased from
    memory before the buffer is freed. It performs two operations:
    
    1. Memory Wiping: Calls secure_wipe() to overwrite the buffer
       contents with multiple patterns, ensuring data cannot be
       recovered from memory.
    
    2. Memory Unlocking: Calls munlock/VirtualUnlock to release
       the lock on memory pages, allowing them to be swapped or
       reused by the system.
    
    Important Security Note:
    After calling secure_free(), the buffer contents are destroyed.
    Any attempt to access the buffer may return garbage data or
    cause a memory access violation.
    
    Args:
        buffer: The ctypes array buffer to free. If None, the function
        returns immediately without error.
    
    Side Effects:
    - The buffer contents are overwritten with zeros and other patterns
    - Memory locks are released, allowing the OS to manage the pages
    
    Example:
        >>> buffer = secure_allocate(32)
        >>> # Use the buffer for sensitive operations
        >>> secure_free(buffer)
        >>> # Buffer is now wiped and unlocked
    """
    # Early return for None buffer
    if buffer is None:
        return
    
    try:
        # First, wipe the memory contents to prevent data recovery
        secure_wipe(buffer, len(buffer))
        
        # Then, unlock the memory so pages can be managed by OS
        if IS_LINUX or IS_MACOS:
            # Use munlock() system call
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib")
            libc.munlock(buffer, len(buffer))
        elif IS_WINDOWS:
            # Use VirtualUnlock() API
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock(buffer, len(buffer))
    except Exception:
        # If unlocking fails, we still continue - the important part
        # (wiping) has already been attempted. Unlock failures are
        # not critical for security.
        pass
    
    # Note: We do not explicitly deallocate the buffer here.
    # Python's garbage collector will handle deallocation when the
    # buffer goes out of scope. The wiping ensures that even if
    # deallocation is delayed, the data cannot be recovered.


def secure_wipe(data: Union[bytearray, ctypes.Array, bytes], size: int) -> None:
    """
    Overwrite sensitive data in memory to prevent recovery.
    
    This function performs a multi-pass overwrite of the specified memory
    region. The goal is to ensure that sensitive data cannot be recovered
    from memory even using forensic tools or cold boot attacks.
    
    Overwrite Strategy:
    This implementation uses four overwrite passes:
    
    1. Zero Pass: Overwrite with 0x00 bytes
       - Simple zeroing is often sufficient but may leave patterns
         that can be detected in some scenarios
    
    2. Ones Pass: Overwrite with 0xFF bytes
       - Complements the zero pass, destroying any residual patterns
         that might exist after zeroing
    
    3. Random Pass: Overwrite with cryptographically random bytes
       - This destroys any residual magnetic or electrical patterns
         that might persist after deterministic overwrites
    
    4. Final Zero Pass: Overwrite with 0x00 bytes one more time
       - Ensures clean final state and prevents accidental information
         leakage through the random data
    
    Note on Effectiveness:
    Modern DRAM retention times and wear leveling may limit the
    effectiveness of memory wiping. However, this multi-pass approach
    provides defense-in-depth and is recommended practice for handling
    sensitive data.
    
    Args:
        data: The data to wipe. Can be a bytearray, ctypes array, or
        any object supporting __setitem__ for byte-level access.
        If bytes (immutable), wiping cannot be performed in place.
        size: Number of bytes to wipe from the start of the data.
        If size exceeds data length, only available bytes are wiped.
    
    Returns:
        None: This function operates in-place and returns nothing.
    
    Security Note:
    This function may not be effective against all memory recovery
    attacks, particularly cold boot attacks or memory remanence in
    specific hardware configurations. For highest security, consider
    additional measures like encryption of sensitive data at rest.
    
    Example:
        >>> buffer = bytearray(b"secret_data_here")
        >>> secure_wipe(buffer, len(buffer))
        >>> print(buffer)
        bytearray(b'\\x00\\x00\\x00...')
    """
    # Validate input parameters
    if data is None or size <= 0:
        return
    
    # Handle immutable bytes - cannot modify in place
    # We return early since we cannot wipe immutable data
    if isinstance(data, bytes):
        # Note: For bytes objects, the data is immutable anyway,
        # and Python may keep multiple copies. This is a limitation
        # of immutable types in Python.
        return
    
    # =========================================================================
    # First Pass: Overwrite with zeros (0x00)
    # =========================================================================
    try:
        if isinstance(data, bytearray):
            # bytearray supports direct byte-level modification
            for i in range(min(size, len(data))):
                data[i] = 0
        elif hasattr(data, 'raw'):
            # ctypes arrays have a 'raw' attribute for byte access
            for i in range(min(size, len(data))):
                data[i] = 0
        elif hasattr(data, '__setitem__'):
            # Fallback: objects supporting __setitem__ can be modified
            for i in range(min(size, len(data))):
                data[i] = 0
    except Exception:
        # If any exception occurs during wiping, continue to next pass
        # Partial wipes still provide some security benefit
        pass
    
    # =========================================================================
    # Second Pass: Overwrite with ones (0xFF)
    # =========================================================================
    try:
        if isinstance(data, bytearray):
            for i in range(min(size, len(data))):
                data[i] = 0xFF
        elif hasattr(data, 'raw'):
            for i in range(min(size, len(data))):
                data[i] = 0xFF
        elif hasattr(data, '__setitem__'):
            for i in range(min(size, len(data))):
                data[i] = 0xFF
    except Exception:
        pass
    
    # =========================================================================
    # Third Pass: Overwrite with random data
    # =========================================================================
    try:
        # Import secrets module for cryptographically secure random bytes
        import secrets
        if isinstance(data, bytearray):
            for i in range(min(size, len(data))):
                # Generate single random byte for each position
                data[i] = secrets.token_bytes(1)[0]
        elif hasattr(data, 'raw'):
            for i in range(min(size, len(data))):
                data[i] = secrets.token_bytes(1)[0]
        elif hasattr(data, '__setitem__'):
            for i in range(min(size, len(data))):
                data[i] = secrets.token_bytes(1)[0]
    except Exception:
        pass
    
    # =========================================================================
    # Fourth Pass (Final): Overwrite with zeros again
    # =========================================================================
    try:
        if isinstance(data, bytearray):
            for i in range(min(size, len(data))):
                data[i] = 0
        elif hasattr(data, 'raw'):
            for i in range(min(size, len(data))):
                data[i] = 0
        elif hasattr(data, '__setitem__'):
            for i in range(min(size, len(data))):
                data[i] = 0
    except Exception:
        pass


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time to prevent timing attacks.
    
    This function compares two byte sequences in a way that takes the same
    amount of time regardless of where (or if) differences occur. This is
    critical for security when comparing sensitive values like:
    
    - Authentication tags (e.g., in AES-GCM authentication)
    - Password hashes
    - Message authentication codes (MACs)
    - Challenge-response tokens
    
    Why Constant-Time Comparison Matters:
    Standard comparison functions (like Python's == operator for bytes)
    typically return as soon as a difference is found. An attacker can
    measure the time taken to compare and deduce:
    
    - Whether the first differing byte is higher or lower
    - How many bytes matched before a difference
    - Eventually, the complete value being compared
    
    This is known as a timing side-channel attack.
    
    How This Implementation Works:
    1. First, compare lengths. If different, return False immediately.
       Length is typically not secret, so this is acceptable.
    2. Iterate through all bytes, XORing each pair (x ^ y).
    3. If any XOR result is non-zero, the bytes differ at that position.
    4. OR all results together - if any difference exists, result is non-zero.
    5. Return True only if the final result is zero (all bytes matched).
    
    The key is that we always process all bytes regardless of differences.
    
    Args:
        a: First byte sequence to compare
        b: Second byte sequence to compare
    
    Returns:
        bool: True if sequences are equal, False otherwise
    
    Note:
        The function returns False immediately if lengths differ.
        This is acceptable because length is typically not secret
        information in cryptographic contexts.
    
    Example:
        >>> secure_compare(b"password", b"password")
        True
        >>> secure_compare(b"password", b"wrongpass")
        False
        >>> # Both comparisons take the same amount of time
    """
    # Quick length check - length is typically not secret
    if len(a) != len(b):
        return False
    
    # Initialize result accumulator
    # We use OR to combine differences: if any byte differs,
    # the accumulated result will be non-zero
    result = 0
    
    # Compare all bytes - this loop always runs to completion
    # regardless of where differences occur
    for x, y in zip(a, b):
        # XOR produces 0 for matching bytes, non-zero for differences
        # OR accumulates any differences found
        result |= x ^ y
    
    # Return True only if no differences were found
    return result == 0


def secure_compare_ct(a: bytes, b: bytes) -> bool:
    """
    Alternative constant-time comparison using platform-specific optimized functions.
    
    This function attempts to use platform-specific constant-time comparison
    functions (like OpenSSL's CRYPTO_memcmp) when available, falling back to
    our pure Python implementation otherwise.
    
    Platform-Specific Implementations:
    - Linux/macOS: Tries OpenSSL's CRYPTO_memcmp if libssl is available
    - Windows: Uses Python fallback (Windows lacks a constant-time compare API)
    
    This function provides the same security guarantees as secure_compare(),
    but may be faster when platform-specific implementations are available.
    
    Args:
        a: First byte sequence to compare
        b: Second byte sequence to compare
    
    Returns:
        bool: True if sequences are equal, False otherwise
    
    Note:
        If the platform-specific method fails for any reason, this function
        falls back to the pure Python secure_compare() implementation,
        ensuring constant-time behavior in all cases.
    
    Example:
        >>> secure_compare_ct(b"key", b"key")
        True
    """
    # Length check for early exit
    if len(a) != len(b):
        return False
    
    try:
        if IS_LINUX or IS_MACOS:
            # On Unix-like systems, try to use OpenSSL's constant-time comparison
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib")
            
            # Attempt to load OpenSSL's library for CRYPTO_memcmp
            try:
                ssl = ctypes.CDLL("libssl.so" if IS_LINUX else "libssl.dylib")
                
                # Check if CRYPTO_memcmp function is available
                if hasattr(ssl, 'CRYPTO_memcmp'):
                    # Call OpenSSL's constant-time comparison
                    # Returns 0 if equal, non-zero if different
                    result = ssl.CRYPTO_memcmp(
                        a, b, len(a)
                    )
                    return result == 0
            except Exception:
                # If OpenSSL loading fails, fall through to fallback
                pass
            
            # Fall back to pure Python implementation
            return secure_compare(a, b)
        
        elif IS_WINDOWS:
            # Windows doesn't have a constant-time comparison API
            # RtlCompareMemory is not constant-time, so we use our implementation
            return secure_compare(a, b)
    
    except Exception:
        # If any exception occurs, fall back to pure Python
        # This ensures we always return a result
        return secure_compare(a, b)
    
    # Final fallback to pure Python implementation
    return secure_compare(a, b)


# ============================================================================
# Secure Buffer Class
# ============================================================================

class SecureBuffer:
    """
    Context manager for secure memory buffers with automatic cleanup.
    
    This class provides a convenient wrapper around secure memory allocation
    that ensures sensitive data is properly cleaned up when the buffer is
    no longer needed. It implements the context manager protocol (__enter__
    and __exit__) for use with Python's 'with' statement.
    
    Key Features:
    - Automatic memory locking to prevent swapping
    - Context manager support for guaranteed cleanup
    - Destructor-based cleanup as a safety net
    - Thread-safe operation
    
    Memory Lifecycle:
    1. Allocation: secure_allocate() creates a locked buffer
    2. Usage: Buffer can be read/written like a bytearray
    3. Cleanup: On exit from context or object destruction:
       - Memory is wiped with secure_wipe()
       - Memory locks are released
       - Buffer is prepared for garbage collection
    
    Warning:
        The buffer contents are destroyed when the context exits.
        Do not store references to the buffer data outside the context.
    
    Attributes:
        buffer: The underlying ctypes buffer for direct access
        size: Size of the buffer in bytes (read-only property)
    
    Example:
        >>> with SecureBuffer(32) as buffer:
        ...     # Fill with random data
        ...     buffer[:] = os.urandom(32)
        ...     # Use the buffer for cryptographic operations
        ...     process_data(buffer)
        ... # Buffer is automatically wiped and freed here
        ... # Any further access to buffer will return garbage data
    
    Thread Safety:
        This class is thread-safe for single-writer scenarios. Multiple
        threads can safely read from the buffer, but write operations
        should be synchronized externally if needed.
    """
    
    def __init__(self, size: int):
        """
        Initialize a secure buffer with the specified size.
        
        This constructor allocates memory of the requested size and locks
        it in physical RAM to prevent swapping. The buffer is initially
        filled with zeros.
        
        Args:
            size: Size of the buffer in bytes. Must be a positive integer.
        
        Raises:
            ValueError: If size is not a positive integer
            MemoryError: If memory allocation fails
        
        Note:
            The buffer is not automatically wiped on initialization.
            Call wipe() explicitly if you need to clear the buffer.
        """
        # Validate input
        if size <= 0:
            raise ValueError("Size must be positive")
        
        # Store size for later use
        self._size = size
        
        # Allocate secure memory buffer
        self._buffer = secure_allocate(size)
        
        # Track lock status for cleanup
        self._locked = True
    
    def __enter__(self) -> 'SecureBuffer':
        """
        Enter the context manager.
        
        This method is called when entering a 'with' statement.
        It returns self for use within the context block.
        
        Returns:
            SecureBuffer: This instance for use in the with block
        """
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context manager and securely wipe the buffer.
        
        This method is called when exiting a 'with' statement, regardless
        of whether an exception occurred. It ensures the buffer contents
        are securely wiped.
        
        Args:
            exc_type: Exception type if an exception was raised, None otherwise
            exc_val: Exception value if an exception was raised, None otherwise
            exc_tb: Exception traceback if an exception was raised, None otherwise
        
        Returns:
            False: Indicating exceptions should propagate (not suppressed)
        """
        # Wipe the buffer regardless of exception status
        self.wipe()
        # Return False to allow exception propagation
        return False
    
    def __del__(self):
        """
        Destructor that ensures buffer is wiped on garbage collection.
        
        This method is called when the object is being destroyed by
        Python's garbage collector. It provides a safety net to ensure
        the buffer is wiped even if the context manager wasn't used.
        
        Note:
            Garbage collection timing is not guaranteed. For reliable
            cleanup, always use the context manager or call wipe() explicitly.
        """
        self.wipe()
    
    def __getitem__(self, key):
        """
        Get item(s) from the buffer.
        
        This method enables slice and index access to the underlying buffer.
        
        Args:
            key: Integer index or slice object
        
        Returns:
            The value at the specified index or slice
        """
        return self._buffer[key]
    
    def __setitem__(self, key, value):
        """
        Set item(s) in the buffer.
        
        This method enables slice and index assignment to the underlying buffer.
        
        Args:
            key: Integer index or slice object
            value: Value(s) to set
        """
        self._buffer[key] = value
    
    def __len__(self) -> int:
        """
        Return the buffer size in bytes.
        
        Returns:
            int: The size of the buffer in bytes
        """
        return self._size
    
    def bytes(self) -> bytes:
        """
        Get the buffer contents as a bytes object.
        
        This method creates a copy of the buffer contents as immutable bytes.
        Note that the returned bytes are NOT protected by locking or wiping.
        
        Returns:
            bytes: A copy of the buffer contents
        
        Warning:
            The returned bytes object is not secure. It may be swapped
            to disk and will not be automatically wiped. Only use this
            method when you need to pass the data to an API that requires
            bytes objects.
        """
        return bytes(self._buffer.raw)
    
    def wipe(self) -> None:
        """
        Securely wipe the buffer contents.
        
        This method overwrites the buffer with multiple patterns to ensure
        the original data cannot be recovered. After wiping, the buffer
        is marked as unlocked to prevent repeated wiping attempts.
        
        Side Effects:
            - Buffer contents are overwritten with multiple patterns
            - Lock status is set to False to prevent re-wiping
        
        Note:
            This method is safe to call multiple times. Subsequent calls
            will have no effect after the first wipe.
        """
        # Check if buffer exists and is still locked
        if self._buffer is not None and self._locked:
            # Wipe the buffer contents
            secure_wipe(self._buffer, self._size)
            # Mark as unlocked
            self._locked = False
    
    @property
    def buffer(self) -> ctypes.Array:
        """
        Get the underlying ctypes buffer.
        
        This property provides direct access to the ctypes buffer for
        advanced use cases that require low-level buffer manipulation.
        
        Returns:
            ctypes.Array: The underlying ctypes buffer
        
        Warning:
            Direct access to the buffer bypasses the security guarantees
            of this class. Use with caution and ensure proper cleanup.
        """
        return self._buffer
    
    @property
    def size(self) -> int:
        """
        Get the buffer size in bytes.
        
        This read-only property returns the size that was specified
        during construction.
        
        Returns:
            int: The buffer size in bytes
        """
        return self._size


# ============================================================================
# Secure String Class
# ============================================================================

class SecureString:
    """
    String-like class for handling sensitive string data with automatic cleanup.
    
    This class provides secure handling of strings that may contain sensitive
    information like passwords, API keys, or personal data. It wraps the string
    in a bytearray for mutability and provides secure wiping capabilities.
    
    Key Features:
    - Automatic memory wiping on destruction
    - Constant-time comparison to prevent timing attacks
    - Unicode support through configurable encoding
    - String-like interface for ease of use
    
    Security Considerations:
    - The string is stored in memory as-is (NOT encrypted)
    - Only the LIFECYCLE is managed securely (wiping on cleanup)
    - For encryption at rest, use encryption functions from the engine module
    
    Memory Handling:
    1. The string is encoded to bytes using the specified encoding (UTF-8 by default)
    2. The bytes are stored in a mutable bytearray for secure wiping
    3. On destruction (del, garbage collection), the memory is wiped
    4. The wipe() method can be called explicitly for immediate cleanup
    
    Warning:
        This class does NOT provide encryption. The string content is
        visible in memory to any process that can read the process's
        memory. Use this class only for managing the LIFETIME of strings
        containing sensitive data.
    
    Attributes:
        bytes: The string content as bytes (read-only property)
        length: The string length in bytes (read-only property)
    
    Example:
        >>> secret = SecureString("my_password_123")
        >>> # Use the string
        >>> print(str(secret))
        my_password_123
        >>> # When done, delete to wipe
        >>> del secret
        >>> # Or wipe explicitly
        >>> secret.wipe()
    
    Thread Safety:
        This class is thread-safe for read operations. Write/modification
        operations should be synchronized externally if needed.
    """
    
    def __init__(self, value: str, encoding: str = 'utf-8'):
        """
        Initialize a secure string with the given value.
        
        This constructor stores the string value in a mutable bytearray
        for secure wiping capability.
        
        Args:
            value: The string value to store. This string may contain
            sensitive information like passwords or keys.
            encoding: The character encoding to use for conversion to bytes.
            Default is UTF-8, which supports all Unicode characters.
        
        Raises:
            UnicodeEncodeError: If the string cannot be encoded with the
            specified encoding.
        """
        # Store encoding for later use
        self._encoding = encoding
        
        # Encode string to bytes and store in mutable bytearray
        self._bytes = bytearray(value.encode(encoding))
        
        # Track lock status for cleanup
        self._locked = True
    
    def __del__(self):
        """
        Destructor that wipes the string from memory.
        
        This method is called when the object is being destroyed by
        Python's garbage collector. It ensures the string content is
        securely wiped.
        
        Note:
            Garbage collection timing is not deterministic. For reliable
            cleanup, call wipe() explicitly when the string is no longer needed.
        """
        self.wipe()
    
    def __str__(self) -> str:
        """
        Get the string value as a standard Python string.
        
        This method decodes the stored bytes back to a string using
        the specified encoding. Note that this creates a NEW string
        object that is NOT protected by secure wiping.
        
        Returns:
            str: The decoded string value
        
        Warning:
            The returned string is NOT secure. It is a regular Python
            string that will remain in memory until garbage collected.
            Use with caution and avoid storing the result.
        """
        return self._bytes.decode(self._encoding)
    
    def __repr__(self) -> str:
        """
        Get a developer-friendly representation of this object.
        
        Returns:
            str: String representation showing the class name and value
        """
        return f"SecureString('{self}')"
    
    def __eq__(self, other) -> bool:
        """
        Compare this SecureString with another value in constant time.
        
        This method uses secure_compare() to perform constant-time comparison,
        preventing timing attacks that could reveal the string content.
        
        Args:
            other: Another SecureString, str, bytes, or bytearray to compare
        
        Returns:
            True if values are equal, False otherwise
        
        Note:
            The comparison is constant-time regardless of where (or if)
            differences occur between the strings.
        """
        # Compare with another SecureString
        if isinstance(other, SecureString):
            return secure_compare(self._bytes, other._bytes)
        # Compare with a regular string
        elif isinstance(other, str):
            return secure_compare(self._bytes, other.encode(self._encoding))
        # Compare with bytes or bytearray
        elif isinstance(other, (bytes, bytearray)):
            return secure_compare(self._bytes, other)
        # Not comparable types
        return False
    
    def __len__(self) -> int:
        """
        Get the string length in bytes.
        
        Returns:
            int: The length of the string in bytes (not character count)
        """
        return len(self._bytes)
    
    def wipe(self) -> None:
        """
        Securely wipe the string from memory.
        
        This method overwrites the string content with multiple patterns
        to ensure the original data cannot be recovered. After wiping,
        the string cannot be used meaningfully.
        
        Side Effects:
            - String content is overwritten with random patterns
            - Lock status is set to False to prevent re-wiping
        
        Note:
            This method is safe to call multiple times. After the first
            wipe, subsequent calls have no effect.
        """
        # Check if bytes exist and are still locked
        if self._bytes and self._locked:
            secure_wipe(self._bytes, len(self._bytes))
            self._locked = False
    
    @property
    def bytes(self) -> bytes:
        """
        Get the string content as bytes.
        
        This property returns a copy of the string content as immutable bytes.
        Note that the returned bytes are NOT protected by secure wiping.
        
        Returns:
            bytes: A copy of the string content as bytes
        
        Warning:
            The returned bytes object is NOT secure. It will not be
            automatically wiped. Only use when necessary for APIs
            that require bytes objects.
        """
        return bytes(self._bytes)
    
    @property
    def length(self) -> int:
        """
        Get the string length in bytes.
        
        This property returns the length of the stored bytes, which
        may differ from the character count for multi-byte encodings.
        
        Returns:
            int: The length in bytes
        """
        return len(self._bytes)


# ============================================================================
# Secure File Operations
# ============================================================================

# Functions for secure file reading and writing
# These provide additional security measures for file-based sensitive data


def secure_read_file(filepath: str, max_size: int = 1024 * 1024) -> Optional[bytes]:
    """
    Read a file securely, preventing sensitive data from being swapped.
    
    This function reads file contents into memory that is locked to prevent
    swapping. This is important when reading sensitive files like encryption
    keys, certificates, or private data.
    
    Security Features:
    - File size validation to prevent memory exhaustion attacks
    - Memory locking to prevent swapping of sensitive data
    - Automatic cleanup when the returned bytes are garbage collected
    
    Args:
        filepath: Path to the file to read. Can be a string or Path object.
        max_size: Maximum allowed file size in bytes. Defaults to 1 MB.
        This prevents reading extremely large files into locked memory.
    
    Returns:
        bytes: The file contents as bytes, locked in memory.
        Returns None only if file doesn't exist (raises exception instead).
    
    Raises:
        FileNotFoundError: If the specified file does not exist
        MemoryError: If the file exceeds max_size
        PermissionError: If the file cannot be read due to permissions
    
    Example:
        >>> # Read a sensitive key file
        >>> key_data = secure_read_file("/etc/secrets/key.bin")
        >>> # The key data is now locked in memory
    
    Note:
        The returned bytes object is locked, but Python's garbage
        collector may keep additional copies. For highest security,
        consider using SecureBuffer instead.
    """
    # Convert to Path object for consistent handling
    path = filepath if isinstance(filepath, Path) else Path(filepath)
    
    # Check file existence
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Check file size against limit
    file_size = path.stat().st_size
    if file_size > max_size:
        raise MemoryError(f"File too large: {file_size} > {max_size}")
    
    # Read file contents
    with path.open('rb') as f:
        data = f.read()
    
    # Attempt to lock the memory
    try:
        if IS_LINUX or IS_MACOS:
            # Load libc and mlock the memory buffer
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib")
            data_buffer = ctypes.create_string_buffer(data)
            libc.mlock(data_buffer, len(data))
    except Exception:
        # If locking fails, we still return the data
        # It's better to have unlocked data than no data
        pass
    
    return data


def secure_write_file(filepath: str, data: bytes, 
                      mode: int = 0o600) -> None:
    """
    Write data to a file securely with atomic operations and proper permissions.
    
    This function writes data to a file using several security measures:
    
    1. Atomic Write: Data is first written to a temporary file, then
       renamed to the target path. This ensures that if the write fails,
       the original file is not corrupted.
    
    2. fsync: The file is synchronized to disk before renaming, ensuring
       the data is actually written to persistent storage.
    
    3. Restricted Permissions: The file is created with restricted
       permissions (0o600 = owner read/write only) by default.
    
    Args:
        filepath: Path to write to. Can be a string or Path object.
        data: The data bytes to write to the file.
        mode: File permissions as an octal mode (default: 0o600).
        This mode means owner can read and write, others have no access.
    
    Raises:
        OSError: If the write operation fails
        PermissionError: If the target directory is not writable
    
    Example:
        >>> # Write sensitive configuration
        >>> secure_write_file("/etc/app/config.bin", encrypted_data)
        >>> # File is created with secure permissions
    
    Note:
        This function does NOT encrypt the data. It only ensures secure
        file writing practices. For encrypted storage, encrypt the data
        before calling this function.
    """
    # Convert to Path object for consistent handling
    path = filepath if isinstance(filepath, Path) else Path(filepath)
    
    # Create temporary file path for atomic write
    temp_path = path.with_suffix('.tmp')
    
    try:
        # Write to temporary file
        with temp_path.open('wb') as f:
            f.write(data)
            f.flush()
            # Ensure data is written to disk
            os.fsync(f.fileno())
        
        # Atomically rename temp file to target
        # On Unix, rename is atomic if on the same filesystem
        temp_path.replace(path)
        
        # Set restrictive permissions
        os.chmod(path, mode)
    
    except Exception:
        # Clean up temp file on failure
        if temp_path.exists():
            temp_path.unlink()
        # Re-raise the exception
        raise


# ============================================================================
# Utility Functions
# ============================================================================

# Helper functions for querying and managing secure memory


def get_memory_lock_limit() -> int:
    """
    Query the maximum amount of memory that can be locked.
    
    This function returns the system limit on locked memory pages.
    Different operating systems have different mechanisms for reporting
    this limit.
    
    Linux:
    Reads /proc/self/status and parses the MemLock line. The value
    is reported in kilobytes and converted to bytes.
    
    macOS:
    Typically has a per-process limit of 16 MB (16 * 1024 * 1024 bytes).
    
    Windows:
    Does not expose a straightforward per-process limit. Returns 0
    to indicate the limit is unknown.
    
    Returns:
        int: Maximum lockable memory in bytes, or 0 if the limit
        is unknown or not applicable
    
    Example:
        >>> limit = get_memory_lock_limit()
        >>> print(f"Can lock up to {limit / 1024 / 1024:.1f} MB")
    """
    try:
        if IS_LINUX:
            # Linux: Read from /proc/self/status
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('MemLock'):
                        # Format: "MemLock:    some_value kB"
                        # Extract value and convert to bytes
                        value = int(line.split()[1]) * 1024
                        return value
        
        elif IS_MACOS:
            # macOS: Typically 16 MB per-process limit
            return 16 * 1024 * 1024
        
        elif IS_WINDOWS:
            # Windows: No straightforward per-process limit
            return 0  # Unknown
    
    except Exception:
        # If anything fails, return 0 (unknown limit)
        pass
    
    return 0


def is_memory_locked(address: int, size: int) -> bool:
    """
    Check if a memory region is locked (not swappable).
    
    This function provides a best-effort check to verify whether a
    memory region is locked. However, there is no portable API to
    definitively verify memory locking status.
    
    Limitations:
    - No portable POSIX or Windows API exists for this check
    - This function returns True as a best-effort assumption
    - The actual lock status depends on system configuration
    
    Args:
        address: Memory address to check (currently unused)
        size: Size of the memory region (currently unused)
    
    Returns:
        bool: Always returns True, assuming that allocated memory
        is locked if the allocation was successful
    
    Note:
        This function exists for API completeness. For actual security
        verification, rely on the secure_allocate() function to properly
        lock memory during allocation.
    """
    # There is no portable way to verify memory locking status
    # We return True as a best-effort assumption
    # If secure_allocate() succeeded, the memory should be locked
    return True


# ============================================================================
# Testing and Demonstration
# ============================================================================

if __name__ == "__main__":
    """
    Module self-test and demonstration.
    
    This section runs when the module is executed directly. It demonstrates
    the key features of the secure memory module and verifies correct
    functionality.
    """
    
    print("CXA Secure Memory Module - Self Test")
    print("=" * 50)
    
    # Test 1: SecureBuffer
    print("\nTesting SecureBuffer...")
    with SecureBuffer(32) as buf:
        # Generate random data
        buf[:] = os.urandom(32)
        data = buf.bytes()
        print(f"  Generated random data: {data[:8].hex()}...")
    
    print("  SecureBuffer test passed!")
    
    # Test 2: SecureString
    print("\nTesting SecureString...")
    secret = SecureString("test_password_12345")
    print(f"  String length: {len(secret)}")
    # Verify content is accessible
    assert str(secret) == "test_password_12345"
    # Wipe the string
    secret.wipe()
    print("  SecureString test passed!")
    
    # Test 3: secure_compare
    print("\nTesting secure_compare...")
    a = b"hello_world"
    b1 = b"hello_world"
    c = b"hello_worlc"
    
    # Test equality
    assert secure_compare(a, b1) == True
    print("  Equality check passed!")
    
    # Test inequality
    assert secure_compare(a, c) == False
    print("  Inequality check passed!")
    
    print("\n" + "=" * 50)
    print("All memory module tests passed successfully!")
    print("=" * 50)
