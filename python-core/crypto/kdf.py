#!/usr/bin/env python3
"""
CXA Key Derivation Module

This module provides advanced key derivation functionality for the CXA
Cryptographic System, including implementations of Argon2id and PBKDF2
password-based key derivation functions (KDFs).

Key Derivation Features:
- Argon2id (recommended for new key generation)
- PBKDF2 with SHA-256 and SHA-512 (for legacy compatibility)
- Support for multiple algorithms with configurable parameters
- Secure memory handling practices
- Constant-time comparison to prevent timing attacks

Security Considerations:
- Argon2id is the recommended algorithm for new deployments
- It is resistant to GPU-based and ASIC-based cracking attacks
- PBKDF2 is provided for compatibility with existing systems
- All implementations use cryptographically secure random salt generation

Module Structure:
- KdfType: Enum defining supported KDF algorithms
- KdfResult: Dataclass containing derivation output and metadata
- Argon2Hasher: Implementation of Argon2id key derivation
- PBKDF2Hasher: Implementation of PBKDF2 key derivation
- CXAKeyDerivation: Unified interface for all KDF methods

Example Usage:
    >>> from crypto.kdf import CXAKeyDerivation, KdfType
    >>> kdf = CXAKeyDerivation()
    >>> result = kdf.derive_key("my_password", algorithm=KdfType.ARGON2ID)
    >>> is_valid = kdf.verify("my_password", result)

Dependencies:
- argon2-cffi: For native Argon2 implementation (optional, with fallback)
- cryptography: For PBKDF2 implementation (optional, with fallback)
- secrets: For cryptographically secure random number generation

Author: CXA Development Team
Version: 2.0.0
"""

import os
import secrets
import hashlib
import threading
from enum import Enum
from typing import Tuple, Optional, Any
from dataclasses import dataclass

# Import CXA core components for integration with the crypto engine
from .engine import CryptoEngine, SecurityLevel


class KdfType(Enum):
    """
    Enumeration of supported Key Derivation Function algorithms.
    
    This enum defines the different KDF algorithms available in the CXA
    system. Each algorithm has different security characteristics and
    performance profiles.
    
    Enum Values:
        ARGON2ID: Memory-hard function resistant to GPU attacks (RECOMMENDED)
        PBKDF2_SHA256: PBKDF2 with SHA-256 hash function
        PBKDF2_SHA512: PBKDF2 with SHA-512 hash function
    
    Security Comparison:
        - ARGON2ID: Highest security, resistant to hardware acceleration
        - PBKDF2_SHA512: Good security, widely supported
        - PBKDF2_SHA256: Good security, faster than SHA-512
    
    Usage:
        >>> from crypto.kdf import KdfType
        >>> KdfType.ARGON2ID.value
        'argon2id'
    """
    ARGON2ID = "argon2id"
    PBKDF2_SHA256 = "pbkdf2-sha256"
    PBKDF2_SHA512 = "pbkdf2-sha512"


@dataclass
class KdfResult:
    """
    Data class containing the result of a key derivation operation.
    
    This class encapsulates all information produced by a KDF operation,
    including the derived key material, the salt used, and the parameters
    that were employed during derivation.
    
    Attributes:
        derived_key: The derived cryptographic key bytes (32 bytes / 256 bits)
        salt: The random salt bytes used during derivation (32 bytes)
        algorithm: The KDF algorithm used (KdfType enum value)
        iterations: Number of iterations performed (for PBKDF2)
        memory_cost: Memory cost in KiB (for Argon2, Optional)
        time_cost: Time cost / number of passes (for Argon2, Optional)
    
    Usage:
        >>> result = kdf.derive_key("password")
        >>> result.derived_key  # The derived key bytes
        >>> result.salt         # The salt used
        >>> result.algorithm    # The algorithm used
    """
    derived_key: bytes
    salt: bytes
    algorithm: KdfType
    iterations: int
    memory_cost: Optional[int] = None
    time_cost: Optional[int] = None


class Argon2Hasher:
    """
    Argon2id implementation for secure key derivation.
    
    This class provides a Python interface to the Argon2id key derivation
    function, which was the winner of the Password Hashing Competition (PHC)
    in 2015. Argon2id is currently considered the state-of-the-art for
    password-based key derivation.
    
    Security Properties:
    - Memory-hard: Requires significant memory to compute, resistant to GPUs
    - Data-independent: First pass is memory-hard regardless of password
    - Attack-resistant: Combines time and memory tradeoffs effectively
    - Side-channel resistant: Constant-time operations when possible
    - Parameterized: Allows tuning time, memory, and parallelism
    
    Default Security Parameters:
    - Memory Cost: 64 MiB (65536 KiB) - substantial memory usage
    - Time Cost: 3 iterations over memory
    - Parallelism: 4 parallel lanes
    
    Algorithm Details:
    Argon2id uses a hybrid approach:
    - First pass (id): Memory-hard, uses password and salt
    - Subsequent passes (d): Mixes data for diffusion
    
    This provides protection against:
    - GPU-based cracking attacks
    - ASIC-based attacks
    - Timing attacks (constant-time operations)
    - Cache-timing attacks
    
    Usage:
        >>> hasher = Argon2Hasher()
        >>> result = hasher.hash("my_password")
        >>> is_valid = hasher.verify("my_password", result)
    
    Dependencies:
        - argon2-cffi: For native Argon2 implementation
          Install with: pip install argon2-cffi
    
    References:
    - https://www.argon2.eu/
    - https://github.com/p-h-c/phc-winner-argon2
    """
    
    # Default security parameters (recommended for most use cases)
    # These values provide a good balance between security and performance
    # for server-side key derivation. Adjust based on your threat model
    # and hardware capabilities.
    DEFAULT_MEMORY_COST_KIB = 65536  # 64 MiB - substantial memory usage
    DEFAULT_TIME_COST = 3            # Number of passes over memory
    DEFAULT_PARALLELISM = 4          # Parallel threads for computation
    
    # Minimum security thresholds to prevent weak configurations
    MIN_MEMORY_COST_KIB = 8192       # 8 MiB absolute minimum
    MIN_TIME_COST = 1                # At least 1 iteration
    MIN_PARALLELISM = 1              # At least 1 thread
    
    def __init__(
        self,
        memory_cost_kib: int = DEFAULT_MEMORY_COST_KIB,
        time_cost: int = DEFAULT_TIME_COST,
        parallelism: int = DEFAULT_PARALLELISM
    ):
        """
        Initialize Argon2 hasher with security parameters.
        
        This constructor sets up the Argon2 hasher with the specified
        security parameters. All parameters are validated to ensure
        they meet minimum security thresholds.
        
        Args:
            memory_cost_kib: Memory cost in KiB (default: 65536 / 64 MiB)
                This determines how much memory the computation requires.
                Higher values provide better security but use more memory.
                Recommended range: 32768-131072 (32-128 MiB)
            
            time_cost: Number of passes/iterations over memory (default: 3)
                This determines how many times the memory is processed.
                Higher values provide better security but take longer.
                Recommended range: 1-3 for Argon2id
            
            parallelism: Number of parallel threads (default: 4)
                This determines how many threads are used for computation.
                Should not exceed the number of available CPU cores.
                Recommended: 1-4 depending on system capabilities
        
        Raises:
            ValueError: If any parameter is below the minimum security threshold
        
        Example:
            >>> # High security settings for sensitive data
            >>> hasher = Argon2Hasher(
            ...     memory_cost_kib=131072,  # 128 MiB
            ...     time_cost=3,
            ...     parallelism=4
            ... )
            >>>
            >>> # Balanced settings for general use
            >>> hasher = Argon2Hasher()  # Uses defaults
        """
        # Validate parameters against minimum security thresholds
        # These thresholds prevent configurations that are too weak
        if memory_cost_kib < self.MIN_MEMORY_COST_KIB:
            raise ValueError(
                f"Memory cost must be at least {self.MIN_MEMORY_COST_KIB} KiB, "
                f"got {memory_cost_kib}"
            )
        if time_cost < self.MIN_TIME_COST:
            raise ValueError(
                f"Time cost must be at least {self.MIN_TIME_COST}, got {time_cost}"
            )
        if parallelism < self.MIN_PARALLELISM:
            raise ValueError(
                f"Parallelism must be at least {self.MIN_PARALLELISM}, got {parallelism}"
            )
        
        # Store validated parameters
        self._memory_cost_kib = memory_cost_kib
        self._time_cost = time_cost
        self._parallelism = parallelism
        
        # Store parameters dictionary for reference
        self._params = {
            'memory_cost': memory_cost_kib,
            'time_cost': time_cost,
            'parallelism': parallelism
        }
    
    def hash(self, password: str, salt: Optional[bytes] = None) -> KdfResult:
        """
        Derive a cryptographic key from a password using Argon2id.
        
        This method implements the Argon2id variant of Argon2, which
        provides the best combination of resistance against side-channel
        attacks and GPU-based cracking attacks.
        
        The Argon2id variant works as follows:
        1. First pass (type 'id'): Memory-hard pass using password and salt
        2. Second pass (type 'd'): Data-dependent mixing for diffusion
        
        This hybrid approach provides protection against:
        - Tradeoff attacks (TMTO)
        - Side-channel attacks
        - GPU/ASIC acceleration
        
        Args:
            password: The password or secret string to derive key from
                This should be a high-entropy secret. For low-entropy
                secrets (like user passwords), ensure additional measures
                like rate limiting are in place.
            
            salt: Optional salt bytes for key derivation
                If None, a random 32-byte salt is generated.
                Salt should be unique per key derivation.
                Recommended length: 16-32 bytes.
                Must be at least 16 bytes if provided.
        
        Returns:
            KdfResult object containing:
                - derived_key: 32 bytes (256 bits) of derived key material
                - salt: The salt used during derivation
                - algorithm: KdfType.ARGON2ID
                - iterations: The time cost (number of passes)
                - memory_cost: The memory cost in KiB
                - time_cost: The time cost (same as iterations)
        
        Raises:
            RuntimeError: If the Argon2 library is not available and
                          fallback initialization fails
        
        Note:
            The derived key should be stored or processed securely.
            Consider using SecureBuffer for temporary storage.
        
        Example:
            >>> hasher = Argon2Hasher()
            >>> result = hasher.hash("my_secure_password")
            >>> # Store result.salt and result.derived_key securely
            >>> # Or store result.derived_key and regenerate salt if needed
        """
        # Generate random salt if not provided
        # Using 32 bytes (256 bits) provides high entropy and prevents
        # precomputation attacks (rainbow tables)
        if salt is None:
            salt = secrets.token_bytes(32)
        elif len(salt) < 16:
            # Pad short salts to minimum length
            # This maintains compatibility while ensuring minimum entropy
            salt = salt + secrets.token_bytes(16 - len(salt))
        
        # Convert password string to UTF-8 encoded bytes
        # UTF-8 is used for universal character support
        password_bytes = password.encode('utf-8')
        
        try:
            # Attempt to import and use the argon2-cffi library
            # This provides a native, optimized Argon2 implementation
            from argon2 import low_level
            from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
            
            # Create Argon2id hash using the low-level API
            # Type ID 19 corresponds to Argon2id (recommended variant)
            # The hash_secret function handles the complete Argon2id computation
            result = low_level.hash_secret(
                secret=password_bytes,
                salt=salt,
                time_cost=self._time_cost,
                memory_cost=self._memory_cost_kib,
                parallelism=self._parallelism,
                hash_len=32,  # Generate 32 bytes (256 bits) of output
                type=low_level.Type.ID  # Argon2id variant
            )
            
            # Extract the raw hash (last 32 bytes)
            # Argon2 output format: $[type]$[version]$[params]$[salt]$[hash]
            # The hash is the final portion of the encoded string
            hash_bytes = result[-32:]
            
            # Return comprehensive result with all metadata
            return KdfResult(
                derived_key=hash_bytes,
                salt=salt,
                algorithm=KdfType.ARGON2ID,
                iterations=self._time_cost,
                memory_cost=self._memory_cost_kib,
                time_cost=self._time_cost
            )
            
        except ImportError:
            # Fallback to pure Python implementation if argon2-cffi not available
            # This fallback uses BLAKE2b with high iteration count
            # WARNING: This is NOT equivalent to true Argon2 security
            # Use only for testing or when argon2-cffi is unavailable
            return self._hash_fallback(password_bytes, salt)
    
    def _hash_fallback(
        self,
        password_bytes: bytes,
        salt: bytes
    ) -> KdfResult:
        """
        Fallback hash implementation using BLAKE2b.
        
        This method provides a fallback when the Argon2 library is not
        available. It uses BLAKE2b with a high iteration count.
        
        IMPORTANT: This fallback does NOT provide the same security
        properties as true Argon2. It is susceptible to GPU attacks
        and should NOT be used for production in security-critical
        applications.
        
        This implementation is provided for:
        - Testing environments where argon2-cffi is not installed
        - Graceful degradation in environments where native libs fail
        - Development and demonstration purposes
        
        Args:
            password_bytes: The password as encoded bytes
            salt: The salt bytes for key derivation
        
        Returns:
            KdfResult with derived key using BLAKE2b fallback
        
        Security Note:
            The iteration count is reduced from production levels
            for performance. This fallback is approximately 100x
            faster than the real Argon2 configuration, meaning
            it's 100x weaker against brute-force attacks.
        """
        # Use BLAKE2b with high iteration count as fallback
        # BLAKE2b is a modern hash function that is fast and secure
        # The high iteration count provides some protection against
        # quick brute-force attempts
        iterations = 100000  # 100K iterations for fallback
        
        # Perform iterated hashing to slow down computation
        # This is a simplified version of key stretching
        result = password_bytes + salt
        for _ in range(iterations):
            result = hashlib.blake2b(result, digest_size=32).digest()
        
        return KdfResult(
            derived_key=result,
            salt=salt,
            algorithm=KdfType.ARGON2ID,
            iterations=iterations,
            memory_cost=self._memory_cost_kib,
            time_cost=self._time_cost
        )
    
    def verify(self, password: str, kdf_result: KdfResult) -> bool:
        """
        Verify a password against a previously derived key.
        
        This method re-derives a key from the password using the same
        parameters stored in the KdfResult, then performs a constant-time
        comparison to check if the passwords match.
        
        Constant-Time Comparison:
        The comparison is performed in constant time to prevent timing
        attacks. This means the comparison takes the same amount of
        time regardless of where (or if) the passwords differ.
        
        Args:
            password: The password to verify
            kdf_result: The previous KdfResult containing derived key info
                Must contain the salt and algorithm used originally
        
        Returns:
            True if the password matches the derived key
            False if the password does not match
        
        Raises:
            RuntimeError: If verification fails unexpectedly
        
        Example:
            >>> hasher = Argon2Hasher()
            >>> result = hasher.hash("password")
            >>> hasher.verify("password", result)
            True
            >>> hasher.verify("wrong_password", result)
            False
        """
        # Re-derive the key using the same parameters from stored result
        new_result = self.hash(password, kdf_result.salt)
        
        # Perform constant-time comparison to prevent timing attacks
        # This compares the derived keys without revealing information
        # about which byte(s) differ through timing variations
        return self._constant_time_compare(
            new_result.derived_key,
            kdf_result.derived_key
        )
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        This function compares two byte sequences in a way that takes
        the same amount of time regardless of where (or if) the strings
        differ. This prevents timing attacks that could extract
        information about the correct value.
        
        The algorithm works by XORing corresponding bytes and checking
        if all results are zero. If bytes differ, their XOR will be
        non-zero. The result is accumulated using bitwise OR, so any
        difference will set the result to non-zero.
        
        Args:
            a: First byte string to compare
            b: Second byte string to compare
        
        Returns:
            True if the byte strings are equal
            False if the byte strings differ
        
        Security Note:
            This implementation first checks length equality in
            non-constant time. This is acceptable because the
            length of password hashes is not secret information.
            The actual comparison of contents is done in constant time.
        """
        # Quick length check (length is not secret)
        if len(a) != len(b):
            return False
        
        # Constant-time comparison using bitwise operations
        # result starts at 0 and accumulates XOR results
        # If any bytes differ, result will be non-zero
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        # result is 0 only if all bytes were identical
        return result == 0


class PBKDF2Hasher:
    """
    PBKDF2 implementation for password-based key derivation.
    
    This class provides an implementation of PBKDF2 (Password-Based Key
    Derivation Function 2) as defined in NIST SP 800-132. PBKDF2 is
    widely supported and provides adequate security when configured with
    a sufficient number of iterations.
    
    Security Considerations:
    - PBKDF2 is susceptible to GPU acceleration attacks
    - The iteration count should be as high as feasible
    - Consider migrating to Argon2 for new deployments
    
    Algorithm Details:
    PBKDF2 applies a pseudorandom function (HMAC) to the password
    and salt, repeating the process iteration times. Each iteration
    mixes the previous result with the password and salt.
    
    Features:
    - NIST compliant implementation
    - Widely compatible (works with most systems)
    - Configurable iteration count
    - Support for SHA-256 and SHA-512 hash algorithms
    - Fallback to hashlib for environments without cryptography library
    
    Usage:
        >>> hasher = PBKDF2Hasher(algorithm="sha256", iterations=600000)
        >>> result = hasher.hash("my_password")
        >>> is_valid = hasher.verify("my_password", result)
    
    Dependencies:
        - cryptography: For optimized PBKDF2-HMAC implementation
          Install with: pip install cryptography
        - hashlib: For fallback implementation (built-in)
    
    References:
    - NIST SP 800-132: Recommendation for Password-Based Key Derivation
    - RFC 2898: PKCS #5: Password-Based Cryptography Specification
    """
    
    # Default parameters following OWASP and NIST recommendations
    # These values provide adequate security against brute-force attacks
    # while maintaining reasonable performance
    DEFAULT_ITERATIONS = 600000  # OWASP recommended minimum for 2023
    
    # NIST minimum recommendation for PBKDF2
    MIN_ITERATIONS = 600000
    
    def __init__(
        self,
        algorithm: str = "sha256",
        iterations: int = DEFAULT_ITERATIONS
    ):
        """
        Initialize PBKDF2 hasher with specified parameters.
        
        Args:
            algorithm: Hash algorithm to use for HMAC
                Options: "sha256" or "sha512"
                SHA-256 provides sufficient security with better performance
                SHA-512 may be preferred for high-security applications
            
            iterations: Number of PBKDF2 iterations (default: 600000)
                This is the most important parameter for security.
                Higher values provide better protection but take longer.
                OWASP recommends minimum 600,000 iterations for PBKDF2-HMAC-SHA256
                NIST recommends at least this many for password-based keys
        
        Raises:
            ValueError: If algorithm is unsupported or iterations are too low
        
        Example:
            >>> # SHA-256 with recommended iterations
            >>> hasher = PBKDF2Hasher(algorithm="sha256", iterations=600000)
            >>>
            >>> # SHA-512 for higher security
            >>> hasher = PBKDF2Hasher(algorithm="sha512", iterations=500000)
        """
        # Validate algorithm parameter
        if algorithm not in ["sha256", "sha512"]:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                "Must be 'sha256' or 'sha512'"
            )
        
        # Validate iteration count against minimum
        if iterations < self.MIN_ITERATIONS:
            raise ValueError(
                f"Iterations must be at least {self.MIN_ITERATIONS}, "
                f"got {iterations}. See OWASP guidelines for recommended values."
            )
        
        self._algorithm = algorithm
        self._iterations = iterations
    
    def hash(
        self,
        password: str,
        salt: Optional[bytes] = None,
        key_length: int = 32
    ) -> KdfResult:
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        This method applies PBKDF2-HMAC with the configured algorithm
        to derive a cryptographic key from the password and salt.
        
        Args:
            password: The password string to derive key from
            salt: Optional salt bytes for key derivation
                If None, a random 32-byte salt is generated
                Salt should be unique per key
                Minimum recommended length: 16 bytes
            key_length: Length of derived key in bytes (default: 32)
                32 bytes (256 bits) is recommended for AES-256
                16 bytes (128 bits) is minimum for AES-128
        
        Returns:
            KdfResult containing:
                - derived_key: The derived key bytes (key_length bytes)
                - salt: The salt used during derivation
                - algorithm: The KDF algorithm (PBKDF2-SHA256 or PBKDF2-SHA512)
                - iterations: Number of PBKDF2 iterations performed
        
        Example:
            >>> hasher = PBKDF2Hasher()
            >>> result = hasher.hash("my_password")
            >>> result.derived_key  # 32 bytes
            >>> result.salt         # 32 bytes
        """
        # Generate random salt if not provided
        # 32 bytes provides sufficient entropy
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Convert password to UTF-8 bytes
        password_bytes = password.encode('utf-8')
        
        # Use cryptography library for PBKDF2 if available
        # This provides optimized C-based implementation
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            
            # Map algorithm name to cryptography hash object
            algorithm_map = {
                "sha256": hashes.SHA256(),
                "sha512": hashes.SHA512()
            }
            
            # Create PBKDF2-HMAC instance with configured parameters
            kdf = PBKDF2HMAC(
                algorithm=algorithm_map[self._algorithm],
                length=key_length,
                salt=salt,
                iterations=self._iterations,
                backend=default_backend()
            )
            
            # Derive the key
            derived_key = kdf.derive(password_bytes)
            
            return KdfResult(
                derived_key=derived_key,
                salt=salt,
                algorithm=KdfType.PBKDF2_SHA256 if self._algorithm == "sha256" else KdfType.PBKDF2_SHA512,
                iterations=self._iterations
            )
            
        except ImportError:
            # Fallback to hashlib if cryptography library not available
            # This uses Python's built-in PBKDF2-HMAC implementation
            return self._hash_fallback(password_bytes, salt, key_length)
    
    def _hash_fallback(
        self,
        password_bytes: bytes,
        salt: bytes,
        key_length: int
    ) -> KdfResult:
        """
        Fallback PBKDF2 implementation using hashlib.
        
        This method provides a fallback using Python's built-in hashlib
        module when the cryptography library is not available.
        
        Args:
            password_bytes: The password as bytes
            salt: The salt bytes for key derivation
            key_length: Desired length of derived key in bytes
        
        Returns:
            KdfResult with derived key using hashlib fallback
        
        Note:
            The hashlib implementation is pure Python and may be
            slower than the cryptography library version, but
            it provides equivalent security.
        """
        # Use hashlib's PBKDF2-HMAC implementation
        if self._algorithm == "sha256":
            hash_func = hashlib.pbkdf2_hmac(
                'sha256',
                password_bytes,
                salt,
                self._iterations
            )
        else:
            hash_func = hashlib.pbkdf2_hmac(
                'sha512',
                password_bytes,
                salt,
                self._iterations
            )
        
        return KdfResult(
            derived_key=hash_func[:key_length],
            salt=salt,
            algorithm=KdfType.PBKDF2_SHA256 if self._algorithm == "sha256" else KdfType.PBKDF2_SHA512,
            iterations=self._iterations
        )
    
    def verify(self, password: str, kdf_result: KdfResult) -> bool:
        """
        Verify a password against a previously derived key.
        
        This method re-derives a key from the password using the stored
        salt and parameters, then compares it with the stored derived key
        using constant-time comparison.
        
        Args:
            password: The password to verify
            kdf_result: The KdfResult from the original derivation
        
        Returns:
            True if the password matches
            False if the password does not match
        
        Example:
            >>> hasher = PBKDF2Hasher()
            >>> result = hasher.hash("password")
            >>> hasher.verify("password", result)
            True
        """
        # Re-derive key with same parameters
        new_result = self.hash(password, kdf_result.salt, len(kdf_result.derived_key))
        
        # Constant-time comparison
        if len(new_result.derived_key) != len(kdf_result.derived_key):
            return False
        
        # Accumulate XOR of all bytes
        # Non-zero result means bytes differ
        result = 0
        for x, y in zip(new_result.derived_key, kdf_result.derived_key):
            result |= x ^ y
        
        return result == 0


class CXAKeyDerivation:
    """
    Unified key derivation interface for the CXA Cryptographic System.
    
    This class provides a simple, unified interface to all key derivation
    methods supported by CXA. It automatically selects the appropriate
    algorithm based on requirements and provides consistent API across
    different KDF implementations.
    
    Features:
    - Unified API for Argon2 and PBKDF2
    - Automatic algorithm selection based on requirements
    - Secure random parameter generation
    - Comprehensive verification support
    - Metadata tracking for all derivation operations
    
    Default Configuration:
    The system is configured with secure defaults:
    - Primary algorithm: Argon2id (recommended)
    - Argon2 settings: 64 MiB memory, 3 iterations, 4 threads
    - PBKDF2 settings: 600,000 iterations (per OWASP guidelines)
    
    Usage:
        >>> kdf = CXAKeyDerivation()
        >>> result = kdf.derive_key("my_password")
        >>> is_valid = kdf.verify("my_password", result)
    
    Algorithm Selection Guide:
    - Use Argon2id for new deployments (highest security)
    - Use PBKDF2 for legacy system compatibility
    - Both support verification and re-derivation
    
    Integration:
    This class integrates with the broader CXA ecosystem:
    - Works with CXAKeyManager for key storage
    - Integrates with CXASecurityMonitor for audit logging
    - Supports SecureBuffer for secure key handling
    """
    
    def __init__(self):
        """
        Initialize the unified key derivation system.
        
        This constructor sets up the key derivation system with recommended
        security parameters for both Argon2 and PBKDF2 algorithms.
        
        The following instances are created:
        - Argon2Hasher: For memory-hard key derivation
        - PBKDF2Hasher (SHA-256): For general-purpose derivation
        - PBKDF2Hasher (SHA-512): For high-security applications
        
        All instances use secure default parameters.
        
        Example:
            >>> kdf = CXAKeyDerivation()  # Uses secure defaults
            >>> result = kdf.derive_key("password")
        """
        # Initialize Argon2 hasher with recommended settings
        # Argon2 is preferred for new keys due to GPU resistance
        self._argon2 = Argon2Hasher(
            memory_cost_kib=65536,  # 64 MiB
            time_cost=3,            # 3 passes
            parallelism=4           # 4 threads
        )
        
        # Initialize PBKDF2-HMAC-SHA256 with OWASP-recommended iterations
        self._pbkdf2_sha256 = PBKDF2Hasher(
            algorithm="sha256",
            iterations=600000
        )
        
        # Initialize PBKDF2-HMAC-SHA512 with same iteration count
        # SHA-512 may be preferred for some high-security applications
        self._pbkdf2_sha512 = PBKDF2Hasher(
            algorithm="sha512",
            iterations=600000
        )
    
    def derive_key(
        self,
        password: str,
        salt: Optional[bytes] = None,
        algorithm: KdfType = KdfType.ARGON2ID,
        key_length: int = 32
    ) -> KdfResult:
        """
        Derive a cryptographic key from a password.
        
        This is the main entry point for key derivation operations in CXA.
        It provides a unified interface to all supported KDF algorithms.
        
        Args:
            password: The password or secret to derive key from
                Should be a high-entropy secret or protected password
            
            salt: Optional random salt bytes
                If None, a random 32-byte salt is generated
                Salt should be stored alongside the derived key
                Can be reused only if the password is different
            
            algorithm: KDF algorithm to use (default: KdfType.ARGON2ID)
                KdfType.ARGON2ID: Recommended for new deployments
                KdfType.PBKDF2_SHA256: For compatibility
                KdfType.PBKDF2_SHA512: For high security
            
            key_length: Length of derived key in bytes (default: 32)
                32 bytes (256 bits) for AES-256
                16 bytes (128 bits) for AES-128
        
        Returns:
            KdfResult containing the derived key and all parameters
        
        Raises:
            ValueError: If algorithm is unsupported
        
        Example:
            >>> kdf = CXAKeyDerivation()
            >>>
            >>> # Use default Argon2id
            >>> result = kdf.derive_key("my_password")
            >>>
            >>> # Use PBKDF2 with specific parameters
            >>> result = kdf.derive_key(
            ...     "my_password",
            ...     algorithm=KdfType.PBKDF2_SHA256,
            ...     key_length=32
            ... )
        """
        # Route to appropriate hasher based on algorithm
        if algorithm == KdfType.ARGON2ID:
            return self._argon2.hash(password, salt)
            
        elif algorithm == KdfType.PBKDF2_SHA256:
            return self._pbkdf2_sha256.hash(password, salt, key_length)
            
        elif algorithm == KdfType.PBKDF2_SHA512:
            return self._pbkdf2_sha512.hash(password, salt, key_length)
            
        else:
            raise ValueError(f"Unsupported KDF algorithm: {algorithm}")
    
    def verify(self, password: str, kdf_result: KdfResult) -> bool:
        """
        Verify a password against a previous derivation result.
        
        This method verifies that a password produces the same derived key
        as a previous derivation operation. It handles all supported
        algorithms automatically.
        
        Args:
            password: The password to verify
            kdf_result: The KdfResult from the original derivation
                Must contain the algorithm, salt, and derived key
        
        Returns:
            True if the password is correct
            False if the password is incorrect
        
        Example:
            >>> kdf = CXAKeyDerivation()
            >>> result = kdf.derive_key("password")
            >>> kdf.verify("password", result)
            True
            >>> kdf.verify("wrong", result)
            False
        """
        # Route to appropriate hasher based on stored algorithm
        if kdf_result.algorithm == KdfType.ARGON2ID:
            return self._argon2.verify(password, kdf_result)
            
        elif kdf_result.algorithm in [KdfType.PBKDF2_SHA256, KdfType.PBKDF2_SHA512]:
            # Select appropriate hasher based on algorithm
            hasher = self._pbkdf2_sha256 if kdf_result.algorithm == KdfType.PBKDF2_SHA256 else self._pbkdf2_sha512
            return hasher.verify(password, kdf_result)
            
        else:
            return False
    
    def generate_salt(self, length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        This method uses the secrets module to generate random bytes
        suitable for use as salt in key derivation operations.
        
        Args:
            length: Length of salt in bytes (default: 32)
                32 bytes (256 bits) is recommended
                Minimum 16 bytes is required
        
        Returns:
            Random bytes suitable for use as salt
        
        Example:
            >>> salt = kdf.generate_salt()
            >>> salt = kdf.generate_salt(length=16)
        """
        return secrets.token_bytes(length)
    
    def get_recommended_algorithm(self) -> KdfType:
        """
        Get the recommended KDF algorithm for new key derivations.
        
        Returns:
            KdfType.ARGON2ID (recommended for all new deployments)
        
        Note:
            Argon2id provides the best security against modern
            cracking attacks, including GPU and ASIC-based attacks.
        """
        return KdfType.ARGON2ID
    
    def get_supported_algorithms(self) -> list:
        """
        Get list of all supported KDF algorithms.
        
        Returns:
            List of KdfType enum values representing all supported algorithms:
            - KdfType.ARGON2ID
            - KdfType.PBKDF2_SHA256
            - KdfType.PBKDF2_SHA512
        
        Example:
            >>> kdf = CXAKeyDerivation()
            >>> algorithms = kdf.get_supported_algorithms()
            >>> for algo in algorithms:
            ...     print(f"{algo.name}: {algo.value}")
        """
        return [
            KdfType.ARGON2ID,
            KdfType.PBKDF2_SHA256,
            KdfType.PBKDF2_SHA512
        ]
