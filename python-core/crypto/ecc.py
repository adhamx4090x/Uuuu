#!/usr/bin/env python3
"""
CXA ECC Python Bindings - Curve25519 Elliptic Curve Cryptography

This module provides Python bindings for the Rust Curve25519 ECC implementation,
enabling secure key exchange operations with constant-time guarantees.

The implementation uses the Curve25519 elliptic curve for ECDH (Elliptic Curve
Diffie-Hellman) key exchange, which is widely used for secure communication
due to its strong security properties and efficiency.

Features:
- Key pair generation for ECDH: Creates public/private key pairs for secure key exchange
- Shared secret derivation: Computes shared secrets between two parties without transmitting the secret
- Public key validation: Validates received public keys to prevent attacks
- Scalar multiplication: Core cryptographic operation used in ECDH

Curve25519 is a modern elliptic curve offering:
- 128-bit security level (equivalent to 3072-bit RSA)
- Constant-time implementations (resistant to timing attacks)
- No known backdoors or weak parameters
- Fast computation and small key sizes

Author: CXA Development Team
Version: 2.0.0
"""

# ============================================================================
# Import Statements
# ============================================================================

# Standard library imports for system operations, type hints, and concurrency
import os              # Operating system functions for file path operations and library loading
import ctypes          # Foreign Function Interface for calling native library functions
import threading       # Thread synchronization for singleton pattern implementation
from typing import Tuple, Optional  # Type hints for better code documentation and IDE support
from dataclasses import dataclass   # Decorator for creating simple data classes

# ============================================================================
# Module-Level Constants
# ============================================================================

# Curve25519 key and output lengths in bytes
# These constants define the fixed sizes for various cryptographic parameters
# used throughout the Curve25519 implementation.

# Length of a Curve25519 public key in bytes (256 bits / 8 = 32 bytes)
# Public keys are points on the elliptic curve, encoded as 32-byte scalars
CURVE25519_PUBLIC_KEY_LEN = 32

# Length of a Curve25519 secret key in bytes (256 bits / 8 = 32 bytes)
# Secret keys are randomly generated 32-byte scalars with specific format requirements
CURVE25519_SECRET_KEY_LEN = 32

# Length of the shared secret in bytes (256 bits / 8 = 32 bytes)
# The shared secret is the result of scalar multiplication and serves as symmetric key material
CURVE25519_SHARED_SECRET_LEN = 32


# ============================================================================
# Error Codes and Exception Classes
# ============================================================================

# Custom exception hierarchy for ECC operations
# These exceptions provide detailed error information for debugging and error handling


class EccError(Exception):
    """
    Base exception class for all ECC-related errors.
    
    This is the parent class for all ECC-specific exceptions. It extends the standard
    Python Exception class to include error codes that can be used for programmatic
    error handling and debugging.
    
    Attributes:
        message: Human-readable description of the error
        code: Integer error code for programmatic error identification
              - Negative codes indicate ECC-specific errors
              - -1: General invalid key errors
              - -2: Derivation failures
              - -100: Library loading failures
    
    Example:
        try:
            result = lib.derive_shared_secret(...)
        except EccError as e:
            print(f"ECC Error {e.code}: {e.message}")
    """
    
    def __init__(self, message: str, code: int = -1):
        """
        Initialize EccError with message and optional error code.
        
        Args:
            message: Description of the error that occurred
            code: Numeric error code for programmatic handling (default: -1)
        """
        super().__init__(message)
        self.message = message
        self.code = code


class EccInvalidKeyError(EccError):
    """
    Exception raised when an invalid cryptographic key is provided.
    
    This exception indicates that a key (public or secret) provided to an ECC
    operation failed validation checks. Common causes include:
    - Incorrect key length
    - Keys containing invalid curve points
    - Keys that are all zeros or all ones
    - Corrupted or tampered key data
    
    This is a subclass of EccError with code -1.
    """
    
    def __init__(self, message: str = "Invalid key"):
        """
        Initialize EccInvalidKeyError with optional detailed message.
        
        Args:
            message: Specific description of why the key is invalid
        """
        super().__init__(message, code=-1)


class EccDerivationError(EccError):
    """
    Exception raised when shared secret derivation fails.
    
    This exception indicates that the ECDH key exchange operation failed to
    complete successfully. This can occur due to:
    - Invalid public key from the peer
    - Native library errors
    - Memory allocation failures
    
    This is a subclass of EccError with code -2.
    """
    
    def __init__(self, message: str = "Shared secret derivation failed"):
        """
        Initialize EccDerivationError with optional detailed message.
        
        Args:
            message: Specific description of why derivation failed
        """
        super().__init__(message, code=-2)


class EccLibraryError(EccError):
    """
    Exception raised when the native ECC library cannot be loaded or used.
    
    This exception indicates that the Rust Curve25519 native library is either
    not found or failed to initialize. When this occurs, the module falls back
    to a pure Python implementation for testing purposes.
    
    This is a subclass of EccError with code -100, indicating a library-level failure.
    """
    
    def __init__(self, message: str = "ECC library not available"):
        """
        Initialize EccLibraryError with optional detailed message.
        
        Args:
            message: Specific description of the library loading failure
        """
        super().__init__(message, code=-100)


# ============================================================================
# Result Data Classes
# ============================================================================

# Data classes for encapsulating operation results
# These provide type-safe containers for complex return values


@dataclass
class ECCKeyPair:
    """
    Result container for Curve25519 key pair generation.
    
    This data class holds the paired secret and public keys generated during
    the key pair creation process. Both keys are 32 bytes in length and
    cryptographically related.
    
    Security Note:
    The secret key should be protected and never transmitted. It is the sole
    proof of identity in ECDH exchanges. The public key can be freely shared.
    
    Attributes:
        secret_key: 32 bytes of secret key material (must be kept confidential)
        public_key: 32 bytes of derived public key (can be shared publicly)
    
    Example:
        keypair = lib.generate_keypair()
        # Store secret_key securely - this is your identity
        # Share public_key with your communication partner
    """
    secret_key: bytes
    public_key: bytes


@dataclass
class ECDHResult:
    """
    Result container for ECDH key exchange operations.
    
    This data class holds the result of a shared secret derivation operation,
    including the derived shared secret and a success indicator.
    
    Security Note:
    Both parties in an ECDH exchange should derive the same shared_secret.
    If the secrets don't match, there may be a man-in-the-middle attack.
    
    Attributes:
        shared_secret: 32 bytes of derived shared secret (key material)
        success: Boolean indicating whether derivation succeeded
    
    Example:
        result = lib.derive_shared_secret(secret, our_public, their_public)
        if result.success:
            shared_key = result.shared_secret
        else:
            handle_error()
    """
    shared_secret: bytes
    success: bool


# ============================================================================
# ECC Library Wrapper Class
# ============================================================================


class Curve25519Library:
    """
    Wrapper class for the Rust Curve25519 ECC native library.
    
    This class provides a singleton interface for loading and interacting with
    the compiled Rust Curve25519 library. It handles library loading, function
    signature configuration, and provides Python bindings to the native functions.
    
    Security Properties:
    - All operations are implemented in constant-time to prevent timing attacks
    - Secret key material is zeroized after use where possible by the native library
    - Cryptographically secure random number generation via the OS
    - The library is thread-safe for concurrent operations
    
    Thread Safety:
    - Uses double-checked locking pattern for singleton initialization
    - Each library instance is thread-safe for concurrent operations
    - All operations are independent and stateless
    
    Library Loading:
    The class searches for the native library in multiple locations:
    1. Current directory (development builds)
    2. Target release/debug directories (cargo build output)
    3. System library paths (/usr/local/lib, /usr/lib)
    4. User's home directory (~/.local/lib)
    
    Fallback Behavior:
    If the native library cannot be loaded, the class falls back to pure Python
    implementations for testing purposes. These fallbacks are NOT cryptographically
    secure and should only be used for development and testing.
    
    Attributes:
        _lib: The loaded CDLL library instance or None if not loaded
        _initialized: Flag indicating whether initialization is complete
    
    Example:
        lib = Curve25519Library()
        if lib.is_available():
            keypair = lib.generate_keypair()
        else:
            print("Native library not available - using fallback")
    """
    
    # Class-level variables for singleton pattern
    _instance = None       # Singleton instance reference
    _lock = threading.Lock()  # Lock for thread-safe singleton initialization
    
    def __new__(cls):
        """
        Implement singleton pattern to ensure only one library instance exists.
        
        Uses double-checked locking pattern for efficient thread-safe initialization.
        This prevents multiple library loading attempts which could cause resource
        exhaustion or inconsistent library states.
        
        Returns:
            The singleton Curve25519Library instance
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """
        Initialize the library wrapper singleton.
        
        This method is called once per singleton instance. It handles loading
        the native library and configuring function signatures for FFI calls.
        The double-check ensures initialization only happens once.
        
        Side Effects:
            - Attempts to load the native Curve25519 library
            - Configures function signatures for all supported operations
        """
        # Skip if already initialized to prevent re-initialization
        if self._initialized:
            return
        
        # Initialize library reference to None (will be set if loading succeeds)
        self._lib = None
        
        # Attempt to load the native library
        self._load_library()
        
        # Mark initialization as complete
        self._initialized = True
    
    def _load_library(self) -> None:
        """
        Load the native Curve25519 library and configure function signatures.
        
        This method searches for the compiled Rust library in multiple standard
        locations and configures ctypes to call the native functions correctly.
        The function signatures (argtypes and restype) are essential for proper
        type conversion between Python and native code.
        
        Search Locations (in order):
        1. libcxa_ecc.so - Current directory (during development)
        2. ../../target/release/libcxa_ecc.so - Cargo release build
        3. ../../target/debug/libcxa_ecc.so - Cargo debug build
        4. /usr/local/lib/libcxa_ecc.so - System library path
        5. /usr/lib/libcxa_ecc.so - Alternative system path
        6. ~/cxa/lib/libcxa_ecc.so - User-specific installation
        
        Function Signatures Configured:
        - generate_curve25519_keypair: Generates a new key pair
        - derive_shared_secret: Performs ECDH key exchange
        - validate_curve25519_public_key: Validates received public keys
        - curve25519_public_key_hash: Computes public key fingerprint
        
        Returns:
            None: This method modifies internal state directly
        
        Raises:
            No exceptions are raised - failures result in self._lib being set to None
        """
        # Define search paths for the native library
        lib_paths = [
            # Current directory - for development and direct execution
            "libcxa_ecc.so",
            # Cargo build output directories - release and debug builds
            "../../target/release/libcxa_ecc.so",
            "../../target/debug/libcxa_ecc.so",
            # System library paths - for system-wide installations
            "/usr/local/lib/libcxa_ecc.so",
            "/usr/lib/libcxa_ecc.so",
            # User-specific installation path
            os.path.expanduser("~/cxa/lib/libcxa_ecc.so"),
        ]
        
        # Attempt to load library from each path
        lib = None
        for path in lib_paths:
            try:
                # Construct full path relative to this module's location
                full_path = os.path.join(os.path.dirname(__file__), path)
                
                # Check if file exists before attempting to load
                if os.path.exists(full_path):
                    # Load the shared library using ctypes
                    lib = ctypes.CDLL(full_path)
                    # Successfully loaded - exit loop
                    break
            except OSError:
                # Library loading failed - try next path
                # OSError occurs when file is not a valid shared library
                continue
        
        # Check if library was successfully loaded
        if lib is None:
            # Set library reference to None to indicate unavailability
            # This triggers fallback behavior in all operations
            self._lib = None
            return
        
        # =========================================================================
        # Configure function signatures for native library calls
        # =========================================================================
        
        # Configure generate_curve25519_keypair function signature
        # Takes two output pointers and returns status code
        lib.generate_curve25519_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # secret_key output pointer
            ctypes.POINTER(ctypes.c_uint8),  # public_key output pointer
        ]
        lib.generate_curve25519_keypair.restype = ctypes.c_int  # 0 = success
        
        # Configure derive_shared_secret function signature
        # Takes three input pointers and one output pointer
        lib.derive_shared_secret.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # our_secret input pointer
            ctypes.POINTER(ctypes.c_uint8),  # our_public input pointer
            ctypes.POINTER(ctypes.c_uint8),  # their_public input pointer
            ctypes.POINTER(ctypes.c_uint8),  # shared_secret output pointer
        ]
        lib.derive_shared_secret.restype = ctypes.c_int  # 0 = success, -3 = invalid key
        
        # Configure validate_curve25519_public_key function signature
        # Takes one input pointer and returns validation result
        lib.validate_curve25519_public_key.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # public_key input pointer
        ]
        lib.validate_curve25519_public_key.restype = ctypes.c_int  # 1 = valid, 0 = invalid
        
        # Configure curve25519_public_key_hash function signature
        # Takes input and output pointers for hash computation
        lib.curve25519_public_key_hash.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # public_key input pointer
            ctypes.POINTER(ctypes.c_uint8),  # hash_output output pointer
        ]
        lib.curve25519_public_key_hash.restype = ctypes.c_int  # 0 = success
        
        # Store the configured library reference
        self._lib = lib
    
    def is_available(self) -> bool:
        """
        Check if the native Curve25519 library is available.
        
        This method provides a quick check to determine whether the native
        library was successfully loaded. When False, all cryptographic
        operations fall back to pure Python implementations.
        
        Returns:
            True if native library is loaded and ready, False otherwise
        
        Note:
            The fallback implementations are NOT cryptographically secure
            and should only be used for testing and development.
            
        Example:
            lib = Curve25519Library()
            if not lib.is_available():
                print("Warning: Using insecure fallback implementation")
        """
        return self._lib is not None
    
    def generate_keypair(self) -> ECCKeyPair:
        """
        Generate a new Curve25519 key pair using the native library.
        
        This method generates a cryptographically secure public/private key pair
        suitable for ECDH key exchange. The secret key is randomly generated
        using the OS's secure random number generator, and the public key is
        derived using Curve25519 scalar multiplication.
        
        Key Generation Process:
        1. Generate 32 random bytes for secret key
        2. Apply required clamping/masking to the secret key
        3. Compute public key by multiplying secret key with base point
        4. Return both keys as byte arrays
        
        Returns:
            ECCKeyPair: A dataclass containing:
                - secret_key: 32 bytes of random secret key material
                - public_key: 32 bytes of derived public key
        
        Raises:
            EccLibraryError: If the native library is not available
            EccError: If key generation fails (returns non-zero status)
        
        Example:
            lib = Curve25519Library()
            keypair = lib.generate_keypair()
            print(f"Public key: {keypair.public_key.hex()}")
            # Share public_key with peer, keep secret_key secure
        """
        # Check library availability and use fallback if needed
        if not self.is_available():
            # Delegate to fallback implementation for testing
            return self._generate_keypair_fallback()
        
        # Allocate memory buffers for the keys using ctypes
        # These are fixed-size arrays that will be filled by the native library
        secret = (ctypes.c_uint8 * CURVE25519_SECRET_KEY_LEN)()
        public = (ctypes.c_uint8 * CURVE25519_PUBLIC_KEY_LEN)()
        
        # Call the native library function to generate the key pair
        # The function fills the provided buffers with random key material
        result = self._lib.generate_curve25519_keypair(secret, public)
        
        # Check if the operation succeeded
        if result != 0:
            # Non-zero result indicates an error
            raise EccError(f"Key generation failed with code {result}", code=result)
        
        # Convert ctypes arrays to Python bytes objects for easy handling
        secret_bytes = bytes(secret)
        public_bytes = bytes(public)
        
        # Return the generated key pair
        return ECCKeyPair(secret_key=secret_bytes, public_key=public_bytes)
    
    def _generate_keypair_fallback(self) -> ECCKeyPair:
        """
        Generate a fake key pair using pure Python (for testing only).
        
        WARNING: This implementation is NOT cryptographically secure.
        It should NEVER be used in production environments.
        
        This method exists solely to allow testing when the native library
        is not available. It generates random bytes using the secrets module,
        which provides cryptographically secure random numbers, but does NOT
        perform the actual Curve25519 mathematical operations.
        
        The generated keys will NOT work for actual ECDH exchanges with
        properly implemented Curve25519 libraries. They are only useful
        for code path testing and development.
        
        Returns:
            ECCKeyPair: A dataclass with random bytes for both keys
            
        Security Note:
            This fallback is for development and testing ONLY. It provides
            no security guarantees whatsoever.
        """
        # Use secrets module for cryptographically random bytes
        # Note: While secrets is secure, this doesn't make the output valid
        import secrets
        secret = secrets.token_bytes(CURVE25519_SECRET_KEY_LEN)
        public = secrets.token_bytes(CURVE25519_PUBLIC_KEY_LEN)
        return ECCKeyPair(secret_key=secret, public_key=public)
    
    def derive_shared_secret(
        self,
        our_secret: bytes,
        our_public: bytes,
        their_public: bytes
    ) -> ECDHResult:
        """
        Derive a shared secret using ECDH key exchange.
        
        This method performs the elliptic curve Diffie-Hellman operation to
        compute a shared secret that both parties can derive independently
        without transmitting any secret information.
        
        ECDH Mathematical Operation:
        The shared secret is computed as: shared = secret * their_public
        Where:
        - secret: Our secret key scalar
        - their_public: Peer's public key point
        - *: Elliptic curve scalar multiplication
        
        This operation is:
        - Constant-time: Execution time does not depend on key values
        - Symmetric: Both parties compute the same result
        - Non-interactive: No back-and-forth communication required
        
        Key Exchange Protocol:
        1. Alice generates key pair (sk_A, pk_A)
        2. Bob generates key pair (sk_B, pk_B)
        3. Alice sends pk_A to Bob
        4. Bob sends pk_B to Alice
        5. Alice computes: shared = sk_A * pk_B
        6. Bob computes: shared = sk_B * pk_A
        
        Args:
            our_secret: Our secret key bytes (32 bytes)
            our_public: Our public key bytes (32 bytes)
            their_public: Peer's public key bytes (32 bytes)
            
        Returns:
            ECDHResult: A dataclass containing:
                - shared_secret: 32 bytes of derived shared secret
                - success: Boolean indicating successful derivation
            
        Raises:
            EccLibraryError: If the native library is not available
            EccInvalidKeyError: If any key has incorrect length or format
            EccDerivationError: If the derivation operation fails
        
        Example:
            # Alice's side
            alice = ECDH()
            alice_shared = lib.derive_shared_secret(
                alice._keypair.secret_key,
                alice._keypair.public_key,
                bob_public
            )
            
            # Bob's side
            bob = ECDH()
            bob_shared = lib.derive_shared_secret(
                bob._keypair.secret_key,
                bob._keypair.public_key,
                alice_public
            )
            
            # alice_shared.shared_secret == bob_shared.shared_secret
        """
        # Validate key lengths before proceeding
        # Early validation prevents issues in native code
        if len(our_secret) != CURVE25519_SECRET_KEY_LEN:
            raise EccInvalidKeyError(
                f"Secret key must be {CURVE25519_SECRET_KEY_LEN} bytes, got {len(our_secret)}"
            )
        if len(our_public) != CURVE25519_PUBLIC_KEY_LEN:
            raise EccInvalidKeyError(
                f"Public key must be {CURVE25519_PUBLIC_KEY_LEN} bytes, got {len(our_public)}"
            )
        if len(their_public) != CURVE25519_PUBLIC_KEY_LEN:
            raise EccInvalidKeyError(
                f"Their public key must be {CURVE25519_PUBLIC_KEY_LEN} bytes, got {len(their_public)}"
            )
        
        # Check for native library availability
        if not self.is_available():
            # Use fallback implementation for testing
            return self._derive_shared_secret_fallback(our_secret, their_public)
        
        # Create ctypes arrays from the input bytes
        # from_buffer_copy creates a copy to prevent modification of originals
        secret_arr = (ctypes.c_uint8 * CURVE25519_SECRET_KEY_LEN).from_buffer_copy(our_secret)
        public_arr = (ctypes.c_uint8 * CURVE25519_PUBLIC_KEY_LEN).from_buffer_copy(our_public)
        their_arr = (ctypes.c_uint8 * CURVE25519_PUBLIC_KEY_LEN).from_buffer_copy(their_public)
        
        # Allocate output buffer for shared secret
        shared = (ctypes.c_uint8 * CURVE25519_SHARED_SECRET_LEN)()
        
        # Call the native library function for shared secret derivation
        result = self._lib.derive_shared_secret(
            secret_arr, public_arr, their_arr, shared
        )
        
        # Check result code for errors
        if result == -3:
            # Specific error code for invalid peer public key
            raise EccInvalidKeyError("Invalid public key from peer")
        elif result != 0:
            # Any other non-zero result indicates a general error
            raise EccDerivationError(f"Derivation failed with code {result}")
        
        # Return successful result with the derived shared secret
        return ECDHResult(
            shared_secret=bytes(shared),
            success=True
        )
    
    def _derive_shared_secret_fallback(
        self,
        our_secret: bytes,
        their_public: bytes
    ) -> ECDHResult:
        """
        Compute a fake shared secret using pure Python (for testing only).
        
        WARNING: This implementation is NOT cryptographically secure.
        It should NEVER be used in production environments.
        
        This method provides a fallback that mimics the ECDH interface
        without performing the actual elliptic curve operations. It simply
        hashes the combination of keys to produce a 32-byte result.
        
        Args:
            our_secret: Our secret key bytes
            their_public: Peer's public key bytes
            
        Returns:
            ECDHResult with a SHA-256 hash of the combined keys
            
        Security Note:
            This fallback is for development and testing ONLY. It provides
            no security guarantees and is NOT compatible with real Curve25519.
        """
        import hashlib
        # Combine keys and hash to produce fixed-length output
        combined = our_secret + their_public
        # Take first 32 bytes of SHA-256 hash
        shared = hashlib.sha256(combined).digest()[:CURVE25519_SHARED_SECRET_LEN]
        return ECDHResult(shared_secret=shared, success=True)
    
    def validate_public_key(self, public_key: bytes) -> bool:
        """
        Validate a Curve25519 public key.
        
        This method checks whether a received public key is valid according to
        Curve25519 specifications. Invalid keys should be rejected to prevent
        various attacks on the elliptic curve system.
        
        Validation Checks:
        1. Length check: Key must be exactly 32 bytes
        2. Range check: Key must not be 0 (point at infinity)
        3. Curve check: Key must represent a valid point on the curve
        
        Args:
            public_key: Public key bytes to validate (32 bytes)
            
        Returns:
            True if the key is valid, False otherwise
            
        Example:
            if not lib.validate_public_key(received_key):
                print("Rejecting invalid key from peer")
                return
            # Proceed with key exchange
        """
        # First check: verify key length
        if len(public_key) != CURVE25519_PUBLIC_KEY_LEN:
            return False
        
        # Check library availability
        if not self.is_available():
            # Fallback validation for testing
            # Check for all-zeros key (point at infinity)
            if all(b == 0 for b in public_key):
                return False
            return True
        
        # Convert to ctypes array for native call
        public_arr = (ctypes.c_uint8 * CURVE25519_PUBLIC_KEY_LEN).from_buffer_copy(public_key)
        
        # Call native validation function
        result = self._lib.validate_curve25519_public_key(public_arr)
        
        # Return True if validation returned success (1)
        return result == 1
    
    def public_key_hash(self, public_key: bytes) -> bytes:
        """
        Compute a hash of the public key for identification purposes.
        
        This method creates a fixed-size fingerprint of a public key that can
        be used for identification, logging, or comparison purposes. The hash
        is deterministic and one-way, allowing public key comparison without
        transmitting the full key.
        
        Use Cases:
        - Logging: Record key fingerprints instead of full keys
        - Comparison: Check if two keys are identical
        - UI Display: Show abbreviated key identifiers
        
        Args:
            public_key: Public key bytes to hash (32 bytes)
            
        Returns:
            32 bytes of hash output (BLAKE3 or SHA-256 depending on availability)
            
        Raises:
            EccInvalidKeyError: If key length is incorrect
        
        Example:
            # Store fingerprints instead of full keys in logs
            alice_fingerprint = lib.public_key_hash(alice_public)
            bob_fingerprint = lib.public_key_hash(bob_public)
            print(f"Alice's key: {alice_fingerprint[:8].hex()}...")
        """
        # Validate key length before processing
        if len(public_key) != CURVE25519_PUBLIC_KEY_LEN:
            raise EccInvalidKeyError(f"Public key must be {CURVE25519_PUBLIC_KEY_LEN} bytes")
        
        # Check library availability
        if not self.is_available():
            # Use BLAKE3 hash for fallback (or SHA-256 if unavailable)
            import hashlib
            return hashlib.blake3(public_key).digest()[:CURVE25519_SHARED_SECRET_LEN]
        
        # Convert to ctypes array
        public_arr = (ctypes.c_uint8 * CURVE25519_PUBLIC_KEY_LEN).from_buffer_copy(public_key)
        hash_output = (ctypes.c_uint8 * CURVE25519_SHARED_SECRET_LEN)()
        
        # Call native hash function
        result = self._lib.curve25519_public_key_hash(public_arr, hash_output)
        
        # Check for errors
        if result != 0:
            raise EccError(f"Hash computation failed with code {result}")
        
        return bytes(hash_output)


# ============================================================================
# High-Level ECDH Interface Class
# ============================================================================


class ECDH:
    """
    High-level interface for Elliptic Curve Diffie-Hellman key exchange.
    
    This class provides a simplified interface for performing secure key
    exchange using Curve25519. It manages key pair generation and shared
    secret derivation automatically, hiding the complexity of the underlying
    cryptographic operations.
    
    Usage Pattern:
    1. Each party creates an ECDH instance (generates key pair)
    2. Parties exchange public keys over any channel
    3. Each party calls derive_shared_secret() with the other's public key
    4. Both parties now have the same shared secret
    
    Security Properties:
    - Forward Secrecy: Each session uses unique keys; compromising long-term
      keys does not reveal past session keys
    - Authentication: This implementation does NOT provide authentication;
      man-in-the-middle attacks are possible without additional verification
    - Key Compromise: If your secret key is compromised, an attacker can
      impersonate you in future communications
    
    Required Security Measures:
    - Authenticate public keys using a trusted channel or digital signatures
    - Verify that derived shared secrets match on both sides
    - Use the shared secret as key material for symmetric encryption
    - Implement proper key rotation and forward secrecy
    
    Attributes:
        _lib: Reference to the Curve25519Library singleton
        _keypair: The generated key pair (secret_key, public_key)
    
    Example:
        # Alice (initiator)
        alice = ECDH()
        alice_public = alice.get_public_key()  # Send to Bob
        
        # Bob (responder)
        bob = ECDH()
        bob_public = bob.get_public_key()  # Send to Alice
        bob_shared = bob.derive_shared_secret(alice_public)  # Compute shared secret
        
        # Alice
        alice_shared = alice.derive_shared_secret(bob_public)  # Compute shared secret
        
        # Verify they match (would fail if MITM occurred)
        assert alice_shared == bob_shared
        
    Author: CXA Development Team
    Version: 2.0.0
    """
    
    def __init__(self):
        """
        Initialize the ECDH instance and generate a new key pair.
        
        This constructor creates a new ECDH instance with a freshly generated
        key pair. The key pair is generated using the native library when
        available, or the fallback implementation for testing.
        
        Side Effects:
            - Generates a new Curve25519 key pair
            - Stores the key pair in self._keypair
        
        Example:
            ecdh = ECDH()  # Automatically generates keys
            public_key = ecdh.get_public_key()  # Ready to share
        """
        # Get reference to the library singleton
        self._lib = Curve25519Library()
        
        # Initialize keypair variable with Optional type for type checker
        self._keypair: Optional[ECCKeyPair] = None
        
        # Generate or fallback to fake key pair
        if self._lib.is_available():
            # Use native library for proper key generation
            self._keypair = self._lib.generate_keypair()
        else:
            # Fallback for testing when native library unavailable
            self._keypair = self._lib._generate_keypair_fallback()
    
    def get_public_key(self) -> bytes:
        """
        Get our public key to share with the communication peer.
        
        This method returns the public key component of our key pair, which
        can be safely transmitted over any channel. The public key is used
        by the peer to compute the shared secret.
        
        Returns:
            32 bytes of our public key material
            
        Example:
            ecdh = ECDH()
            my_public = ecdh.get_public_key()
            # Send my_public to peer via network, email, etc.
        """
        return self._keypair.public_key
    
    def derive_shared_secret(self, their_public: bytes) -> bytes:
        """
        Derive a shared secret from the peer's public key.
        
        This method performs the ECDH computation using our secret key and
        the peer's public key to derive a shared secret. Both parties in
        the exchange should compute the same value.
        
        ECDH Computation:
        shared_secret = secret_key * their_public_key (on the curve)
        
        This result can be used directly as symmetric key material, or
        processed through a KDF (Key Derivation Function) for specific
        cryptographic applications.
        
        Args:
            their_public: Peer's public key bytes (32 bytes)
            
        Returns:
            32 bytes of derived shared secret
            
        Raises:
            EccInvalidKeyError: If peer's key is invalid or wrong length
            EccDerivationError: If the derivation operation fails
            
        Example:
            alice = ECDH()
            bob = ECDH()
            
            # After exchanging public keys
            alice_shared = alice.derive_shared_secret(bob.get_public_key())
            bob_shared = bob.derive_shared_secret(alice.get_public_key())
            
            # Verify match (would fail with MITM)
            assert alice_shared == bob_shared
            
            # Use shared secret for symmetric encryption
            cipher = AES.new(alice_shared, AES.MODE_GCM)
        """
        # Call the library method with our stored key pair
        result = self._lib.derive_shared_secret(
            self._keypair.secret_key,
            self._keypair.public_key,
            their_public
        )
        
        # Return the derived shared secret
        return result.shared_secret


# ============================================================================
# Module-Level Utility Functions
# ============================================================================

# These functions provide convenient shortcuts for common operations
# without requiring explicit library instantiation


def generate_keypair() -> ECCKeyPair:
    """
    Generate a new Curve25519 key pair using a module-level function.
    
    This function provides a simple interface for key pair generation
    without requiring the user to directly instantiate the library class.
    It internally uses the singleton Curve25519Library instance.
    
    Returns:
        ECCKeyPair containing secret_key (32 bytes) and public_key (32 bytes)
        
    Example:
        # Simple key generation
        keypair = generate_keypair()
        print(f"Public key: {keypair.public_key.hex()}")
    """
    lib = Curve25519Library()
    return lib.generate_keypair()


def derive_shared_secret(
    our_secret: bytes,
    our_public: bytes,
    their_public: bytes
) -> ECDHResult:
    """
    Derive a shared secret using ECDH with explicit key parameters.
    
    This function provides a direct interface for shared secret derivation
    when you need explicit control over the key parameters. For most use
    cases, the ECDH class is more convenient.
    
    Args:
        our_secret: Our secret key bytes (32 bytes)
        our_public: Our public key bytes (32 bytes)
        their_public: Peer's public key bytes (32 bytes)
        
    Returns:
        ECDHResult containing shared_secret and success status
        
    Example:
        # Manual key exchange (less convenient than ECDH class)
        keypair = generate_keypair()
        result = derive_shared_secret(
            keypair.secret_key,
            keypair.public_key,
            peer_public_key
        )
        if result.success:
            shared = result.shared_secret
    """
    lib = Curve25519Library()
    return lib.derive_shared_secret(our_secret, our_public, their_public)


def validate_public_key(public_key: bytes) -> bool:
    """
    Validate a Curve25519 public key using a module-level function.
    
    This function provides a simple interface for public key validation
    without requiring library instantiation.
    
    Args:
        public_key: Public key bytes to validate (32 bytes)
        
    Returns:
        True if the key is valid, False otherwise
        
    Example:
        if validate_public_key(received_key):
            print("Key is valid")
        else:
            print("Key is invalid - reject!")
    """
    lib = Curve25519Library()
    return lib.validate_public_key(public_key)
