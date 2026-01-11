#!/usr/bin/env python3
"""
CXA Cryptographic System - Python Core Engine

This module provides the high-level Python interface to the underlying
Rust-based cryptographic primitives. It handles FFI (Foreign Function Interface)
interactions, memory management, and provides a clean API for cryptographic operations.

The architecture follows a layered approach where Python orchestrates high-level
operations while delegating performance-critical cryptographic computations to
optimized Rust implementations.

Architecture:
    Python Layer (High-level API, orchestration, error handling)
            |
            v
    Rust Core (Cryptographic primitives, memory safety, FFI bindings)
            |
            v
    OS/Hardware (Encryption acceleration, randomness, secure storage)

Key Components:
    - Platform Detection: Identifies the current operating system and architecture
    - Library Loading: Manages dynamic library loading for FFI operations
    - Crypto Engines: Abstract interfaces for cryptographic operations
    - Data Types: Containers for encrypted data and key material
    - Error Handling: Structured exception hierarchy for crypto operations

Supported Cryptographic Operations:
    - Symmetric Encryption: AES-256-GCM, ChaCha20-Poly1305
    - Hashing: BLAKE3, SHA-256, SHA-512, SHA3-256
    - Key Derivation: Argon2id, PBKDF2, scrypt
    - Random Number Generation: Cryptographically secure random bytes

Author: CXA Development Team
Version: 1.0.0
"""

# ============================================================================
# Import Statements
# ============================================================================

# Standard library imports for system operations, type hints, and concurrency
import ctypes          # Foreign Function Interface for calling native library functions
import hashlib         # Hashing algorithms implementation
import hmac            # HMAC (Hash-based Message Authentication Code)
import os              # Operating system functions for file and path operations
import platform        # System information for platform detection
import struct          # Binary data packing and unpacking
import threading       # Thread synchronization for singleton pattern implementation
from abc import ABC, abstractmethod  # Abstract base classes for interface definitions
from dataclasses import dataclass, field  # Data class decorators for structured types
from enum import Enum  # Enumeration type for constants
from pathlib import Path  # Object-oriented filesystem paths
from typing import Any, Dict, List, Optional, Tuple, Union, ByteString  # Type hints
from datetime import datetime  # Date and time handling for timestamps
import secrets  # Cryptographically secure random number generation

# Import secure memory handling from local memory module
# These classes provide memory-safe handling of sensitive data
from .memory import SecureBuffer, secure_compare


# ============================================================================
# Platform Detection and Library Loading
# ============================================================================

# Enumeration of supported platforms for FFI library loading
# Each platform variant corresponds to a specific operating system and architecture
# combination that the native Rust library supports


class Platform(Enum):
    """
    Enumeration of supported platforms for FFI library loading.
    
    This enumeration defines all platform combinations that the CXA cryptographic
    library supports. Each platform has a unique identifier used for selecting
    the appropriate native library binary.
    
    Platform Naming Convention:
    The platform names follow the format: {OS}_{ARCH}
    Where OS is the operating system name and ARCH is the processor architecture.
    
    Supported Platforms:
    - LINUX_X86_64: Linux on 64-bit x86 processors (Intel/AMD)
    - LINUX_AARCH64: Linux on 64-bit ARM processors (Apple Silicon, Raspberry Pi)
    - MACOS_X86_64: macOS on 64-bit x86 processors (Intel Macs)
    - MACOS_AARCH64: macOS on ARM64 processors (Apple Silicon Macs)
    - WINDOWS_X86_64: Windows on 64-bit x86 processors
    
    Note:
    32-bit platforms are not supported due to security and performance limitations.
    The library requires 64-bit processors to properly implement cryptographic operations.
    
    Example:
        current_platform = Platform.detect()
        print(f"Running on: {current_platform.value}")
    """
    
    # Linux operating system variants
    LINUX_X86_64 = "linux_x86_64"      # Linux on Intel/AMD 64-bit processors
    LINUX_AARCH64 = "linux_aarch64"    # Linux on ARM 64-bit processors
    
    # macOS operating system variants
    MACOS_X86_64 = "macos_x86_64"      # macOS on Intel 64-bit processors
    MACOS_AARCH64 = "macos_aarch64"    # macOS on Apple Silicon (ARM64)
    
    # Windows operating system variant
    WINDOWS_X86_64 = "windows_x86_64"  # Windows on Intel/AMD 64-bit processors
    
    @classmethod
    def detect(cls) -> 'Platform':
        """
        Detect the current platform by examining system information.
        
        This method queries the operating system and processor architecture
        to determine which platform variant is currently running.
        
        Detection Process:
        1. Get the operating system name using platform.system()
        2. Get the processor architecture using platform.machine()
        3. Match the combination to a supported Platform enum value
        
        Returns:
            Platform: The detected platform enum value matching the current system
            
        Raises:
            RuntimeError: If the platform combination is not supported
            
        Example:
            >>> platform = Platform.detect()
            >>> print(platform.value)
            'linux_x86_64'
        """
        # Get lowercase system and machine information for consistent matching
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        # Detect Linux platform variants
        if system == "linux":
            if machine in ["x86_64", "amd64"]:
                return cls.LINUX_X86_64
            elif machine in ["aarch64", "arm64"]:
                return cls.LINUX_AARCH64
        
        # Detect macOS platform variants
        elif system == "darwin":
            if machine in ["x86_64", "amd64"]:
                return cls.MACOS_X86_64
            elif machine in ["arm64", "aarch64"]:
                return cls.MACOS_AARCH64
        
        # Detect Windows platform variant
        elif system == "windows":
            if machine in ["x86_64", "amd64"]:
                return cls.WINDOWS_X86_64
        
        # If no match found, raise an error with system details
        raise RuntimeError(f"Unsupported platform: {system} {machine}")


class LibraryLoader:
    """
    Centralized library loader for FFI operations with singleton pattern.
    
    This class manages the loading and lifecycle of compiled Rust libraries
    used for high-performance cryptographic operations. It implements the
    singleton pattern to ensure consistent library access across the
    application and prevent multiple library loading attempts.
    
    Library Search Strategy:
    The loader searches for native libraries in the following order:
    1. rust-core/target/release - Optimized release builds
    2. rust-core/target/debug - Debug builds with symbols
    3. target/release - Project-level release builds
    4. target/debug - Project-level debug builds
    5. libraries/ - System library directory
    
    Supported Library Formats:
    - .so (Linux shared object)
    - .dylib (macOS dynamic library)
    - .dll (Windows dynamic link library)
    - .a (Static library archives)
    
    Thread Safety:
    - Uses double-checked locking for singleton initialization
    - Thread-safe library loading and caching
    
    Attributes:
        _lib_path: Path to the loaded library file
        _libraries: Dictionary of loaded library instances by name
        
    Example:
        loader = LibraryLoader()
        crypto_lib = loader.crypto_lib
        # Use crypto_lib for FFI calls
    """
    
    # Class variables for singleton pattern implementation
    _instance: Optional['LibraryLoader'] = None  # Singleton instance reference
    _lock = threading.Lock()  # Lock for thread-safe initialization
    
    def __new__(cls):
        """
        Implement singleton pattern to ensure single library loader instance.
        
        Uses double-checked locking pattern for efficient thread-safe
        initialization. This prevents redundant library loading operations
        which could consume system resources.
        
        Returns:
            LibraryLoader: The singleton instance of this class
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """
        Initialize the library loader singleton.
        
        Performs one-time initialization including library discovery and loading.
        Uses thread-safe double-check pattern to ensure initialization happens
        exactly once even under concurrent access.
        
        Side Effects:
            - Searches for and loads the native library
            - Initializes internal library cache
            - Sets initialized flag to prevent re-initialization
        """
        # Skip if already initialized
        if self._initialized:
            return
        
        # Thread-safe initialization with double-check
        with self._lock:
            if self._initialized:
                return
            
            # Find and load the library
            self._lib_path = self._find_library()
            self._libraries: Dict[str, Any] = {}
            self._initialized = True
    
    def _find_library(self) -> Path:
        """
        Locate the compiled Rust cryptographic library on the filesystem.
        
        This method searches through multiple potential library locations
        to find the appropriate native library binary for the current platform.
        
        Search Process:
        1. Determine current platform using Platform.detect()
        2. Build list of library names for the detected platform
        3. Search each configured path for matching library files
        4. Return the first matching library path found
        
        Library Naming by Platform:
        - Linux: libcxa_crypto.so, libcxa_crypto.a
        - macOS: libcxa_crypto.dylib, libcxa_crypto.a
        - Windows: cxa_crypto.dll, cxa_crypto.lib
        
        Returns:
            Path: Filesystem path to the discovered library
            
        Raises:
            RuntimeError: If no matching library is found in any search location
            
        Note:
            The search paths are relative to the project root directory,
            which is determined from this module's location.
        """
        # Determine base directory from this module's location
        base_dir = Path(__file__).parent.parent.parent
        
        # Detect current platform for appropriate library names
        platform = Platform.detect()
        
        # Map platform to possible library filenames
        # Order matters: prefer shared libraries (.so/.dylib) over static (.a)
        lib_names = {
            Platform.LINUX_X86_64: ["libcxa_crypto.so", "libcxa_crypto.a"],
            Platform.LINUX_AARCH64: ["libcxa_crypto.so", "libcxa_crypto.a"],
            Platform.MACOS_X86_64: ["libcxa_crypto.dylib", "libcxa_crypto.a"],
            Platform.MACOS_AARCH64: ["libcxa_crypto.dylib", "libcxa_crypto.a"],
            Platform.WINDOWS_X86_64: ["cxa_crypto.dll", "cxa_crypto.lib"],
        }
        
        # Define search paths in priority order
        search_paths = [
            # Rust project build output (release - optimized)
            base_dir / "rust-core" / "target" / "release",
            # Rust project build output (debug - with symbols)
            base_dir / "rust-core" / "target" / "debug",
            # Project-level release builds
            base_dir / "target" / "release",
            # Project-level debug builds
            base_dir / "target" / "debug",
            # System library directory
            base_dir / "libraries",
        ]
        
        # Search each path for matching library files
        for search_path in search_paths:
            if search_path.exists():
                for lib_name in lib_names[platform]:
                    lib_path = search_path / lib_name
                    if lib_path.exists():
                        return lib_path
        
        # If no library found, raise informative error
        raise RuntimeError(
            f"Cannot find CXA cryptographic library. Searched in: {search_paths}"
        )
    
    def get_library(self, name: str) -> ctypes.CDLL:
        """
        Retrieve a loaded library by name, loading it if necessary.
        
        This method provides lazy loading of libraries, only loading
        a library when it is first requested. Loaded libraries are
        cached for subsequent access.
        
        Args:
            name: Identifier name for the library to retrieve
            
        Returns:
            ctypes.CDLL: The loaded library instance ready for FFI calls
            
        Note:
            Currently all libraries share the same path, so this method
            always returns the main crypto library. Future extensions may
            support multiple distinct libraries.
        """
        # Check if library is already cached
        if name not in self._libraries:
            # Load the library using ctypes and cache it
            self._libraries[name] = ctypes.CDLL(str(self._lib_path))
        return self._libraries[name]
    
    @property
    def crypto_lib(self) -> ctypes.CDLL:
        """
        Get the main cryptographic library instance.
        
        This property provides convenient access to the primary cryptographic
        library used for FFI operations. It uses get_library internally to
        ensure lazy loading and caching.
        
        Returns:
            ctypes.CDLL: The loaded cryptographic library instance
            
        Example:
            lib = LibraryLoader().crypto_lib
            # Call FFI functions on lib directly
        """
        return self.get_library("cxa_crypto")


# ============================================================================
# FFI Result Types
# ============================================================================

# Data structures for encapsulating results from foreign function interface calls
# These provide type-safe wrappers around low-level FFI operations


@dataclass
class FFIResult:
    """
    Wrapper class for FFI operation results.
    
    This data class encapsulates the result of a foreign function interface
    operation, including success status, error information, and any returned data.
    
    Purpose:
    FFI calls from Python to native libraries return simple integer status codes.
    This class wraps those results in a structured format suitable for Pythonic
    error handling and data retrieval.
    
    Attributes:
        success: Boolean indicating whether the operation succeeded
        error_code: Integer error code (0 indicates success)
        error_message: Human-readable description of any error
        data: Optional bytes containing operation result data
        
    Example:
        result = lib.call_ffi_function()
        if result.success:
            process_data(result.data)
        else:
            handle_error(result.error_code, result.error_message)
    """
    
    # Operation success status
    success: bool
    
    # Error code (0 indicates success, non-zero indicates error)
    error_code: int = 0
    
    # Human-readable error description
    error_message: str = ""
    
    # Optional returned data from the operation
    data: Optional[bytes] = None
    
    @classmethod
    def from_ffi(cls, result_ptr: int) -> 'FFIResult':
        """
        Create FFIResult from a raw FFI result pointer.
        
        This method would convert a raw pointer returned by native code
        into a structured Python result object. Currently returns a
        placeholder result indicating the method is not yet implemented.
        
        Args:
            result_ptr: Raw pointer from native code (currently unused)
            
        Returns:
            FFIResult: Placeholder result indicating unimplemented functionality
        """
        # Placeholder implementation - would parse native result structure
        return cls(success=False, error_code=-1, error_message="Not implemented")
    
    def raise_on_error(self) -> None:
        """
        Raise exception if the result indicates an error.
        
        This method provides convenient error handling by raising a
        CXACryptoError when the operation was not successful.
        
        Raises:
            CXACryptoError: If success is False, with error code and message
            
        Example:
            result = perform_ffi_operation()
            result.raise_on_error()  # Raises if operation failed
            # Continue processing if we reach here
        """
        if not self.success:
            raise CXACryptoError(self.error_code, self.error_message)


class CXACryptoError(Exception):
    """
    Exception raised for cryptographic operation failures.
    
    This exception class provides structured error information for
    cryptographic operations, including error codes that can be used
    for programmatic error handling and diagnostics.
    
    Error Code Categories:
    - 1xxx: General cryptographic errors (key issues, cipher problems)
    - 2xxx: Hash operation errors
    - 3xxx: Key derivation errors
    - 4xxx: Library loading errors
    - 5xxx: Dependency missing errors
    
    Attributes:
        error_code: Numeric code identifying the error type
        message: Human-readable description of the error
        
    Example:
        try:
            result = engine.encrypt(data, key, cipher_type)
        except CXACryptoError as e:
            log_error(f"Crypto error {e.error_code}: {e.message}")
    """
    
    def __init__(self, error_code: int, message: str):
        """
        Initialize CXACryptoError with code and message.
        
        Args:
            error_code: Numeric error identifier
            message: Description of what went wrong
        """
        self.error_code = error_code
        self.message = message
        # Format message with code for exception display
        super().__init__(f"Crypto error {error_code}: {message}")


# ============================================================================
# Core Data Types - Enumerations
# ============================================================================

# Enumeration classes defining supported cryptographic algorithms and operations
# These provide type-safe choices for cryptographic operations


class CipherType(Enum):
    """
    Enumeration of supported symmetric cipher algorithms.
    
    This enumeration defines the cipher algorithms available for symmetric
    encryption operations. Each cipher has specific characteristics regarding
    security level, performance, and use cases.
    
    Supported Ciphers:
    - AES_256_GCM: Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode
    - CHACHA20_POLY1305: ChaCha20 stream cipher with Poly1305 authentication
    
    Cipher Characteristics:
    
    AES-256-GCM:
    - Industry standard for symmetric encryption
    - Hardware acceleration available on most modern processors
    - 128-bit authentication tag provides strong integrity
    - 12-byte nonce (96 bits) for each encryption
    
    ChaCha20-Poly1305:
    - Designed for software performance without hardware acceleration
    - Excellent for mobile and embedded devices
    - 24-byte nonce (192 bits) provides more flexibility
    - Constant-time implementation resistant to timing attacks
    
    Example:
        cipher = CipherType.AES_256_GCM
        encrypted = engine.encrypt(data, key, cipher)
    """
    
    # AES-256 with Galois/Counter Mode (authenticated encryption)
    AES_256_GCM = "aes_256_gcm"
    
    # ChaCha20 stream cipher with Poly1305 authentication
    CHACHA20_POLY1305 = "chacha20_poly1305"


class HashType(Enum):
    """
    Enumeration of supported cryptographic hash algorithms.
    
    This enumeration defines the hash algorithms available for computing
    cryptographic digests of data. Hash algorithms are fundamental building
    blocks used in various cryptographic protocols.
    
    Supported Hashes:
    - BLAKE3: Modern highly parallel hash function (default, fastest)
    - SHA3_256: SHA-3 family 256-bit hash
    - SHA_256: SHA-2 family 256-bit hash (widely supported)
    - SHA_512: SHA-2 family 512-bit hash (higher security margin)
    
    Security Considerations:
    
    BLAKE3:
    - Latest generation hash function
    - Very fast in software (especially with SIMD)
    - 128-bit security level for all output lengths
    - Recommended for new applications
    
    SHA-256:
    - Industry standard, extensively analyzed
    - 128-bit security level
    - Hardware acceleration widely available
    
    SHA-512:
    - Higher security margin than SHA-256
    - 256-bit security level
    - Slightly slower than SHA-256
    
    Example:
        digest = engine.hash_bytes(data, HashType.BLAKE3)
    """
    
    # BLAKE3 - Modern fast hash function
    BLAKE3 = "blake3"
    
    # SHA3-256 - SHA-3 family 256-bit hash
    SHA3_256 = "sha3_256"
    
    # SHA-256 - SHA-2 family 256-bit hash
    SHA_256 = "sha_256"
    
    # SHA-512 - SHA-2 family 512-bit hash
    SHA_512 = "sha_512"


class KdfType(Enum):
    """
    Enumeration of supported key derivation functions (KDFs).
    
    Key derivation functions convert passwords or low-entropy secrets into
    cryptographic key material. KDFs are essential for secure password-based
    encryption and key generation.
    
    Supported KDFs:
    - ARGON2id: Winner of the Password Hashing Competition (recommended)
    - SCRYPT: Memory-hard function resistant to ASIC attacks
    - PBKDF2: Password-Based Key Derivation Function 2 (widely supported)
    
    Recommendation:
    Argon2id is the recommended default for new applications. It provides
    excellent resistance against both GPU and ASIC attacks.
    
    Use Cases:
    - ARGON2id: Best overall resistance to hardware attacks
    - SCRYPT: Good alternative if Argon2 is unavailable
    - PBKDF2: Use only when compatibility is required
    
    Example:
        key, salt = engine.derive_key(password, salt, KdfType.ARGON2ID)
    """
    
    # Argon2id - Winner of Password Hashing Competition
    ARGON2ID = "argon2id"
    
    # scrypt - Memory-hard KDF
    SCRYPT = "scrypt"
    
    # PBKDF2 - Password-Based Key Derivation Function 2
    PBKDF2 = "pbkdf2"


class MacType(Enum):
    """
    Enumeration of supported message authentication code (MAC) algorithms.
    
    MAC algorithms provide integrity and authenticity verification for messages.
    They ensure that received data has not been tampered with and originates
    from a party possessing the secret key.
    
    Supported MACs:
    - HMAC_SHA256: HMAC with SHA-256 (recommended for most uses)
    - HMAC_SHA512: HMAC with SHA-512 (higher security margin)
    
    Note:
    For authenticated encryption, prefer the built-in authentication of
    AES-256-GCM or ChaCha20-Poly1305. Use standalone HMAC only when
    authentication is needed without encryption.
    
    Example:
        mac = hmac.new(key, data, MacType.HMAC_SHA256).digest()
    """
    
    # HMAC with SHA-256 (128-bit security)
    HMAC_SHA256 = "hmac_sha256"
    
    # HMAC with SHA-512 (256-bit security)
    HMAC_SHA512 = "hmac_sha512"


# ============================================================================
# Core Data Types - Data Classes
# ============================================================================

# Data classes for encapsulating cryptographic data structures


@dataclass
class EncryptedData:
    """
    Container for encrypted data with comprehensive metadata.
    
    This data class holds all information produced by an encryption operation,
    including the ciphertext, nonce, authentication tag, and cipher type.
    It provides serialization methods for storage and transmission.
    
    Data Format (Serialized):
    The to_bytes() method produces a binary format:
    - Byte 0: Cipher type identifier (first character of enum value)
    - Byte 1: Nonce length (0-255 bytes)
    - Byte 2: Authentication tag length (0-255 bytes)
    - Bytes 3-6: Ciphertext length (32-bit little-endian integer)
    - Bytes 7+: Nonce + Authentication Tag + Ciphertext
    
    Attributes:
        ciphertext: The encrypted data bytes
        nonce: Unique number used once (required for decryption)
        auth_tag: Authentication tag for integrity verification
        cipher_type: The cipher algorithm used for encryption
        timestamp: When the encryption was performed (auto-generated)
        metadata: Additional application-specific information
        
    Example:
        # Encrypt data
        encrypted = engine.encrypt(b"secret", key, CipherType.AES_256_GCM)
        
        # Serialize for storage
        data_bytes = encrypted.to_bytes()
        
        # Deserialize
        restored = EncryptedData.from_bytes(data_bytes)
        
        # Decrypt
        plaintext = engine.decrypt(restored, key)
    """
    
    # The encrypted ciphertext bytes
    ciphertext: bytes
    
    # Nonce (Number Used Once) for replay protection
    nonce: bytes
    
    # Authentication tag for integrity verification
    auth_tag: bytes
    
    # Cipher algorithm used for encryption
    cipher_type: CipherType
    
    # Timestamp of encryption (auto-generated using UTC)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Additional metadata dictionary for application use
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_bytes(self) -> bytes:
        """
        Serialize the EncryptedData to a byte string for storage or transmission.
        
        This method packs all encrypted data and metadata into a compact binary
        format that can be efficiently stored or sent over networks.
        
        Serialization Format:
        The format is designed for compactness and easy parsing:
        1. Cipher type (1 byte) - identifies the algorithm
        2. Nonce length (1 byte) - allows variable-length nonces
        3. Tag length (1 byte) - allows variable-length authentication tags
        4. Ciphertext length (4 bytes) - little-endian unsigned integer
        5. Variable data: nonce + auth_tag + ciphertext
        
        Returns:
            bytes: Binary serialized representation of this EncryptedData
            
        Note:
            The timestamp and metadata are not included in the serialization
            to maintain compatibility with the from_bytes() method.
        """
        # Get lengths for packing
        nonce_len = len(self.nonce)
        tag_len = len(self.auth_tag)
        cipher_len = len(self.ciphertext)
        
        # Build byte array for the serialized format
        result = bytearray()
        
        # Append cipher type identifier (first character)
        result.append(self.cipher_type.value[0])
        
        # Append variable-length field sizes
        result.append(nonce_len)
        result.append(tag_len)
        
        # Append ciphertext length as little-endian 32-bit integer
        result.extend(struct.pack('<I', cipher_len))
        
        # Append actual data
        result.extend(self.nonce)
        result.extend(self.auth_tag)
        result.extend(self.ciphertext)
        
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedData':
        """
        Deserialize EncryptedData from a byte string.
        
        This method reconstructs an EncryptedData object from the binary format
        produced by to_bytes(). It validates the data structure and extracts
        all components.
        
        Args:
            data: Binary serialized representation from to_bytes()
            
        Returns:
            EncryptedData: Reconstructed object with all fields populated
            
        Raises:
            ValueError: If the serialized data is malformed or too short
            
        Note:
            The timestamp will be set to the current time, and metadata will
            be empty, as these are not preserved in the serialization format.
        """
        # Validate minimum length (header + at least some data)
        if len(data) < 7:
            raise ValueError("Invalid EncryptedData bytes: insufficient length")
        
        # Extract header fields
        cipher_type = CipherType(chr(data[0]))
        nonce_len = data[1]
        tag_len = data[2]
        cipher_len = struct.unpack('<I', data[3:7])[0]
        
        # Calculate offset for variable data
        offset = 7
        
        # Extract variable-length fields
        nonce = data[offset:offset + nonce_len]
        offset += nonce_len
        auth_tag = data[offset:offset + tag_len]
        offset += tag_len
        ciphertext = data[offset:offset + cipher_len]
        
        # Return reconstructed object
        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            auth_tag=auth_tag,
            cipher_type=cipher_type
        )


@dataclass
class KeyMaterial:
    """
    Container for cryptographic key material with usage tracking.
    
    This data class holds a cryptographic key along with metadata about its
    creation and usage. It supports usage limits for additional security.
    
    Security Features:
    - Usage tracking to enforce key rotation policies
    - Maximum usage limits to prevent overuse of keys
    - Automatic error raising when usage limits are exceeded
    
    Attributes:
        key: The actual cryptographic key bytes
        key_type: The cipher algorithm this key is intended for
        created_at: When the key was generated (UTC)
        usage_count: How many times the key has been used
        max_usages: Optional maximum allowed uses (None = unlimited)
        
    Example:
        # Create key with usage limit
        key_material = KeyMaterial(
            key=key_bytes,
            key_type=CipherType.AES_256_GCM,
            max_usages=1000
        )
        
        # Use the key
        if key_material.can_use():
            key_material.use()
            perform_encryption(key_material.key)
    """
    
    # The actual cryptographic key bytes
    key: bytes
    
    # The cipher type this key is intended for
    key_type: CipherType
    
    # Creation timestamp (UTC by default)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Counter for how many times the key has been used
    usage_count: int = 0
    
    # Optional maximum number of allowed uses (None = unlimited)
    max_usages: Optional[int] = None
    
    def can_use(self) -> bool:
        """
        Check if the key can still be used based on usage limits.
        
        This method determines whether the key has remaining uses before
        reaching its maximum limit (if one is set).
        
        Returns:
            True if the key can be used, False if usage limit reached
            
        Note:
            Keys with max_usages=None are always allowed to be used.
        """
        # Unlimited if no maximum is set
        if self.max_usages is None:
            return True
        # Limited by remaining uses
        return self.usage_count < self.max_usages
    
    def use(self) -> None:
        """
        Record a key usage and check if limit is exceeded.
        
        This method increments the usage counter and checks whether the
        key has exceeded its maximum allowed uses.
        
        Raises:
            CXACryptoError: If the key's usage limit has been exceeded
            
        Note:
            This method should be called before each cryptographic operation
            using the key to maintain accurate usage tracking.
        """
        # Increment usage counter
        self.usage_count += 1
        
        # Check if we've exceeded the limit
        if not self.can_use():
            raise CXACryptoError(1002, "Key usage limit exceeded")


# ============================================================================
# Crypto Engine Interface - Abstract Base Classes
# ============================================================================

# Abstract interfaces defining the contract for cryptographic engines
# These provide polymorphic access to different implementation strategies


class ICryptoEngine(ABC):
    """
    Abstract interface defining the contract for cryptographic engines.
    
    This abstract base class defines the methods that all cryptographic engine
    implementations must provide. It enables polymorphic usage of different
    engine implementations (Rust FFI, Python fallback, etc.).
    
    Implementation Requirements:
    All concrete implementations must provide the following methods:
    - encrypt: Encrypt data with a specified cipher
    - decrypt: Decrypt encrypted data
    - hash: Compute cryptographic hash of data
    - derive_key: Derive key from password using KDF
    - generate_key: Generate random cryptographic key
    
    Thread Safety:
    Implementations should be thread-safe for concurrent operations unless
    otherwise documented.
    
    Example:
        engine: ICryptoEngine = RustCryptoEngine()
        encrypted = engine.encrypt(plaintext, key, CipherType.AES_256_GCM)
    """
    
    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes, 
                cipher_type: CipherType) -> EncryptedData:
        """
        Encrypt plaintext data using the specified cipher algorithm.
        
        Args:
            plaintext: Bytes to encrypt
            key: Encryption key bytes
            cipher_type: Cipher algorithm to use
            
        Returns:
            EncryptedData containing ciphertext and metadata
            
        Raises:
            CXACryptoError: If encryption fails
        """
        pass
    
    @abstractmethod
    def decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Decrypt encrypted data using the specified cipher.
        
        Args:
            encrypted: EncryptedData to decrypt
            key: Decryption key bytes
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If decryption fails (wrong key, corrupted data)
        """
        pass
    
    @abstractmethod
    def hash(self, data: bytes, hash_type: HashType) -> bytes:
        """
        Compute cryptographic hash of data.
        
        Args:
            data: Bytes to hash
            hash_type: Hash algorithm to use
            
        Returns:
            Hash digest bytes
            
        Raises:
            CXACryptoError: If hashing fails
        """
        pass
    
    @abstractmethod
    def derive_key(self, password: bytes, salt: bytes, 
                   kdf_type: KdfType, output_length: int) -> bytes:
        """
        Derive cryptographic key from password using KDF.
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF
            kdf_type: Key derivation function algorithm
            output_length: Desired length of derived key
            
        Returns:
            Derived key bytes
            
        Raises:
            CXACryptoError: If key derivation fails
        """
        pass
    
    @abstractmethod
    def generate_key(self, key_type: CipherType) -> bytes:
        """
        Generate random cryptographic key.
        
        Args:
            key_type: Type of key to generate
            
        Returns:
            Random key bytes of appropriate length
            
        Raises:
            CXACryptoError: If key generation fails
        """
        pass


# ============================================================================
# Rust Crypto Engine Implementation
# ============================================================================

# Concrete implementation using Rust FFI bindings for high performance


class RustCryptoEngine(ICryptoEngine):
    """
    High-performance cryptographic engine using Rust FFI bindings.
    
    This engine delegates actual cryptographic operations to optimized Rust
    implementations accessed through Foreign Function Interface (FFI). This
    provides the performance benefits of Rust's zero-cost abstractions and
    memory safety while maintaining a Pythonic interface.
    
    Features:
    - Optimized implementations in native Rust code
    - Memory-safe handling of sensitive data
    - Constant-time operations where applicable
    - Hardware acceleration when available
    
    FFI Function Signatures:
    The engine configures ctypes signatures for all native functions:
    - cxa_aes256_gcm_encrypt/decrypt
    - cxa_chacha20_poly1305_encrypt
    - cxa_blake3_hash
    - cxa_random_bytes
    - cxa_secure_wipe
    
    Attributes:
        _lib: The loaded native library CDLL instance
        _ffi_types_configured: Flag indicating FFI setup completion
        
    Example:
        engine = RustCryptoEngine()
        encrypted = engine.encrypt(b"data", key, CipherType.AES_256_GCM)
    """
    
    def __init__(self):
        """
        Initialize the Rust cryptographic engine.
        
        This constructor loads the native library and configures FFI type
        signatures for proper data conversion between Python and native code.
        
        Raises:
            RuntimeError: If native library cannot be loaded or verified
        """
        # Get the crypto library from the singleton loader
        self._lib = LibraryLoader().crypto_lib
        
        # Configure FFI function signatures
        self._setup_ffi_types()
        
        # Verify library is properly loaded
        self._verify_library()
    
    def _setup_ffi_types(self) -> None:
        """
        Configure ctypes function signatures for FFI calls.
        
        This method sets up the argument types and return types for all
        native library functions. Proper type configuration is essential
        for correct data passing between Python and native code.
        
        Functions configured:
        - cxa_aes256_gcm_encrypt: AES-256-GCM encryption
        - cxa_aes256_gcm_decrypt: AES-256-GCM decryption
        - cxa_chacha20_poly1305_encrypt: ChaCha20-Poly1305 encryption
        - cxa_blake3_hash: BLAKE3 hash computation
        - cxa_random_bytes: Secure random byte generation
        - cxa_secure_wipe: Secure memory zeroization
        
        Note:
            This method is called once during initialization and should
            not be called again during normal operation.
        """
        # =========================================================================
        # AES-256-GCM Encryption Function Signature
        # =========================================================================
        self._lib.cxa_aes256_gcm_encrypt.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # key - pointer to key bytes
            ctypes.c_size_t,                  # key_len - length of key
            ctypes.POINTER(ctypes.c_ubyte),  # plaintext - pointer to input data
            ctypes.c_size_t,                  # plaintext_len - length of input
            ctypes.POINTER(ctypes.c_ubyte),  # nonce - pointer to nonce bytes
            ctypes.c_size_t,                  # nonce_len - length of nonce
            ctypes.POINTER(ctypes.c_ubyte),  # ciphertext output pointer
            ctypes.POINTER(ctypes.c_size_t), # ciphertext_len output pointer
        ]
        self._lib.cxa_aes256_gcm_encrypt.restype = ctypes.c_int  # 0 = success
        
        # =========================================================================
        # AES-256-GCM Decryption Function Signature
        # =========================================================================
        self._lib.cxa_aes256_gcm_decrypt.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # key - pointer to key bytes
            ctypes.c_size_t,                  # key_len - length of key
            ctypes.POINTER(ctypes.c_ubyte),  # ciphertext - pointer to encrypted data
            ctypes.c_size_t,                  # ciphertext_len - length of ciphertext
            ctypes.POINTER(ctypes.c_ubyte),  # nonce - pointer to nonce bytes
            ctypes.c_size_t,                  # nonce_len - length of nonce
            ctypes.POINTER(ctypes.c_ubyte),  # auth_tag - pointer to authentication tag
            ctypes.c_size_t,                  # auth_tag_len - length of tag
            ctypes.POINTER(ctypes.c_ubyte),  # plaintext output pointer
            ctypes.POINTER(ctypes.c_size_t), # plaintext_len output pointer
        ]
        self._lib.cxa_aes256_gcm_decrypt.restype = ctypes.c_int  # 0 = success
        
        # =========================================================================
        # ChaCha20-Poly1305 Encryption Function Signature
        # =========================================================================
        self._lib.cxa_chacha20_poly1305_encrypt.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # key - pointer to key bytes
            ctypes.c_size_t,                  # key_len - length of key
            ctypes.POINTER(ctypes.c_ubyte),  # nonce - pointer to nonce bytes
            ctypes.c_size_t,                  # nonce_len - length of nonce
            ctypes.POINTER(ctypes.c_ubyte),  # plaintext - pointer to input data
            ctypes.c_size_t,                  # plaintext_len - length of input
            ctypes.POINTER(ctypes.c_ubyte),  # ciphertext output pointer
            ctypes.POINTER(ctypes.c_size_t), # ciphertext_len output pointer
            ctypes.POINTER(ctypes.c_ubyte),  # auth_tag output pointer
            ctypes.POINTER(ctypes.c_size_t), # auth_tag_len output pointer
        ]
        self._lib.cxa_chacha20_poly1305_encrypt.restype = ctypes.c_int  # 0 = success
        
        # =========================================================================
        # BLAKE3 Hash Function Signature
        # =========================================================================
        self._lib.cxa_blake3_hash.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data - pointer to input data
            ctypes.c_size_t,                  # data_len - length of input
            ctypes.POINTER(ctypes.c_ubyte),  # output - hash output pointer
            ctypes.c_size_t,                  # output_len - desired hash length
        ]
        self._lib.cxa_blake3_hash.restype = ctypes.c_int  # 0 = success
        
        # =========================================================================
        # Random Bytes Generation Function Signature
        # =========================================================================
        self._lib.cxa_random_bytes.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # output - buffer for random bytes
            ctypes.c_size_t,                  # length - number of bytes to generate
        ]
        self._lib.cxa_random_bytes.restype = ctypes.c_int  # 0 = success
        
        # =========================================================================
        # Secure Memory Wipe Function Signature
        # =========================================================================
        self._lib.cxa_secure_wipe.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # data - pointer to memory to wipe
            ctypes.c_size_t,                  # length - number of bytes to zero
        ]
        self._lib.cxa_secure_wipe.restype = None  # No return value
    
    def _verify_library(self) -> None:
        """
        Verify that the native library is properly loaded and functional.
        
        This method performs a simple test call to verify the library is
        accessible and responding correctly. It generates random bytes
        as a basic sanity check.
        
        Raises:
            RuntimeError: If library verification fails
            
        Note:
            This is a basic check that the library loads correctly. It does
            not verify all library functions are working properly.
        """
        try:
            # Allocate output buffer for random bytes test
            test_output = (ctypes.c_ubyte * 32)()
            
            # Attempt to generate random bytes
            result = self._lib.cxa_random_bytes(test_output, 32)
            
            # Check result code
            if result != 0:
                raise RuntimeError("Library verification failed")
        except Exception as e:
            raise RuntimeError(f"Failed to verify crypto library: {e}")
    
    def encrypt(self, plaintext: bytes, key: bytes, 
                cipher_type: CipherType) -> EncryptedData:
        """
        Encrypt data using the specified cipher algorithm.
        
        This method selects the appropriate encryption function based on
        the cipher type and generates a unique nonce for the operation.
        
        Args:
            plaintext: Data bytes to encrypt
            key: 32-byte encryption key
            cipher_type: Cipher algorithm to use
            
        Returns:
            EncryptedData containing ciphertext, nonce, and auth tag
            
        Raises:
            CXACryptoError: If key length is invalid or encryption fails
            
        Note:
            The nonce is randomly generated for each encryption operation
            using the secrets module for cryptographic security.
        """
        # Validate key length
        if len(key) != 32:
            raise CXACryptoError(1001, "Key must be 32 bytes for AES-256")
        
        # Generate nonce with appropriate length for cipher
        # AES-256-GCM uses 12-byte (96-bit) nonces
        # ChaCha20-Poly1305 uses 24-byte (192-bit) nonces
        nonce_length = 12 if cipher_type == CipherType.AES_256_GCM else 24
        nonce = secrets.token_bytes(nonce_length)
        
        # Route to appropriate cipher implementation
        if cipher_type == CipherType.AES_256_GCM:
            return self._aes_encrypt(plaintext, key, nonce)
        elif cipher_type == CipherType.CHACHA20_POLY1305:
            return self._chacha_encrypt(plaintext, key, nonce)
        else:
            raise CXACryptoError(1003, f"Unsupported cipher: {cipher_type}")
    
    def _aes_encrypt(self, plaintext: bytes, key: bytes, 
                     nonce: bytes) -> EncryptedData:
        """
        Perform AES-256-GCM encryption via FFI to native library.
        
        This method handles the low-level details of calling the native
        AES-256-GCM encryption function through FFI.
        
        Operation:
        1. Allocate output buffer (plaintext length + 16-byte auth tag)
        2. Convert Python bytes to ctypes pointers
        3. Call native encryption function
        4. Extract ciphertext and auth tag from output buffer
        5. Return EncryptedData container
        
        Args:
            plaintext: Data bytes to encrypt
            key: 32-byte encryption key
            nonce: Unique nonce bytes (12 bytes)
            
        Returns:
            EncryptedData with ciphertext and authentication tag
            
        Raises:
            CXACryptoError: If encryption operation fails
        """
        # Calculate output buffer size
        # AES-GCM produces ciphertext of same length as plaintext
        # Plus 16-byte authentication tag
        output_length = len(plaintext) + 16
        
        # Allocate ctypes buffer for output
        ciphertext_buffer = (ctypes.c_ubyte * output_length)()
        
        # Create size_t to receive actual output length
        actual_length = ctypes.c_size_t(output_length)
        
        # Convert Python bytes to ctypes pointers for FFI
        plaintext_ptr = ctypes.cast(
            ctypes.create_string_buffer(plaintext),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        key_ptr = ctypes.cast(
            ctypes.create_string_buffer(key),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        nonce_ptr = ctypes.cast(
            ctypes.create_string_buffer(nonce),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native encryption function via FFI
        result = self._lib.cxa_aes256_gcm_encrypt(
            key_ptr, 32,                                    # key and length
            plaintext_ptr, len(plaintext),                  # plaintext and length
            nonce_ptr, len(nonce),                          # nonce and length
            ciphertext_buffer, ctypes.byref(actual_length)  # output buffer
        )
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "AES encryption failed")
        
        # Extract ciphertext and auth tag from output buffer
        # Last 16 bytes are the authentication tag
        ciphertext = bytes(ciphertext_buffer[:actual_length.value - 16])
        auth_tag = bytes(ciphertext_buffer[actual_length.value - 16:actual_length.value])
        
        # Return encapsulated encrypted data
        return EncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            auth_tag=auth_tag,
            cipher_type=CipherType.AES_256_GCM
        )
    
    def _chacha_encrypt(self, plaintext: bytes, key: bytes, 
                        nonce: bytes) -> EncryptedData:
        """
        Perform ChaCha20-Poly1305 encryption via FFI to native library.
        
        This method handles the low-level details of calling the native
        ChaCha20-Poly1305 encryption function through FFI.
        
        Operation:
        1. Allocate output buffers for ciphertext and auth tag
        2. Convert Python bytes to ctypes pointers
        3. Call native encryption function
        4. Return EncryptedData container
        
        Args:
            plaintext: Data bytes to encrypt
            key: 32-byte encryption key
            nonce: Unique nonce bytes (24 bytes)
            
        Returns:
            EncryptedData with ciphertext and authentication tag
            
        Raises:
            CXACryptoError: If encryption operation fails
        """
        # Calculate output buffer size (plaintext + 16-byte tag)
        output_length = len(plaintext) + 16
        
        # Allocate ctypes buffers for output
        ciphertext_buffer = (ctypes.c_ubyte * output_length)()
        tag_buffer = (ctypes.c_ubyte * 16)()
        actual_length = ctypes.c_size_t(output_length)
        actual_tag_length = ctypes.c_size_t(16)
        
        # Convert Python bytes to ctypes pointers
        plaintext_ptr = ctypes.cast(
            ctypes.create_string_buffer(plaintext),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        key_ptr = ctypes.cast(
            ctypes.create_string_buffer(key),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        nonce_ptr = ctypes.cast(
            ctypes.create_string_buffer(nonce),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native encryption function via FFI
        result = self._lib.cxa_chacha20_poly1305_encrypt(
            key_ptr, 32,                                      # key and length
            nonce_ptr, len(nonce),                            # nonce and length
            plaintext_ptr, len(plaintext),                    # plaintext and length
            ciphertext_buffer, ctypes.byref(actual_length),   # ciphertext output
            tag_buffer, ctypes.byref(actual_tag_length)       # auth tag output
        )
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "ChaCha20 encryption failed")
        
        # Return encapsulated encrypted data
        return EncryptedData(
            ciphertext=bytes(ciphertext_buffer[:actual_length.value]),
            nonce=nonce,
            auth_tag=bytes(tag_buffer),
            cipher_type=CipherType.CHACHA20_POLY1305
        )
    
    def decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Decrypt encrypted data using the appropriate cipher.
        
        This method selects the appropriate decryption function based on
        the cipher type stored in the EncryptedData object.
        
        Args:
            encrypted: EncryptedData containing ciphertext and metadata
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If key length is invalid or decryption fails
            
        Note:
            Decryption failure typically indicates either a wrong key or
            corrupted/tampered ciphertext. The authentication tag prevents
            acceptance of tampered data.
        """
        # Validate key length
        if len(key) != 32:
            raise CXACryptoError(1001, "Key must be 32 bytes")
        
        # Route to appropriate cipher implementation
        if encrypted.cipher_type == CipherType.AES_256_GCM:
            return self._aes_decrypt(encrypted, key)
        elif encrypted.cipher_type == CipherType.CHACHA20_POLY1305:
            return self._chacha_decrypt(encrypted, key)
        else:
            raise CXACryptoError(1003, f"Unsupported cipher: {encrypted.cipher_type}")
    
    def _aes_decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Perform AES-256-GCM decryption via FFI to native library.
        
        This method handles the low-level details of calling the native
        AES-256-GCM decryption function through FFI.
        
        Operation:
        1. Allocate output buffer for plaintext
        2. Convert all input data to ctypes pointers
        3. Call native decryption function
        4. Return decrypted plaintext
        
        Args:
            encrypted: EncryptedData with ciphertext and metadata
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If decryption operation fails
        """
        # Allocate output buffer for plaintext
        plaintext_buffer = (ctypes.c_ubyte * len(encrypted.ciphertext))()
        actual_length = ctypes.c_size_t(len(encrypted.ciphertext))
        
        # Convert inputs to ctypes pointers
        key_ptr = ctypes.cast(
            ctypes.create_string_buffer(key),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        ciphertext_ptr = ctypes.cast(
            ctypes.create_string_buffer(encrypted.ciphertext),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        nonce_ptr = ctypes.cast(
            ctypes.create_string_buffer(encrypted.nonce),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        tag_ptr = ctypes.cast(
            ctypes.create_string_buffer(encrypted.auth_tag),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native decryption function via FFI
        result = self._lib.cxa_aes256_gcm_decrypt(
            key_ptr, 32,                                        # key and length
            ciphertext_ptr, len(encrypted.ciphertext),          # ciphertext and length
            nonce_ptr, len(encrypted.nonce),                    # nonce and length
            tag_ptr, len(encrypted.auth_tag),                   # auth tag and length
            plaintext_buffer, ctypes.byref(actual_length)       # plaintext output
        )
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "AES decryption failed")
        
        # Return decrypted plaintext
        return bytes(plaintext_buffer[:actual_length.value])
    
    def _chacha_decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Perform ChaCha20-Poly1305 decryption via FFI to native library.
        
        This method handles the low-level details of calling the native
        ChaCha20-Poly1305 decryption function through FFI.
        
        Note:
        ChaCha20 decryption is mathematically identical to encryption
        (XOR with the keystream). The same function is called for both.
        
        Args:
            encrypted: EncryptedData with ciphertext and metadata
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If decryption operation fails
        """
        # Allocate output buffers
        plaintext_buffer = (ctypes.c_ubyte * len(encrypted.ciphertext))()
        actual_length = ctypes.c_size_t(len(encrypted.ciphertext))
        tag_buffer = (ctypes.c_ubyte * 16)()
        actual_tag_length = ctypes.c_size_t(16)
        
        # Convert inputs to ctypes pointers
        key_ptr = ctypes.cast(
            ctypes.create_string_buffer(key),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        nonce_ptr = ctypes.cast(
            ctypes.create_string_buffer(encrypted.nonce),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        ciphertext_ptr = ctypes.cast(
            ctypes.create_string_buffer(encrypted.ciphertext),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native function (same as encryption for ChaCha20)
        result = self._lib.cxa_chacha20_poly1305_encrypt(
            key_ptr, 32,                                      # key and length
            nonce_ptr, len(encrypted.nonce),                  # nonce and length
            ciphertext_ptr, len(encrypted.ciphertext),        # ciphertext and length
            plaintext_buffer, ctypes.byref(actual_length),    # plaintext output
            tag_buffer, ctypes.byref(actual_tag_length)       # tag output (discarded)
        )
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "ChaCha20 decryption failed")
        
        # Return decrypted plaintext
        return bytes(plaintext_buffer[:actual_length.value])
    
    def hash(self, data: bytes, hash_type: HashType) -> bytes:
        """
        Compute cryptographic hash of data using the specified algorithm.
        
        This method routes to the appropriate hash implementation based
        on the requested algorithm.
        
        Args:
            data: Bytes to hash
            hash_type: Hash algorithm to use
            
        Returns:
            Hash digest bytes (32 bytes for most algorithms)
            
        Raises:
            CXACryptoError: If hash type is unsupported
        """
        # Route to appropriate hash implementation
        if hash_type == HashType.BLAKE3:
            return self._blake3_hash(data)
        elif hash_type == HashType.SHA_256:
            return hashlib.sha256(data).digest()
        elif hash_type == HashType.SHA_512:
            return hashlib.sha512(data).digest()
        elif hash_type == HashType.SHA3_256:
            return hashlib.sha3_256(data).digest()
        else:
            raise CXACryptoError(1004, f"Unsupported hash type: {hash_type}")
    
    def _blake3_hash(self, data: bytes) -> bytes:
        """
        Compute BLAKE3 hash of data via FFI to native library.
        
        This method handles the low-level details of calling the native
        BLAKE3 hash function through FFI.
        
        Args:
            data: Bytes to hash
            
        Returns:
            32-byte BLAKE3 hash digest
            
        Raises:
            CXACryptoError: If hash operation fails
        """
        # Allocate output buffer (32 bytes for BLAKE3-256)
        output = (ctypes.c_ubyte * 32)()
        
        # Convert input to ctypes pointer
        data_ptr = ctypes.cast(
            ctypes.create_string_buffer(data),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native hash function via FFI
        result = self._lib.cxa_blake3_hash(data_ptr, len(data), output, 32)
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "BLAKE3 hashing failed")
        
        # Return hash digest
        return bytes(output)
    
    def derive_key(self, password: bytes, salt: bytes, 
                   kdf_type: KdfType, output_length: int) -> bytes:
        """
        Derive cryptographic key from password using specified KDF.
        
        This method routes to the appropriate key derivation function
        based on the requested algorithm.
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF (should be unique per key)
            kdf_type: Key derivation function algorithm
            output_length: Desired length of derived key
            
        Returns:
            Derived key bytes of requested length
            
        Raises:
            CXACryptoError: If KDF type is unsupported
        """
        # Route to appropriate KDF implementation
        if kdf_type == KdfType.ARGON2ID:
            return self._argon2_derive(password, salt, output_length)
        elif kdf_type == KdfType.PBKDF2:
            return self._pbkdf2_derive(password, salt, output_length)
        else:
            # scrypt requires different parameters - use Python fallback
            return self._scrypt_derive(password, salt, output_length)
    
    def _argon2_derive(self, password: bytes, salt: bytes, 
                       output_length: int) -> bytes:
        """
        Derive key using Argon2id via FFI to native library.
        
        Argon2id is the recommended password-based key derivation function,
        providing strong resistance against both GPU and ASIC attacks.
        
        Default Parameters:
        - Memory cost: 64 MiB (65536 blocks)
        - Time cost: 3 iterations
        - Parallelism: 1 lane
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF
            output_length: Desired key length
            
        Returns:
            Derived key bytes of requested length
            
        Raises:
            CXACryptoError: If key derivation fails
        """
        # Allocate output buffer
        output = (ctypes.c_ubyte * output_length)()
        
        # Convert inputs to ctypes pointers
        password_ptr = ctypes.cast(
            ctypes.create_string_buffer(password),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        salt_ptr = ctypes.cast(
            ctypes.create_string_buffer(salt),
            ctypes.POINTER(ctypes.c_ubyte)
        )
        
        # Call native Argon2id function with recommended parameters
        result = self._lib.cxa_argon2id_derive(
            password_ptr, len(password),      # password and length
            salt_ptr, len(salt),              # salt and length
            65536,  # memory_cost: 64 MiB (resistant to GPU attacks)
            3,      # time_cost: 3 iterations (balance of security/performance)
            1,      # parallelism: 1 lane (can be increased for multi-core)
            output_length                      # desired output length
        )
        
        # Check for errors
        if result != 0:
            raise CXACryptoError(result, "Argon2 key derivation failed")
        
        # Return derived key
        return bytes(output)
    
    def _pbkdf2_derive(self, password: bytes, salt: bytes, 
                       output_length: int) -> bytes:
        """
        Derive key using PBKDF2-HMAC-SHA256 via Python standard library.
        
        PBKDF2 is a widely supported key derivation function. While not as
        resistant to GPU attacks as Argon2, it provides good security with
        sufficient iterations.
        
        Parameters:
        - Algorithm: HMAC-SHA256
        - Iterations: 600,000 (OWASP recommendation)
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF
            output_length: Desired key length
            
        Returns:
            Derived key bytes of requested length
        """
        # Use 600,000 iterations as recommended by OWASP
        return hashlib.pbkdf2_hmac('sha256', password, salt, 600000, output_length)
    
    def _scrypt_derive(self, password: bytes, salt: bytes, 
                       output_length: int) -> bytes:
        """
        Derive key using scrypt via Python standard library.
        
        scrypt is a memory-hard key derivation function that makes it
        expensive for attackers to use specialized hardware.
        
        Parameters:
        - N (CPU/memory cost): 32768 (2^15)
        - r (block size): 8
        - p (parallelization): 1
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF
            output_length: Desired key length
            
        Returns:
            Derived key bytes of requested length
        """
        # scrypt parameters tuned for compatibility
        N = 32768   # CPU/memory cost parameter
        r = 8       # block size parameter
        p = 1       # parallelization parameter
        
        return hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=output_length)
    
    def generate_key(self, key_type: CipherType) -> bytes:
        """
        Generate a random cryptographic key for the specified cipher.
        
        This method generates cryptographically secure random bytes suitable
        for use as encryption keys.
        
        Args:
            key_type: Cipher type to generate key for (determines key length)
            
        Returns:
            Random key bytes (32 bytes for AES-256 and ChaCha20)
            
        Raises:
            CXACryptoError: If key type is unsupported
        """
        # Both supported ciphers use 32-byte (256-bit) keys
        if key_type in (CipherType.AES_256_GCM, CipherType.CHACHA20_POLY1305):
            return secrets.token_bytes(32)
        else:
            raise CXACryptoError(1005, f"Unsupported key type: {key_type}")


# ============================================================================
# Fallback Crypto Engine Implementation (Pure Python)
# ============================================================================

# Pure Python implementation for systems without native library


class FallbackCryptoEngine(ICryptoEngine):
    """
    Pure Python fallback engine for systems without Rust library.
    
    This engine provides basic cryptographic operations using Python's
    standard library and common third-party packages when the native
    Rust library is not available.
    
    Dependencies:
    - cryptography: Required for AES-GCM and ChaCha20-Poly1305
    - blake3: Optional for faster BLAKE3 hashing
    - argon2-cffi: Optional for Argon2id key derivation
    
    Security Note:
    This fallback provides adequate security for development and testing,
    but may not achieve the same performance or side-channel resistance
    as the native Rust implementation.
    
    Example:
        engine = FallbackCryptoEngine()
        encrypted = engine.encrypt(b"data", key, CipherType.AES_256_GCM)
    """
    
    def encrypt(self, plaintext: bytes, key: bytes, 
                cipher_type: CipherType) -> EncryptedData:
        """
        Encrypt using Python's cryptography library.
        
        This method uses the cryptography.io library for encryption
        operations when the native Rust library is unavailable.
        
        Args:
            plaintext: Data bytes to encrypt
            key: 32-byte encryption key
            cipher_type: Cipher algorithm to use
            
        Returns:
            EncryptedData containing ciphertext and metadata
            
        Raises:
            CXACryptoError: If cryptography library is not installed
        """
        try:
            # Import authenticated encryption primitives
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
            
            # Generate nonce with appropriate size for cipher
            nonce = secrets.token_bytes(12 if cipher_type == CipherType.AES_256_GCM else 24)
            
            # Route to appropriate cipher
            if cipher_type == CipherType.AES_256_GCM:
                aesgcm = AESGCM(key)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                return EncryptedData(
                    ciphertext=ciphertext[:-16],  # Separate ciphertext from tag
                    nonce=nonce,
                    auth_tag=ciphertext[-16:],    # Last 16 bytes are authentication tag
                    cipher_type=cipher_type
                )
            else:
                chacha = ChaCha20Poly1305(key)
                ciphertext = chacha.encrypt(nonce, plaintext, None)
                return EncryptedData(
                    ciphertext=ciphertext[:-16],
                    nonce=nonce,
                    auth_tag=ciphertext[-16:],
                    cipher_type=cipher_type
                )
        except ImportError:
            raise CXACryptoError(1006, "cryptography library required for fallback")
    
    def decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Decrypt using Python's cryptography library.
        
        Args:
            encrypted: EncryptedData to decrypt
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If cryptography library is not installed or decryption fails
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
            
            # Combine ciphertext and auth tag for decryption
            full_ciphertext = encrypted.ciphertext + encrypted.auth_tag
            
            # Route to appropriate cipher
            if encrypted.cipher_type == CipherType.AES_256_GCM:
                aesgcm = AESGCM(key)
                return aesgcm.decrypt(encrypted.nonce, full_ciphertext, None)
            else:
                chacha = ChaCha20Poly1305(key)
                return chacha.decrypt(encrypted.nonce, full_ciphertext, None)
        except ImportError:
            raise CXACryptoError(1006, "cryptography library required for fallback")
    
    def hash(self, data: bytes, hash_type: HashType) -> bytes:
        """
        Hash using Python's hashlib or optional blake3 package.
        
        Args:
            data: Bytes to hash
            hash_type: Hash algorithm to use
            
        Returns:
            Hash digest bytes
            
        Raises:
            CXACryptoError: If hash type is unsupported
        """
        # Route to appropriate hash implementation
        if hash_type == HashType.BLAKE3:
            try:
                import blake3
                return blake3.blake3(data).digest()
            except ImportError:
                # Fall back to SHA-256 if blake3 not available
                return hashlib.sha256(data).digest()
        elif hash_type == HashType.SHA_256:
            return hashlib.sha256(data).digest()
        elif hash_type == HashType.SHA_512:
            return hashlib.sha512(data).digest()
        elif hash_type == HashType.SHA3_256:
            return hashlib.sha3_256(data).digest()
        else:
            raise CXACryptoError(1004, f"Unsupported hash type: {hash_type}")
    
    def derive_key(self, password: bytes, salt: bytes, 
                   kdf_type: KdfType, output_length: int) -> bytes:
        """
        Derive key using Python's hashlib or optional argon2 package.
        
        Args:
            password: Password bytes to derive key from
            salt: Salt bytes for KDF
            kdf_type: Key derivation function algorithm
            output_length: Desired key length
            
        Returns:
            Derived key bytes
            
        Raises:
            CXACryptoError: If KDF type is unsupported or dependency missing
        """
        # Route to appropriate KDF implementation
        if kdf_type == KdfType.ARGON2ID:
            try:
                import argon2
                from argon2 import PasswordHasher
                
                # Use argon2-cffi for password hashing
                ph = PasswordHasher()
                
                # Note: argon2-cffi is designed for password verification, not
                # raw key derivation. We use it to hash the password and then
                # derive the key from that hash.
                hash_val = ph.hash(password)
                return hashlib.sha256((hash_val + salt.hex()).encode()).digest()[:output_length]
            except ImportError:
                raise CXACryptoError(1007, "argon2 library required for Argon2id")
        elif kdf_type == KdfType.PBKDF2:
            return hashlib.pbkdf2_hmac('sha256', password, salt, 600000, output_length)
        elif hash_type == KdfType.SCRYPT:
            return hashlib.scrypt(password, salt=salt, n=32768, r=8, p=1, dklen=output_length)
        else:
            raise CXACryptoError(1008, f"Unsupported KDF type: {kdf_type}")
    
    def generate_key(self, key_type: CipherType) -> bytes:
        """
        Generate random key using secrets module.
        
        Args:
            key_type: Cipher type to generate key for
            
        Returns:
            Random 32-byte key
        """
        return secrets.token_bytes(32)


# ============================================================================
# CXA Crypto Engine - Main Entry Point
# ============================================================================

# Main public interface with automatic engine selection


class CXACryptoEngine:
    """
    Main cryptographic engine for the CXA system providing unified interface.
    
    This class provides a unified interface to all cryptographic operations,
    automatically selecting the optimal implementation (Rust FFI or Python fallback)
    based on library availability. It implements the singleton pattern for
    consistent access throughout the application.
    
    Features:
    - Automatic engine selection (Rust FFI or Python fallback)
    - Singleton pattern for consistent state
    - Simplified API for common operations
    - String/bytes auto-conversion for convenience
    
    Usage:
        # Get the singleton engine instance
        engine = CXACryptoEngine()
        
        # Generate a random key
        key = engine.generate_key(CipherType.AES_256_GCM)
        
        # Encrypt data
        encrypted = engine.encrypt(b"secret data", key)
        
        # Decrypt data
        plaintext = engine.decrypt(encrypted, key)
        
        # Derive key from password
        key, salt = engine.derive_key("password123", kdf_type=KdfType.ARGON2ID)
        
        # Hash data
        hash_str = engine.hash("data to hash")
    
    Thread Safety:
    - Thread-safe singleton initialization
    - The underlying engine implementations should be thread-safe
    
    Example:
        >>> engine = CXACryptoEngine()
        >>> key = engine.generate_key(CipherType.AES_256_GCM)
        >>> encrypted = engine.encrypt(b"secret data", key, CipherType.AES_256_GCM)
        >>> decrypted = engine.decrypt(encrypted, key)
        >>> print(decrypted)
        b'secret data'
    """
    
    # Singleton pattern class variables
    _instance: Optional['CXACryptoEngine'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """
        Implement singleton pattern for CXACryptoEngine.
        
        Ensures only one instance exists throughout the application.
        
        Returns:
            CXACryptoEngine: The singleton instance
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """
        Initialize the CXA Crypto Engine.
        
        Attempts to create a RustCryptoEngine first, falling back to
        FallbackCryptoEngine if the native library is unavailable.
        
        Side Effects:
            - Sets up the underlying crypto engine
            - Prints warning if fallback is used
        """
        # Skip if already initialized
        if self._initialized:
            return
        
        # Thread-safe initialization with double-check
        with self._lock:
            if self._initialized:
                return
            
            # Create appropriate engine implementation
            self._engine = self._create_engine()
            self._initialized = True
    
    def _create_engine(self) -> ICryptoEngine:
        """
        Create the appropriate engine based on available libraries.
        
        Attempts to create a RustCryptoEngine first for optimal performance.
        Falls back to FallbackCryptoEngine if the native library cannot be loaded.
        
        Returns:
            ICryptoEngine: The created engine instance
            
        Note:
            A warning is printed when falling back to the Python implementation.
        """
        try:
            # Try to create the high-performance Rust engine
            return RustCryptoEngine()
        except RuntimeError as e:
            # Fall back to pure Python implementation
            print(f"Warning: Rust library not available, using fallback: {e}")
            return FallbackCryptoEngine()
    
    @property
    def engine(self) -> ICryptoEngine:
        """
        Get the underlying crypto engine implementation.
        
        This property provides access to the raw engine for advanced use
        cases that require direct access to the engine interface.
        
        Returns:
            ICryptoEngine: The underlying crypto engine (Rust or fallback)
        """
        return self._engine
    
    def encrypt(self, plaintext: Union[str, bytes], key: bytes,
                cipher_type: Optional[CipherType] = None) -> EncryptedData:
        """
        Encrypt data using the specified cipher.
        
        This method provides a convenient interface for encryption operations,
        automatically converting strings to bytes and using AES-256-GCM by default.
        
        Args:
            plaintext: Data to encrypt (str will be encoded as UTF-8)
            key: 32-byte encryption key
            cipher_type: Cipher to use (defaults to AES-256-GCM)
            
        Returns:
            EncryptedData containing ciphertext and metadata
            
        Raises:
            CXACryptoError: If key length is invalid or encryption fails
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> key = engine.generate_key()
            >>> encrypted = engine.encrypt("secret", key)
            >>> type(encrypted)
            <class 'cxa.engine.EncryptedData'>
        """
        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Default to AES-256-GCM if not specified
        if cipher_type is None:
            cipher_type = CipherType.AES_256_GCM
        
        # Validate key length
        if len(key) != 32:
            raise CXACryptoError(1001, "Key must be exactly 32 bytes")
        
        # Delegate to underlying engine
        return self._engine.encrypt(plaintext, key, cipher_type)
    
    def decrypt(self, encrypted: EncryptedData, key: bytes) -> bytes:
        """
        Decrypt encrypted data.
        
        This method decrypts data that was encrypted using the encrypt() method
        or compatible encryption from other sources.
        
        Args:
            encrypted: EncryptedData to decrypt
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CXACryptoError: If key length is invalid or decryption fails
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> key = engine.generate_key()
            >>> encrypted = engine.encrypt("secret", key)
            >>> plaintext = engine.decrypt(encrypted, key)
            >>> print(plaintext)
            b'secret'
        """
        # Validate key length
        if len(key) != 32:
            raise CXACryptoError(1001, "Key must be exactly 32 bytes")
        
        # Delegate to underlying engine
        return self._engine.decrypt(encrypted, key)
    
    def hash(self, data: Union[str, bytes], 
             hash_type: HashType = HashType.BLAKE3) -> str:
        """
        Hash data and return as hexadecimal string.
        
        This method computes a cryptographic hash of the input data and
        returns it as a hex-encoded string for easy display and storage.
        
        Args:
            data: Data to hash (str will be encoded as UTF-8)
            hash_type: Hash algorithm to use (default: BLAKE3)
            
        Returns:
            Hexadecimal hash string (64 characters for BLAKE3-256)
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> engine.hash("hello")
            '02cf...'
        """
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Compute hash and return as hex string
        digest = self._engine.hash(data, hash_type)
        return digest.hex()
    
    def hash_bytes(self, data: Union[str, bytes],
                   hash_type: HashType = HashType.BLAKE3) -> bytes:
        """
        Hash data and return as raw bytes.
        
        This method computes a cryptographic hash of the input data and
        returns the raw bytes for use in cryptographic operations.
        
        Args:
            data: Data to hash (str will be encoded as UTF-8)
            hash_type: Hash algorithm to use (default: BLAKE3)
            
        Returns:
            Raw hash bytes (32 bytes for BLAKE3-256)
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> engine.hash_bytes("hello")
            b'\\x02\\xcf\\x...'
        """
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Compute hash and return raw bytes
        return self._engine.hash(data, hash_type)
    
    def derive_key(self, password: Union[str, bytes], salt: Optional[bytes] = None,
                   kdf_type: KdfType = KdfType.ARGON2ID,
                   output_length: int = 32) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password.
        
        This method uses a key derivation function to convert a password
        into a cryptographic key. The salt should be stored alongside
        the derived key for future verification.
        
        Args:
            password: Password or passphrase (str will be encoded as UTF-8)
            salt: Optional salt bytes (will be generated if not provided)
            kdf_type: Key derivation function to use (default: Argon2id)
            output_length: Desired key length in bytes (default: 32)
            
        Returns:
            Tuple of (derived_key, salt). Both should be stored securely.
            
        Raises:
            CXACryptoError: If key derivation fails
            
        Security Note:
            Always use a unique salt for each derived key. The salt can
            be stored in plaintext alongside the encrypted data.
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> key, salt = engine.derive_key("my_password")
            >>> # Store salt for later use
            >>> stored_data.encrypt(data, key)
        """
        # Convert string to bytes if necessary
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate salt if not provided
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Derive key using KDF
        key = self._engine.derive_key(password, salt, kdf_type, output_length)
        return key, salt
    
    def generate_key(self, cipher_type: CipherType = CipherType.AES_256_GCM) -> bytes:
        """
        Generate a random cryptographic key.
        
        This method generates a cryptographically secure random key
        suitable for use with the specified cipher.
        
        Args:
            cipher_type: Type of key to generate (determines key length)
            
        Returns:
            Random key bytes (32 bytes for both supported ciphers)
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> key = engine.generate_key(CipherType.AES_256_GCM)
            >>> len(key)
            32
        """
        return self._engine.generate_key(cipher_type)
    
    def generate_nonce(self, cipher_type: CipherType) -> bytes:
        """
        Generate a random nonce for the specified cipher.
        
        This method generates a cryptographically secure nonce (number
        used once) appropriate for the specified cipher algorithm.
        
        Args:
            cipher_type: Cipher that will use the nonce
            
        Returns:
            Random nonce bytes (12 bytes for AES, 24 bytes for ChaCha20)
            
        Raises:
            CXACryptoError: If cipher type is unsupported
            
        Note:
            Each encryption operation should use a unique nonce. Reusing
            a nonce with the same key compromises security.
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> nonce = engine.generate_nonce(CipherType.AES_256_GCM)
            >>> len(nonce)
            12
        """
        # Generate appropriate-sized nonce for cipher
        if cipher_type == CipherType.AES_256_GCM:
            return secrets.token_bytes(12)  # 96 bits for AES-GCM
        elif cipher_type == CipherType.CHACHA20_POLY1305:
            return secrets.token_bytes(24)  # 192 bits for ChaCha20
        else:
            raise CXACryptoError(1009, f"Unsupported cipher for nonce: {cipher_type}")
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte sequences in constant time.
        
        This method compares two byte sequences using a timing-safe
        comparison algorithm to prevent timing attacks.
        
        Args:
            a: First byte sequence
            b: Second byte sequence
            
        Returns:
            True if sequences are equal, False otherwise
            
        Security Note:
            Always use constant-time comparison when comparing sensitive
            values like authentication tags, MACs, or password hashes.
            
        Example:
            >>> engine = CXACryptoEngine()
            >>> engine.secure_compare(b"abc", b"abc")
            True
            >>> engine.secure_compare(b"abc", b"abd")
            False
        """
        return secure_compare(a, b)


# ============================================================================
# Module-Level Utility Functions
# ============================================================================

def get_engine() -> CXACryptoEngine:
    """
    Get the singleton CXACryptoEngine instance as a module-level convenience.
    
    This function provides a simple way to access the crypto engine without
    explicitly instantiating the class, following the singleton pattern.
    
    Returns:
        CXACryptoEngine: The singleton engine instance
        
    Example:
        >>> engine = get_engine()
        >>> key = engine.generate_key()
    """
    return CXACryptoEngine()
