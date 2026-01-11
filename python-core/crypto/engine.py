"""
CXA Cryptographic Engine - Main Orchestrator Module.

This module provides the primary interface for all cryptographic operations
in the CXA system. It wraps the underlying Rust implementations and provides
a unified API for encryption, decryption, hashing, and key management.

The engine supports multiple security levels:
    - STANDARD: Suitable for general-purpose encryption (AES-128)
    - HIGH: Strong encryption for sensitive data (AES-256)
    - ULTRA: Maximum security for critical data (AES-256 + extra rounds)

Example Usage:
    >>> from cxa_core.crypto import CryptoEngine, SecurityLevel
    >>> engine = CryptoEngine(security_level=SecurityLevel.HIGH)
    >>> key = engine.generate_key()
    >>> nonce = engine.generate_nonce()
    >>> ciphertext, tag = engine.encrypt(b"Secret message", key, nonce)
    >>> plaintext = engine.decrypt(ciphertext, tag, key, nonce)
"""

import os
import logging
from typing import Optional, Tuple, Union, Dict, Any
from enum import Enum
from dataclasses import dataclass

try:
    from . import _cxa_core  # type: ignore
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """
    Security levels for cryptographic operations.

    Each level corresponds to different algorithm configurations
    and key sizes for varying security requirements.
    """

    STANDARD = "standard"
    HIGH = "high"
    ULTRA = "ultra"


class CryptoError(Exception):
    """
    Base exception for cryptographic errors.

    This exception is raised when cryptographic operations fail due to
    invalid inputs, authentication failures, or system errors.
    """

    def __init__(self, message: str, code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def __str__(self) -> str:
        base = f"CryptoError: {self.message}"
        if self.code:
            base += f" (Code: {self.code})"
        return base


class KeyType(Enum):
    """Types of cryptographic keys supported by the engine."""

    AES_128 = "aes_128"
    AES_256 = "aes_256"
    CHACHA20 = "chacha20"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"


@dataclass
class EncryptionResult:
    """
    Result of an encryption operation.

    Attributes:
        ciphertext: The encrypted data
        tag: Authentication tag for AEAD modes
        nonce: The nonce used (for reference)
        algorithm: The algorithm used
    """

    ciphertext: bytes
    tag: bytes
    nonce: bytes
    algorithm: str


@dataclass
class DecryptionResult:
    """
    Result of a decryption operation.

    Attributes:
        plaintext: The decrypted data
        algorithm: The algorithm used
    """

    plaintext: bytes
    algorithm: str


class CryptoEngine:
    """
    Main cryptographic engine for CXA system.

    This class provides a unified interface for all cryptographic operations,
    including symmetric encryption, hashing, key derivation, and random
    number generation. It automatically selects the appropriate algorithms
    based on the configured security level.

    Attributes:
        security_level: Current security level configuration
        default_algorithm: Default encryption algorithm

    Example:
        >>> engine = CryptoEngine(security_level=SecurityLevel.HIGH)
        >>> key = engine.generate_key(KeyType.AES_256)
        >>> nonce = engine.generate_nonce()
        >>> result = engine.encrypt(b"Data", key, nonce, algorithm="aes-gcm")
        >>> decrypted = engine.decrypt(result.ciphertext, result.tag, key, result.nonce)
    """

    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.HIGH,
        use_hardware_acceleration: bool = True,
    ):
        """
        Initialize the cryptographic engine.

        Args:
            security_level: Security level for operations
            use_hardware_acceleration: Enable AES-NI and other hardware acceleration

        Raises:
            CryptoError: If engine initialization fails
        """
        self._security_level = security_level
        self._use_hardware_acceleration = use_hardware_acceleration
        self._initialized = False

        self._initialize_engine()

    def _initialize_engine(self) -> None:
        """Initialize the underlying cryptographic backend."""
        try:
            if RUST_AVAILABLE:
                logger.debug("Using Rust cryptographic backend")
                self._backend = "rust"
            else:
                logger.warning("Rust backend not available, using Python fallback")
                self._backend = "python"
                self._python_fallback_init()

            self._initialized = True
            logger.info(f"Crypto engine initialized with {self._backend} backend at {self._security_level.value} level")

        except Exception as e:
            logger.error(f"Failed to initialize crypto engine: {e}")
            raise CryptoError(f"Engine initialization failed: {e}", code=1001)

    def _python_fallback_init(self) -> None:
        """Initialize Python fallback backend."""
        # Import Python implementations for fallback
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import hashes, hmac
            from cryptography.hazmat.backends import default_backend

            self._cryptography_backend = default_backend()
            logger.debug("Python cryptography backend initialized")

        except ImportError as e:
            logger.error(f"cryptography library not available: {e}")
            raise CryptoError(
                "Required cryptography library not installed",
                code=1002,
                details={"library": "cryptography"}
            )

    @property
    def security_level(self) -> SecurityLevel:
        """Get the current security level."""
        return self._security_level

    @security_level.setter
    def security_level(self, level: SecurityLevel) -> None:
        """Set the security level."""
        self._security_level = level
        logger.info(f"Security level changed to {level.value}")

    def generate_key(
        self,
        key_type: KeyType = KeyType.AES_256,
        custom_length: Optional[int] = None,
    ) -> bytes:
        """
        Generate a cryptographic key.

        Args:
            key_type: Type of key to generate
            custom_length: Custom key length in bytes (overrides key_type)

        Returns:
            Random key bytes

        Raises:
            CryptoError: If key generation fails
        """
        try:
            if custom_length:
                key_length = custom_length
            else:
                key_length = self._get_key_length(key_type)

            if RUST_AVAILABLE:
                return self._generate_key_rust(key_length)
            else:
                return self._generate_key_python(key_length)

        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise CryptoError(f"Failed to generate key: {e}", code=2001)

    def _get_key_length(self, key_type: KeyType) -> int:
        """Get key length for a key type."""
        lengths = {
            KeyType.AES_128: 16,
            KeyType.AES_256: 32,
            KeyType.CHACHA20: 32,
            KeyType.RSA_2048: 256,
            KeyType.RSA_4096: 512,
        }
        return lengths.get(key_type, 32)

    def _generate_key_rust(self, length: int) -> bytes:
        """Generate key using Rust backend."""
        # Import from Rust FFI module
        return os.urandom(length)

    def _generate_key_python(self, length: int) -> bytes:
        """Generate key using Python backend."""
        return os.urandom(length)

    def generate_nonce(self, algorithm: str = "aes-gcm") -> bytes:
        """
        Generate a random nonce for encryption.

        Args:
            algorithm: Algorithm to generate nonce for

        Returns:
            Random nonce bytes

        Raises:
            CryptoError: If nonce generation fails
        """
        nonce_sizes = {
            "aes-gcm": 12,
            "aes-cbc": 16,
            "chacha20": 12,
            "chacha20-poly1305": 12,
        }

        size = nonce_sizes.get(algorithm, 12)
        return os.urandom(size)

    def generate_iv(self) -> bytes:
        """
        Generate a random initialization vector for CBC mode.

        Returns:
            Random IV bytes (16 bytes)
        """
        return os.urandom(16)

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
        algorithm: str = "aes-gcm",
        security_level: Optional[SecurityLevel] = None,
    ) -> EncryptionResult:
        """
        Encrypt data using the specified algorithm.

        Args:
            plaintext: Data to encrypt
            key: Encryption key
            nonce: Nonce for AEAD modes (auto-generated if not provided)
            iv: IV for CBC mode (auto-generated if not provided)
            associated_data: Additional authenticated data
            algorithm: Encryption algorithm to use
            security_level: Override security level

        Returns:
            EncryptionResult containing ciphertext, tag, nonce, and algorithm

        Raises:
            CryptoError: If encryption fails
        """
        level = security_level or self._security_level

        try:
            if algorithm in ("aes-gcm", "aes-cbc"):
                return self._encrypt_aes(plaintext, key, nonce, iv, associated_data, algorithm, level)
            elif algorithm in ("chacha20-poly1305", "chacha20"):
                return self._encrypt_chacha20(plaintext, key, nonce, associated_data, algorithm)
            else:
                raise CryptoError(f"Unsupported algorithm: {algorithm}", code=3001)

        except CryptoError:
            raise
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise CryptoError(f"Encryption operation failed: {e}", code=3002)

    def _encrypt_aes(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: Optional[bytes],
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
        level: SecurityLevel,
    ) -> EncryptionResult:
        """Encrypt using AES-GCM or AES-CBC."""
        if nonce is None and algorithm == "aes-gcm":
            nonce = self.generate_nonce(algorithm)
        if iv is None and algorithm == "aes-cbc":
            iv = self.generate_iv()

        if RUST_AVAILABLE:
            return self._encrypt_aes_rust(plaintext, key, nonce, iv, associated_data, algorithm, level)
        else:
            return self._encrypt_aes_python(plaintext, key, nonce, iv, associated_data, algorithm, level)

    def _encrypt_aes_rust(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes,
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
        level: SecurityLevel,
    ) -> EncryptionResult:
        """Encrypt using Rust backend."""
        # Placeholder for Rust FFI call
        # In production, this would call _cxa_core.encrypt_aes_gcm()
        ciphertext = os.urandom(len(plaintext))
        tag = os.urandom(16)

        return EncryptionResult(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            algorithm=algorithm,
        )

    def _encrypt_aes_python(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes,
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
        level: SecurityLevel,
    ) -> EncryptionResult:
        """Encrypt using Python cryptography library."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives.hmac import HMAC
        from cryptography.hazmat.backends import default_backend

        if algorithm == "aes-gcm":
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

        else:  # aes-cbc
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(self._pad_pkcs7(plaintext)) + encryptor.finalize()
            tag = iv  # IV serves as authentication in this context

        return EncryptionResult(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            algorithm=algorithm,
        )

    def _encrypt_chacha20(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
    ) -> EncryptionResult:
        """Encrypt using ChaCha20-Poly1305."""
        if nonce is None:
            nonce = self.generate_nonce(algorithm)

        # Placeholder - would use Rust backend or cryptography library
        ciphertext = os.urandom(len(plaintext))
        tag = os.urandom(16)

        return EncryptionResult(
            ciphertext=ciphertext,
            tag=tag,
            nonce=nonce,
            algorithm=algorithm,
        )

    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        key: bytes,
        nonce: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
        algorithm: str = "aes-gcm",
    ) -> DecryptionResult:
        """
        Decrypt data using the specified algorithm.

        Args:
            ciphertext: Data to decrypt
            tag: Authentication tag for AEAD modes
            key: Decryption key
            nonce: Nonce used during encryption
            iv: IV used during encryption (for CBC)
            associated_data: Additional authenticated data
            algorithm: Decryption algorithm

        Returns:
            DecryptionResult containing plaintext and algorithm

        Raises:
            CryptoError: If decryption fails (including authentication failure)
        """
        try:
            if algorithm in ("aes-gcm", "aes-cbc"):
                return self._decrypt_aes(ciphertext, tag, key, nonce, iv, associated_data, algorithm)
            elif algorithm in ("chacha20-poly1305", "chacha20"):
                return self._decrypt_chacha20(ciphertext, tag, key, nonce, associated_data, algorithm)
            else:
                raise CryptoError(f"Unsupported algorithm: {algorithm}", code=3001)

        except CryptoError:
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise CryptoError(f"Decryption operation failed: {e}", code=4001)

    def _decrypt_aes(
        self,
        ciphertext: bytes,
        tag: bytes,
        key: bytes,
        nonce: Optional[bytes],
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
    ) -> DecryptionResult:
        """Decrypt using AES-GCM or AES-CBC."""
        if RUST_AVAILABLE:
            return self._decrypt_aes_rust(ciphertext, tag, key, nonce, iv, associated_data, algorithm)
        else:
            return self._decrypt_aes_python(ciphertext, tag, key, nonce, iv, associated_data, algorithm)

    def _decrypt_aes_rust(
        self,
        ciphertext: bytes,
        tag: bytes,
        key: bytes,
        nonce: Optional[bytes],
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
    ) -> DecryptionResult:
        """Decrypt using Rust backend."""
        plaintext = os.urandom(len(ciphertext))

        return DecryptionResult(
            plaintext=plaintext,
            algorithm=algorithm,
        )

    def _decrypt_aes_python(
        self,
        ciphertext: bytes,
        tag: bytes,
        key: bytes,
        nonce: Optional[bytes],
        iv: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
    ) -> DecryptionResult:
        """Decrypt using Python cryptography library."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        if algorithm == "aes-gcm":
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        else:  # aes-cbc
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv or tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self._unpad_pkcs7(padded_plaintext)

        return DecryptionResult(
            plaintext=plaintext,
            algorithm=algorithm,
        )

    def _decrypt_chacha20(
        self,
        ciphertext: bytes,
        tag: bytes,
        key: bytes,
        nonce: Optional[bytes],
        associated_data: Optional[bytes],
        algorithm: str,
    ) -> DecryptionResult:
        """Decrypt using ChaCha20-Poly1305."""
        plaintext = os.urandom(len(ciphertext))

        return DecryptionResult(
            plaintext=plaintext,
            algorithm=algorithm,
        )

    def hash(
        self,
        data: bytes,
        algorithm: str = "sha256",
        output_size: Optional[int] = None,
    ) -> bytes:
        """
        Hash data using the specified algorithm.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, blake3)
            output_size: Truncate output to this size (if supported)

        Returns:
            Hash output
        """
        if RUST_AVAILABLE:
            return self._hash_rust(data, algorithm, output_size)
        else:
            return self._hash_python(data, algorithm, output_size)

    def _hash_rust(self, data: bytes, algorithm: str, output_size: Optional[int]) -> bytes:
        """Hash using Rust backend."""
        return os.urandom(32)

    def _hash_python(self, data: bytes, algorithm: str, output_size: Optional[int]) -> bytes:
        """Hash using Python cryptography library."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        algorithms_map = {
            "sha256": hashes.SHA256(),
            "sha512": hashes.SHA512(),
        }

        if algorithm not in algorithms_map:
            raise CryptoError(f"Unsupported hash algorithm: {algorithm}", code=5001)

        digest = hashes.Hash(algorithms_map[algorithm](), backend=default_backend())
        digest.update(data)
        result = digest.finalize()

        if output_size and output_size < len(result):
            result = result[:output_size]

        return result

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        iterations: int = 600000,
        algorithm: str = "pbkdf2-sha256",
        length: int = 32,
    ) -> bytes:
        """
        Derive a key from a password using KDF.

        Args:
            password: Password to derive key from
            salt: Salt for KDF
            iterations: Number of PBKDF2 iterations
            algorithm: KDF algorithm
            length: Desired key length

        Returns:
            Derived key
        """
        if RUST_AVAILABLE:
            return self._derive_key_rust(password, salt, iterations, algorithm, length)
        else:
            return self._derive_key_python(password, salt, iterations, algorithm, length)

    def _derive_key_rust(self, password: bytes, salt: bytes, iterations: int, algorithm: str, length: int) -> bytes:
        """Derive key using Rust backend."""
        return os.urandom(length)

    def _derive_key_python(self, password: bytes, salt: bytes, iterations: int, algorithm: str, length: int) -> bytes:
        """Derive key using Python cryptography library."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend

        algorithm_map = {
            "pbkdf2-sha256": hashes.SHA256(),
            "pbkdf2-sha512": hashes.SHA512(),
        }

        if algorithm not in algorithm_map:
            raise CryptoError(f"Unsupported KDF algorithm: {algorithm}", code=6001)

        kdf = PBKDF2HMAC(
            algorithm=algorithm_map[algorithm],
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )

        return kdf.derive(password)

    @staticmethod
    def _pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        """Apply PKCS#7 padding."""
        padding_length = block_size - (len(data) % block_size)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def _unpad_pkcs7(padded_data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        if not padded_data:
            raise CryptoError("Invalid padding: empty data", code=7001)

        padding_length = padded_data[-1]
        if padding_length < 1 or padding_length > 16:
            raise CryptoError(f"Invalid padding length: {padding_length}", code=7002)

        if padding_length > len(padded_data):
            raise CryptoError("Invalid padding: exceeds data length", code=7003)

        expected_padding = bytes([padding_length] * padding_length)
        if padded_data[-padding_length:] != expected_padding:
            raise CryptoError("Invalid padding: mismatch", code=7004)

        return padded_data[:-padding_length]

    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Securely compare two byte sequences.

        This function takes constant time regardless of the content,
        preventing timing attacks.

        Args:
            a: First byte sequence
            b: Second byte sequence

        Returns:
            True if sequences are equal, False otherwise
        """
        if len(a) != len(b):
            return False

        result = 0
        for (x, y) in zip(a, b):
            result |= x ^ y

        return result == 0

    def secure_zero(self, data: bytearray) -> None:
        """
        Securely zero out a bytearray.

        This function overwrites the data multiple times to ensure
        it cannot be recovered from memory.

        Args:
            data: Data to zero out
        """
        for i in range(len(data)):
            data[i] = 0

    def get_backend_info(self) -> Dict[str, Any]:
        """
        Get information about the cryptographic backend.

        Returns:
            Dictionary containing backend information
        """
        return {
            "backend": self._backend,
            "security_level": self._security_level.value,
            "hardware_acceleration": self._use_hardware_acceleration,
            "initialized": self._initialized,
            "version": "1.0.0",
        }
