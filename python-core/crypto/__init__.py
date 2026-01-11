"""
CXA Cryptographic System - Python Core Package.

This package provides the Python interface to the CXA cryptographic system,
wrapping the Rust core modules for high-performance cryptographic operations.

Modules:
    engine: Main cryptographic engine coordinating all operations
    aes: AES-GCM and AES-CBC encryption wrappers
    chacha20: ChaCha20-Poly1305 encryption wrappers
    hash: SHA-256, SHA-512, and BLAKE3 hash function wrappers
    kdf: Key derivation functions (Argon2id, PBKDF2)
    ecc: Elliptic Curve Cryptography (Curve25519)
    random: Cryptographically secure random number generation

New in Version 2.0:
    - Argon2id key derivation (memory-hard, GPU-resistant)
    - PBKDF2 with configurable iterations
    - Curve25519 ECDH for secure key exchange
    - DCT-based steganography for robust data hiding
    - ML-powered threat detection

Usage:
    >>> from cxa_core.crypto import CryptoEngine
    >>> engine = CryptoEngine()
    >>> ciphertext, tag = engine.encrypt_aes_gcm(b"Hello, World!", key, nonce)
    
    >>> from cxa_core.crypto.kdf import CXAKeyDerivation, KdfType
    >>> kdf = CXAKeyDerivation()
    >>> result = kdf.derive_key("password", algorithm=KdfType.ARGON2ID)
    
    >>> from cxa_core.crypto.ecc import ECDH, generate_keypair
    >>> ecdh = ECDH()
    >>> shared_secret = ecdh.derive_shared_secret(peers_public_key)
"""

from .engine import CryptoEngine, CryptoError, SecurityLevel
from .kdf import CXAKeyDerivation, KdfType, KdfResult, Argon2Hasher, PBKDF2Hasher
from .ecc import (
    ECDH, 
    ECCKeyPair, 
    ECDHResult, 
    generate_keypair, 
    derive_shared_secret,
    validate_public_key,
    Curve25519Library
)

# Optional modules - may not be available in all configurations
try:
    from .aes import AesGcm256, AesCbc256
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False
    AesGcm256 = None
    AesCbc256 = None

try:
    from .chacha20 import ChaCha20Poly1305
    _CHACHA20_AVAILABLE = True
except ImportError:
    _CHACHA20_AVAILABLE = False
    ChaCha20Poly1305 = None

try:
    from .hash import Sha256, Sha512, Blake3
    _HASH_AVAILABLE = True
except ImportError:
    _HASH_AVAILABLE = False
    Sha256 = None
    Sha512 = None
    Blake3 = None

try:
    from .random import SecureRandom
    _RANDOM_AVAILABLE = True
except ImportError:
    _RANDOM_AVAILABLE = False
    SecureRandom = None

__all__ = [
    # Core engine
    "CryptoEngine",
    "CryptoError",
    "SecurityLevel",
    # Key Derivation (NEW)
    "CXAKeyDerivation",
    "KdfType",
    "KdfResult",
    "Argon2Hasher",
    "PBKDF2Hasher",
    # Elliptic Curve Cryptography (NEW)
    "ECDH",
    "ECCKeyPair",
    "ECDHResult",
    "generate_keypair",
    "derive_shared_secret",
    "validate_public_key",
    "Curve25519Library",
    # Optional modules (may be None if not available)
    "AesGcm256",
    "AesCbc256",
    "ChaCha20Poly1305",
    "Sha256",
    "Sha512",
    "Blake3",
    "SecureRandom",
]

__version__ = "2.0.0"
