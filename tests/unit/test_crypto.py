"""
Unit Tests for CXA Crypto Engine

This module contains unit tests for the cryptographic engine,
testing encryption, decryption, hashing, and key derivation.
"""

import pytest
import hashlib
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))

from crypto.engine import CXACryptoEngine
from crypto.key_manager import CXAKeyManager


class TestCXACryptoEngine:
    """Test cases for CXACryptoEngine class."""

    @pytest.fixture
    def crypto_engine(self):
        """Create a crypto engine instance for testing."""
        return CXACryptoEngine()

    def test_engine_initialization(self, crypto_engine):
        """Test that crypto engine initializes correctly."""
        assert crypto_engine is not None
        assert hasattr(crypto_engine, 'cipher')
        assert hasattr(crypto_engine, 'hash')

    def test_sha256_hash(self, crypto_engine):
        """Test SHA-256 hash generation."""
        test_data = b"Hello, World!"
        expected_hash = hashlib.sha256(test_data).hexdigest()
        
        result = crypto_engine.sha256(test_data)
        
        assert result == expected_hash
        assert len(result) == 64  # SHA-256 produces 64 hex characters

    def test_sha256_empty_data(self, crypto_engine):
        """Test SHA-256 with empty data."""
        result = crypto_engine.sha256(b"")
        expected = hashlib.sha256(b"").hexdigest()
        
        assert result == expected

    def test_sha512_hash(self, crypto_engine):
        """Test SHA-512 hash generation."""
        test_data = b"SHA-512 test data"
        
        result = crypto_engine.sha512(test_data)
        
        assert len(result) == 128  # SHA-512 produces 128 hex characters

    def test_aes_encrypt_decrypt(self, crypto_engine):
        """Test AES encryption and decryption roundtrip."""
        key = crypto_engine.generate_key(32)  # 256-bit key
        nonce = crypto_engine.generate_nonce()
        plaintext = b"Secret message for AES encryption"
        
        # Encrypt
        ciphertext = crypto_engine.aes_encrypt(plaintext, key, nonce)
        
        # Decrypt
        decrypted = crypto_engine.aes_decrypt(ciphertext, key, nonce)
        
        assert decrypted == plaintext
        assert ciphertext != plaintext

    def test_aes_encrypt_randomness(self, crypto_engine):
        """Test that encryption produces different outputs each time."""
        key = crypto_engine.generate_key(32)
        nonce1 = crypto_engine.generate_nonce()
        nonce2 = crypto_engine.generate_nonce()
        plaintext = b"Same plaintext"
        
        ciphertext1 = crypto_engine.aes_encrypt(plaintext, key, nonce1)
        ciphertext2 = crypto_engine.aes_encrypt(plaintext, key, nonce2)
        
        # Different nonces should produce different ciphertexts
        assert ciphertext1 != ciphertext2

    def test_chacha20_encrypt_decrypt(self, crypto_engine):
        """Test ChaCha20 encryption and decryption roundtrip."""
        key = crypto_engine.generate_key(32)
        nonce = crypto_engine.generate_nonce(12)  # ChaCha20 uses 12-byte nonce
        plaintext = b"ChaCha20 encryption test"
        
        ciphertext = crypto_engine.chacha20_encrypt(plaintext, key, nonce)
        decrypted = crypto_engine.chacha20_decrypt(ciphertext, key, nonce)
        
        assert decrypted == plaintext

    def test_generate_key_sizes(self, crypto_engine):
        """Test key generation with different sizes."""
        key_16 = crypto_engine.generate_key(16)  # 128-bit
        key_24 = crypto_engine.generate_key(24)  # 192-bit
        key_32 = crypto_engine.generate_key(32)  # 256-bit
        
        assert len(key_16) == 16
        assert len(key_24) == 24
        assert len(key_32) == 32

    def test_generate_random_bytes(self, crypto_engine):
        """Test random byte generation."""
        random_16 = crypto_engine.random_bytes(16)
        random_32 = crypto_engine.random_bytes(32)
        
        assert len(random_16) == 16
        assert len(random_32) == 32
        
        # Ensure randomness
        assert random_16 != crypto_engine.random_bytes(16)

    def test_pbkdf2_derivation(self, crypto_engine):
        """Test PBKDF2 key derivation."""
        password = b"test_password"
        salt = b"salt_value"
        iterations = 1000
        
        key = crypto_engine.pbkdf2(password, salt, iterations, 32)
        
        assert len(key) == 32
        # Same inputs should produce same output
        key2 = crypto_engine.pbkdf2(password, salt, iterations, 32)
        assert key == key2

    def test_hmac_generation(self, crypto_engine):
        """Test HMAC generation and verification."""
        key = crypto_engine.generate_key(32)
        message = b"Message for HMAC"
        
        mac = crypto_engine.hmac(message, key)
        
        assert len(mac) == 32  # SHA-256 HMAC
        
        # Verify HMAC
        assert crypto_engine.hmac_verify(message, key, mac)


class TestCXAKeyManager:
    """Test cases for CXAKeyManager class."""

    @pytest.fixture
    def key_manager(self, tmp_path):
        """Create a key manager instance with temp directory."""
        return CXAKeyManager(str(tmp_path))

    def test_key_generation(self, key_manager):
        """Test key generation."""
        key_id = key_manager.generate_key("test_key")
        
        assert key_id is not None
        assert len(key_id) > 0

    def test_key_storage_and_retrieval(self, key_manager, tmp_path):
        """Test storing and retrieving keys."""
        key_id = key_manager.generate_key("storage_test")
        original_key = key_manager.get_key(key_id)
        
        assert original_key is not None
        assert len(original_key) == 32  # Default 256-bit key

    def test_key_encryption(self, key_manager):
        """Test key encryption with password."""
        key_id = key_manager.generate_key("encrypted_test")
        password = "strong_password_123"
        
        encrypted = key_manager.encrypt_key(key_id, password)
        
        assert encrypted is not None
        
        # Decrypt and verify
        decrypted = key_manager.decrypt_key(key_id, password)
        assert decrypted is not None

    def test_key_deletion(self, key_manager):
        """Test key deletion."""
        key_id = key_manager.generate_key("to_delete")
        
        result = key_manager.delete_key(key_id)
        
        assert result is True
        
        # Verify key is gone
        key = key_manager.get_key(key_id)
        assert key is None

    def test_key_listing(self, key_manager):
        """Test listing stored keys."""
        key_manager.generate_key("key1")
        key_manager.generate_key("key2")
        
        keys = key_manager.list_keys()
        
        assert len(keys) >= 2
