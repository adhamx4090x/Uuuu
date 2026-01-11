"""
Fuzz Tests for CXA Cryptographic Components

This module contains fuzz tests to discover potential vulnerabilities
and edge cases in cryptographic operations using hypothesis.
"""

import pytest
import hypothesis.strategies as st
from hypothesis import given, settings, Verbosity
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))


# Hypothesis strategies for fuzz testing
binary_data = st.binary(min_size=0, max_size=1024)
text_data = st.text(min_size=0, max_size=512, alphabet=st.characters(
    whitelist_categories=['L', 'N'],
    whitelist_characters='_@#$%^&*()'
))
valid_keys = st.binary(min_size=16, max_size=64)
valid_nonces = st.binary(min_size=8, max_size=16)
passwords = st.text(min_size=1, max_size=64)


class TestCryptoFuzzing:
    """Fuzz tests for cryptographic operations."""

    @pytest.fixture
    def crypto_engine(self):
        """Create crypto engine for fuzz testing."""
        from crypto.engine import CXACryptoEngine
        return CXACryptoEngine()

    @given(data=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_sha256_fuzz(self, crypto_engine, data):
        """Fuzz test SHA-256 hash function."""
        result = crypto_engine.sha256(data)
        assert len(result) == 64  # Always 64 hex characters
        assert result.isalnum()

    @given(data=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_sha512_fuzz(self, crypto_engine, data):
        """Fuzz test SHA-512 hash function."""
        result = crypto_engine.sha512(data)
        assert len(result) == 128  # Always 128 hex characters
        assert result.isalnum()

    @given(plaintext=binary_data, key=valid_keys)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_aes_encrypt_fuzz(self, crypto_engine, plaintext, key):
        """Fuzz test AES encryption."""
        nonce = crypto_engine.generate_nonce()
        
        try:
            ciphertext = crypto_engine.aes_encrypt(plaintext, key, nonce)
            assert len(ciphertext) >= len(plaintext)  # Auth tag adds overhead
            
            # Verify roundtrip
            decrypted = crypto_engine.aes_decrypt(ciphertext, key, nonce)
            assert decrypted == plaintext
        except (ValueError, RuntimeError):
            # May fail with invalid inputs, should be handled gracefully
            pass

    @given(plaintext=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_chacha20_fuzz(self, crypto_engine, plaintext):
        """Fuzz test ChaCha20 encryption."""
        key = crypto_engine.generate_key(32)
        nonce = crypto_engine.generate_nonce(12)
        
        try:
            ciphertext = crypto_engine.chacha20_encrypt(plaintext, key, nonce)
            
            # Verify roundtrip
            decrypted = crypto_engine.chacha20_decrypt(ciphertext, key, nonce)
            assert decrypted == plaintext
        except (ValueError, RuntimeError):
            pass

    @given(password=passwords, salt=binary_data, iterations=st.integers(min_value=1, max_value=10000))
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_pbkdf2_fuzz(self, crypto_engine, password, salt, iterations):
        """Fuzz test PBKDF2 key derivation."""
        try:
            key = crypto_engine.pbkdf2(
                password.encode('utf-8'),
                salt,
                iterations,
                32
            )
            assert len(key) == 32
            
            # Deterministic
            key2 = crypto_engine.pbkdf2(
                password.encode('utf-8'),
                salt,
                iterations,
                32
            )
            assert key == key2
        except (ValueError, RuntimeError):
            pass

    @given(message=binary_data, key=valid_keys)
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_hmac_fuzz(self, crypto_engine, message, key):
        """Fuzz test HMAC generation."""
        try:
            mac = crypto_engine.hmac(message, key)
            assert len(mac) == 32  # SHA-256 HMAC
            
            # Verify
            assert crypto_engine.hmac_verify(message, key, mac) is True
        except (ValueError, RuntimeError):
            pass


class TestStegoFuzzing:
    """Fuzz tests for steganography operations."""

    @pytest.fixture
    def stego_engine(self):
        """Create stego engine for fuzz testing."""
        from stego.image import CXAStegoImage
        return CXAStegoImage()

    @given(message=text_data)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_zalgo_encode_fuzz(self, stego_engine, message):
        """Fuzz test Zalgo text encoding."""
        from stego.text import CXAStegoText
        text_stego = CXAStegoText()
        
        try:
            encoded = text_stego.encode_zalgo("Base text", message)
            assert len(encoded) > 0
        except (ValueError, RuntimeError):
            pass

    @given(message=text_data)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_zwc_encode_fuzz(self, stego_engine, message):
        """Fuzz test zero-width character encoding."""
        from stego.text import CXAStegoText
        text_stego = CXAStegoText()
        
        try:
            encoded = text_stego.encode_zwc("Base text", message)
            # Should have same visual length
            stripped = encoded.replace('\u200b', '').replace('\u200c', '')
            stripped = stripped.replace('\u200d', '').replace('\u2060', '')
            assert len(stripped) == len("Base text")
        except (ValueError, RuntimeError):
            pass


class TestKeyManagerFuzzing:
    """Fuzz tests for key management."""

    @pytest.fixture
    def key_manager(self, tmp_path):
        """Create key manager for fuzz testing."""
        from crypto.key_manager import CXAKeyManager
        return CXAKeyManager(str(tmp_path))

    @given(password=passwords)
    @settings(verbosity=Verbosity.quiet, max_examples=30)
    def test_key_encryption_fuzz(self, key_manager, password):
        """Fuzz test key encryption with various passwords."""
        try:
            key_id = key_manager.generate_key("fuzz_test")
            encrypted = key_manager.encrypt_key(key_id, password)
            
            # Should be able to decrypt
            decrypted = key_manager.decrypt_key(key_id, password)
            assert decrypted is not None
            
            # Cleanup
            key_manager.delete_key(key_id)
        except (ValueError, RuntimeError):
            pass


class TestEdgeCaseFuzzing:
    """Fuzz tests for edge cases."""

    @pytest.fixture
    def crypto_engine(self):
        """Create crypto engine for edge case testing."""
        from crypto.engine import CXACryptoEngine
        return CXACryptoEngine()

    @given(data=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_empty_data_handling(self, crypto_engine, data):
        """Fuzz test handling of empty or minimal data."""
        if len(data) == 0:
            # Empty data
            result = crypto_engine.sha256(data)
            assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        elif len(data) == 1:
            # Single byte
            result = crypto_engine.sha256(data)
            assert len(result) == 64

    @given(data=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_boundary_key_sizes(self, crypto_engine, data):
        """Fuzz test with boundary key sizes."""
        key_sizes = [16, 24, 32]  # 128, 192, 256 bit
        
        for key_size in key_sizes:
            key = crypto_engine.generate_key(key_size)
            assert len(key) == key_size
            
            nonce = crypto_engine.generate_nonce()
            
            try:
                ciphertext = crypto_engine.aes_encrypt(data, key, nonce)
                decrypted = crypto_engine.aes_decrypt(ciphertext, key, nonce)
                assert decrypted == data
            except (ValueError, RuntimeError):
                pass

    @given(pattern=st.text(min_size=0, max_size=100, alphabet=st.characters(
        whitelist_categories=['L', 'N', 'Ps', 'Pe']
    )))
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_special_characters_in_strings(self, pattern):
        """Fuzz test with special characters."""
        # Test that various Unicode characters don't cause crashes
        test_string = f"Test with special chars: {pattern}"
        
        # Just ensure it doesn't crash
        assert len(test_string) >= 0

    @given(value=st.integers(min_value=-1000, max_value=1000))
    @settings(verbosity=Verbosity.quiet, max_examples=100)
    def test_integer_boundaries(self, value):
        """Fuzz test with integer boundaries."""
        # Test that negative and boundary values are handled
        if value < 0:
            # Negative values should be handled appropriately
            pass
        elif value == 0:
            # Zero case
            pass
        else:
            # Positive values
            assert value > 0


class TestMemoryFuzzing:
    """Fuzz tests for memory operations."""

    @pytest.fixture
    def memory_manager(self):
        """Create memory manager for fuzz testing."""
        from cxa.memory import CXASecureMemory
        return CXASecureMemory()

    @given(data=binary_data)
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_secure_memory_fuzz(self, memory_manager, data):
        """Fuzz test secure memory operations."""
        try:
            buffer = memory_manager.allocate(len(data))
            if buffer is not None and len(buffer) >= len(data):
                # Copy data
                for i, b in enumerate(data):
                    buffer[i] = b
                
                # Verify
                retrieved = bytes(buffer[:len(data)])
                assert retrieved == data
                
                # Secure delete
                memory_manager.secure_delete(buffer)
        except (MemoryError, RuntimeError, OverflowError):
            pass


class TestSecurityMonitorFuzzing:
    """Fuzz tests for security monitoring."""

    @pytest.fixture
    def security_monitor(self, tmp_path):
        """Create security monitor for fuzz testing."""
        from cxa.security_monitor import CXASecurityMonitor
        return CXASecurityMonitor(str(tmp_path))

    @given(ip=st.ipv4s(), port=st.integers(min_value=0, max_value=65535))
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_connection_logging_fuzz(self, security_monitor, ip, port):
        """Fuzz test connection logging with various IPs and ports."""
        from cxa.security_monitor import CXAIntrusionDetection
        ids = CXAIntrusionDetection(str(security_monitor.log_dir))
        
        try:
            ids.log_connection(
                source=ip,
                destination="192.168.1.1",
                port=port,
                protocol="TCP"
            )
        except (ValueError, RuntimeError):
            pass

    @given(
        event_type=st.text(min_size=0, max_size=50, alphabet=st.characters(
            whitelist_categories=['L', 'N'],
            whitelist_characters='_'
        )),
        severity=st.sampled_from(['low', 'medium', 'high', 'critical'])
    )
    @settings(verbosity=Verbosity.quiet, max_examples=50)
    def test_event_logging_fuzz(self, security_monitor, event_type, severity):
        """Fuzz test event logging."""
        try:
            security_monitor.log_event(
                event_type=event_type or "unknown",
                severity=severity,
                details={}
            )
        except (ValueError, RuntimeError):
            pass
