"""
Integration Tests for CXA Complete Workflow

This module contains integration tests that test the complete
workflow of CXA, including cross-component interactions.
"""

import pytest
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))


class TestCryptoStegoIntegration:
    """Integration tests for crypto and steganography combined."""

    @pytest.fixture
    def combined_system(self, tmp_path):
        """Set up the combined crypto and stego system."""
        from crypto.engine import CXACryptoEngine
        from stego.image import CXAStegoImage
        
        return {
            'crypto': CXACryptoEngine(),
            'stego': CXAStegoImage(),
            'tmp': tmp_path
        }

    def test_encrypted_steganography_workflow(self, combined_system, tmp_path):
        """Test encrypting data then hiding in image."""
        crypto = combined_system['crypto']
        stego = combined_system['stego']
        
        # Create test image
        from PIL import Image
        import numpy as np
        img_array = np.zeros((100, 100, 3), dtype=np.uint8)
        img_array[:, :, 0] = 255
        img = Image.fromarray(img_array, 'RGB')
        img_path = tmp_path / "base.png"
        img.save(str(img_path))
        
        # 1. Encrypt the secret data
        secret = b"TOP SECRET MESSAGE"
        key = crypto.generate_key(32)
        nonce = crypto.generate_nonce()
        encrypted = crypto.aes_encrypt(secret, key, nonce)
        
        # 2. Hide encrypted data in image
        output_path = str(tmp_path / "stego_encrypted.png")
        stego.embed_lsb(str(img_path), encrypted.decode('latin-1'), output_path)
        
        # 3. Extract and decrypt
        extracted = stego.extract_lsb(output_path)
        decrypted = crypto.aes_decrypt(extracted.encode('latin-1'), key, nonce)
        
        assert decrypted == secret

    def test_stego_then_encrypt_workflow(self, combined_system, tmp_path):
        """Test hiding data then encrypting the image."""
        crypto = combined_system['crypto']
        stego = combined_system['stego']
        
        # Create test image
        from PIL import Image
        import numpy as np
        img_array = np.zeros((100, 100, 3), dtype=np.uint8)
        img_array[:, :, 1] = 128
        img = Image.fromarray(img_array, 'RGB')
        img_path = tmp_path / "stego_base.png"
        img.save(str(img_path))
        
        # 1. Hide secret in image
        secret = "Hidden message"
        output_path = str(tmp_path / "hidden.png")
        stego.embed_lsb(str(img_path), secret, output_path)
        
        # 2. Encrypt the stego image
        key = crypto.generate_key(32)
        nonce = crypto.generate_nonce()
        with open(output_path, 'rb') as f:
            image_data = f.read()
        encrypted_image = crypto.aes_encrypt(image_data, key, nonce)
        
        # 3. Save encrypted image
        encrypted_path = str(tmp_path / "encrypted_stego.cxa")
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_image)
        
        # 4. Decrypt and verify
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = crypto.aes_decrypt(encrypted_data, key, nonce)
        
        # Write and extract
        restored_path = str(tmp_path / "restored.png")
        with open(restored_path, 'wb') as f:
            f.write(decrypted_data)
        
        extracted = stego.extract_lsb(restored_path)
        assert extracted == secret


class TestBackupSecurityIntegration:
    """Integration tests for backup and security features."""

    @pytest.fixture
    def backup_security_system(self, tmp_path):
        """Set up backup and security system."""
        from cxa.backup import CXABackupManager
        from cxa.security_monitor import CXASecurityMonitor
        
        return {
            'backup': CXABackupManager(str(tmp_path)),
            'security': CXASecurityMonitor(str(tmp_path)),
            'tmp': tmp_path
        }

    def test_secure_backup_with_logging(self, backup_security_system, tmp_path):
        """Test creating backup while logging security events."""
        backup = backup_security_system['backup']
        security = backup_security_system['security']
        
        # Create source data
        data_dir = tmp_path / "secure_data"
        data_dir.mkdir()
        (data_dir / "secret.txt").write_text("Confidential data")
        
        # Create backup
        backup_path = backup.create_backup(
            source=data_dir,
            name="secure_backup_test"
        )
        
        # Check security events were logged
        events = security.get_events()
        backup_events = [e for e in events if 'backup' in e['type'].lower()]
        
        assert backup_path is not None
        assert len(backup_events) >= 1

    def test_backup_threat_detection(self, backup_security_system, tmp_path):
        """Test detecting threats in backup operations."""
        backup = backup_security_system['backup']
        security = backup_security_system['security']
        
        # Create source data
        data_dir = tmp_path / "threat_data"
        data_dir.mkdir()
        (data_dir / "data.txt").write_text("Test")
        
        # Create backup
        backup_path = backup.create_backup(
            source=data_dir,
            name="threat_test"
        )
        
        # Simulate security check
        security.log_event(
            event_type="backup_integrity_check",
            severity="medium",
            details={"backup": backup_path}
        )
        
        threats = security.get_threats()
        
        # Integrity should be verified
        is_valid = backup.verify_backup(backup_path)
        assert is_valid is True


class TestKeyManagementIntegration:
    """Integration tests for key management with other components."""

    @pytest.fixture
    def key_system(self, tmp_path):
        """Set up key management system."""
        from crypto.key_manager import CXAKeyManager
        from crypto.engine import CXACryptoEngine
        
        return {
            'key_manager': CXAKeyManager(str(tmp_path)),
            'crypto': CXACryptoEngine(),
            'tmp': tmp_path
        }

    def test_key_encryption_backup_cycle(self, key_system, tmp_path):
        """Test key generation, encryption, and backup."""
        key_mgr = key_system['key_manager']
        crypto = key_system['crypto']
        
        # Generate key
        key_id = key_mgr.generate_key("cycle_test")
        
        # Get raw key
        raw_key = key_mgr.get_key(key_id)
        
        # Use key for encryption
        message = b"Test message with managed key"
        nonce = crypto.generate_nonce()
        ciphertext = crypto.aes_encrypt(message, raw_key, nonce)
        
        # Decrypt with same key
        decrypted = crypto.aes_decrypt(ciphertext, raw_key, nonce)
        
        assert decrypted == message
        
        # Backup the key
        from cxa.backup import CXABackupManager
        backup_mgr = CXABackupManager(str(tmp_path))
        key_backup = backup_mgr.create_backup(
            source=str(tmp_path / f"{key_id}.key"),
            name="key_backup_test"
        )

    def test_key_derivation_for_stego(self, key_system, tmp_path):
        """Test using derived keys for steganography."""
        key_mgr = key_system['key_manager']
        crypto = key_system['crypto']
        
        # Generate master key
        master_key_id = key_mgr.generate_key("master")
        master_key = key_mgr.get_key(master_key_id)
        
        # Derive key for specific purpose
        salt = b"stego_salt_2024"
        stego_key = crypto.pbkdf2(master_key, salt, iterations=100000, key_len=32)
        
        # Use derived key
        assert len(stego_key) == 32
        assert stego_key != master_key


class TestEndToEndEncryption:
    """End-to-end encryption workflow tests."""

    @pytest.fixture
    def e2e_system(self, tmp_path):
        """Set up complete E2E system."""
        from crypto.engine import CXACryptoEngine
        from crypto.key_manager import CXAKeyManager
        from stego.image import CXAStegoImage
        from cxa.backup import CXABackupManager
        
        return {
            'crypto': CXACryptoEngine(),
            'key_mgr': CXAKeyManager(str(tmp_path)),
            'stego': CXAStegoImage(),
            'backup': CXABackupManager(str(tmp_path)),
            'tmp': tmp_path
        }

    def test_complete_secure_workflow(self, e2e_system, tmp_path):
        """Test complete workflow: key gen -> encrypt -> stego -> backup."""
        crypto = e2e_system['crypto']
        key_mgr = e2e_system['key_mgr']
        stego = e2e_system['stego']
        backup = e2e_system['backup']
        
        # 1. Generate and store key
        key_id = key_mgr.generate_key("e2e_test")
        key = key_mgr.get_key(key_id)
        
        # 2. Create secret data
        secret = b"End-to-end encrypted secret"
        
        # 3. Encrypt data
        nonce = crypto.generate_nonce()
        encrypted = crypto.aes_encrypt(secret, key, nonce)
        
        # 4. Hide in image
        from PIL import Image
        import numpy as np
        img_array = np.zeros((200, 200, 3), dtype=np.uint8)
        img_array[50:150, 50:150, 2] = 255
        img = Image.fromarray(img_array, 'RGB')
        img_path = tmp_path / "carrier.png"
        img.save(str(img_path))
        
        stego_path = str(tmp_path / "stego_final.png")
        stego.embed_lsb(str(img_path), encrypted.decode('latin-1'), stego_path)
        
        # 5. Backup everything
        backup_path = backup.create_backup(
            source=stego_path,
            name="e2e_backup"
        )
        
        # Verification
        assert os.path.exists(stego_path)
        assert os.path.exists(backup_path)
        
        # Extract and decrypt
        extracted = stego.extract_lsb(stego_path)
        decrypted = crypto.aes_decrypt(extracted.encode('latin-1'), key, nonce)
        
        assert decrypted == secret

    def test_multi_recipient_workflow(self, e2e_system, tmp_path):
        """Test encrypting for multiple recipients."""
        crypto = e2e_system['crypto']
        key_mgr = e2e_system['key_mgr']
        
        # Generate keys for multiple recipients
        keys = {}
        for i in range(3):
            key_id = key_mgr.generate_key(f"recipient_{i}")
            keys[f"recipient_{i}"] = key_mgr.get_key(key_id)
        
        # Encrypt with hybrid approach
        message = b"Shared secret message"
        session_key = crypto.generate_key(32)
        session_nonce = crypto.generate_nonce()
        
        # Encrypt with session key
        encrypted = crypto.aes_encrypt(message, session_key, session_nonce)
        
        # Encrypt session key for each recipient
        encrypted_keys = {}
        for recipient, key in keys.items():
            enc_session_key = crypto.aes_encrypt(session_key, key, crypto.generate_nonce())
            encrypted_keys[recipient] = enc_session_key
        
        # Verify all can decrypt
        for recipient, enc_key in encrypted_keys.items():
            # In real scenario, recipient would decrypt enc_key first
            decrypted_key = crypto.aes_decrypt(enc_key, keys[recipient], crypto.generate_nonce())
            final_decrypted = crypto.aes_decrypt(encrypted, decrypted_key, session_nonce)
            assert final_decrypted == message


class TestPerformanceIntegration:
    """Integration tests for performance monitoring."""

    def test_large_file_encryption_performance(self, tmp_path):
        """Test encryption performance with large files."""
        import time
        from crypto.engine import CXACryptoEngine
        
        crypto = CXACryptoEngine()
        
        # Create large test file (10MB)
        large_file = tmp_path / "large.dat"
        large_file.write_bytes(b"x" * (10 * 1024 * 1024))
        
        # Measure encryption time
        key = crypto.generate_key(32)
        nonce = crypto.generate_nonce()
        
        start = time.time()
        with open(large_file, 'rb') as f:
            data = f.read()
        encrypted = crypto.aes_encrypt(data, key, nonce)
        elapsed = time.time() - start
        
        # Should complete in reasonable time (less than 10 seconds)
        assert elapsed < 10.0
        
        # Verify correctness
        decrypted = crypto.aes_decrypt(encrypted, key, nonce)
        assert decrypted == data
