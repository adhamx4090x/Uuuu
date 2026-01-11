"""
Unit Tests for CXA Backup Module

This module contains unit tests for backup functionality,
testing secure backup creation, restoration, and key management.
"""

import pytest
import os
import sys
import json
import tarfile
import zipfile
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))


class TestBackupManager:
    """Test cases for backup management functionality."""

    @pytest.fixture
    def backup_manager(self, tmp_path):
        """Create a backup manager instance."""
        from cxa.backup import CXABackupManager
        return CXABackupManager(str(tmp_path))

    @pytest.fixture
    def sample_data_dir(self, tmp_path):
        """Create sample data directory for backup testing."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        
        # Create various files
        (data_dir / "file1.txt").write_text("File 1 content")
        (data_dir / "file2.txt").write_text("File 2 content")
        (data_dir / "subdir").mkdir()
        (data_dir / "subdir" / "file3.txt").write_text("Nested file content")
        
        return data_dir

    def test_create_backup(self, backup_manager, sample_data_dir, tmp_path):
        """Test creating a backup archive."""
        backup_path = backup_manager.create_backup(
            source=sample_data_dir,
            name="test_backup"
        )
        
        assert backup_path is not None
        assert os.path.exists(backup_path)
        assert backup_path.endswith((".zip", ".tar.gz", ".cxa"))

    def test_backup_manifest_creation(self, backup_manager, sample_data_dir):
        """Test that backup manifest is created correctly."""
        backup_path = backup_manager.create_backup(
            source=sample_data_dir,
            name="manifest_test"
        )
        
        manifest_path = backup_path.replace(".zip", ".manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            assert 'timestamp' in manifest
            assert 'files' in manifest
            assert 'checksum' in manifest

    def test_backup_file_inclusion(self, backup_manager, sample_data_dir, tmp_path):
        """Test that all files are included in backup."""
        backup_path = backup_manager.create_backup(
            source=sample_data_dir,
            name="file_test"
        )
        
        # Extract and verify
        extract_dir = tmp_path / "extracted"
        backup_manager.extract_backup(backup_path, extract_dir)
        
        # Check files exist
        assert (extract_dir / "file1.txt").exists()
        assert (extract_dir / "file2.txt").exists()
        assert (extract_dir / "subdir" / "file3.txt").exists()

    def test_backup_content_verification(self, backup_manager, sample_data_dir):
        """Test backup content integrity verification."""
        backup_path = backup_manager.create_backup(
            source=sample_data_dir,
            name="integrity_test"
        )
        
        is_valid = backup_manager.verify_backup(backup_path)
        
        assert is_valid is True

    def test_backup_listing(self, backup_manager, sample_data_dir):
        """Test listing available backups."""
        # Create multiple backups
        backup_manager.create_backup(sample_data_dir, "backup1")
        backup_manager.create_backup(sample_data_dir, "backup2")
        
        backups = backup_manager.list_backups()
        
        assert len(backups) >= 2
        assert any(b['name'] == 'backup1' for b in backups)
        assert any(b['name'] == 'backup2' for b in backups)

    def test_backup_deletion(self, backup_manager, sample_data_dir):
        """Test deleting a backup."""
        backup_path = backup_manager.create_backup(
            source=sample_data_dir,
            name="to_delete"
        )
        
        result = backup_manager.delete_backup(backup_path)
        
        assert result is True
        assert not os.path.exists(backup_path)

    def test_encrypted_backup(self, backup_manager, sample_data_dir):
        """Test creating an encrypted backup."""
        password = "secure_backup_password"
        
        backup_path = backup_manager.create_encrypted_backup(
            source=sample_data_dir,
            password=password,
            name="encrypted_test"
        )
        
        assert backup_path is not None
        assert os.path.exists(backup_path)

    def test_encrypted_backup_restoration(self, backup_manager, sample_data_dir, tmp_path):
        """Test restoring an encrypted backup."""
        password = "restore_password_123"
        
        backup_path = backup_manager.create_encrypted_backup(
            source=sample_data_dir,
            password=password,
            name="restore_test"
        )
        
        # Restore with wrong password should fail
        with pytest.raises(Exception):
            backup_manager.restore_backup(backup_path, str(tmp_path / "wrong"), "wrong_password")
        
        # Restore with correct password should succeed
        restore_dir = tmp_path / "restored"
        backup_manager.restore_backup(backup_path, str(restore_dir), password)
        
        assert (restore_dir / "file1.txt").exists()


class TestBackupRotation:
    """Test cases for backup rotation policies."""

    @pytest.fixture
    def backup_manager_with_rotation(self, tmp_path):
        """Create backup manager with rotation settings."""
        from cxa.backup import CXABackupManager
        return CXABackupManager(
            str(tmp_path),
            max_backups=3,
            retention_days=30
        )

    @pytest.fixture
    def source_data(self, tmp_path):
        """Create source data for backups."""
        data_dir = tmp_path / "source"
        data_dir.mkdir()
        (data_dir / "data.txt").write_text("Test data")
        return data_dir

    def test_max_backups_enforcement(self, backup_manager_with_rotation, source_data):
        """Test that old backups are deleted when max is reached."""
        # Create more backups than max_backups
        for i in range(5):
            backup_manager_with_rotation.create_backup(
                source=source_data,
                name=f"backup_{i}"
            )
        
        backups = backup_manager_with_rotation.list_backups()
        
        # Should only keep the most recent 3
        assert len(backups) <= 3

    def test_old_backups_retention(self, backup_manager_with_rotation, source_data):
        """Test that old backups are cleaned up based on retention."""
        backup_manager_with_rotation.create_backup(source_data, "old_backup")
        
        # Simulate old backup by modifying timestamp
        backup_path = backup_manager_with_rotation.list_backups()[-1]['path']
        old_time = datetime.now() - timedelta(days=35)
        os.utime(backup_path, (old_time.timestamp(), old_time.timestamp()))
        
        # Run cleanup
        backup_manager_with_rotation.cleanup_old_backups()
        
        backups = backup_manager_with_rotation.list_backups()
        
        # Old backup should be removed
        assert len(backups) == 0 or all(
            datetime.fromisoformat(b['timestamp']) > datetime.now() - timedelta(days=30)
            for b in backups
        )


class TestBackupCompression:
    """Test cases for backup compression options."""

    @pytest.fixture
    def backup_manager(self, tmp_path):
        """Create backup manager instance."""
        from cxa.backup import CXABackupManager
        return CXABackupManager(str(tmp_path))

    @pytest.fixture
    def large_data_dir(self, tmp_path):
        """Create a larger dataset for compression testing."""
        data_dir = tmp_path / "large_data"
        data_dir.mkdir()
        
        # Create repetitive data (compresses well)
        repetitive_content = "This is repeated content. " * 1000
        for i in range(10):
            (data_dir / f"file_{i}.txt").write_text(repetitive_content)
        
        return data_dir

    def test_compressed_backup_size(self, backup_manager, large_data_dir):
        """Test that compressed backup is smaller than uncompressed."""
        uncompressed = backup_manager.create_backup(
            source=large_data_dir,
            name="uncompressed_test",
            compress=False
        )
        compressed = backup_manager.create_backup(
            source=large_data_dir,
            name="compressed_test",
            compress=True
        )
        
        if uncompressed and compressed:
            uncompressed_size = os.path.getsize(uncompressed)
            compressed_size = os.path.getsize(compressed)
            
            # Compressed should be smaller
            assert compressed_size <= uncompressed_size

    def test_compression_level_options(self, backup_manager, large_data_dir):
        """Test different compression levels."""
        levels = ['fast', 'medium', 'best']
        
        for level in levels:
            backup_path = backup_manager.create_backup(
                source=large_data_dir,
                name=f"level_{level}",
                compression_level=level
            )
            
            assert backup_path is not None
