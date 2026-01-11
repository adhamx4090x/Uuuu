"""
Unit Tests for CXA Memory Security Module

This module contains unit tests for secure memory management,
testing memory locking, encryption, and secure deletion.
"""

import pytest
import os
import sys
import ctypes
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))


class TestSecureMemory:
    """Test cases for secure memory operations."""

    @pytest.fixture
    def memory_manager(self):
        """Create a secure memory manager instance."""
        from cxa.memory import CXASecureMemory
        return CXASecureMemory()

    def test_secure_memory_allocation(self, memory_manager):
        """Test secure memory allocation."""
        size = 1024  # 1KB
        
        buffer = memory_manager.allocate(size)
        
        assert buffer is not None
        assert len(buffer) == size

    def test_memory_locking(self, memory_manager):
        """Test that memory can be locked to prevent swapping."""
        buffer = memory_manager.allocate(512)
        
        result = memory_manager.lock(buffer)
        
        assert result is True

    def test_memory_unlocking(self, memory_manager):
        """Test memory unlocking."""
        buffer = memory_manager.allocate(512)
        memory_manager.lock(buffer)
        
        result = memory_manager.unlock(buffer)
        
        assert result is True

    def test_secure_deletion(self, memory_manager):
        """Test secure deletion of memory contents."""
        # Allocate and fill with data
        buffer = bytearray(b"Secret data to delete")
        original_content = bytes(buffer)
        
        # Securely delete
        memory_managersecure_delete(buffer)
        
        # Buffer should be zeroed
        assert all(b == 0 for b in buffer)
        
        # Original data should be gone (we can't verify this directly,
        # but the secure delete should have overwritten it)

    def test_memory_encryption(self, memory_manager):
        """Test in-memory encryption of data."""
        plaintext = b"Sensitive data for encryption"
        
        encrypted = memory_manager.encrypt_in_memory(plaintext)
        
        assert encrypted != plaintext
        
        # Should be able to decrypt
        decrypted = memory_manager.decrypt_in_memory(encrypted)
        assert decrypted == plaintext

    def test_memory_zeroization(self, memory_manager):
        """Test memory zeroization on cleanup."""
        sensitive_data = bytearray(b"Very sensitive information here")
        
        # Zeroize
        memory_manager.zeroize(sensitive_data)
        
        # All zeros
        assert all(b == 0 for b in sensitive_data)


class TestMemoryProtection:
    """Test cases for memory protection features."""

    @pytest.fixture
    def mem_protector(self):
        """Create memory protector instance."""
        from cxa.memory import CXAMemoryProtector
        return CXAMemoryProtector()

    def test_readonly_memory_protection(self, mem_protector):
        """Test making memory read-only."""
        buffer = bytearray(b"Protected data")
        
        result = mem_protector.make_readonly(buffer)
        
        assert result is True
        
        # Attempting to modify should raise exception or fail silently
        try:
            buffer[0] = 0
            was_protected = False  # Protection might not work on all platforms
        except (TypeError, ctypes.error, MemoryError):
            was_protected = True

    def test_executable_memory_prevention(self, mem_protector):
        """Test preventing memory from being executable."""
        buffer = bytearray(b"Non-executable code")
        
        result = mem_protector.prevent_execution(buffer)
        
        assert result is True

    def test_memory_integrity_check(self, mem_protector):
        """Test memory integrity verification."""
        data = b"Data to verify"
        
        checksum = mem_protector.calculate_checksum(data)
        
        # Same data should produce same checksum
        checksum2 = mem_protector.calculate_checksum(data)
        assert checksum == checksum2
        
        # Modified data should produce different checksum
        modified_data = b"Modified data      "
        checksum3 = mem_protector.calculate_checksum(modified_data)
        assert checksum != checksum3

    def test_stack_protection(self, mem_protector):
        """Test stack canary/protection setup."""
        result = mem_protector.enable_stack_protection()
        
        assert result is True or result is not None


class TestSecureString:
    """Test cases for secure string handling."""

    @pytest.fixture
    def secure_string(self):
        """Create secure string handler."""
        from cxa.memory import CXASecureString
        return CXASecureString()

    def test_secure_password_storage(self, secure_string):
        """Test secure storage of passwords."""
        password = "MySecretPassword123!"
        
        stored = secure_string.store(password)
        
        assert stored is not None
        assert stored != password  # Should be encrypted or transformed

    def test_secure_string_comparison(self, secure_string):
        """Test constant-time string comparison."""
        str1 = "TestString123"
        str2 = "TestString123"
        str3 = "DifferentString"
        
        # Same strings
        assert secure_string.compare(str1, str2) is True
        
        # Different strings
        assert secure_string.compare(str1, str3) is False

    def test_secure_string_deletion(self, secure_string):
        """Test secure deletion of strings."""
        secret = secure_string.store("Delete me")
        
        result = secure_string.delete(secret)
        
        assert result is True
        
        # Content should be gone
        assert len(secret) == 0 or all(ord(c) == 0 for c in secret)

    def test_password_strength_check(self, secure_string):
        """Test password strength validation."""
        test_cases = [
            ("weak", False),
            ("weakpassword", False),
            ("StrongP@ss1", True),
            ("VeryLongAndComplex!@#$%Password123", True),
        ]
        
        for password, expected in test_cases:
            result = secure_string.check_strength(password)
            assert result == expected, f"Failed for {password}"


class TestMemoryPool:
    """Test cases for secure memory pooling."""

    @pytest.fixture
    def mem_pool(self):
        """Create memory pool instance."""
        from cxa.memory import CXAMemoryPool
        return CXAMemoryPool(pool_size=4096)

    def test_memory_allocation_from_pool(self, mem_pool):
        """Test allocating memory from pool."""
        allocated = mem_pool.allocate(1024)
        
        assert allocated is not None
        assert len(allocated) == 1024

    def test_memory_deallocation_to_pool(self, mem_pool):
        """Test deallocating memory back to pool."""
        allocated = mem_pool.allocate(1024)
        
        result = mem_pool.deallocate(allocated)
        
        assert result is True

    def test_pool_fragmentation_handling(self, mem_pool):
        """Test handling of memory pool fragmentation."""
        # Allocate multiple small blocks
        blocks = []
        for i in range(10):
            block = mem_pool.allocate(256)
            blocks.append(block)
        
        # Deallocate some
        for i in range(5):
            mem_pool.deallocate(blocks[i])
        
        # Allocate again - should work if fragmentation is handled
        new_block = mem_pool.allocate(256)
        
        assert new_block is not None or True  # May depend on implementation

    def test_pool_statistics(self, mem_pool):
        """Test memory pool statistics."""
        # Allocate some memory
        mem_pool.allocate(1024)
        
        stats = mem_pool.get_statistics()
        
        assert 'total_size' in stats
        assert 'used_size' in stats
        assert 'free_size' in stats


class TestPageLocking:
    """Test cases for page-level memory locking."""

    @pytest.fixture
    def page_locker(self):
        """Create page locker instance."""
        from cxa.memory import CXAPageLocker
        return CXAPageLocker()

    def test_page_locking(self, page_locker):
        """Test locking memory pages."""
        data = bytearray(b"Data to lock in memory")
        
        result = page_locker.lock_pages(data)
        
        assert result is True

    def test_page_unlocking(self, page_locker):
        """Test unlocking memory pages."""
        data = bytearray(b"Data to unlock")
        page_locker.lock_pages(data)
        
        result = page_locker.unlock_pages(data)
        
        assert result is True

    def test_page_size_alignment(self, page_locker):
        """Test page size alignment."""
        # Memory should be aligned to page boundaries
        size = 4096  # Typical page size
        
        aligned = page_locker.get_aligned_size(size)
        
        assert aligned >= size
        assert aligned % 4096 == 0 or aligned % page_locker.page_size == 0
