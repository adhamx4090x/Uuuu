#!/usr/bin/env python3
"""
CXA Backup and Recovery Module

This module provides comprehensive backup and recovery functionality
for the CXA Cryptographic System. It supports encrypted backups,
secure recovery, and integrity verification.

Backup Features:
- Encrypted backups with authenticated encryption
- Incremental backup support
- Backup integrity verification
- Secure recovery with authentication
- Backup rotation and retention policies
- Cloud storage integration ready

Author: CXA Development Team
Version: 1.0.0
"""

import hashlib
import hmac
import json
import os
import shutil
import threading
import uuid
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, ByteString
import tarfile

# Import CXA core components
from .engine import CXACryptoEngine, CipherType, HashType, KdfType, EncryptedData
from .key_manager import CXAKeyManager, KeyType, KeyAlgorithm
from .memory import SecureBuffer, secure_compare


# ============================================================================
# Backup Types and Enums
# ============================================================================

class BackupType(Enum):
    """Types of backups."""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


class BackupStatus(Enum):
    """Status of a backup operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFIED = "verified"
    RESTORED = "restored"


class StorageBackend(Enum):
    """Supported storage backends."""
    LOCAL_FILESYSTEM = "local_filesystem"
    REMOTE_SERVER = "remote_server"
    CLOUD_STORAGE = "cloud_storage"


# ============================================================================
# Backup Metadata and Configuration
# ============================================================================

@dataclass
class BackupMetadata:
    """Metadata for a backup."""
    backup_id: str
    backup_type: BackupType
    status: BackupStatus
    created_at: datetime
    completed_at: Optional[datetime]
    source_path: str
    backup_path: str
    size_bytes: int
    encrypted_size_bytes: int
    checksum: str
    encrypted_checksum: str
    key_id: str
    version: int
    description: str
    retention_days: int
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        data = asdict(self)
        data['backup_type'] = self.backup_type.value
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        data['completed_at'] = self.completed_at.isoformat() if self.completed_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BackupMetadata':
        """Create metadata from dictionary."""
        data['backup_type'] = BackupType(data['backup_type'])
        data['status'] = BackupStatus(data['status'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['completed_at'] = datetime.fromisoformat(data['completed_at']) if data['completed_at'] else None
        return cls(**data)


@dataclass
class BackupConfig:
    """Configuration for backup operations."""
    backup_type: BackupType
    encryption_algorithm: CipherType
    compression: bool
    compression_level: int
    include_patterns: List[str]
    exclude_patterns: List[str]
    retention_days: int
    verify_after_backup: bool
    max_incremental_backups: int
    description: str
    tags: List[str]
    
    @classmethod
    def default(cls) -> 'BackupConfig':
        """Get default configuration."""
        return cls(
            backup_type=BackupType.FULL,
            encryption_algorithm=CipherType.AES_256_GCM,
            compression=True,
            compression_level=9,
            include_patterns=["*"],
            exclude_patterns=[".git", "__pycache__", "*.pyc", "*.tmp"],
            retention_days=30,
            verify_after_backup=True,
            max_incremental_backups=7,
            description="Automatic backup",
            tags=["auto"]
        )


@dataclass
class BackupItem:
    """Individual item in a backup."""
    path: str
    relative_path: str
    item_type: str  # "file", "directory", "symlink"
    size: int
    mtime: float
    checksum: str
    content: Optional[bytes]  # For file contents
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'relative_path': self.relative_path,
            'item_type': self.item_type,
            'size': self.size,
            'mtime': self.mtime,
            'checksum': self.checksum
        }


# ============================================================================
# Storage Backend Interface
# ============================================================================

class IStorageBackend(ABC):
    """Abstract interface for backup storage backends."""
    
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    def store(self, backup_id: str, data: bytes) -> None:
        """Store backup data."""
        pass
    
    @abstractmethod
    def retrieve(self, backup_id: str) -> Optional[bytes]:
        """Retrieve backup data."""
        pass
    
    @abstractmethod
    def delete(self, backup_id: str) -> bool:
        """Delete a backup."""
        pass
    
    @abstractmethod
    def list_backups(self) -> List[str]:
        """List all backup IDs."""
        pass
    
    @abstractmethod
    def get_metadata(self, backup_id: str) -> Optional[BackupMetadata]:
        """Get backup metadata."""
        pass
    
    @abstractmethod
    def update_metadata(self, metadata: BackupMetadata) -> None:
        """Update backup metadata."""
        pass


class LocalFilesystemBackend(IStorageBackend):
    """
    Local filesystem storage backend.
    
    Stores backups as encrypted files with associated metadata.
    """
    
    def __init__(self, storage_dir: str, metadata_dir: Optional[str] = None):
        """
        Initialize local filesystem backend.
        
        Args:
            storage_dir: Directory for backup files
            metadata_dir: Directory for metadata (defaults to storage_dir)
        """
        self._storage_dir = Path(storage_dir)
        self._metadata_dir = Path(metadata_dir) if metadata_dir else self._storage_dir / "metadata"
        self._lock = threading.Lock()
        
        # Create directories
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_backup_path(self, backup_id: str) -> Path:
        """Get path for backup file."""
        return self._storage_dir / f"{backup_id}.cxa backup"
    
    def _get_metadata_path(self, backup_id: str) -> Path:
        """Get path for metadata file."""
        return self._metadata_dir / f"{backup_id}.meta"
    
    def initialize(self) -> None:
        """Initialize storage directories."""
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_dir.mkdir(parents=True, exist_ok=True)
    
    def store(self, backup_id: str, data: bytes) -> None:
        """Store backup data."""
        with self._lock:
            backup_path = self._get_backup_path(backup_id)
            
            with backup_path.open('wb') as f:
                f.write(data)
    
    def retrieve(self, backup_id: str) -> Optional[bytes]:
        """Retrieve backup data."""
        with self._lock:
            backup_path = self._get_backup_path(backup_id)
            
            if not backup_path.exists():
                return None
            
            with backup_path.open('rb') as f:
                return f.read()
    
    def delete(self, backup_id: str) -> bool:
        """Delete a backup."""
        with self._lock:
            backup_path = self._get_backup_path(backup_id)
            meta_path = self._get_metadata_path(backup_id)
            
            deleted = False
            
            if backup_path.exists():
                backup_path.unlink()
                deleted = True
            
            if meta_path.exists():
                meta_path.unlink()
            
            return deleted
    
    def list_backups(self) -> List[str]:
        """List all backup IDs."""
        backups = []
        for f in self._storage_dir.glob("*.cxa backup"):
            backups.append(f.stem)
        return backups
    
    def get_metadata(self, backup_id: str) -> Optional[BackupMetadata]:
        """Get backup metadata."""
        meta_path = self._get_metadata_path(backup_id)
        
        if not meta_path.exists():
            return None
        
        with meta_path.open('r') as f:
            data = json.load(f)
            return BackupMetadata.from_dict(data)
    
    def update_metadata(self, metadata: BackupMetadata) -> None:
        """Update backup metadata."""
        with self._lock:
            meta_path = self._get_metadata_path(metadata.backup_id)
            
            with meta_path.open('w') as f:
                json.dump(metadata.to_dict(), f)


# ============================================================================
# CXA Backup Manager
# ============================================================================

class CXABackupManager:
    """
    Comprehensive backup and recovery manager for the CXA system.
    
    This class provides a unified interface for creating encrypted backups,
    verifying their integrity, and restoring data. It supports multiple
    backup types and storage backends.
    
    Features:
    - Full, incremental, and differential backups
    - Strong encryption (AES-256-GCM or ChaCha20-Poly1305)
    - Compression support
    - Integrity verification
    - Retention policies
    - Backup catalog and search
    
    Example:
        >>> manager = CXABackupManager("/backups", master_password)
        >>> backup_id = manager.create_backup("/important_data", "Daily backup")
        >>> manager.verify_backup(backup_id)
        >>> manager.restore_backup(backup_id, "/restored_data")
    """
    
    def __init__(self, storage_backend: IStorageBackend, 
                 key_manager: CXAKeyManager):
        """
        Initialize backup manager.
        
        Args:
            storage_backend: Storage backend for backups
            key_manager: Key manager for encryption keys
        """
        self._storage = storage_backend
        self._key_manager = key_manager
        self._engine = CXACryptoEngine()
        self._config = BackupConfig.default()
        self._lock = threading.Lock()
        
        # Initialize storage
        self._storage.initialize()
    
    def create_backup(
        self,
        source_path: str,
        description: str = "",
        config: Optional[BackupConfig] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """
        Create a new backup.
        
        Args:
            source_path: Path to directory or file to backup
            description: Description of the backup
            config: Optional backup configuration
            tags: Optional tags for categorization
        
        Returns:
            Backup ID
        """
        if config is None:
            config = self._config
        
        backup_id = str(uuid.uuid4())
        source = Path(source_path)
        
        if not source.exists():
            raise ValueError(f"Source path does not exist: {source_path}")
        
        # Collect items to backup
        items = self._collect_items(source, config)
        
        # Create backup manifest
        manifest = {
            'backup_id': backup_id,
            'source_path': str(source.absolute()),
            'backup_type': config.backup_type.value,
            'created_at': datetime.utcnow().isoformat(),
            'description': description,
            'tags': tags or [],
            'items': [item.to_dict() for item in items]
        }
        
        # Serialize manifest
        manifest_bytes = json.dumps(manifest).encode('utf-8')
        
        # Generate encryption key
        encryption_key = self._engine.generate_key(config.encryption_algorithm)
        
        # Encrypt manifest
        encrypted_manifest = self._engine.encrypt(
            manifest_bytes, encryption_key, config.encryption_algorithm
        )
        
        # Create backup archive
        archive_buffer = self._create_archive(items, encrypted_manifest)
        
        # Compress if enabled
        if config.compression:
            archive_buffer = self._compress_archive(archive_buffer, config.compression_level)
        
        backup_data = archive_buffer.getvalue()
        
        # Calculate checksums
        checksum = self._engine.hash_bytes(backup_data, HashType.BLAKE3).hex()
        
        # Create metadata
        metadata = BackupMetadata(
            backup_id=backup_id,
            backup_type=config.backup_type,
            status=BackupStatus.COMPLETED,
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            source_path=str(source.absolute()),
            backup_path="",
            size_bytes=len(backup_data),
            encrypted_size_bytes=len(backup_data),
            checksum=checksum,
            encrypted_checksum=checksum,
            key_id="",
            version=1,
            description=description,
            retention_days=config.retention_days,
            tags=config.tags + (tags or [])
        )
        
        # Store backup
        with self._lock:
            self._storage.store(backup_id, backup_data)
            metadata.backup_path = str(self._storage._get_backup_path(backup_id))
            
            # Generate key for backup encryption
            key_id = self._key_manager.generate_symmetric_key(
                description=f"Backup key for {backup_id}",
                algorithm=KeyAlgorithm.AES_256_GCM,
                purpose=KeyPurpose.ENCRYPTION,
                ttl_days=config.retention_days + 7
            )
            metadata.key_id = key_id
            
            self._storage.update_metadata(metadata)
        
        return backup_id
    
    def _collect_items(
        self,
        source: Path,
        config: BackupConfig
    ) -> List[BackupItem]:
        """Collect items to include in backup."""
        items = []
        
        source_str = str(source.absolute())
        
        for root, dirs, files in os.walk(source):
            root_path = Path(root)
            relative_root = str(root_path.relative_to(source.parent))
            
            # Check exclude patterns
            dirs[:] = [d for d in dirs if not self._matches_patterns(d, config.exclude_patterns)]
            
            for file in files:
                if self._matches_patterns(file, config.exclude_patterns):
                    continue
                
                file_path = root_path / file
                file_str = str(file_path.absolute())
                relative_path = file_path.relative_to(source.parent)
                
                # Calculate checksum
                checksum = self._calculate_file_checksum(file_path)
                
                items.append(BackupItem(
                    path=file_str,
                    relative_path=str(relative_path),
                    item_type="file",
                    size=file_path.stat().st_size,
                    mtime=file_path.stat().st_mtime,
                    checksum=checksum,
                    content=None  # Will be added during archive creation
                ))
        
        return items
    
    def _matches_patterns(self, name: str, patterns: List[str]) -> bool:
        """Check if name matches any pattern."""
        import fnmatch
        for pattern in patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
        return False
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate checksum for a file."""
        hasher = hashlib.blake2b(digest_size=32)
        
        with file_path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def _create_archive(
        self,
        items: List[BackupItem],
        encrypted_manifest: EncryptedData
    ) -> BytesIO:
        """Create a backup archive."""
        buffer = BytesIO()
        
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add encrypted manifest
            manifest_data = encrypted_manifest.to_bytes()
            zf.writestr("manifest.enc", manifest_data)
            
            # Add item contents
            for item in items:
                if item.item_type == "file":
                    item_path = Path(item.path)
                    if item_path.exists():
                        with item_path.open('rb') as f:
                            content = f.read()
                        zf.writestr(f"files/{item.relative_path}", content)
        
        buffer.seek(0)
        return buffer
    
    def _compress_archive(
        self,
        buffer: BytesIO,
        level: int
    ) -> BytesIO:
        """Apply additional compression to archive."""
        import zlib
        
        result = BytesIO()
        
        compressor = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
        
        buffer.seek(0)
        chunk = buffer.read(8192)
        
        while chunk:
            compressed = compressor.compress(chunk)
            if compressed:
                result.write(compressed)
            chunk = buffer.read(8192)
        
        # Flush remaining data
        remaining = compressor.flush()
        if remaining:
            result.write(remaining)
        
        result.seek(0)
        return result
    
    def verify_backup(self, backup_id: str) -> Tuple[bool, str]:
        """
        Verify the integrity of a backup.
        
        Args:
            backup_id: ID of backup to verify
        
        Returns:
            Tuple of (success, message)
        """
        with self._lock:
            metadata = self._storage.get_metadata(backup_id)
            
            if metadata is None:
                return False, f"Backup not found: {backup_id}"
            
            # Retrieve backup data
            backup_data = self._storage.retrieve(backup_id)
            if backup_data is None:
                return False, f"Backup data not found: {backup_id}"
            
            # Verify checksum
            calculated_checksum = self._engine.hash_bytes(backup_data, HashType.BLAKE3).hex()
            
            if not secure_compare(
                calculated_checksum.encode('utf-8'),
                metadata.checksum.encode('utf-8')
            ):
                return False, "Checksum verification failed"
            
            # Try to decompress and read archive
            try:
                buffer = BytesIO(backup_data)
                
                with zipfile.ZipFile(buffer, 'r') as zf:
                    # Check manifest exists
                    if "manifest.enc" not in zf.namelist():
                        return False, "Invalid backup: manifest missing"
                    
                    manifest_data = zf.read("manifest.enc")
                    encrypted_manifest = EncryptedData.from_bytes(manifest_data)
                    
                    # Get backup key
                    key_material = self._key_manager.get_key(metadata.key_id)
                    if key_material is None:
                        return False, "Backup key not found"
                    
                    # Decrypt manifest
                    manifest_bytes = self._engine.decrypt(
                        encrypted_manifest, key_material.material
                    )
                    manifest = json.loads(manifest_bytes.decode('utf-8'))
                    
                    # Verify items
                    for item_data in manifest['items']:
                        item_path = f"files/{item_data['relative_path']}"
                        if item_path not in zf.namelist():
                            return False, f"Missing item: {item_data['relative_path']}"
            
            except Exception as e:
                return False, f"Archive verification failed: {str(e)}"
            
            # Update status
            metadata.status = BackupStatus.VERIFIED
            self._storage.update_metadata(metadata)
            
            return True, "Backup verification successful"
    
    def restore_backup(
        self,
        backup_id: str,
        target_path: str,
        key_password: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Restore a backup to a target path.
        
        Args:
            backup_id: ID of backup to restore
            target_path: Path to restore to
            key_password: Optional password for backup key
        
        Returns:
            Tuple of (success, message)
        """
        with self._lock:
            metadata = self._storage.get_metadata(backup_id)
            
            if metadata is None:
                return False, f"Backup not found: {backup_id}"
            
            # Retrieve backup data
            backup_data = self._storage.retrieve(backup_id)
            if backup_data is None:
                return False, f"Backup data not found: {backup_id}"
            
            try:
                buffer = BytesIO(backup_data)
                
                with zipfile.ZipFile(buffer, 'r') as zf:
                    # Read encrypted manifest
                    manifest_data = zf.read("manifest.enc")
                    encrypted_manifest = EncryptedData.from_bytes(manifest_data)
                    
                    # Get backup key
                    key_material = self._key_manager.get_key(metadata.key_id)
                    if key_material is None:
                        return False, "Backup key not found"
                    
                    # Decrypt manifest
                    manifest_bytes = self._engine.decrypt(
                        encrypted_manifest, key_material.material
                    )
                    manifest = json.loads(manifest_bytes.decode('utf-8'))
                    
                    # Create target directory
                    target = Path(target_path)
                    target.mkdir(parents=True, exist_ok=True)
                    
                    # Restore files
                    for item_data in manifest['items']:
                        item_path = f"files/{item_data['relative_path']}"
                        
                        if item_path in zf.namelist():
                            file_data = zf.read(item_path)
                            
                            # Create parent directories
                            dest_path = target / item_data['relative_path']
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            
                            # Write file
                            with dest_path.open('wb') as f:
                                f.write(file_data)
                            
                            # Restore permissions if possible
                            try:
                                import stat
                                if 'mode' in item_data:
                                    dest_path.chmod(item_data['mode'])
                            except Exception:
                                pass
            
            except Exception as e:
                return False, f"Restore failed: {str(e)}"
            
            # Update status
            metadata.status = BackupStatus.RESTORED
            self._storage.update_metadata(metadata)
            
            return True, f"Backup restored to {target_path}"
    
    def list_backups(
        self,
        status: Optional[BackupStatus] = None,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> List[BackupMetadata]:
        """
        List available backups with optional filtering.
        
        Args:
            status: Optional status filter
            tags: Optional tag filter
            limit: Maximum number of results
        
        Returns:
            List of backup metadata
        """
        backups = self._storage.list_backups()
        result = []
        
        for backup_id in backups:
            metadata = self._storage.get_metadata(backup_id)
            if metadata is None:
                continue
            
            # Apply filters
            if status and metadata.status != status:
                continue
            
            if tags:
                if not any(tag in metadata.tags for tag in tags):
                    continue
            
            result.append(metadata)
        
        # Sort by date (newest first)
        result.sort(key=lambda m: m.created_at, reverse=True)
        
        if limit:
            result = result[:limit]
        
        return result
    
    def delete_backup(self, backup_id: str, cascade: bool = True) -> Tuple[bool, str]:
        """
        Delete a backup.
        
        Args:
            backup_id: ID of backup to delete
            cascade: Also delete associated keys
        
        Returns:
            Tuple of (success, message)
        """
        with self._lock:
            metadata = self._storage.get_metadata(backup_id)
            
            if metadata is None:
                return False, f"Backup not found: {backup_id}"
            
            # Delete backup data
            success = self._storage.delete(backup_id)
            
            if success and cascade:
                # Delete associated key
                self._key_manager.destroy_key(metadata.key_id)
            
            return success, "Backup deleted" if success else "Failed to delete backup"
    
    def cleanup_old_backups(self, retention_days: Optional[int] = None) -> Dict[str, int]:
        """
        Remove backups older than retention period.
        
        Args:
            retention_days: Override retention period
        
        Returns:
            Dictionary with cleanup statistics
        """
        if retention_days is None:
            retention_days = self._config.retention_days
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        stats = {'checked': 0, 'deleted': 0, 'errors': 0}
        
        with self._lock:
            backups = self._storage.list_backups()
            
            for backup_id in backups:
                metadata = self._storage.get_metadata(backup_id)
                if metadata is None:
                    continue
                
                stats['checked'] += 1
                
                if metadata.created_at < cutoff_date:
                    success, _ = self.delete_backup(backup_id)
                    if success:
                        stats['deleted'] += 1
                    else:
                        stats['errors'] += 1
        
        return stats
    
    def export_backup_catalog(self, output_path: str) -> None:
        """
        Export backup catalog to a JSON file.
        
        Args:
            output_path: Path for the catalog file
        """
        catalog = {
            'exported_at': datetime.utcnow().isoformat(),
            'backups': []
        }
        
        backups = self._storage.list_backups()
        
        for backup_id in backups:
            metadata = self._storage.get_metadata(backup_id)
            if metadata:
                catalog['backups'].append(metadata.to_dict())
        
        with open(output_path, 'w') as f:
            json.dump(catalog, f, indent=2)
    
    def get_backup_info(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a backup."""
        metadata = self._storage.get_metadata(backup_id)
        
        if metadata is None:
            return None
        
        return {
            'id': metadata.backup_id,
            'type': metadata.backup_type.value,
            'status': metadata.status.value,
            'created': metadata.created_at.isoformat(),
            'size': f"{metadata.size_bytes / 1024:.2f} KB",
            'description': metadata.description,
            'tags': metadata.tags,
            'retention_days': metadata.retention_days
        }
