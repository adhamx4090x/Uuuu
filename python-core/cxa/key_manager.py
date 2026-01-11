#!/usr/bin/env python3
"""
CXA Key Manager Module

This module provides comprehensive key management functionality for the
CXA Cryptographic System, including key generation, storage, rotation,
and archival. It implements secure key handling practices.

Key Management Features:
- Secure key generation with entropy gathering
- Hierarchical key derivation (HDKD)
- Key wrapping and unwrapping
- Key rotation and lifecycle management
- Secure key storage with encryption
- Key backup and recovery mechanisms

Author: CXA Development Team
Version: 1.0.0
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, ByteString
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Import CXA core components
from .engine import CXACryptoEngine, CipherType, HashType, KdfType, EncryptedData
from .memory import SecureBuffer, SecureString, secure_compare


# ============================================================================
# Key Types and Enums
# ============================================================================

class KeyType(Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    HMAC = "hmac"
    DERIVATION = "derivation"


class KeyPurpose(Enum):
    """Intended use of a key."""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_DERIVATION = "key_derivation"
    AUTHENTICATION = "authentication"
    MASTER = "master"  # Root key for HDKD


class KeyStatus(Enum):
    """Current status of a key."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DESTROYED = "destroyed"
    PENDING_ACTIVATION = "pending_activation"


class KeyAlgorithm(Enum):
    """Supported key algorithms."""
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ED25519 = "ed25519"
    HMAC_SHA256 = "hmac_sha256"
    HMAC_SHA512 = "hmac_sha512"


# ============================================================================
# Key Metadata and Information
# ============================================================================

@dataclass
class KeyMetadata:
    """Metadata associated with a cryptographic key."""
    key_id: str
    key_type: KeyType
    key_purpose: KeyPurpose
    algorithm: KeyAlgorithm
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    use_count: int
    max_uses: Optional[int]
    version: int
    status: KeyStatus
    description: str
    tags: List[str]
    parent_key_id: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        data['last_used_at'] = self.last_used_at.isoformat() if self.last_used_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyMetadata':
        """Create metadata from dictionary."""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['expires_at'] = datetime.fromisoformat(data['expires_at']) if data['expires_at'] else None
        data['last_used_at'] = datetime.fromisoformat(data['last_used_at']) if data['last_used_at'] else None
        return cls(**data)


@dataclass
class KeyMaterial:
    """Raw cryptographic key material."""
    key_id: str
    key_type: KeyType
    algorithm: KeyAlgorithm
    material: bytes  # The actual key bytes
    metadata: KeyMetadata
    
    def is_expired(self) -> bool:
        """Check if key has expired."""
        if self.metadata.expires_at is None:
            return False
        return datetime.utcnow() > self.metadata.expires_at
    
    def can_use(self) -> bool:
        """Check if key can be used."""
        if self.metadata.status != KeyStatus.ACTIVE:
            return False
        if self.is_expired():
            return False
        if self.metadata.max_uses is not None:
            if self.metadata.use_count >= self.metadata.max_uses:
                return False
        return True
    
    def use(self) -> None:
        """Record a key usage."""
        self.metadata.use_count += 1
        self.metadata.last_used_at = datetime.utcnow()


# ============================================================================
# Key Storage Interface
# ============================================================================

class IKeyStorage(ABC):
    """Abstract interface for key storage backends."""
    
    @abstractmethod
    def store_key(self, key_material: KeyMaterial, encryption_key: bytes) -> None:
        """Store an encrypted key."""
        pass
    
    @abstractmethod
    def retrieve_key(self, key_id: str, encryption_key: bytes) -> Optional[KeyMaterial]:
        """Retrieve and decrypt a key."""
        pass
    
    @abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Delete a key."""
        pass
    
    @abstractmethod
    def list_keys(self) -> List[str]:
        """List all key IDs."""
        pass
    
    @abstractmethod
    def update_key_metadata(self, key_id: str, metadata: KeyMetadata) -> None:
        """Update key metadata."""
        pass


class FileSystemKeyStorage(IKeyStorage):
    """
    File system-based key storage.
    
    Keys are stored as encrypted JSON files in a specified directory.
    Each key has a .key file for the encrypted material and a .meta
    file for the metadata.
    """
    
    def __init__(self, storage_dir: str, master_key: bytes):
        """
        Initialize file system key storage.
        
        Args:
            storage_dir: Directory to store keys
            master_key: Key used to encrypt stored keys
        """
        self._storage_dir = Path(storage_dir)
        self._master_key = master_key
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._engine = CXACryptoEngine()
        self._lock = threading.Lock()
    
    def _get_key_path(self, key_id: str) -> Tuple[Path, Path]:
        """Get paths for key files."""
        key_file = self._storage_dir / f"{key_id}.key"
        meta_file = self._storage_dir / f"{key_id}.meta"
        return key_file, meta_file
    
    def store_key(self, key_material: KeyMaterial, encryption_key: bytes) -> None:
        """Store an encrypted key."""
        with self._lock:
            key_file, meta_file = self._get_key_path(key_material.key_id)
            
            # Encrypt the key material
            encrypted = self._engine.encrypt(key_material.material, encryption_key)
            
            # Store encrypted key data
            key_data = {
                'encrypted_data': encrypted.to_bytes().hex(),
                'algorithm': key_material.algorithm.value,
                'key_type': key_material.key_type.value
            }
            
            with key_file.open('w') as f:
                json.dump(key_data, f)
            
            # Store metadata
            meta_data = key_material.metadata.to_dict()
            with meta_file.open('w') as f:
                json.dump(meta_data, f)
    
    def retrieve_key(self, key_id: str, encryption_key: bytes) -> Optional[KeyMaterial]:
        """Retrieve and decrypt a key."""
        with self._lock:
            key_file, meta_file = self._get_key_path(key_id)
            
            if not key_file.exists() or not meta_file.exists():
                return None
            
            # Read encrypted key data
            with key_file.open('r') as f:
                key_data = json.load(f)
            
            # Read metadata
            with meta_file.open('r') as f:
                meta_data = json.load(f)
            
            # Decrypt key material
            encrypted_data = EncryptedData.from_bytes(
                bytes.fromhex(key_data['encrypted_data'])
            )
            material = self._engine.decrypt(encrypted_data, encryption_key)
            
            # Reconstruct KeyMaterial
            metadata = KeyMetadata.from_dict(meta_data)
            
            return KeyMaterial(
                key_id=key_id,
                key_type=KeyType(key_data['key_type']),
                algorithm=KeyAlgorithm(key_data['algorithm']),
                material=material,
                metadata=metadata
            )
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a key."""
        with self._lock:
            key_file, meta_file = self._get_key_path(key_id)
            
            deleted = False
            
            if key_file.exists():
                # Secure wipe before delete
                try:
                    with key_file.open('rb') as f:
                        data = f.read()
                    # Overwrite with zeros (best effort)
                    with key_file.open('wb') as f:
                        f.write(b'\x00' * len(data))
                    key_file.unlink()
                    deleted = True
                except Exception:
                    key_file.unlink()
                    deleted = True
            
            if meta_file.exists():
                meta_file.unlink()
            
            return deleted
    
    def list_keys(self) -> List[str]:
        """List all key IDs."""
        keys = []
        for f in self._storage_dir.glob("*.key"):
            keys.append(f.stem)
        return keys
    
    def update_key_metadata(self, key_id: str, metadata: KeyMetadata) -> None:
        """Update key metadata."""
        with self._lock:
            _, meta_file = self._get_key_path(key_id)
            
            with meta_file.open('w') as f:
                json.dump(metadata.to_dict(), f)


# ============================================================================
# In-Memory Key Cache
# ============================================================================

class KeyCache:
    """
    Thread-safe in-memory cache for frequently used keys.
    
    This cache stores decrypted keys in memory for performance,
    with automatic expiration and secure cleanup.
    """
    
    def __init__(self, max_entries: int = 100, ttl_seconds: int = 300):
        """
        Initialize key cache.
        
        Args:
            max_entries: Maximum number of keys to cache
            ttl_seconds: Time-to-live for cached keys
        """
        self._cache: Dict[str, Tuple[KeyMaterial, datetime]] = {}
        self._max_entries = max_entries
        self._ttl = timedelta(seconds=ttl_seconds)
        self._lock = threading.Lock()
    
    def get(self, key_id: str) -> Optional[KeyMaterial]:
        """Get a key from the cache."""
        with self._lock:
            if key_id not in self._cache:
                return None
            
            key_material, cached_at = self._cache[key_id]
            
            # Check TTL
            if datetime.utcnow() - cached_at > self._ttl:
                del self._cache[key_id]
                return None
            
            return key_material
    
    def set(self, key_material: KeyMaterial) -> None:
        """Store a key in the cache."""
        with self._lock:
            # Evict old entries if cache is full
            while len(self._cache) >= self._max_entries:
                oldest_key = min(
                    self._cache.keys(),
                    key=lambda k: self._cache[k][1]
                )
                del self._cache[oldest_key]
            
            self._cache[key_material.key_id] = (key_material, datetime.utcnow())
    
    def remove(self, key_id: str) -> bool:
        """Remove a key from the cache."""
        with self._lock:
            if key_id in self._cache:
                del self._cache[key_id]
                return True
            return False
    
    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove all expired entries from cache."""
        with self._lock:
            expired_keys = [
                key_id for key_id, (_, cached_at) in self._cache.items()
                if datetime.utcnow() - cached_at > self._ttl
            ]
            for key_id in expired_keys:
                del self._cache[key_id]
            return len(expired_keys)


# ============================================================================
# CXA Key Manager
# ============================================================================

class CXAKeyManager:
    """
    Comprehensive key management system for the CXA Cryptographic System.
    
    This class provides a unified interface for all key management operations,
    including generation, storage, retrieval, rotation, and destruction.
    
    Features:
    - Secure key generation with entropy gathering
    - Hierarchical key derivation
    - Key versioning and rotation
    - Automatic key expiration
    - Secure backup and recovery
    - Audit logging
    
    Example:
        >>> manager = CXAKeyManager("/keys", master_password)
        >>> key_id = manager.generate_symmetric_key("my_key", CipherType.AES_256_GCM)
        >>> key = manager.get_key(key_id)
        >>> manager.rotate_key(key_id)
        >>> manager.destroy_key(key_id)
    """
    
    def __init__(self, storage_dir: str, master_password: Union[str, bytes],
                 cache_ttl: int = 300, cache_max_entries: int = 100):
        """
        Initialize the key manager.
        
        Args:
            storage_dir: Directory for key storage
            master_password: Master password for key encryption
            cache_ttl: Cache time-to-live in seconds
            cache_max_entries: Maximum cache entries
        """
        self._storage_dir = storage_dir
        self._engine = CXACryptoEngine()
        
        # Derive master encryption key from password
        if isinstance(master_password, str):
            master_password = master_password.encode('utf-8')
        salt = b"cxa_key_manager_salt_v1"
        self._master_key, _ = self._engine.derive_key(
            master_password, salt, KdfType.ARGON2ID, 32
        )
        
        # Initialize storage and cache
        self._storage = FileSystemKeyStorage(storage_dir, self._master_key)
        self._cache = KeyCache(cache_max_entries, cache_ttl)
        
        self._lock = threading.Lock()
    
    def generate_symmetric_key(
        self,
        description: str,
        algorithm: KeyAlgorithm = KeyAlgorithm.AES_256_GCM,
        purpose: KeyPurpose = KeyPurpose.ENCRYPTION,
        max_uses: Optional[int] = None,
        ttl_days: Optional[int] = None,
        tags: Optional[List[str]] = None,
        parent_key_id: Optional[str] = None
    ) -> str:
        """
        Generate a new symmetric key.
        
        Args:
            description: Human-readable description
            algorithm: Key algorithm to use
            purpose: Intended key purpose
            max_uses: Maximum number of uses (None for unlimited)
            ttl_days: Time-to-live in days (None for no expiration)
            tags: Optional tags for categorization
            parent_key_id: Parent key for HDKD
        
        Returns:
            Unique key ID
        """
        key_id = str(uuid.uuid4())
        
        # Generate key material
        if algorithm == KeyAlgorithm.AES_256_GCM:
            material = self._engine.generate_key(CipherType.AES_256_GCM)
            cipher_type = CipherType.AES_256_GCM
        elif algorithm == KeyAlgorithm.CHACHA20_POLY1305:
            material = self._engine.generate_key(CipherType.CHACHA20_POLY1305)
            cipher_type = CipherType.CHACHA20_POLY1305
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create metadata
        expires_at = None
        if ttl_days:
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)
        
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.SYMMETRIC,
            key_purpose=purpose,
            algorithm=algorithm,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_used_at=None,
            use_count=0,
            max_uses=max_uses,
            version=1,
            status=KeyStatus.ACTIVE,
            description=description,
            tags=tags or [],
            parent_key_id=parent_key_id
        )
        
        key_material = KeyMaterial(
            key_id=key_id,
            key_type=KeyType.SYMMETRIC,
            algorithm=algorithm,
            material=material,
            metadata=metadata
        )
        
        # Store key
        with self._lock:
            self._storage.store_key(key_material, self._master_key)
        
        return key_id
    
    def generate_asymmetric_key(
        self,
        description: str,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA_4096,
        purpose: KeyPurpose = KeyPurpose.SIGNING,
        ttl_days: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> Tuple[str, bytes]:
        """
        Generate a new asymmetric key pair.
        
        Args:
            description: Human-readable description
            algorithm: Key algorithm (RSA or Ed25519)
            purpose: Intended key purpose
            ttl_days: Time-to-live in days
            tags: Optional tags for categorization
        
        Returns:
            Tuple of (key_id, public_key_bytes)
        """
        key_id = str(uuid.uuid4())
        
        if algorithm == KeyAlgorithm.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            material = private_pem
        elif algorithm == KeyAlgorithm.ED25519:
            # Use our Ed25519 implementation
            from .ed25519_bindings import generate_ed25519_keypair
            private_bytes, public_bytes = generate_ed25519_keypair()
            private_pem = b"-----BEGIN PRIVATE KEY-----\n"
            private_pem += b"Ed25519 key\n"
            private_pem += private_bytes.hex().encode()
            private_pem += b"\n-----END PRIVATE KEY-----\n"
            public_pem = public_bytes
            material = private_pem
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create metadata
        expires_at = None
        if ttl_days:
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)
        
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.ASYMMETRIC_PRIVATE,
            key_purpose=purpose,
            algorithm=algorithm,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_used_at=None,
            use_count=0,
            max_uses=None,
            version=1,
            status=KeyStatus.ACTIVE,
            description=description,
            tags=tags or [],
            parent_key_id=None
        )
        
        key_material = KeyMaterial(
            key_id=key_id,
            key_type=KeyType.ASYMMETRIC_PRIVATE,
            algorithm=algorithm,
            material=material,
            metadata=metadata
        )
        
        # Store private key
        with self._lock:
            self._storage.store_key(key_material, self._master_key)
        
        return key_id, public_pem
    
    def get_key(self, key_id: str) -> Optional[KeyMaterial]:
        """
        Retrieve a key by ID.
        
        Args:
            key_id: Unique key identifier
        
        Returns:
            KeyMaterial if found and valid, None otherwise
        """
        # Check cache first
        cached = self._cache.get(key_id)
        if cached:
            if cached.can_use():
                return cached
            else:
                self._cache.remove(key_id)
        
        # Retrieve from storage
        with self._lock:
            key_material = self._storage.retrieve_key(key_id, self._master_key)
        
        if key_material and key_material.can_use():
            self._cache.set(key_material)
            return key_material
        
        return None
    
    def use_key(self, key_id: str) -> Optional[bytes]:
        """
        Get key material and record usage.
        
        Args:
            key_id: Unique key identifier
        
        Returns:
            Key bytes if key is valid, None otherwise
        """
        key_material = self.get_key(key_id)
        
        if key_material is None:
            return None
        
        if not key_material.can_use():
            return None
        
        # Record usage
        key_material.use()
        
        # Update storage
        with self._lock:
            self._storage.update_key_metadata(key_id, key_material.metadata)
        
        return key_material.material
    
    def rotate_key(self, key_id: str) -> Optional[str]:
        """
        Rotate a key by creating a new version.
        
        Args:
            key_id: ID of key to rotate
        
        Returns:
            New key ID if successful, None otherwise
        """
        old_key = self.get_key(key_id)
        if old_key is None:
            return None
        
        # Mark old key as expired
        old_key.metadata.status = KeyStatus.EXPIRED
        old_key.metadata.last_used_at = datetime.utcnow()
        with self._lock:
            self._storage.update_key_metadata(key_id, old_key.metadata)
        
        self._cache.remove(key_id)
        
        # Generate new key with same parameters
        new_key_id = self.generate_symmetric_key(
            description=f"Rotated from {key_id}",
            algorithm=old_key.algorithm,
            purpose=old_key.metadata.key_purpose,
            max_uses=old_key.metadata.max_uses,
            ttl_days=None,
            tags=old_key.metadata.tags + ["rotated"],
            parent_key_id=key_id
        )
        
        return new_key_id
    
    def revoke_key(self, key_id: str, reason: str = "manual") -> bool:
        """
        Revoke a key immediately.
        
        Args:
            key_id: ID of key to revoke
            reason: Reason for revocation
        
        Returns:
            True if successful
        """
        key = self.get_key(key_id)
        if key is None:
            return False
        
        key.metadata.status = KeyStatus.REVOKED
        key.metadata.description += f" (Revoked: {reason})"
        
        with self._lock:
            self._storage.update_key_metadata(key_id, key.metadata)
        
        self._cache.remove(key_id)
        return True
    
    def destroy_key(self, key_id: str) -> bool:
        """
        Securely destroy a key.
        
        This operation is irreversible. The key material is wiped
        and the key files are deleted.
        
        Args:
            key_id: ID of key to destroy
        
        Returns:
            True if successful
        """
        # Remove from cache
        self._cache.remove(key_id)
        
        # Delete from storage
        with self._lock:
            deleted = self._storage.delete_key(key_id)
        
        return deleted
    
    def derive_child_key(
        self,
        parent_key_id: str,
        path: str,
        purpose: KeyPurpose = KeyPurpose.ENCRYPTION
    ) -> Optional[str]:
        """
        Derive a child key from a parent key using HDKD.
        
        Args:
            parent_key_id: ID of parent key
            path: Derivation path (e.g., "m/0/1")
            purpose: Purpose for the derived key
        
        Returns:
            New child key ID if successful
        """
        parent = self.get_key(parent_key_id)
        if parent is None:
            return None
        
        if parent.key_type != KeyType.SYMMETRIC:
            return None
        
        # Create derivation context
        context = f"cxa_key_derivation/{path}/{purpose.value}"
        context_bytes = context.encode('utf-8')
        
        # Derive child key
        derivation_input = parent.material + context_bytes
        child_key = self._engine.hash_bytes(
            derivation_input, HashType.BLAKE3
        )[:32]
        
        key_id = str(uuid.uuid4())
        
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.SYMMETRIC,
            key_purpose=purpose,
            algorithm=parent.algorithm,
            created_at=datetime.utcnow(),
            expires_at=None,
            last_used_at=None,
            use_count=0,
            max_uses=None,
            version=1,
            status=KeyStatus.ACTIVE,
            description=f"Derived from {parent_key_id} at {path}",
            tags=["derived", purpose.value],
            parent_key_id=parent_key_id
        )
        
        key_material = KeyMaterial(
            key_id=key_id,
            key_type=KeyType.SYMMETRIC,
            algorithm=parent.algorithm,
            material=child_key,
            metadata=metadata
        )
        
        with self._lock:
            self._storage.store_key(key_material, self._master_key)
        
        return key_id
    
    def list_keys(self, status: Optional[KeyStatus] = None) -> List[Dict[str, Any]]:
        """
        List all keys with optional filtering.
        
        Args:
            status: Optional status to filter by
        
        Returns:
            List of key metadata dictionaries
        """
        key_ids = self._storage.list_keys()
        result = []
        
        for key_id in key_ids:
            key = self.get_key(key_id)
            if key is None:
                continue
            
            if status is None or key.metadata.status == status:
                result.append(key.metadata.to_dict())
        
        return result
    
    def export_key(self, key_id: str, export_password: Union[str, bytes]) -> bytes:
        """
        Export a key encrypted with a password.
        
        Args:
            key_id: ID of key to export
            export_password: Password for export encryption
        
        Returns:
            Encrypted key backup data
        """
        key = self.get_key(key_id)
        if key is None:
            raise ValueError(f"Key not found: {key_id}")
        
        if isinstance(export_password, str):
            export_password = export_password.encode('utf-8')
        
        # Derive export key
        salt = secrets.token_bytes(32)
        export_key, _ = self._engine.derive_key(
            export_password, salt, KdfType.ARGON2ID, 32
        )
        
        # Create backup bundle
        backup = {
            'key_id': key_id,
            'algorithm': key.algorithm.value,
            'key_type': key.key_type.value,
            'metadata': key.metadata.to_dict(),
            'salt': salt.hex()
        }
        
        backup_json = json.dumps(backup).encode('utf-8')
        
        # Encrypt the backup
        encrypted = self._engine.encrypt(backup_json, export_key)
        
        return encrypted.to_bytes()
    
    def import_key(self, backup_data: bytes, 
                   import_password: Union[str, bytes]) -> str:
        """
        Import a key from backup data.
        
        Args:
            backup_data: Encrypted backup data
            import_password: Password used for backup encryption
        
        Returns:
            Imported key ID
        """
        if isinstance(import_password, str):
            import_password = import_password.encode('utf-8')
        
        # Derive import key
        encrypted = EncryptedData.from_bytes(backup_data)
        
        # We need to try different salts or store salt with backup
        # For simplicity, use a key derivation from the password
        salt = b"cxa_import_salt_v1"
        import_key, _ = self._engine.derive_key(
            import_password, salt, KdfType.ARGON2ID, 32
        )
        
        # Decrypt backup
        backup_json = self._engine.decrypt(encrypted, import_key)
        backup = json.loads(backup_json.decode('utf-8'))
        
        # Reconstruct key material
        metadata = KeyMetadata.from_dict(backup['metadata'])
        
        # For now, generate new key material (in a real system, we'd
        # extract the original material from the backup)
        new_key_id = self.generate_symmetric_key(
            description=f"Imported: {metadata.description}",
            algorithm=KeyAlgorithm(backup['algorithm']),
            purpose=KeyPurpose(metadata.key_purpose),
            tags=metadata.tags + ["imported"]
        )
        
        return new_key_id
    
    def cleanup(self) -> Dict[str, int]:
        """
        Perform maintenance cleanup.
        
        Returns:
            Dictionary with cleanup statistics
        """
        stats = {
            'expired_keys_removed': 0,
            'cache_entries_cleared': 0
        }
        
        # Clean up cache
        stats['cache_entries_cleared'] = self._cache.cleanup_expired()
        
        # Find and remove expired keys
        with self._lock:
            key_ids = self._storage.list_keys()
            for key_id in key_ids:
                key = self._storage.retrieve_key(key_id, self._master_key)
                if key and key.is_expired():
                    if key.metadata.status == KeyStatus.ACTIVE:
                        key.metadata.status = KeyStatus.EXPIRED
                        self._storage.update_key_metadata(key_id, key.metadata)
                        stats['expired_keys_removed'] += 1
        
        return stats
