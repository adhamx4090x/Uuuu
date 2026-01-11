# CXA Core Module
# Python orchestration layer for the CXA Cryptographic System
#
# This package provides the main interfaces for:
# - Cryptographic operations (engine)
# - Key management and storage (key_manager)
# - Secure backups (backup)
# - Security monitoring and threat detection (security_monitor)
# - Steganography for covert data embedding (steganography)
#
# Version: 2.0.0
# New features:
# - ML-powered threat detection with Isolation Forest
# - DCT-based steganography for robust data hiding
# - Enhanced anomaly detection

from .engine import CXACryptoEngine, get_engine
from .key_manager import CXAKeyManager, KeyType, KeyPurpose, KeyAlgorithm
from .backup import CXABackupManager, BackupType
from .security_monitor import (
    CXASecurityMonitor, 
    SecurityEventType,
    SecurityLevel,
    MLThreatDetector,
    ThreatDetectionEngine
)
from .steganography import (
    CXASteganographyManager, 
    ImageSteganographer,
    TextSteganographer,
    DCTSteganographer,  # NEW
    StegoMethod,
    StegoResult
)

__all__ = [
    # Core engine
    'CXACryptoEngine',
    'get_engine',
    # Key management
    'CXAKeyManager',
    'KeyType',
    'KeyPurpose',
    'KeyAlgorithm',
    # Backup
    'CXABackupManager',
    'BackupType',
    # Security monitoring (enhanced)
    'CXASecurityMonitor',
    'SecurityEventType',
    'SecurityLevel',
    'MLThreatDetector',
    'ThreatDetectionEngine',
    # Steganography (enhanced)
    'CXASteganographyManager',
    'ImageSteganographer',
    'TextSteganographer',
    'DCTSteganographer',  # NEW
    'StegoMethod',
    'StegoResult',
]

__version__ = "2.0.0"
