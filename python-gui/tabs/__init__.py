# CXA GUI Tabs Package
# This package contains all GUI tabs for the CXA application

from .dashboard import DashboardTab
from .encryption import EncryptionTab
from .decryption import DecryptionTab
from .key_management import KeyManagementTab
from .backup import BackupTab
from .settings import SettingsTab

__all__ = [
    'DashboardTab',
    'EncryptionTab',
    'DecryptionTab',
    'KeyManagementTab',
    'BackupTab',
    'SettingsTab',
]
