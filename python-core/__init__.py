"""
CXA Python Core Package

This package provides the Python interface to the CXA cryptographic system,
wrapping Rust core modules for high-performance cryptographic operations.

Subpackages:
    crypto: Cryptographic engine and primitives
    cxa: Core CXA functionality (backup, key management, security monitoring)
    stego: Steganography operations for hidden data transmission

Version: 1.0.0
Author: MiniMax Agent
"""

from . import crypto
from . import cxa
from . import stego

__all__ = ['crypto', 'cxa', 'stego']

__version__ = "1.0.0"
