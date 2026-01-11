"""
CXA Steganography Module - Hidden Data Transmission.

This module provides steganographic capabilities for hiding data within
various carrier media including images and text. All embedded payloads
are encrypted before embedding for maximum security.

Modules:
    image: Image-based steganography (LSB, DCT)
    text: Text-based steganography (zero-width, whitespace)

Usage:
    >>> from cxa_core.stego import ImageStego, TextStego
    >>> stego = ImageStego()
    >>> # Embed secret in image
    >>> stego_image = stego.embed(secret_data, carrier_image, password)
    >>> # Extract secret from image
    >>> secret = stego.extract(stego_image, password)
"""

from .image import ImageStego, ImageStegoError
from .text import TextStego, TextStegoError

__all__ = [
    "ImageStego",
    "ImageStegoError",
    "TextStego",
    "TextStegoError",
]

__version__ = "1.0.0"
