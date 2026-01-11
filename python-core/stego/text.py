"""
Text Steganography Module.

This module provides text-based steganography capabilities for hiding
data within text content. It supports multiple encoding methods including
zero-width characters, whitespace encoding, and Unicode substitution.

Features:
    - Zero-width character embedding (invisible)
    - Whitespace encoding (spaces and tabs)
    - Unicode homoglyph substitution
    - Encryption of embedded payloads
    - Format-agnostic embedding (works with any text)

Usage:
    >>> from cxa_core.stego import TextStego
    >>> stego = TextStego()
    >>> # Embed secret in text
    >>> stego_text = stego.embed("Hello, World!", secret_data, password)
    >>> # Extract secret from text
    >>> secret = stego.extract(stego_text, password)
"""

import os
import re
import logging
import struct
from typing import Optional, Tuple, Union, List, Dict, Any
from enum import Enum
from dataclasses import dataclass

try:
    from ..crypto import CryptoEngine, SecurityLevel
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


logger = logging.getLogger(__name__)


class EncodingMethod(Enum):
    """Supported text encoding methods."""

    ZERO_WIDTH = "zero_width"
    WHITESPACE = "whitespace"
    UNICODE = "unicode"
    COMBINED = "combined"


class TextStegoError(Exception):
    """Exception raised for text steganography errors."""

    def __init__(self, message: str, code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def __str__(self) -> str:
        base = f"TextStegoError: {self.message}"
        if self.code:
            base += f" (Code: {self.code})"
        return base


@dataclass
class TextEmbeddingResult:
    """
    Result of a text steganography embedding operation.

    Attributes:
        text: Stego text with embedded data
        capacity_used: Number of bytes embedded
        capacity_total: Total available capacity
        method: Method used for encoding
        carrier_length: Length of carrier text
        overhead_percent: Percentage overhead added
    """

    text: str
    capacity_used: int
    capacity_total: int
    method: EncodingMethod
    carrier_length: int
    overhead_percent: float


@dataclass
class TextExtractionResult:
    """
    Result of a text steganography extraction operation.

    Attributes:
        data: Extracted data
        method: Method used for encoding
        original_size: Original size of embedded data
    """

    data: bytes
    method: EncodingMethod
    original_size: int


class TextStego:
    """
    Text steganography handler.

    This class provides methods for embedding and extracting hidden data
    within text content using various encoding techniques.

    Attributes:
        method: Default encoding method
        encryption_enabled: Whether to encrypt embedded payloads

    Example:
        >>> stego = TextStego(method=EncodingMethod.ZERO_WIDTH)
        >>> # Embed secret in text
        >>> result = stego.embed("Hello, World!", b"Secret message", password="secure")
        >>> print(result.text)
        >>> # Extract secret from text
        >>> extracted = stego.extract(result.text, password="secure")
        >>> print(extracted.data)
    """

    # Zero-width characters for embedding
    ZERO_WIDTH_SPACE = "\u200B"  # Zero width space
    ZERO_WIDTH_NONJOINER = "\u200C"  # Zero width non-joiner
    ZERO_WIDTH_JOINER = "\u200D"  # Zero width joiner
    LEFT_TO_RIGHT_MARK = "\u200E"  # Left-to-right mark
    RIGHT_TO_LEFT_MARK = "\u200F"  # Right-to-left mark

    # Whitespace characters
    SPACE = " "
    TAB = "\t"
    NON_BREAKING_SPACE = "\u00A0"
    OGHAM_SPACE_MARK = "\u1680"

    # Zero-width bit mapping (2 bits per character)
    ZW_BIT_MAP = {
        "00": ZERO_WIDTH_SPACE,
        "01": ZERO_WIDTH_NONJOINER,
        "10": ZERO_WIDTH_JOINER,
        "11": LEFT_TO_RIGHT_MARK,
    }

    # Whitespace bit mapping (2 bits per character)
    WS_BIT_MAP = {
        "00": SPACE,
        "01": TAB,
        "10": NON_BREAKING_SPACE,
        "11": OGHAM_SPACE_MARK,
    }

    def __init__(
        self,
        method: EncodingMethod = EncodingMethod.ZERO_WIDTH,
        encryption_enabled: bool = True,
        crypto_engine: Optional["CryptoEngine"] = None,
    ):
        """
        Initialize the text steganography handler.

        Args:
            method: Default encoding method to use
            encryption_enabled: Whether to encrypt embedded payloads
            crypto_engine: Optional crypto engine instance for encryption

        Raises:
            ImportError: If required dependencies are not available
        """
        self._method = method
        self._encryption_enabled = encryption_enabled
        self._crypto_engine = crypto_engine or CryptoEngine(security_level=SecurityLevel.HIGH)

        logger.info(f"TextStego initialized with method={method.value}, encryption={encryption_enabled}")

    @property
    def method(self) -> EncodingMethod:
        """Get the current encoding method."""
        return self._method

    @method.setter
    def method(self, value: EncodingMethod) -> None:
        """Set the encoding method."""
        self._method = value

    def calculate_capacity(
        self,
        carrier_text: str,
        method: Optional[EncodingMethod] = None,
    ) -> int:
        """
        Calculate the maximum embeddable data size for carrier text.

        Args:
            carrier_text: Text to embed data within
            method: Encoding method to calculate capacity for

        Returns:
            Maximum number of embeddable bytes
        """
        method = method or self._method

        if method == EncodingMethod.ZERO_WIDTH:
            # 2 bits per character, so 4 characters per byte
            return len(carrier_text) // 4

        elif method == EncodingMethod.WHITESPACE:
            # 2 bits per whitespace character
            # Roughly 1 bit per word boundary
            return len(carrier_text) // 8

        elif method == EncodingMethod.UNICODE:
            # Depends on available homoglyphs
            # Estimate: 1 byte per 10 characters
            return len(carrier_text) // 10

        elif method == EncodingMethod.COMBINED:
            # Combined uses multiple methods
            return self.calculate_capacity(carrier_text, EncodingMethod.ZERO_WIDTH)

        return 0

    def embed(
        self,
        carrier_text: str,
        data: bytes,
        password: Optional[str] = None,
        method: Optional[EncodingMethod] = None,
    ) -> TextEmbeddingResult:
        """
        Embed hidden data within text.

        Args:
            carrier_text: Text to embed data within
            data: Data to embed (bytes)
            password: Optional password for encryption
            method: Encoding method to use

        Returns:
            TextEmbeddingResult containing the stego text and metadata

        Raises:
            TextStegoError: If embedding fails
        """
        method = method or self._method

        # Calculate capacity
        capacity = self.calculate_capacity(carrier_text, method)
        if len(data) > capacity:
            raise TextStegoError(
                f"Data size ({len(data)}) exceeds text capacity ({capacity})",
                code=2001,
                details={"data_size": len(data), "capacity": capacity}
            )

        logger.info(f"Embedding {len(data)} bytes using {method.value}, capacity={capacity}")

        # Prepare data with header
        prepared_data = self._prepare_data_for_embedding(data, method)

        # Encrypt if required
        if self._encryption_enabled and password:
            prepared_data = self._encrypt_data(prepared_data, password)

        # Encode using selected method
        if method == EncodingMethod.ZERO_WIDTH:
            return self._embed_zero_width(carrier_text, prepared_data)
        elif method == EncodingMethod.WHITESPACE:
            return self._embed_whitespace(carrier_text, prepared_data)
        elif method == EncodingMethod.UNICODE:
            return self._embed_unicode(carrier_text, prepared_data)
        elif method == EncodingMethod.COMBINED:
            return self._embed_combined(carrier_text, prepared_data)
        else:
            raise TextStegoError(f"Unsupported encoding method: {method}", code=2002)

    def extract(
        self,
        stego_text: str,
        password: Optional[str] = None,
        method: Optional[EncodingMethod] = None,
    ) -> TextExtractionResult:
        """
        Extract hidden data from text.

        Args:
            stego_text: Text containing hidden data
            password: Optional password for decryption
            method: Encoding method to use for extraction

        Returns:
            TextExtractionResult containing the extracted data

        Raises:
            TextStegoError: If extraction fails
        """
        # Auto-detect method if not specified
        if method is None:
            method = self._detect_method(stego_text)
            if method is None:
                raise TextStegoError(
                    "Could not detect encoding method from text",
                    code=2010
                )

        logger.info(f"Extracting using {method.value}")

        # Decode using selected method
        if method == EncodingMethod.ZERO_WIDTH:
            extracted_data = self._extract_zero_width(stego_text)
        elif method == EncodingMethod.WHITESPACE:
            extracted_data = self._extract_whitespace(stego_text)
        elif method == EncodingMethod.UNICODE:
            extracted_data = self._extract_unicode(stego_text)
        elif method == EncodingMethod.COMBINED:
            extracted_data = self._extract_combined(stego_text)
        else:
            raise TextStegoError(f"Unsupported encoding method: {method}", code=2011)

        # Decrypt if required
        if self._encryption_enabled and password:
            try:
                extracted_data = self._decrypt_data(extracted_data, password)
            except Exception as e:
                raise TextStegoError(
                    f"Decryption failed: {e}",
                    code=2012
                )

        # Parse header to get original data
        original_data, original_size = self._parse_data_from_extraction(extracted_data)

        return TextExtractionResult(
            data=original_data,
            method=method,
            original_size=original_size,
        )

    def _prepare_data_for_embedding(
        self,
        data: bytes,
        method: EncodingMethod,
    ) -> bytes:
        """
        Prepare data for embedding by adding header with metadata.

        The header contains:
        - Magic number (4 bytes): "CXA1"
        - Data size (4 bytes): Original data size
        - Method (1 byte): Encoding method used
        - Reserved (3 bytes): For future use
        """
        header = struct.pack("!4sIII", b"CXA1", len(data), method.value.encode(), 0)
        return header + data

    def _parse_data_from_extraction(self, data: bytes) -> Tuple[bytes, int]:
        """Parse data after extraction, extracting header information."""
        if len(data) < 16:
            raise TextStegoError("Extracted data too short", code=2020)

        magic, size, method_byte, reserved = struct.unpack("!4sIII", data[:16])

        if magic != b"CXA1":
            raise TextStegoError(
                f"Invalid magic number: {magic}",
                code=2021
            )

        return data[16:16 + size], size

    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data before embedding."""
        if not CRYPTO_AVAILABLE:
            # Simple XOR fallback
            key = self._derive_simple_key(password, len(data))
            return bytes([d ^ k for d, k in zip(data, key)])

        salt = os.urandom(16)
        key = self._crypto_engine.derive_key(
            password.encode(),
            salt,
            iterations=100000,
            length=32,
        )

        nonce = self._crypto_engine.generate_nonce("aes-gcm")
        encrypt_result = self._crypto_engine.encrypt(
            data,
            key,
            nonce,
            algorithm="aes-gcm",
        )

        return salt + nonce + encrypt_result.ciphertext + encrypt_result.tag

    def _decrypt_data(self, data: bytes, password: str) -> bytes:
        """Decrypt data after extraction."""
        if not CRYPTO_AVAILABLE:
            key = self._derive_simple_key(password, len(data) - 32)
            return bytes([d ^ k for d, k in zip(data[32:], key)])

        if len(data) < 16 + 12 + 16:
            raise TextStegoError("Encrypted data too short", code=2030)

        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:-16]
        tag = data[-16:]

        key = self._crypto_engine.derive_key(
            password.encode(),
            salt,
            iterations=100000,
            length=32,
        )

        decrypt_result = self._crypto_engine.decrypt(
            ciphertext,
            tag,
            key,
            nonce,
            algorithm="aes-gcm",
        )

        return decrypt_result.plaintext

    def _derive_simple_key(self, password: str, length: int) -> bytes:
        """Simple key derivation for fallback encryption."""
        key = bytearray(length)
        password_bytes = password.encode()
        for i in range(length):
            key[i] = password_bytes[i % len(password_bytes)] ^ (i % 256)
        return bytes(key)

    def _embed_zero_width(
        self,
        carrier_text: str,
        data: bytes,
    ) -> TextEmbeddingResult:
        """Embed data using zero-width characters."""
        # Convert data to bits
        data_bits = self._bytes_to_bits(data)

        # Pad bits to make complete groups of 2
        while len(data_bits) % 2 != 0:
            data_bits += "0"

        # Encode bits as zero-width character pairs
        encoded_parts = []
        bit_index = 0

        for char in carrier_text:
            encoded_parts.append(char)

            # Every 4 characters, embed 2 bits (1 byte per 4 characters)
            if bit_index < len(data_bits):
                bit_pair = data_bits[bit_index:bit_index + 2]
                if bit_pair in self.ZW_BIT_MAP:
                    encoded_parts.append(self.ZW_BIT_MAP[bit_pair])
                    bit_index += 2

        stego_text = "".join(encoded_parts)

        capacity = len(carrier_text) // 4
        overhead_percent = ((len(stego_text) - len(carrier_text)) / len(carrier_text)) * 100

        return TextEmbeddingResult(
            text=stego_text,
            capacity_used=len(data),
            capacity_total=capacity,
            method=EncodingMethod.ZERO_WIDTH,
            carrier_length=len(carrier_text),
            overhead_percent=overhead_percent,
        )

    def _extract_zero_width(self, stego_text: str) -> bytes:
        """Extract data using zero-width characters."""
        # Find all zero-width characters
        zw_chars = {
            self.ZERO_WIDTH_SPACE,
            self.ZERO_WIDTH_NONJOINER,
            self.ZERO_WIDTH_JOINER,
            self.LEFT_TO_RIGHT_MARK,
            self.RIGHT_TO_LEFT_MARK,
        }

        # Reverse mapping
        bit_map = {v: k for k, v in self.ZW_BIT_MAP.items()}

        bits = []
        for char in stego_text:
            if char in zw_chars:
                if char in bit_map:
                    bits.append(bit_map[char])

        # Convert bits to bytes
        return self._bits_to_bytes([b for bs in bits for b in bs])

    def _embed_whitespace(
        self,
        carrier_text: str,
        data: bytes,
    ) -> TextEmbeddingResult:
        """Embed data using whitespace characters."""
        # Convert data to bits
        data_bits = self._bytes_to_bits(data)

        # Pad bits to make complete groups of 2
        while len(data_bits) % 2 != 0:
            data_bits += "0"

        # Split carrier text into words
        words = carrier_text.split()

        encoded_words = []
        bit_index = 0

        for word in words:
            encoded_words.append(word)

            # After each word, embed 2 bits as whitespace
            if bit_index < len(data_bits):
                bit_pair = data_bits[bit_index:bit_index + 2]
                if bit_pair in self.WS_BIT_MAP:
                    encoded_words.append(self.WS_BIT_MAP[bit_pair])
                    bit_index += 2

        stego_text = "".join(encoded_words)

        capacity = len(carrier_text) // 8
        overhead_percent = ((len(stego_text) - len(carrier_text)) / len(carrier_text)) * 100

        return TextEmbeddingResult(
            text=stego_text,
            capacity_used=len(data),
            capacity_total=capacity,
            method=EncodingMethod.WHITESPACE,
            carrier_length=len(carrier_text),
            overhead_percent=overhead_percent,
        )

    def _extract_whitespace(self, stego_text: str) -> bytes:
        """Extract data using whitespace characters."""
        ws_chars = {
            self.SPACE,
            self.TAB,
            self.NON_BREAKING_SPACE,
            self.OGHAM_SPACE_MARK,
        }

        bit_map = {v: k for k, v in self.WS_BIT_MAP.items()}

        bits = []
        for char in stego_text:
            if char in ws_chars:
                if char in bit_map:
                    bits.append(bit_map[char])

        return self._bits_to_bytes([b for bs in bits for b in bs])

    def _embed_unicode(
        self,
        carrier_text: str,
        data: bytes,
    ) -> TextEmbeddingResult:
        """Embed data using Unicode homoglyphs."""
        # This is a more complex method that substitutes similar-looking characters
        # For simplicity, we'll use a basic implementation

        # Homoglyph pairs (Latin characters that look similar to others)
        homoglyphs = {
            'a': 'а',  # Cyrillic 'а'
            'e': 'е',  # Cyrillic 'е'
            'o': 'о',  # Cyrillic 'о'
            'p': 'р',  # Cyrillic 'р'
            'c': 'с',  # Cyrillic 'с'
            'y': 'у',  # Cyrillic 'у'
            'x': 'х',  # Cyrillic 'х'
        }

        # Convert data to bits
        data_bits = self._bytes_to_bits(data)
        bit_index = 0

        encoded_chars = []
        for char in carrier_text:
            # Try to substitute if we need to embed bits
            if bit_index < len(data_bits) and char.lower() in homoglyphs:
                if data_bits[bit_index] == "1":
                    # Substitute with lookalike
                    if char.isupper():
                        encoded_chars.append(homoglyphs[char.lower()].upper())
                    else:
                        encoded_chars.append(homoglyphs[char])
                    bit_index += 1
                else:
                    encoded_chars.append(char)
            else:
                encoded_chars.append(char)

        stego_text = "".join(encoded_chars)

        capacity = len(carrier_text) // 10
        overhead_percent = 0  # No visible overhead

        return TextEmbeddingResult(
            text=stego_text,
            capacity_used=len(data),
            capacity_total=capacity,
            method=EncodingMethod.UNICODE,
            carrier_length=len(carrier_text),
            overhead_percent=overhead_percent,
        )

    def _extract_unicode(self, stego_text: str) -> bytes:
        """Extract data using Unicode homoglyphs."""
        homoglyphs = {
            'а': 'a',  # Cyrillic to Latin
            'е': 'e',
            'о': 'o',
            'р': 'p',
            'с': 'c',
            'у': 'y',
            'х': 'x',
        }

        bits = []
        for char in stego_text:
            if char.lower() in homoglyphs:
                # Found a homoglyph, this represents a '1' bit
                bits.append("1")
            elif char.lower() in homoglyphs.values():
                # Regular character, represents a '0' bit
                bits.append("0")

        return self._bits_to_bytes(bits)

    def _embed_combined(
        self,
        carrier_text: str,
        data: bytes,
    ) -> TextEmbeddingResult:
        """Embed data using combined methods."""
        # Use zero-width as primary, whitespace as secondary
        # For now, just use zero-width
        return self._embed_zero_width(carrier_text, data)

    def _extract_combined(self, stego_text: str) -> bytes:
        """Extract data using combined methods."""
        # Try zero-width first, then whitespace
        try:
            return self._extract_zero_width(stego_text)
        except:
            return self._extract_whitespace(stego_text)

    def _bytes_to_bits(self, data: bytes) -> str:
        """Convert bytes to a string of bits."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append(str((byte >> (7 - i)) & 1))
        return "".join(bits)

    def _bits_to_bytes(self, bits: List[str]) -> bytes:
        """Convert a list of bits to bytes."""
        # Filter out any non-bit characters
        clean_bits = [b for b in bits if b in ("0", "1")]

        if len(clean_bits) % 8 != 0:
            while len(clean_bits) % 8 != 0:
                clean_bits.append("0")

        bytes_list = []
        for i in range(0, len(clean_bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | int(clean_bits[i + j])
            bytes_list.append(byte)

        return bytes(bytes_list)

    def _detect_method(self, text: str) -> Optional[EncodingMethod]:
        """Detect which encoding method was used."""
        # Check for zero-width characters
        for char in text:
            if char in [self.ZERO_WIDTH_SPACE, self.ZERO_WIDTH_NONJOINER,
                       self.ZERO_WIDTH_JOINER, self.LEFT_TO_RIGHT_MARK,
                       self.RIGHT_TO_LEFT_MARK]:
                return EncodingMethod.ZERO_WIDTH

        # Check for whitespace encoding
        for char in text:
            if char in [self.TAB, self.NON_BREAKING_SPACE, self.OGHAM_SPACE_MARK]:
                return EncodingMethod.WHITESPACE

        # Default to zero-width
        return None

    def validate_text(self, text: str) -> Tuple[bool, str]:
        """
        Validate if text is suitable for steganography.

        Args:
            text: Text to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if len(text) < 16:
            return False, "Text too short for steganography"

        capacity = self.calculate_capacity(text)
        if capacity < 16:
            return False, f"Text capacity too small: {capacity} bytes"

        return True, f"Text valid, capacity: {capacity} bytes"
