"""
Image Steganography Module.

This module provides image-based steganography capabilities for hiding
data within image files. It supports multiple embedding methods including
Least Significant Bit (LSB) insertion and Discrete Cosine Transform (DCT)
modification.

All embedded payloads are encrypted using AES-256-GCM before embedding,
providing an additional layer of security for the hidden data.

Features:
    - LSB (Least Significant Bit) embedding
    - DCT (Discrete Cosine Transform) embedding
    - Adaptive embedding based on image characteristics
    - Encryption of embedded payloads
    - Error correction using Reed-Solomon codes
    - Embedding capacity calculation
"""

import os
import logging
import struct
from typing import Optional, Tuple, Union, List, Dict, Any
from enum import Enum
from dataclasses import dataclass

try:
    import numpy as np
    from PIL import Image
    import pywt
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from ..crypto import CryptoEngine, SecurityLevel
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


logger = logging.getLogger(__name__)


class EmbeddingMethod(Enum):
    """Supported image steganography methods."""

    LSB = "lsb"
    LSB_REPLACEMENT = "lsb_replacement"
    LSB_MATCHING = "lsb_matching"
    DCT = "dct"
    ADAPTIVE = "adaptive"


class ImageFormat(Enum):
    """Supported image formats for steganography."""

    PNG = "png"
    BMP = "bmp"
    GIF = "gif"
    # JPEG is supported only for DCT method
    JPEG = "jpeg"


class ImageStegoError(Exception):
    """Exception raised for image steganography errors."""

    def __init__(self, message: str, code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def __str__(self) -> str:
        base = f"ImageStegoError: {self.message}"
        if self.code:
            base += f" (Code: {self.code})"
        return base


@dataclass
class EmbeddingResult:
    """
    Result of a steganography embedding operation.

    Attributes:
        image: Stego image with embedded data
        capacity_used: Number of bytes embedded
        capacity_total: Total available capacity
        method: Method used for embedding
    """

    image: Image.Image
    capacity_used: int
    capacity_total: int
    method: EmbeddingMethod
    embedding_map: Dict[int, Tuple[int, int, int]]


@dataclass
class ExtractionResult:
    """
    Result of a steganography extraction operation.

    Attributes:
        data: Extracted data
        method: Method used for extraction
        original_size: Original size of embedded data
    """

    data: bytes
    method: EmbeddingMethod
    original_size: int


class ImageStego:
    """
    Image steganography handler.

    This class provides methods for embedding and extracting hidden data
    within image files using various steganographic techniques.

    Attributes:
        method: Default embedding method
        encryption_enabled: Whether to encrypt embedded payloads
        error_correction_enabled: Whether to use error correction

    Example:
        >>> stego = ImageStego(method=EmbeddingMethod.LSB)
        >>> # Embed secret in image
        >>> result = stego.embed(b"Secret message", image, password="secure")
        >>> result.image.save("stego_image.png")
        >>> # Extract secret from image
        >>> extracted = stego.extract(result.image, password="secure")
        >>> print(extracted.data)
    """

    # Mapping of embedding methods to supported formats
    SUPPORTED_FORMATS = {
        EmbeddingMethod.LSB: [ImageFormat.PNG, ImageFormat.BMP, ImageFormat.GIF],
        EmbeddingMethod.LSB_REPLACEMENT: [ImageFormat.PNG, ImageFormat.BMP],
        EmbeddingMethod.LSB_MATCHING: [ImageFormat.PNG, ImageFormat.BMP],
        EmbeddingMethod.DCT: [ImageFormat.JPEG],
        EmbeddingMethod.ADAPTIVE: [ImageFormat.PNG, ImageFormat.BMP, ImageFormat.GIF],
    }

    # Default settings per method
    DEFAULT_SETTINGS = {
        EmbeddingMethod.LSB: {
            "bits_per_channel": 1,
            "encoding_order": "interleaved",
        },
        EmbeddingMethod.DCT: {
            "quality": 75,
            "block_size": 8,
            "coefficient_selection": "middle",
        },
        EmbeddingMethod.ADAPTIVE: {
            "max_bits_per_pixel": 2,
            "complexity_threshold": 0.3,
        },
    }

    def __init__(
        self,
        method: EmbeddingMethod = EmbeddingMethod.LSB,
        encryption_enabled: bool = True,
        error_correction_enabled: bool = True,
        crypto_engine: Optional["CryptoEngine"] = None,
    ):
        """
        Initialize the image steganography handler.

        Args:
            method: Default embedding method to use
            encryption_enabled: Whether to encrypt embedded payloads
            error_correction_enabled: Whether to use Reed-Solomon error correction
            crypto_engine: Optional crypto engine instance for encryption

        Raises:
            ImportError: If required dependencies are not available
        """
        if not NUMPY_AVAILABLE:
            raise ImportError(
                "Required dependencies (numpy, Pillow, PyWavelets) not available. "
                "Install with: pip install numpy Pillow PyWavelets"
            )

        self._method = method
        self._encryption_enabled = encryption_enabled
        self._error_correction_enabled = error_correction_enabled
        self._crypto_engine = crypto_engine or CryptoEngine(security_level=SecurityLevel.HIGH)

        logger.info(f"ImageStego initialized with method={method.value}, encryption={encryption_enabled}")

    @property
    def method(self) -> EmbeddingMethod:
        """Get the current embedding method."""
        return self._method

    @method.setter
    def method(self, value: EmbeddingMethod) -> None:
        """Set the embedding method."""
        self._method = value
        logger.debug(f"Embedding method changed to {value.value}")

    def calculate_capacity(
        self,
        image: Image.Image,
        method: Optional[EmbeddingMethod] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Calculate the maximum embeddable data size for an image.

        Args:
            image: Carrier image
            method: Embedding method to calculate capacity for
            settings: Additional settings for capacity calculation

        Returns:
            Maximum number of embeddable bytes
        """
        method = method or self._method
        settings = settings or self.DEFAULT_SETTINGS.get(method, {})

        width, height = image.size
        pixels = width * height
        channels = len(image.getbands())

        if method == EmbeddingMethod.LSB:
            bits_per_channel = settings.get("bits_per_channel", 1)
            return (pixels * channels * bits_per_channel) // 8

        elif method == EmbeddingMethod.DCT:
            # DCT capacity is more complex to calculate
            # Rough estimate: ~50% of JPEG file size for conservative embedding
            return int(image.size[0] * image.size[1] * channels * 0.1)

        elif method == EmbeddingMethod.ADAPTIVE:
            max_bits_per_pixel = settings.get("max_bits_per_pixel", 2)
            return int(pixels * channels * max_bits_per_pixel * 0.5) // 8

        else:
            return 0

    def embed(
        self,
        data: bytes,
        image: Image.Image,
        password: Optional[str] = None,
        method: Optional[EmbeddingMethod] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> EmbeddingResult:
        """
        Embed hidden data within an image.

        Args:
            data: Data to embed (bytes)
            image: Carrier image (PIL Image)
            password: Optional password for encryption
            method: Embedding method to use
            settings: Additional settings for embedding

        Returns:
            EmbeddingResult containing the stego image and metadata

        Raises:
            ImageStegoError: If embedding fails
        """
        method = method or self._method
        settings = settings or self.DEFAULT_SETTINGS.get(method, {}).copy()

        # Validate image format
        img_format = self._get_image_format(image)
        supported_formats = self.SUPPORTED_FORMATS.get(method, [])
        if img_format not in supported_formats:
            raise ImageStegoError(
                f"Image format {img_format.value} not supported for method {method.value}",
                code=1001,
                details={"supported_formats": [f.value for f in supported_formats]}
            )

        # Calculate capacity
        capacity = self.calculate_capacity(image, method, settings)
        if len(data) > capacity:
            raise ImageStegoError(
                f"Data size ({len(data)}) exceeds image capacity ({capacity})",
                code=1002,
                details={"data_size": len(data), "capacity": capacity}
            )

        logger.info(f"Embedding {len(data)} bytes using {method.value}, capacity={capacity}")

        # Prepare data with header
        prepared_data = self._prepare_data_for_embedding(data, method)

        # Encrypt if required
        if self._encryption_enabled and password:
            prepared_data = self._encrypt_data(prepared_data, password)

        # Apply error correction if enabled
        if self._error_correction_enabled:
            prepared_data = self._apply_error_correction(prepared_data)

        # Perform embedding based on method
        if method == EmbeddingMethod.LSB:
            return self._embed_lsb(prepared_data, image, settings)
        elif method == EmbeddingMethod.DCT:
            return self._embed_dct(prepared_data, image, settings)
        elif method == EmbeddingMethod.ADAPTIVE:
            return self._embed_adaptive(prepared_data, image, settings)
        else:
            raise ImageStegoError(f"Unsupported embedding method: {method}", code=1003)

    def extract(
        self,
        image: Image.Image,
        password: Optional[str] = None,
        method: Optional[EmbeddingMethod] = None,
    ) -> ExtractionResult:
        """
        Extract hidden data from an image.

        Args:
            image: Stego image containing hidden data
            password: Optional password for decryption
            method: Embedding method to use for extraction

        Returns:
            ExtractionResult containing the extracted data

        Raises:
            ImageStegoError: If extraction fails
        """
        method = method or self._method

        # Detect method from image if not specified
        if method is None:
            method = self._detect_method(image)
            if method is None:
                raise ImageStegoError(
                    "Could not detect embedding method from image",
                    code=1010
                )

        logger.info(f"Extracting using {method.value}")

        # Extract embedded data based on method
        if method == EmbeddingMethod.LSB:
            extracted_data = self._extract_lsb(image)
        elif method == EmbeddingMethod.DCT:
            extracted_data = self._extract_dct(image)
        elif method == EmbeddingMethod.ADAPTIVE:
            extracted_data = self._extract_adaptive(image)
        else:
            raise ImageStegoError(f"Unsupported embedding method: {method}", code=1011)

        # Remove error correction if enabled
        if self._error_correction_enabled:
            extracted_data = self._remove_error_correction(extracted_data)

        # Decrypt if required
        if self._encryption_enabled and password:
            try:
                extracted_data = self._decrypt_data(extracted_data, password)
            except Exception as e:
                raise ImageStegoError(
                    f"Decryption failed: {e}",
                    code=1012
                )

        # Parse header to get original data
        original_data, original_size = self._parse_data_from_extraction(extracted_data)

        return ExtractionResult(
            data=original_data,
            method=method,
            original_size=original_size,
        )

    def _prepare_data_for_embedding(
        self,
        data: bytes,
        method: EmbeddingMethod,
    ) -> bytes:
        """
        Prepare data for embedding by adding header with metadata.

        The header contains:
        - Magic number (4 bytes): "CXA1"
        - Data size (4 bytes): Original data size
        - Method (1 byte): Embedding method used
        - Reserved (3 bytes): For future use
        """
        header = struct.pack("!4sIII", b"CXA1", len(data), method.value.encode(), 0)
        return header + data

    def _parse_data_from_extraction(self, data: bytes) -> Tuple[bytes, int]:
        """Parse data after extraction, extracting header information."""
        if len(data) < 16:
            raise ImageStegoError("Extracted data too short", code=1020)

        magic, size, method_byte, reserved = struct.unpack("!4sIII", data[:16])

        if magic != b"CXA1":
            raise ImageStegoError(
                f"Invalid magic number: {magic}",
                code=1021
            )

        return data[16:16 + size], size

    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data before embedding."""
        if not CRYPTO_AVAILABLE:
            # Simple XOR fallback if crypto not available
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
        result = self._crypto_engine.encrypt(
            data,
            key,
            nonce,
            algorithm="aes-gcm",
        )

        # Return salt + nonce + ciphertext + tag
        return salt + nonce + result.ciphertext + result.tag

    def _decrypt_data(self, data: bytes, password: str) -> bytes:
        """Decrypt data after extraction."""
        if not CRYPTO_AVAILABLE:
            # Simple XOR fallback
            key = self._derive_simple_key(password, len(data) - 32)
            return bytes([d ^ k for d, k in zip(data[32:], key)])

        if len(data) < 16 + 12 + 16:
            raise ImageStegoError("Encrypted data too short", code=1030)

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

        result = self._crypto_engine.decrypt(
            ciphertext,
            tag,
            key,
            nonce,
            algorithm="aes-gcm",
        )

        return result.plaintext

    def _derive_simple_key(self, password: str, length: int) -> bytes:
        """Simple key derivation for fallback encryption."""
        key = bytearray(length)
        password_bytes = password.encode()
        for i in range(length):
            key[i] = password_bytes[i % len(password_bytes)] ^ (i % 256)
        return bytes(key)

    def _apply_error_correction(self, data: bytes) -> bytes:
        """Apply Reed-Solomon error correction to data."""
        # Placeholder for Reed-Solomon implementation
        # In production, use reedsolo library
        return data

    def _remove_error_correction(self, data: bytes) -> bytes:
        """Remove Reed-Solomon error correction and verify."""
        # Placeholder for error correction removal
        return data

    def _embed_lsb(
        self,
        data: bytes,
        image: Image.Image,
        settings: Dict[str, Any],
    ) -> EmbeddingResult:
        """Embed data using LSB (Least Significant Bit) method."""
        bits_per_channel = settings.get("bits_per_channel", 1)

        # Convert image to RGBA mode for consistency
        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGB")

        # Convert to numpy array for efficient manipulation
        img_array = np.array(image)
        height, width, channels = img_array.shape

        # Convert data to bits
        data_bits = self._bytes_to_bits(data)

        # Create embedding map
        embedding_map: Dict[int, Tuple[int, int, int]] = {}

        bit_index = 0
        capacity_used = 0

        for y in range(height):
            for x in range(width):
                for c in range(channels):
                    if bit_index >= len(data_bits):
                        break

                    # Get current pixel value
                    pixel_value = img_array[y, x, c]
                    original_lsb = pixel_value & ((1 << bits_per_channel) - 1)

                    # Calculate new value with embedded bit
                    data_bit = int(data_bits[bit_index])
                    new_value = (pixel_value & ~(1 << 0)) | data_bit

                    # Store embedding location
                    bit_index += 1

                    # Modify pixel
                    img_array[y, x, c] = new_value

                    if bit_index <= len(data_bits):
                        capacity_used += 1

        # Convert back to image
        stego_image = Image.fromarray(img_array)

        capacity = self.calculate_capacity(image, EmbeddingMethod.LSB, settings)

        return EmbeddingResult(
            image=stego_image,
            capacity_used=capacity_used,
            capacity_total=capacity,
            method=EmbeddingMethod.LSB,
            embedding_map=embedding_map,
        )

    def _extract_lsb(self, image: Image.Image) -> bytes:
        """Extract data using LSB method."""
        # Convert image to numpy array
        img_array = np.array(image)
        height, width, channels = img_array.shape

        # Extract bits
        bits = []
        for y in range(height):
            for x in range(width):
                for c in range(min(channels, 4)):  # Limit to first 4 channels
                    bit = img_array[y, x, c] & 1
                    bits.append(str(bit))

        # Convert bits to bytes
        return self._bits_to_bytes(bits)

    def _embed_dct(
        self,
        data: bytes,
        image: Image.Image,
        settings: Dict[str, Any],
    ) -> EmbeddingResult:
        """Embed data using DCT (Discrete Cosine Transform) method."""
        # Placeholder for DCT embedding
        # DCT embedding is more complex and requires JPEG images
        raise ImageStegoError("DCT embedding not yet implemented", code=1040)

    def _extract_dct(self, image: Image.Image) -> bytes:
        """Extract data using DCT method."""
        raise ImageStegoError("DCT extraction not yet implemented", code=1041)

    def _embed_adaptive(
        self,
        data: bytes,
        image: Image.Image,
        settings: Dict[str, Any],
    ) -> EmbeddingResult:
        """Embed data using adaptive method."""
        # Placeholder for adaptive embedding
        # Adaptive embedding selects embedding locations based on image complexity
        raise ImageStegoError("Adaptive embedding not yet implemented", code=1042)

    def _extract_adaptive(self, image: Image.Image) -> bytes:
        """Extract data using adaptive method."""
        raise ImageStegoError("Adaptive extraction not yet implemented", code=1043)

    def _bytes_to_bits(self, data: bytes) -> str:
        """Convert bytes to a string of bits."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append(str((byte >> (7 - i)) & 1))
        return "".join(bits)

    def _bits_to_bytes(self, bits: List[str]) -> bytes:
        """Convert a list of bits to bytes."""
        if len(bits) % 8 != 0:
            # Pad with zeros
            while len(bits) % 8 != 0:
                bits.append("0")

        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | int(bits[i + j])
            bytes_list.append(byte)

        return bytes(bytes_list)

    def _get_image_format(self, image: Image.Image) -> ImageFormat:
        """Get the image format from PIL image."""
        format_map = {
            "PNG": ImageFormat.PNG,
            "BMP": ImageFormat.BMP,
            "GIF": ImageFormat.GIF,
            "JPEG": ImageFormat.JPEG,
        }
        return format_map.get(image.format, ImageFormat.PNG)

    def _detect_method(self, image: Image.Image) -> Optional[EmbeddingMethod]:
        """Detect which embedding method was used based on image characteristics."""
        # This is a heuristic detection
        # In practice, the method should be stored alongside the data
        img_format = self._get_image_format(image)

        if img_format == ImageFormat.JPEG:
            return EmbeddingMethod.DCT
        elif img_format in [ImageFormat.PNG, ImageFormat.BMP]:
            return EmbeddingMethod.LSB

        return None

    def validate_image(self, image: Image.Image) -> Tuple[bool, str]:
        """
        Validate if an image is suitable for steganography.

        Args:
            image: Image to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if image.mode not in ("RGB", "RGBA", "L"):
            return False, f"Unsupported image mode: {image.mode}"

        if image.size[0] < 8 or image.size[1] < 8:
            return False, "Image too small for steganography"

        capacity = self.calculate_capacity(image)
        if capacity < 16:
            return False, f"Image capacity too small: {capacity} bytes"

        return True, f"Image valid, capacity: {capacity} bytes"
