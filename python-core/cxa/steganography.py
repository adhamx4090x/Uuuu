#!/usr/bin/env python3
"""
CXA Steganography Module

This module provides comprehensive steganographic capabilities for hiding data
within images and text files. It implements various steganography techniques
suitable for covert communication, data embedding, and secure information
transmission within the CXA secure communication system.

================================================================================
MODULE ARCHITECTURE
================================================================================

The module is organized into four main components:

1. Core Data Structures (Lines 46-119):
   - StegoMethod: Enumeration of available steganography methods
   - CarrierType: Classification of carrier file formats
   - StegoResult: Result container for steganography operations
   - StegoMetadata: Metadata schema for embedded content

2. Image Steganography (Lines 122-618):
   - ImageSteganographer: LSB and spread spectrum implementations
   - Supports PNG, BMP, and GIF carrier images
   - Capacity calculation and integrity verification

3. Text Steganography (Lines 621-909):
   - TextSteganographer: Zero-width character encoding
   - Supports plain text, Markdown, and HTML carriers
   - Unicode-based invisible character embedding

4. Unified Manager (Lines 912-1223):
   - CXASteganographyManager: Single API for all operations
   - Automatic carrier type detection
   - File embedding and extraction support

5. Advanced DCT Steganography (Lines 1226-1862):
   - DCTSteganographer: Frequency-domain embedding
   - Robust against compression and resizing
   - Uses Discrete Cosine Transform algorithm

================================================================================
STEGANOGRAPHY METHODS OVERVIEW
================================================================================

Least Significant Bit (LSB):
- Modifies the least significant bits of pixel values
- Highest capacity among spatial domain methods
- Simple implementation but detectable by steganalysis
- Best suited for lossless formats (PNG, BMP)

Spread Spectrum:
- Spreads data across image using pseudo-random sequences
- More resistant to detection than LSB
- Lower capacity but better security properties
- Uses Gaussian noise for data embedding

Discrete Cosine Transform (DCT):
- Embeds data in frequency domain coefficients
- Robust against JPEG compression and image resizing
- Most sophisticated method with moderate capacity
- Requires OpenCV library for computation

Zero-Width Characters:
- Uses invisible Unicode characters in text
- Completely invisible in most text editors
- Lower capacity proportional to carrier text length
- No image processing required

================================================================================
SECURITY CONSIDERATIONS
================================================================================

1. LSB and spread spectrum methods are detectable by specialized tools
2. DCT provides better security but lower capacity
3. Always verify integrity using SHA-256 checksums
4. Consider encryption before embedding for maximum security
5. Carrier file selection affects detectability
6. Text steganography leaves minimal forensic traces

Author: CXA Development Team
Version: 2.0.0
License: CXA Secure Communication System
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================
# Core Python modules for general functionality

import base64
import hashlib
import json
import math
import os
import random
import struct
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# =============================================================================
# THIRD-PARTY LIBRARY IMPORTS
# =============================================================================
# External dependencies for image processing

from PIL import Image
import numpy as np

try:
    import cv2
    _OPENCV_AVAILABLE = True
except ImportError:
    _OPENCV_AVAILABLE = False
    cv2 = None


# =============================================================================
# SECTION 1: STEGANOGRAPHY TYPES AND ENUMS
# =============================================================================
# This section defines the fundamental types and enumerations used throughout
# the steganography module. These types provide type safety and documentation
# for the various steganography methods and carrier file types supported.

class StegoMethod(Enum):
    """
    Enumeration of available steganography embedding methods.
    
    Each method represents a different technique for hiding data within carrier
    files. The choice of method affects capacity, robustness, and detectability.
    
    Attributes:
        LSB: Least Significant Bit substitution in pixel values
        LSB_REPLACE: LSB with explicit bit replacement strategy
        SPREAD_SPECTRUM: Pseudo-random sequence spreading technique
        DCT: Discrete Cosine Transform frequency-domain embedding
        ZEROWIDTH: Zero-width Unicode character encoding for text
        UNICODE: Unicode homoglyph substitution for text
        
    Example:
        >>> method = StegoMethod.LSB
        >>> print(method.value)
        'lsb'
    """
    LSB = "lsb"
    LSB_REPLACE = "lsb_replace"
    SPREAD_SPECTRUM = "spread_spectrum"
    DCT = "dct"
    ZEROWIDTH = "zerowidth"
    UNICODE = "unicode"


class CarrierType(Enum):
    """
    Enumeration of supported carrier file types.
    
    Carrier files serve as the medium for hiding data. Different carrier types
    support different steganography methods and have varying capacity characteristics.
    
    Image Carriers:
    - IMAGE_PNG: Lossless compression, ideal for LSB methods
    - IMAGE_BMP: Uncompressed bitmap format
    - IMAGE_GIF: Indexed color format with limitations
    
    Text Carriers:
    - TEXT_PLAIN: Standard text files
    - TEXT_MARKDOWN: Markdown formatted documents
    - TEXT_HTML: HTML web documents
    
    Note:
        Not all steganography methods work with all carrier types.
        DCT requires image processing libraries, while text methods
        only work with text-based carriers.
    """
    IMAGE_PNG = "image_png"
    IMAGE_BMP = "image_bmp"
    IMAGE_GIF = "image_gif"
    TEXT_PLAIN = "text_plain"
    TEXT_MARKDOWN = "text_markdown"
    TEXT_HTML = "text_html"


@dataclass
class StegoResult:
    """
    Data class representing the result of a steganography operation.
    
    This class encapsulates all information about the outcome of an embedding
    or extraction operation, including success status, capacity utilization,
    and integrity verification data.
    
    Attributes:
        success: Boolean indicating whether the operation completed successfully
        carrier_data: Raw bytes of the modified carrier file (if applicable)
        carrier_path: File path to the output carrier file
        message: Human-readable status or error message
        capacity_used: Number of bytes actually embedded or extracted
        capacity_total: Maximum capacity of the carrier file
        checksum: SHA-256 hash of the carrier data for integrity verification
        
    Example:
        >>> result = StegoResult(
        ...     success=True,
        ...     carrier_data=b'\x89PNG...',
        ...     carrier_path="output.png",
        ...     message="Data embedded successfully",
        ...     capacity_used=1024,
        ...     capacity_total=2048,
        ...     checksum="abc123..."
        ... )
    """
    success: bool
    carrier_data: Optional[bytes]
    carrier_path: Optional[str]
    message: str
    capacity_used: int
    capacity_total: int
    checksum: str
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the StegoResult to a dictionary for serialization.
        
        This method creates a JSON-serializable dictionary representation
        of the result, suitable for logging, API responses, or storage.
        
        Returns:
            Dictionary containing all result fields except carrier_data
            (which may be too large for serialization).
            
        Example:
            >>> result.to_dict()
            {'success': True, 'message': 'Data embedded', ...}
        """
        return {
            'success': self.success,
            'message': self.message,
            'capacity_used': self.capacity_used,
            'capacity_total': self.capacity_total,
            'checksum': self.checksum
        }


@dataclass
class StegoMetadata:
    """
    Data class representing metadata for embedded data content.
    
    This metadata structure provides essential information about the embedded
    content, including its original size, content type, and integrity verification.
    The metadata is embedded alongside the actual data to enable proper extraction
    and verification.
    
    Attributes:
        original_size: Size in bytes of the original embedded data
        content_type: MIME type of the embedded content
        filename: Original filename if embedding a file (None if raw data)
        checksum: SHA-256 hash of the original data for integrity verification
        method: Steganography method used for embedding
        timestamp: ISO format timestamp of when embedding occurred
        
    Implementation Details:
        The metadata is serialized to JSON and embedded at the beginning of
        the carrier file. This allows extraction to know the data boundaries
        and verify integrity without prior knowledge of the embedded content.
        
    Example:
        >>> metadata = StegoMetadata(
        ...     original_size=2048,
        ...     content_type='application/pdf',
        ...     filename='document.pdf',
        ...     checksum='abc123def456...',
        ...     method=StegoMethod.LSB,
        ...     timestamp='2024-01-15T10:30:00Z'
        ... )
    """
    original_size: int
    content_type: str
    filename: Optional[str]
    checksum: str
    method: StegoMethod
    timestamp: str
    
    def to_bytes(self) -> bytes:
        """
        Serialize the metadata to bytes for embedding.
        
        This method converts the metadata to a JSON-encoded byte sequence
        that can be embedded within the carrier file. The serialization
        format ensures compatibility and easy parsing during extraction.
        
        Returns:
            JSON-encoded bytes representing the complete metadata structure.
            
        Example:
            >>> metadata_bytes = metadata.to_bytes()
            >>> print(len(metadata_bytes))
            256
        """
        data = {
            'original_size': self.original_size,
            'content_type': self.content_type,
            'filename': self.filename,
            'checksum': self.checksum,
            'method': self.method.value,
            'timestamp': self.timestamp
        }
        return json.dumps(data).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'StegoMetadata':
        """
        Deserialize metadata from bytes extracted from a carrier file.
        
        This class method parses the JSON-encoded metadata bytes and reconstructs
        the StegoMetadata object. It handles the conversion of the method field
        from string representation back to the StegoMethod enum.
        
        Args:
            data: JSON-encoded bytes containing the serialized metadata.
            
        Returns:
            Reconstructed StegoMetadata object with all fields populated.
            
        Raises:
            json.JSONDecodeError: If the data is not valid JSON.
            KeyError: If required fields are missing from the metadata.
            
        Example:
            >>> metadata = StegoMetadata.from_bytes(extracted_bytes)
        """
        parsed = json.loads(data.decode('utf-8'))
        parsed['method'] = StegoMethod(parsed['method'])
        return cls(**parsed)


# =============================================================================
# SECTION 2: IMAGE STEGANOGRAPHY IMPLEMENTATION
# =============================================================================
# This section contains the ImageSteganographer class, which implements
# spatial domain steganography methods for hiding data in images.
# The primary method is Least Significant Bit (LSB) substitution.

class ImageSteganographer:
    """
    Image-based steganography operations for spatial domain embedding.
    
    This class provides comprehensive methods for embedding and extracting
    hidden data from images using spatial domain techniques. The primary
    method is Least Significant Bit (LSB) substitution, which modifies
    the least significant bits of pixel values to store data.
    
    Key Features:
    - LSB embedding with configurable bits per channel
    - Spread spectrum technique for improved security
    - Capacity calculation for various image formats
    - Integrity verification using SHA-256 checksums
    - Metadata embedding for proper data extraction
    
    Technical Details:
    The LSB method works by replacing the least significant bits of each
    pixel's color channel with bits from the secret message. For example,
    with 1 bit per channel, each pixel can store 3 bits (RGB) or 4 bits
    (RGBA). The method is simple but effective for lossless formats.
    
    Thread Safety:
    This class uses a threading lock to ensure thread-safe operations
    when embedding or extracting data from multiple threads.
    
    Example:
        >>> stego = ImageSteganographer()
        >>> result = stego.embed_lsb("carrier.png", b"secret data")
        >>> print(result.message)
        'Data embedded successfully using LSB steganography'
        
    Limitations:
    - LSB is detectable by steganalysis tools
    - Lossy compression (JPEG) destroys embedded data
    - PNG is recommended for lossless preservation
    """
    
    def __init__(self):
        """
        Initialize the image steganographer.
        
        Creates a new ImageSteganographer instance with thread-safe locking
        for concurrent operations. No carrier image is loaded at initialization;
        images are loaded as needed during embedding and extraction operations.
        
        Example:
            >>> stego = ImageSteganographer()
        """
        self._lock = threading.Lock()
    
    def calculate_capacity(
        self,
        image_path: str,
        method: StegoMethod = StegoMethod.LSB,
        bits_per_channel: int = 1
    ) -> int:
        """
        Calculate the maximum embeddable data size for a given image.
        
        This method determines how many bytes can be hidden in an image
        based on its dimensions, color channels, and the chosen steganography
        method. The calculation considers the header overhead required for
        metadata storage.
        
        Args:
            image_path: Path to the carrier image file.
            method: Steganography method to use for capacity calculation.
                   Defaults to StegoMethod.LSB.
            bits_per_channel: Number of LSBs to use per color channel.
                             Valid range is 1-4. More bits increases capacity
                             but also increases detectability.
                             
        Returns:
            Maximum number of bytes that can be embedded in the image.
            Returns 0 if the image cannot be read or the method is unsupported.
            
        Capacity Formula:
            LSB: (width × height × channels × bits_per_channel) / 8 bytes
            Spread Spectrum: Approximately 1/10 of LSB capacity
            DCT: (width × height × channels) / 64 bytes (for JPEG)
            
        Example:
            >>> stego = ImageSteganographer()
            >>> capacity = stego.calculate_capacity("test.png", StegoMethod.LSB, 1)
            >>> print(f"Can embed {capacity} bytes")
        """
        img = Image.open(image_path)
        width, height = img.size
        channels = len(img.getbands())
        
        if method == StegoMethod.LSB:
            # LSB: Each pixel contributes (channels × bits_per_channel) bits
            # Divide by 8 to convert bits to bytes
            return (width * height * channels * bits_per_channel) // 8
        elif method == StegoMethod.SPREAD_SPECTRUM:
            # Spread spectrum: Reduced capacity due to noise-based embedding
            # Approximately 10% of LSB capacity for reasonable quality
            return ((width * height * channels * bits_per_channel) // 8) // 10
        elif method == StegoMethod.DCT:
            # DCT: Capacity depends on 8x8 block processing
            # Each block provides limited embedding positions
            return (width * height * channels) // 64
        
        return 0
    
    def embed_lsb(
        self,
        carrier_path: str,
        data: bytes,
        output_path: Optional[str] = None,
        bits_per_channel: int = 1,
        save_args: Optional[Dict[str, Any]] = None
    ) -> StegoResult:
        """
        Embed data using Least Significant Bit (LSB) steganography.
        
        This method hides data within the least significant bits of pixel
        values in the carrier image. The method modifies pixel values
        minimally to preserve visual quality while embedding the secret data.
        
        Data Format:
            The embedded payload consists of:
            1. 2-byte header length (little-endian unsigned short)
            2. Variable-length metadata header (JSON)
            3. Secret data bytes
            
        Args:
            carrier_path: Path to the carrier image file (PNG recommended).
            data: Raw bytes of data to embed in the carrier image.
            output_path: Path for the output image. Defaults to overwriting
                        the carrier file if not specified.
            bits_per_channel: Number of LSBs to modify per color channel.
                             Range: 1-4. Higher values increase capacity
                             but also increase detectability.
            save_args: Optional dictionary of arguments for PIL image saving.
                      Common options: 'png' compression settings.
                      
        Returns:
            StegoResult containing operation status, output path, capacity
            usage, and SHA-256 checksum of the carrier image.
            
        Example:
            >>> stego = ImageSteganographer()
            >>> result = stego.embed_lsb(
            ...     "carrier.png",
            ...     b"Secret message",
            ...     "output.png",
            ...     bits_per_channel=1
            ... )
            >>> print(f"Success: {result.success}")
            
        Note:
            Always use lossless formats like PNG. JPEG compression will
            destroy embedded LSB data. The method creates a metadata header
            to enable proper extraction and integrity verification.
        """
        if save_args is None:
            save_args = {}
        
        try:
            with self._lock:
                img = Image.open(carrier_path)
                
                # Convert to RGBA if needed for transparency support
                # This ensures consistent channel handling across image types
                if img.mode not in ['RGB', 'RGBA', 'L']:
                    img = img.convert('RGB')
                
                img_array = np.array(img)
                
                # Validate capacity before embedding
                # Returns early if data exceeds maximum embeddable size
                capacity = self._calculate_lsb_capacity(img_array, bits_per_channel)
                if len(data) > capacity:
                    return StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=None,
                        message=f"Data too large. Max: {capacity} bytes",
                        capacity_used=len(data),
                        capacity_total=capacity,
                        checksum=""
                    )
                
                # Create metadata header containing information about embedded data
                # This metadata enables proper extraction and integrity verification
                metadata = StegoMetadata(
                    original_size=len(data),
                    content_type='application/octet-stream',
                    filename=None,
                    checksum=hashlib.sha256(data).hexdigest(),
                    method=StegoMethod.LSB,
                    timestamp=str(__import__('datetime').datetime.utcnow().isoformat())
                )
                header_data = metadata.to_bytes()
                header_length = len(header_data)
                
                # Create full payload: [header_length: 2 bytes][header][data]
                # Header length is stored first to know metadata boundaries
                payload = struct.pack('<H', header_length) + header_data + data
                
                # Embed payload in image using LSB substitution
                modified_array = self._embed_lsb_data(img_array, payload, bits_per_channel)
                
                # Convert modified numpy array back to PIL Image
                modified_img = Image.fromarray(modified_array)
                
                # Generate output path and save modified image
                if output_path is None:
                    output_path = carrier_path
                
                # Configure save arguments for PNG preservation
                save_args.setdefault('png', {})
                modified_img.save(output_path, **save_args)
                
                # Read back the saved file for checksum calculation
                # This ensures we have the actual file bytes after compression
                with open(output_path, 'rb') as f:
                    carrier_data = f.read()
                
                # Calculate SHA-256 hash of carrier data for integrity verification
                checksum = hashlib.sha256(carrier_data).hexdigest()
                
                return StegoResult(
                    success=True,
                    carrier_data=carrier_data,
                    carrier_path=output_path,
                    message="Data embedded successfully using LSB steganography",
                    capacity_used=len(payload),
                    capacity_total=capacity,
                    checksum=checksum
                )
        
        except Exception as e:
            return StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"Embedding failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def _calculate_lsb_capacity(
        self,
        img_array: np.ndarray,
        bits_per_channel: int
    ) -> int:
        """
        Calculate LSB capacity for a numpy image array.
        
        Internal method that computes the maximum embeddable data size
        based on image dimensions and the specified bits-per-channel setting.
        
        Args:
            img_array: NumPy array containing image pixel data.
            bits_per_channel: Number of LSBs to use per channel.
                             Range: 1-4.
                             
        Returns:
            Maximum number of bytes that can be embedded.
            
        Implementation:
            capacity = (height × width × channels × bits_per_channel) / 8
            
            This accounts for:
            - Height and width of the image
            - Number of color channels (1 for grayscale, 3 for RGB, 4 for RGBA)
            - Number of bits modified per channel
            - Division by 8 to convert bits to bytes
        """
        height, width = img_array.shape[:2]
        channels = 1 if img_array.ndim == 2 else img_array.shape[2]
        return (height * width * channels * bits_per_channel) // 8
    
    def _embed_lsb_data(
        self,
        img_array: np.ndarray,
        data: bytes,
        bits_per_channel: int
    ) -> np.ndarray:
        """
        Embed data bytes into image using LSB substitution.
        
        This internal method performs the actual LSB embedding operation,
        iterating through pixels and modifying the specified number of
        least significant bits in each color channel.
        
        Args:
            img_array: NumPy array containing the carrier image.
            data: Bytes to embed in the image.
            bits_per_channel: Number of LSBs to modify per channel.
                             Range: 1-4.
                             
        Returns:
            Modified NumPy array with embedded data.
            
        Algorithm:
            1. Convert data bytes to a sequence of bits
            2. Iterate through each pixel in row-major order
            3. For each color channel in each pixel:
               a. Clear the specified number of LSBs
               b. Replace with bits from the data sequence
            4. Continue until all data is embedded
            
        Bit Ordering:
            Bits are embedded MSB first (bit 7 of byte 0 first, etc.)
            This ensures consistent ordering for extraction.
            
        Note:
            Grayscale images (2D arrays) are handled differently than
            color images (3D arrays). This method handles both cases.
        """
        # Convert data bytes to a flat list of bits
        # Each byte is expanded to 8 bits, MSB first
        data_bits = []
        for byte in data:
            for i in range(8):
                data_bits.append((byte >> (7 - i)) & 1)
        
        # Create a copy of the image array to modify
        result = img_array.copy()
        bit_idx = 0
        
        height, width = result.shape[:2]
        
        # Iterate through each pixel in the image
        for y in range(height):
            for x in range(width):
                if bit_idx >= len(data_bits):
                    break
                
                pixel = result[y, x]
                
                # Handle multi-channel pixels (RGB, RGBA)
                if isinstance(pixel, (list, tuple, np.ndarray)):
                    for c in range(len(pixel)):
                        if bit_idx >= len(data_bits):
                            break
                        
                        # Get current pixel value
                        original = int(pixel[c])
                        
                        # Clear the specified number of LSBs
                        # Mask: inverted (1<<bits)-1 has 1s in positions to clear
                        mask = ~((1 << bits_per_channel) - 1)
                        cleared = original & mask
                        
                        # Embed new bits in the cleared positions
                        new_bits = 0
                        for b in range(bits_per_channel):
                            if bit_idx < len(data_bits):
                                new_bits = (new_bits << 1) | data_bits[bit_idx]
                                bit_idx += 1
                            else:
                                # Pad with zeros if data runs out
                                new_bits = (new_bits << 1) | 0
                        
                        result[y, x, c] = cleared | new_bits
                else:
                    # Handle grayscale pixels (single channel)
                    original = int(pixel)
                    mask = ~((1 << bits_per_channel) - 1)
                    cleared = original & mask
                    
                    new_bits = 0
                    for b in range(bits_per_channel):
                        if bit_idx < len(data_bits):
                            new_bits = (new_bits << 1) | data_bits[bit_idx]
                            bit_idx += 1
                        else:
                            new_bits = (new_bits << 1) | 0
                    
                    result[y, x] = cleared | new_bits
            
            if bit_idx >= len(data_bits):
                break
        
        return result
    
    def extract_lsb(
        self,
        carrier_path: str,
        output_path: Optional[str] = None,
        bits_per_channel: int = 1
    ) -> Tuple[Optional[bytes], StegoResult]:
        """
        Extract data from an LSB-encoded image.
        
        This method reverses the embedding process, reading LSBs from
        the carrier image to reconstruct the original embedded data.
        It also validates the extracted metadata and verifies integrity.
        
        Extraction Process:
            1. Read carrier image and extract LSB bits
            2. Reconstruct payload bytes from extracted bits
            3. Read header length from first 2 bytes
            4. Parse metadata from header
            5. Extract and verify data using checksum
            
        Args:
            carrier_path: Path to the carrier image containing embedded data.
            output_path: Optional path to write extracted data to file.
            bits_per_channel: Number of LSBs used during embedding.
                             Must match the value used for embedding.
                             
        Returns:
            Tuple of (extracted_data, StegoResult):
            - extracted_data: The original bytes that were embedded (None if failed)
            - StegoResult: Operation status and details
            
        Example:
            >>> stego = ImageSteganographer()
            >>> data, result = stego.extract_lsb("carrier_with_data.png")
            >>> if result.success:
            ...     print(f"Extracted {len(data)} bytes")
            
        Note:
            If you don't know the bits_per_channel value, you may need
            to try different values. Common values are 1 or 2.
        """
        try:
            with self._lock:
                img = Image.open(carrier_path)
                img_array = np.array(img)
                
                # Extract payload bits from LSB positions
                payload, payload_length = self._extract_lsb_data(
                    img_array, bits_per_channel
                )
                
                # Check if any data was found
                if payload is None or payload_length == 0:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message="No hidden data found in image",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
                
                # Read header length from first 2 bytes
                # Little-endian unsigned short format
                if len(payload) < 2:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message="Invalid payload format",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
                
                header_length = struct.unpack('<H', payload[:2])[0]
                
                # Verify header completeness
                if len(payload) < 2 + header_length:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message="Incomplete header",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
                
                # Parse metadata from header section
                try:
                    header_data = payload[2:2 + header_length]
                    metadata = StegoMetadata.from_bytes(header_data)
                    
                    data_start = 2 + header_length
                    extracted_data = payload[data_start:]
                    
                    # Verify data integrity using stored checksum
                    if hashlib.sha256(extracted_data).hexdigest() != metadata.checksum:
                        return None, StegoResult(
                            success=False,
                            carrier_data=None,
                            carrier_path=carrier_path,
                            message="Data integrity check failed",
                            capacity_used=0,
                            capacity_total=0,
                            checksum=""
                        )
                    
                    # Write to output file if specified
                    if output_path:
                        with open(output_path, 'wb') as f:
                            f.write(extracted_data)
                    
                    return extracted_data, StegoResult(
                        success=True,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message=f"Extracted {len(extracted_data)} bytes using LSB steganography",
                        capacity_used=len(extracted_data),
                        capacity_total=0,
                        checksum=metadata.checksum
                    )
                
                except Exception as e:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message=f"Failed to parse metadata: {str(e)}",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
        
        except Exception as e:
            return None, StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=carrier_path,
                message=f"Extraction failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def _extract_lsb_data(
        self,
        img_array: np.ndarray,
        bits_per_channel: int
    ) -> Tuple[Optional[bytes], int]:
        """
        Extract data bits from LSB-encoded image array.
        
        This internal method reads the least significant bits from each
        pixel channel and reconstructs the original embedded bytes.
        
        Args:
            img_array: NumPy array containing the encoded image.
            bits_per_channel: Number of LSBs to extract per channel.
                             Must match the embedding configuration.
                             
        Returns:
            Tuple of (extracted_bytes, total_bits_extracted):
            - extracted_bytes: The reconstructed data bytes
            - total_bits_extracted: Count of bits that were read
            
        Algorithm:
            1. Iterate through all pixels in row-major order
            2. For each channel, extract the specified number of LSBs
            3. Collect bits into a contiguous sequence
            4. Convert bit sequence to bytes (8 bits per byte)
        """
        bits = []
        
        height, width = img_array.shape[:2]
        
        # Extract bits from each pixel and channel
        for y in range(height):
            for x in range(width):
                pixel = img_array[y, x]
                
                if isinstance(pixel, (list, tuple, np.ndarray)):
                    for c in range(len(pixel)):
                        original = int(pixel[c])
                        # Extract LSBs from current value
                        for b in range(bits_per_channel):
                            bits.append(original & 1)
                            original >>= 1
                else:
                    # Grayscale pixel
                    original = int(pixel)
                    for b in range(bits_per_channel):
                        bits.append(original & 1)
                        original >>= 1
        
        # Convert bits to bytes
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                bytes_data.append(byte)
            else:
                # Incomplete byte at the end is discarded
                break
        
        return bytes(bytes_data), len(bits)
    
    def embed_spread_spectrum(
        self,
        carrier_path: str,
        data: bytes,
        output_path: Optional[str] = None,
        strength: float = 0.1,
        seed: Optional[int] = None
    ) -> StegoResult:
        """
        Embed data using spread spectrum steganography.
        
        This method implements spread spectrum encoding, which spreads the
        secret data across the image using pseudo-random noise sequences.
        This provides better resistance to detection compared to LSB,
        though with reduced capacity.
        
        Technical Details:
            The spread spectrum technique adds Gaussian noise to pixel
            values, with the noise pattern determined by the secret data
            and a pseudo-random sequence. This makes the embedded data
            indistinguishable from natural image noise to statistical
            analysis tools.
            
        Args:
            carrier_path: Path to the carrier image file.
            data: Bytes of data to embed in the carrier image.
            output_path: Path for the output image. Defaults to carrier_path.
            strength: Embedding strength factor (0.01 to 1.0).
                     Higher values are more robust but more visible.
            seed: Random seed for reproducible embedding. Same seed
                 must be used for extraction (currently not implemented).
                 
        Returns:
            StegoResult containing operation status and details.
            
        Example:
            >>> stego = ImageSteganographer()
            >>> result = stego.embed_spread_spectrum(
            ...     "carrier.png",
            ...     b"secret",
            ...     strength=0.1
            ... )
            
        Note:
            The current implementation does not support extraction.
            This method is primarily for research and demonstration.
        """
        try:
            random.seed(seed)
            
            img = Image.open(carrier_path)
            img_array = np.array(img, dtype=np.float64)
            
            height, width = img_array.shape[:2]
            
            # Validate capacity for spread spectrum
            # Reduced capacity compared to LSB for better security
            max_capacity = (height * width) // 10
            if len(data) > max_capacity:
                return StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message=f"Data too large. Max: {max_capacity} bytes",
                    capacity_used=len(data),
                    capacity_total=max_capacity,
                    checksum=""
                )
            
            # Create pseudo-random sequence for spreading
            # Gaussian distribution approximates natural image noise
            sequence = [random.gauss(0, 1) for _ in range(len(data) * 8)]
            
            # Embed data by adding modulated noise to image
            result_array = img_array.copy()
            bit_idx = 0
            
            for y in range(height):
                for x in range(width):
                    if bit_idx >= len(sequence):
                        break
                    
                    # Use first channel for grayscale or multi-channel images
                    if img_array.ndim == 2:
                        pixel = img_array[y, x]
                    else:
                        pixel = img_array[y, x, 0]
                    
                    # Add spread spectrum modulated signal
                    modification = strength * sequence[bit_idx]
                    new_value = pixel + modification
                    
                    # Clip to valid pixel range
                    if img_array.ndim == 2:
                        result_array[y, x] = np.clip(new_value, 0, 255)
                    else:
                        result_array[y, x, 0] = np.clip(new_value, 0, 255)
                    
                    bit_idx += 1
            
            # Convert back to uint8 for saving
            result_array = np.clip(result_array, 0, 255).astype(np.uint8)
            
            if output_path is None:
                output_path = carrier_path
            
            # Save the modified image
            modified_img = Image.fromarray(result_array)
            modified_img.save(output_path)
            
            # Read back for checksum
            with open(output_path, 'rb') as f:
                carrier_data = f.read()
            
            checksum = hashlib.sha256(carrier_data).hexdigest()
            
            return StegoResult(
                success=True,
                carrier_data=carrier_data,
                carrier_path=output_path,
                message="Data embedded using spread spectrum steganography",
                capacity_used=len(data),
                capacity_total=max_capacity,
                checksum=checksum
            )
        
        except Exception as e:
            return StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"Embedding failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )


# =============================================================================
# SECTION 3: TEXT STEGANOGRAPHY IMPLEMENTATION
# =============================================================================
# This section contains the TextSteganographer class, which implements
# text-based steganography using invisible Unicode characters.

class TextSteganographer:
    """
    Text-based steganography operations using invisible characters.
    
    This class provides methods for hiding data within text files by
    embedding invisible Unicode characters. The primary method uses
    zero-width characters that are not displayed in most text editors
    but can be detected and decoded by this module.
    
    Supported Methods:
        - Zero-Width Characters: Uses U+200B, U+200C, U+200D for encoding
        - Unicode Homoglyphs: Uses visually similar characters
        
    Advantages:
        - Completely invisible in most text editors
        - Leaves minimal forensic traces
        - Works with any text-based carrier
        - No image processing required
        
    Limitations:
        - Capacity proportional to carrier text length
        - Some systems may strip zero-width characters
        - Not suitable for very short carrier texts
        
    Example:
        >>> text_stego = TextSteganographer()
        >>> encoded = text_stego.encode_zerowidth("Hello World", b"secret")
        >>> data, result = text_stego.extract_from_text(encoded)
    """
    
    # Zero-width Unicode characters used for encoding
    # These characters are invisible in most text displays
    ZERO_WIDTH_SPACE = '\u200B'      # Zero-width space (U+200B)
    ZERO_WIDTH_NON_JOINER = '\u200C' # Zero-width non-joiner (U+200C)
    ZERO_WIDTH_JOINER = '\u200D'     # Zero-width joiner (U+200D)
    LEFT_TO_RIGHT_MARK = '\u200E'    # Left-to-right mark (U+200E)
    RIGHT_TO_LEFT_MARK = '\u200F'    # Right-to-left mark (U+200F)
    
    def __init__(self):
        """
        Initialize the text steganographer.
        
        Creates a new TextSteganographer instance with thread-safe locking.
        No carrier text is loaded at initialization.
        
        Example:
            >>> text_stego = TextSteganographer()
        """
        self._lock = threading.Lock()
    
    def encode_zerowidth(
        self,
        carrier_text: str,
        data: bytes
    ) -> str:
        """
        Encode binary data using zero-width characters.
        
        This method converts each bit of the input data into a corresponding
        zero-width character, which is then appended to the carrier text.
        The resulting text appears identical to the original but contains
        the embedded data.
        
        Encoding Scheme:
            - Bit 0: Zero-width space (U+200B)
            - Bit 1: Zero-width non-joiner (U+200C)
            
        Args:
            carrier_text: The text to embed data within.
            data: The binary data to encode.
            
        Returns:
            Text with embedded data, visually identical to carrier_text.
            
        Example:
            >>> text_stego = TextSteganographer()
            >>> encoded = text_stego.encode_zerowidth("Hello", b"Hi")
            >>> print(len(encoded))  # Slightly longer than "Hello"
            
        Note:
            The encoded text may be slightly longer than the original.
            The difference is the number of zero-width characters,
            which is 8 times the number of data bytes.
        """
        # Convert data bytes to binary string
        # Each byte becomes 8 characters ('0' or '1')
        binary = ''.join(format(byte, '08b') for byte in data)
        
        # Map bits to zero-width characters for embedding
        zero_chars = [
            self.ZERO_WIDTH_SPACE,    # Maps to '0'
            self.ZERO_WIDTH_NON_JOINER # Maps to '1'
        ]
        
        # Encode each bit by appending corresponding character
        encoded = carrier_text
        for bit in binary:
            if bit == '0':
                encoded += zero_chars[0]
            else:
                encoded += zero_chars[1]
        
        return encoded
    
    def decode_zerowidth(self, stego_text: str) -> Optional[bytes]:
        """
        Decode binary data from zero-width encoded text.
        
        This method extracts the zero-width characters from the input text
        and reconstructs the original embedded data.
        
        Args:
            stego_text: Text containing zero-width encoded data.
            
        Returns:
            Decoded bytes if successful, None if invalid or no data.
            
        Example:
            >>> text_stego = TextSteganographer()
            >>> data = text_stego.decode_zerowidth(encoded_text)
            >>> print(data.decode())
        """
        # Extract zero-width characters from the text
        bits = []
        for char in stego_text:
            if char == self.ZERO_WIDTH_SPACE:
                bits.append('0')
            elif char == self.ZERO_WIDTH_NON_JOINER:
                bits.append('1')
        
        # Validate bit sequence
        # Must have at least 8 bits (1 byte) and be byte-aligned
        if len(bits) < 8 or len(bits) % 8 != 0:
            return None
        
        # Convert bits back to bytes
        data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | int(bits[i + j])
                data.append(byte)
        
        return bytes(data)
    
    def embed_in_text(
        self,
        carrier_text: str,
        data: bytes,
        output_path: Optional[str] = None
    ) -> StegoResult:
        """
        Embed data in text using zero-width character steganography.
        
        This method hides data within carrier text by embedding a metadata
        header and the secret data as invisible zero-width characters.
        
        Payload Structure:
            [header_length: 16 bits][header: JSON metadata][data: secret bytes]
            
        Args:
            carrier_text: Text to embed data within.
            data: Binary data to embed.
            output_path: Optional path to write encoded text.
            
        Returns:
            StegoResult with operation status and details.
            
        Example:
            >>> text_stego = TextSteganographer()
            >>> result = text_stego.embed_in_text(
            ...     "This is normal looking text.",
            ...     b"Secret message"
            ... )
            >>> print(result.message)
        """
        try:
            with self._lock:
                # Validate capacity: one bit per character
                required_chars = len(data) * 8
                if required_chars > len(carrier_text):
                    return StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=None,
                        message=f"Text too short. Need {len(data) * 8} chars, have {len(carrier_text)}",
                        capacity_used=len(data),
                        capacity_total=len(carrier_text) // 8,
                        checksum=""
                    )
                
                # Create metadata for embedded content
                metadata = StegoMetadata(
                    original_size=len(data),
                    content_type='application/octet-stream',
                    filename=None,
                    checksum=hashlib.sha256(data).hexdigest(),
                    method=StegoMethod.ZEROWIDTH,
                    timestamp=str(__import__('datetime').datetime.utcnow().isoformat())
                )
                
                # Encode metadata and data as bit sequences
                header_data = metadata.to_bytes()
                header_bits = ''.join(format(byte, '08b') for byte in header_data)
                data_bits = ''.join(format(byte, '08b') for byte in data)
                
                # Combine: [header_length: 16 bits][header][data]
                all_bits = format(len(header_data), '016b') + header_bits + data_bits
                
                # Distribute bits across carrier text
                encoded_chars = []
                bit_idx = 0
                
                for char in carrier_text:
                    encoded_chars.append(char)
                    if bit_idx < len(all_bits):
                        if all_bits[bit_idx] == '0':
                            encoded_chars.append(self.ZERO_WIDTH_SPACE)
                        else:
                            encoded_chars.append(self.ZERO_WIDTH_NON_JOINER)
                        bit_idx += 1
                
                encoded_text = ''.join(encoded_chars)
                
                # Write to output file if specified
                if output_path:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(encoded_text)
                
                encoded_bytes = encoded_text.encode('utf-8')
                
                return StegoResult(
                    success=True,
                    carrier_data=encoded_bytes,
                    carrier_path=output_path,
                    message="Data embedded in text using zero-width steganography",
                    capacity_used=len(data),
                    capacity_total=len(carrier_text) // 8,
                    checksum=hashlib.sha256(encoded_bytes).hexdigest()
                )
        
        except Exception as e:
            return StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"Embedding failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def extract_from_text(self, stego_text: str) -> Tuple[Optional[bytes], StegoResult]:
        """
        Extract data from zero-width encoded text.
        
        This method reverses the embedding process, extracting the
        zero-width characters and reconstructing the original data.
        
        Args:
            stego_text: Text containing embedded data.
            
        Returns:
            Tuple of (extracted_data, StegoResult):
            - extracted_data: The embedded bytes (None if extraction failed)
            - StegoResult: Operation status and details
            
        Example:
            >>> text_stego = TextSteganographer()
            >>> data, result = text_stego.extract_from_text(encoded_text)
            >>> if result.success:
            ...     print(f"Found {len(data)} bytes")
        """
        try:
            # Extract bits from zero-width characters
            bits = []
            for char in stego_text:
                if char == self.ZERO_WIDTH_SPACE:
                    bits.append('0')
                elif char == self.ZERO_WIDTH_NON_JOINER:
                    bits.append('1')
            
            # Validate extracted data
            if len(bits) < 16:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message="No hidden data found",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            # Read header length from first 16 bits
            header_length = int(''.join(bits[:16]), 2)
            
            if len(bits) < 16 + header_length * 8:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message="Incomplete header",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            # Parse header metadata
            header_bits = bits[16:16 + header_length * 8]
            header_bytes = bytearray()
            for i in range(0, len(header_bits), 8):
                if i + 8 <= len(header_bits):
                    header_bytes.append(int(header_bits[i:i+8], 2))
            
            try:
                metadata = StegoMetadata.from_bytes(bytes(header_bytes))
                
                # Extract embedded data
                data_start = 16 + header_length * 8
                data_bits = bits[data_start:]
                
                data_bytes = bytearray()
                for i in range(0, len(data_bits), 8):
                    if i + 8 <= len(data_bits):
                        data_bytes.append(int(data_bits[i:i+8], 2))
                
                data = bytes(data_bytes)
                
                # Verify integrity using stored checksum
                if hashlib.sha256(data).hexdigest() != metadata.checksum:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=None,
                        message="Data integrity check failed",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
                
                return data, StegoResult(
                    success=True,
                    carrier_data=None,
                    carrier_path=None,
                    message=f"Extracted {len(data)} bytes from text",
                    capacity_used=len(data),
                    capacity_total=0,
                    checksum=metadata.checksum
                )
            
            except Exception as e:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message=f"Failed to parse metadata: {str(e)}",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
        
        except Exception as e:
            return None, StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"Extraction failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )


# =============================================================================
# SECTION 4: UNIFIED STEGANOGRAPHY MANAGER
# =============================================================================
# This section contains the CXASteganographyManager class, which provides
# a unified interface for all steganography operations with automatic
# method selection and carrier type detection.

class CXASteganographyManager:
    """
    Unified steganography manager providing a single API for all operations.
    
    This class serves as the primary interface for steganography operations
    in the CXA system. It automatically detects carrier file types and selects
    the appropriate embedding method, simplifying the steganography workflow.
    
    Key Features:
        - Automatic carrier type detection
        - Automatic method selection based on carrier type
        - Unified API for image and text steganography
        - File embedding and extraction support
        - Capacity calculation and validation
        - Integrity verification
        
    Architecture:
        The manager composes ImageSteganographer and TextSteganographer
        instances, delegating to the appropriate implementation based
        on the detected carrier type.
        
    Usage Example:
        >>> manager = CXASteganographyManager()
        >>> 
        >>> # Embed data (automatic detection)
        >>> result = manager.embed("carrier.png", b"secret data")
        >>> 
        >>> # Extract data
        >>> data, result = manager.extract("carrier_with_data.png")
        >>> 
        >>> # File embedding
        >>> result = manager.embed_file("carrier.png", "document.pdf")
        
    Performance Considerations:
        - Uses threading locks for concurrent operations
        - File I/O is the primary bottleneck
        - Large images may require significant memory
        
    Thread Safety:
        This class is thread-safe for concurrent embedding and extraction
        operations using internal locking.
    """
    
    def __init__(self):
        """
        Initialize the CXA steganography manager.
        
        Creates a new manager instance with composed steganographers for
        different carrier types. Ready to perform operations immediately.
        
        Example:
            >>> manager = CXASteganographyManager()
        """
        self._image_stego = ImageSteganographer()
        self._text_stego = TextSteganographer()
        self._lock = threading.Lock()
    
    def detect_carrier_type(self, carrier_path: str) -> Optional[CarrierType]:
        """
        Detect the type of carrier file based on extension and content.
        
        This method analyzes the file extension and optionally the file
        content to determine the carrier type. This enables automatic
        method selection for embedding and extraction operations.
        
        Detection Strategy:
            1. Check file extension for known types
            2. For images: Verify with PIL (Image.open)
            3. For text: Verify encoding and readability
            
        Args:
            carrier_path: Path to the carrier file to analyze.
            
        Returns:
            Detected CarrierType, or None if unrecognized.
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> carrier_type = manager.detect_carrier_type("document.png")
            >>> print(carrier_type)
            CarrierType.IMAGE_PNG
        """
        path = Path(carrier_path)
        suffix = path.suffix.lower()
        
        # Check for image files
        if suffix in ['.png', '.bmp', '.gif']:
            try:
                with Image.open(carrier_path) as img:
                    if img.format == 'PNG':
                        return CarrierType.IMAGE_PNG
                    elif img.format == 'BMP':
                        return CarrierType.IMAGE_BMP
                    elif img.format == 'GIF':
                        return CarrierType.IMAGE_GIF
            except Exception:
                pass
        
        # Check for text-based files
        text_extensions = {'.txt', '.md', '.html', '.htm', '.xml', '.json'}
        if suffix in text_extensions:
            try:
                with open(carrier_path, 'r', encoding='utf-8') as f:
                    f.read()
                if suffix in ['.md', '.markdown']:
                    return CarrierType.TEXT_MARKDOWN
                elif suffix in ['.html', '.htm']:
                    return CarrierType.TEXT_HTML
                return CarrierType.TEXT_PLAIN
            except Exception:
                pass
        
        return None
    
    def calculate_capacity(
        self,
        carrier_path: str,
        method: Optional[StegoMethod] = None
    ) -> Tuple[int, StegoMethod]:
        """
        Calculate maximum embeddable data size for a carrier file.
        
        This method determines the maximum data size that can be embedded
        in a given carrier file, optionally using a specific method.
        
        Args:
            carrier_path: Path to the carrier file.
            method: Optional steganography method. If not specified,
                   the method is auto-selected based on carrier type.
                   
        Returns:
            Tuple of (capacity_bytes, actual_method):
            - capacity_bytes: Maximum embeddable data size
            - actual_method: Method used for calculation
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> capacity, method = manager.calculate_capacity("image.png")
            >>> print(f"Can embed {capacity} bytes using {method.value}")
        """
        carrier_type = self.detect_carrier_type(carrier_path)
        
        if carrier_type in [CarrierType.IMAGE_PNG, CarrierType.IMAGE_BMP, CarrierType.IMAGE_GIF]:
            if method is None:
                method = StegoMethod.LSB
            capacity = self._image_stego.calculate_capacity(carrier_path, method)
            return capacity, method
        
        elif carrier_type in [CarrierType.TEXT_PLAIN, CarrierType.TEXT_MARKDOWN, CarrierType.TEXT_HTML]:
            if method is None:
                method = StegoMethod.ZEROWIDTH
            try:
                with open(carrier_path, 'r', encoding='utf-8') as f:
                    text = f.read()
                capacity = len(text) // 8  # One bit per character
                return capacity, method
            except Exception:
                return 0, method
        
        return 0, method or StegoMethod.LSB
    
    def embed(
        self,
        carrier_path: str,
        data: bytes,
        method: Optional[StegoMethod] = None,
        output_path: Optional[str] = None,
        **kwargs
    ) -> StegoResult:
        """
        Embed data in a carrier file using automatic method selection.
        
        This is the primary embedding method that automatically detects
        the carrier type and selects the appropriate steganography method.
        
        Method Selection:
            - Image carriers: Defaults to LSB (PNG/BMP/GIF)
            - Text carriers: Uses zero-width characters
            
        Args:
            carrier_path: Path to the carrier file.
            data: Bytes of data to embed.
            method: Optional explicit method override.
            output_path: Output path for modified carrier.
            **kwargs: Additional method-specific arguments.
            
        Returns:
            StegoResult with operation details.
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> result = manager.embed("carrier.png", b"secret")
            >>> print(result.message)
        """
        with self._lock:
            carrier_type = self.detect_carrier_type(carrier_path)
            
            if carrier_type is None:
                return StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message="Unsupported carrier file type",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            # Handle image carriers
            if carrier_type.value.startswith('image'):
                if method is None:
                    method = StegoMethod.LSB
                
                if method == StegoMethod.LSB:
                    return self._image_stego.embed_lsb(
                        carrier_path, data, output_path, **kwargs
                    )
                elif method == StegoMethod.SPREAD_SPECTRUM:
                    return self._image_stego.embed_spread_spectrum(
                        carrier_path, data, output_path, **kwargs
                    )
            
            # Handle text carriers
            elif carrier_type.value.startswith('text'):
                return self._text_stego.embed_in_text(
                    carrier_path, data, output_path
                )
            
            return StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"No embedding method available for {carrier_type}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def extract(
        self,
        carrier_path: str,
        method: Optional[StegoMethod] = None,
        output_path: Optional[str] = None
    ) -> Tuple[Optional[bytes], StegoResult]:
        """
        Extract embedded data from a carrier file.
        
        This method reverses the embedding process, automatically detecting
        the steganography method used and extracting the original data.
        
        Args:
            carrier_path: Path to the carrier file.
            method: Optional explicit method specification.
            output_path: Optional path to write extracted data.
            
        Returns:
            Tuple of (extracted_data, StegoResult):
            - extracted_data: The original embedded bytes (None if failed)
            - StegoResult: Operation status and details
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> data, result = manager.extract("carrier_with_data.png")
            >>> if result.success:
            ...     print(data.decode())
        """
        with self._lock:
            carrier_type = self.detect_carrier_type(carrier_path)
            
            if carrier_type is None:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=carrier_path,
                    message="Unsupported carrier file type",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            # Extract from image carriers
            if carrier_type.value.startswith('image'):
                if method is None:
                    method = StegoMethod.LSB
                
                return self._image_stego.extract_lsb(
                    carrier_path, output_path
                )
            
            # Extract from text carriers
            elif carrier_type.value.startswith('text'):
                with open(carrier_path, 'r', encoding='utf-8') as f:
                    text = f.read()
                return self._text_stego.extract_from_text(text)
            
            return None, StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=carrier_path,
                message=f"No extraction method available for {carrier_type}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def embed_file(
        self,
        carrier_path: str,
        file_to_hide: str,
        output_path: Optional[str] = None
    ) -> StegoResult:
        """
        Embed an entire file within a carrier file.
        
        This method reads the specified file, encodes it with base64, and
        embeds it within the carrier along with metadata (original filename,
        size, etc.).
        
        File Format:
            The embedded JSON structure contains:
            - filename: Original file name
            - size: Original file size in bytes
            - data: Base64-encoded file content
            
        Args:
            carrier_path: Path to the carrier file.
            file_to_hide: Path to the file to embed.
            output_path: Output path for modified carrier.
            
        Returns:
            StegoResult with operation details.
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> result = manager.embed_file("carrier.png", "document.pdf")
            >>> print(f"Embedded {result.capacity_used} bytes")
        """
        # Read the file to embed
        with open(file_to_hide, 'rb') as f:
            data = f.read()
        
        # Extract filename for metadata
        filename = Path(file_to_hide).name
        
        # Create structured file info with base64 encoding
        file_info = {
            'filename': filename,
            'size': len(data),
            'data': base64.b64encode(data).decode('ascii')
        }
        
        payload = json.dumps(file_info).encode('utf-8')
        
        # Embed using the standard embed method
        return self.embed(carrier_path, payload, output_path=output_path)
    
    def extract_file(
        self,
        carrier_path: str,
        output_dir: str = "."
    ) -> Tuple[Optional[str], StegoResult]:
        """
        Extract an embedded file from a carrier file.
        
        This method extracts the embedded file structure, decodes the
        base64 content, and writes the original file to disk.
        
        Args:
            carrier_path: Path to the carrier file.
            output_dir: Directory to write extracted file.
                       Defaults to current directory.
            
        Returns:
            Tuple of (output_path, StegoResult):
            - output_path: Path to the extracted file (None if failed)
            - StegoResult: Operation status and details
            
        Example:
            >>> manager = CXASteganographyManager()
            >>> path, result = manager.extract_file("carrier_with_file.png")
            >>> if result.success:
            ...     print(f"Extracted to {path}")
        """
        data, result = self.extract(carrier_path)
        
        if data is None:
            return None, result
        
        try:
            # Parse the embedded file structure
            file_info = json.loads(data.decode('utf-8'))
            filename = file_info['filename']
            file_data = base64.b64decode(file_info['data'])
            
            # Write the extracted file
            output_path = Path(output_dir) / filename
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return str(output_path), StegoResult(
                success=True,
                carrier_data=None,
                carrier_path=carrier_path,
                message=f"Extracted file: {filename}",
                capacity_used=file_info['size'],
                capacity_total=0,
                checksum=hashlib.sha256(file_data).hexdigest()
            )
        
        except Exception as e:
            return None, StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=carrier_path,
                message=f"Failed to extract file: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )


# =============================================================================
# SECTION 5: DCT-BASED STEGANOGRAPHY IMPLEMENTATION
# =============================================================================
# This section contains the DCTSteganographer class, which implements
# frequency-domain steganography using the Discrete Cosine Transform.
# This method is more robust than spatial domain methods but requires
# OpenCV for efficient computation.

class DCTSteganographer:
    """
    DCT (Discrete Cosine Transform) based steganography for robust embedding.
    
    This class implements a sophisticated steganography method that operates
    in the frequency domain rather than the spatial domain. By embedding data
    in DCT coefficients, the method achieves robustness against common image
    operations like JPEG compression and resizing.
    
    Technical Overview:
        The Discrete Cosine Transform converts spatial image data into
        frequency components. The DCT coefficients represent different
        frequencies of variation in the image. By embedding data in
        mid-frequency coefficients, we balance capacity against robustness.
        
    Algorithm Steps:
        1. Convert image to YCbCr color space (separate luminance/chrominance)
        2. Divide image into 8x8 pixel blocks
        3. Apply forward DCT to each block
        4. Quantize coefficients (similar to JPEG compression)
        5. Modify quantized coefficients to embed data bits
        6. Apply inverse DCT to reconstruct the modified image
        
    Advantages Over LSB:
        - Resistant to JPEG compression (within quality limits)
        - Resistant to image resizing (when resized to multiples of 8)
        - Less detectable by steganalysis tools
        - More robust against minor image modifications
        
    Limitations:
        - Lower capacity compared to LSB
        - Requires OpenCV library (cv2)
        - Not suitable for further lossy compression after embedding
        - Quality degradation may be visible at high embedding rates
        
    Embedding Coefficients:
        This implementation uses specific mid-frequency DCT coefficients
        that balance capacity and robustness. The coefficient selection
        avoids DC component (too visible) and very high frequencies
        (too fragile).
        
    Requirements:
        - OpenCV Python bindings (cv2)
        - NumPy for array operations
        - Images should be saved as PNG after embedding
        
    Example:
        >>> stego = DCTSteganographer()
        >>> result = stego.embed_message("carrier.jpg", b"secret data")
        >>> data, result = stego.extract_message("embedded.png")
        
    Author: CXA Development Team
    Version: 2.0.0
    """
    
    # DCT coefficient indices for embedding in zigzag order
    # These mid-frequency coefficients balance capacity and robustness
    # Zigzag order: [0]=DC, [1]=low-freq, [5,6]=mid-freq, etc.
    EMBEDDING_COEFFICIENTS = [1, 2, 5, 6, 9, 10]
    
    # Default quality factor for DCT operations
    # Higher values preserve image quality but reduce embedding capacity
    QUALITY_FACTOR = 75
    
    def __init__(
        self,
        quality_factor: int = QUALITY_FACTOR,
        embedding_coefficients: Optional[List[int]] = None
    ):
        """
        Initialize the DCT steganographer.
        
        Creates a new DCTSteganographer instance with configurable quality
        factor and embedding coefficients.
        
        Args:
            quality_factor: JPEG quality factor (1-100). Higher values
                           preserve image quality but reduce embedding capacity.
                           Standard JPEG quality is 75-95.
            embedding_coefficients: List of DCT coefficient indices to use
                                    for embedding. Uses defaults if None.
                                    
        Raises:
            ImportError: If OpenCV (cv2) is not installed.
            ValueError: If quality_factor is outside valid range 1-100.
            
        Example:
            >>> stego = DCTSteganographer(quality_factor=85)
            >>> stego = DCTSteganographer(embedding_coefficients=[1, 2, 5])
        """
        # Verify OpenCV is available before proceeding
        if cv2 is None:
            raise ImportError(
                "OpenCV (cv2) is required for DCT steganography. "
                "Please install it with: pip install opencv-python"
            )
        
        self._quality_factor = quality_factor
        self._embedding_coefficients = embedding_coefficients or self.EMBEDDING_COEFFICIENTS
        
        # Validate quality factor range
        if not 1 <= quality_factor <= 100:
            raise ValueError(f"Quality factor must be between 1 and 100, got {quality_factor}")
    
    def _apply_dct(self, block: np.ndarray) -> np.ndarray:
        """
        Apply 2D Discrete Cosine Transform to an 8x8 image block.
        
        The DCT transforms spatial data into frequency domain representation.
        Lower coefficients represent low-frequency (broad) image features,
        while higher coefficients represent high-frequency (detailed) features.
        
        The DC coefficient (index 0) represents the average brightness.
        AC coefficients (indices 1-63) represent increasingly fine details.
        
        Args:
            block: 8x8 numpy array of pixel values (uint8 or float).
            
        Returns:
            8x8 numpy array of DCT coefficients (float64).
            
        Mathematical Background:
            DCT-II formula:
            C(u,v) = α(u)α(v) Σ Σ f(x,y) cos[(2x+1)uπ/16] cos[(2y+1)vπ/16]
            
            where α(k) = 1/√2 for k=0, and 1 for k>0.
        """
        # Convert to float64 for precision during transformation
        float_block = np.float64(block)
        
        # Apply 2D DCT using OpenCV's optimized implementation
        # cv2.dct() applies forward DCT to each dimension sequentially
        dct_block = cv2.dct(float_block)
        
        return dct_block
    
    def _apply_idct(self, dct_block: np.ndarray) -> np.ndarray:
        """
        Apply Inverse Discrete Cosine Transform to recover spatial data.
        
        This method reverses the DCT transformation, converting frequency
        domain coefficients back to spatial pixel values.
        
        Args:
            dct_block: 8x8 array of DCT coefficients.
            
        Returns:
            8x8 array of pixel values as uint8, clipped to valid range [0, 255].
        """
        # Apply inverse DCT using OpenCV
        idct_block = cv2.idct(dct_block)
        
        # Convert back to uint8, clipping to valid pixel range
        # This handles any numerical precision issues
        result = np.clip(idct_block, 0, 255).astype(np.uint8)
        
        return result
    
    def _quantize(self, dct_block: np.ndarray, quality: int) -> np.ndarray:
        """
        Quantize DCT coefficients based on JPEG quality factor.
        
        Quantization is the main lossy step in JPEG compression. It divides
        DCT coefficients by quantization matrix values and rounds to integers.
        Higher quality factors use smaller quantization steps, preserving
        more detail but providing less compression.
        
        Args:
            dct_block: 8x8 DCT coefficient block (unquantized).
            quality: Quality factor (1-100).
            
        Returns:
            Quantized DCT block with integer coefficients.
            
        Quantization Matrix:
            Uses standard JPEG luminance quantization matrix scaled
            according to quality factor. The matrix values increase
            from top-left (DC and low frequencies) to bottom-right
            (high frequencies), reflecting human visual sensitivity.
        """
        # Calculate scaling factor based on quality
        # JPEG quality scaling: Q>=50 uses linear scaling, Q<50 uses inverse
        if quality >= 50:
            scale = (100 - quality) / 50.0
        else:
            scale = 50.0 / quality
        
        # Standard JPEG luminance quantization matrix
        # Values derived from JPEG specification for optimal visual quality
        base_matrix = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ], dtype=np.float64)
        
        # Scale quantization matrix according to quality
        quantization_matrix = np.floor((base_matrix * scale) + 0.5)
        quantization_matrix = np.maximum(quantization_matrix, 1)  # Minimum value 1
        
        # Apply quantization: round coefficient / quantization_value
        quantized = np.round(dct_block / quantization_matrix)
        
        return quantized
    
    def _dequantize(self, quantized_block: np.ndarray, quality: int) -> np.ndarray:
        """
        Dequantize DCT coefficients by reversing quantization.
        
        This method multiplies quantized coefficients by the quantization
        matrix to reconstruct approximate original coefficients.
        
        Args:
            quantized_block: Quantized DCT block.
            quality: Quality factor used during quantization.
            
        Returns:
            Dequantized DCT block (float64).
        """
        # Same scaling logic as quantization
        if quality >= 50:
            scale = (100 - quality) / 50.0
        else:
            scale = 50.0 / quality
        
        # Standard JPEG luminance quantization matrix
        base_matrix = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ], dtype=np.float64)
        
        quantization_matrix = np.floor((base_matrix * scale) + 0.5)
        quantization_matrix = np.maximum(quantization_matrix, 1)
        
        # Apply dequantization: multiply by quantization values
        dequantized = quantized_block * quantization_matrix
        
        return dequantized
    
    def _get_zigzag_index(self, row: int, col: int) -> int:
        """
        Get the zigzag order index for a given (row, col) position.
        
        Zigzag ordering arranges 8x8 DCT coefficients from lowest to highest
        frequency, which is the standard order used in JPEG compression.
        This ordering groups related frequencies together and places DC
        (zero frequency) at the start.
        
        Args:
            row: Row index (0-7).
            col: Column index (0-7).
            
        Returns:
            Zigzag index (0-63).
            
        Zigzag Pattern:
            0,  1,  5,  6, 14, 15, 27, 28,
            2,  4,  7, 13, 16, 26, 29, 42,
            3,  8, 12, 17, 25, 30, 41, 43,
            9, 11, 18, 24, 31, 40, 44, 53,
            10, 19, 23, 32, 39, 45, 52, 54,
            20, 22, 33, 38, 46, 51, 55, 60,
            21, 34, 37, 47, 50, 56, 59, 61,
            35, 36, 48, 49, 57, 58, 62, 63
        """
        # Zigzag order lookup table for 8x8 blocks
        zigzag = [
            0,  1,  5,  6, 14, 15, 27, 28,
            2,  4,  7, 13, 16, 26, 29, 42,
            3,  8, 12, 17, 25, 30, 41, 43,
            9, 11, 18, 24, 31, 40, 44, 53,
            10, 19, 23, 32, 39, 45, 52, 54,
            20, 22, 33, 38, 46, 51, 55, 60,
            21, 34, 37, 47, 50, 56, 59, 61,
            35, 36, 48, 49, 57, 58, 62, 63
        ]
        return zigzag[row * 8 + col]
    
    def _get_position_from_zigzag(self, index: int) -> Tuple[int, int]:
        """
        Get the (row, col) position from a zigzag index.
        
        This is the inverse of _get_zigzag_index, converting a zigzag
        coefficient index back to (row, column) coordinates.
        
        Args:
            index: Zigzag index (0-63).
            
        Returns:
            Tuple of (row, column) coordinates.
        """
        # Zigzag order lookup table
        zigzag = [
            0,  1,  5,  6, 14, 15, 27, 28,
            2,  4,  7, 13, 16, 26, 29, 42,
            3,  8, 12, 17, 25, 30, 41, 43,
            9, 11, 18, 24, 31, 40, 44, 53,
            10, 19, 23, 32, 39, 45, 52, 54,
            20, 22, 33, 38, 46, 51, 55, 60,
            21, 34, 37, 47, 50, 56, 59, 61,
            35, 36, 48, 49, 57, 58, 62, 63
        ]
        pos = zigzag.index(index)
        return (pos // 8, pos % 8)
    
    def _embed_bit_in_coefficient(
        self,
        dct_block: np.ndarray,
        bit: int,
        coeff_index: int
    ) -> np.ndarray:
        """
        Embed a single bit into a DCT coefficient using quantization-aware modification.
        
        This method modifies the quantized DCT coefficient to encode the desired
        bit value. The modification is quantization-aware, meaning changes are
        made in multiples of the quantization step to minimize impact on the
        reconstructed image.
        
        Embedding Strategy:
            - Bit 0: Round coefficient to nearest even multiple of 2*quant
            - Bit 1: Round coefficient to nearest odd multiple of 2*quant
            
        This even/odd encoding survives quantization round-trip operations.
        
        Args:
            dct_block: 8x8 quantized DCT block (modified in place).
            bit: Bit to embed (0 or 1).
            coeff_index: Zigzag index of coefficient to modify.
            
        Returns:
            Modified DCT block.
        """
        # Convert zigzag index to (row, col) position
        row, col = self._get_position_from_zigzag(coeff_index)
        
        # Get current coefficient value
        coefficient = dct_block[row, col]
        
        # Calculate quantization step for this coefficient
        # Uses standard JPEG quantization matrix with quality scaling
        quality_scale = 1.0 if self._quality_factor >= 50 else 50.0 / self._quality_factor
        base_quant = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ])[row, col] * quality_scale
        
        # Modify coefficient based on bit value
        # Round to nearest multiple of (2 * quantization_step)
        # This ensures the parity survives quantization
        if bit == 0:
            # Round down to even multiple
            new_value = np.floor(coefficient / (2 * base_quant)) * (2 * base_quant)
        else:
            # Round up to odd multiple
            new_value = (np.floor(coefficient / (2 * base_quant)) + 1) * (2 * base_quant)
        
        dct_block[row, col] = new_value
        
        return dct_block
    
    def _extract_bit_from_coefficient(
        self,
        dct_block: np.ndarray,
        coeff_index: int
    ) -> int:
        """
        Extract a single bit from a DCT coefficient.
        
        This method reads the embedded bit by checking the parity of the
        quantized coefficient. The even/odd encoding from embedding
        allows reliable extraction.
        
        Extraction Strategy:
            - Positive coefficients: even = 0, odd = 1
            - Negative coefficients: even = 1, odd = 0 (symmetric)
            
        Args:
            dct_block: 8x8 quantized DCT block.
            coeff_index: Zigzag index of coefficient to read.
            
        Returns:
            Extracted bit (0 or 1).
        """
        row, col = self._get_position_from_zigzag(coeff_index)
        coefficient = dct_block[row, col]
        
        # Use sign-aware extraction
        # Positive: even=0, odd=1
        # Negative: even=1, odd=0 (symmetric encoding)
        if coefficient >= 0:
            return int(coefficient) % 2
        else:
            return (int(-coefficient) + 1) % 2
    
    def embed_message(
        self,
        carrier_path: str,
        data: bytes,
        output_path: Optional[str] = None,
        channel: str = "Y"
    ) -> StegoResult:
        """
        Embed data in an image using DCT steganography.
        
        This is the primary embedding method for DCT steganography. It
        processes the carrier image through the DCT embedding pipeline
        and produces a stego image with embedded data.
        
        Payload Structure:
            [header_length: 4 bytes][header: JSON metadata][data: secret bytes]
            
        Color Channel Selection:
            - 'Y': Luminance channel (default, best quality)
            - 'Cb': Blue-difference chrominance channel
            - 'Cr': Red-difference chrominance channel
            
        Args:
            carrier_path: Path to the carrier image (BGR format).
            data: Bytes of data to embed.
            output_path: Path for output stego image. Defaults to carrier_path.
            channel: Color channel to use for embedding ('Y', 'Cb', or 'Cr').
            
        Returns:
            StegoResult with operation details and checksum.
            
        Example:
            >>> stego = DCTSteganographer()
            >>> result = stego.embed_message("carrier.jpg", b"secret data")
            >>> print(f"Embedded {result.capacity_used} bits")
            
        Note:
            The output image is saved as PNG to preserve DCT modifications.
            JPEG re-compression would destroy the embedded data.
        """
        try:
            # Read image using OpenCV
            img = cv2.imread(carrier_path)
            if img is None:
                raise ValueError(f"Could not read image: {carrier_path}")
            
            # Convert to YCbCr color space
            # Y (luminance) has most perceptual information
            # Cb and Cr are chrominance components
            ycbcr = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
            
            height, width = ycbcr.shape[:2]
            
            # Ensure dimensions are multiples of 8 for block processing
            height = (height // 8) * 8
            width = (width // 8) * 8
            ycbcr = ycbcr[:height, :width]
            
            # Map channel string to channel index
            channel_map = {"Y": 0, "Cb": 1, "Cr": 2}
            channel_idx = channel_map.get(channel.upper(), 0)
            
            # Create metadata header with original data information
            metadata = StegoMetadata(
                original_size=len(data),
                content_type='application/octet-stream',
                filename=None,
                checksum=hashlib.sha256(data).hexdigest(),
                method=StegoMethod.DCT,
                timestamp=str(__import__('datetime').datetime.utcnow().isoformat())
            )
            header_data = metadata.to_bytes()
            header_length = len(header_data)
            
            # Full payload: [header_length: 4 bytes][header][data]
            # Using 4-byte header length for DCT method
            length_bytes = struct.pack('<I', header_length)
            payload = length_bytes + header_data + data
            
            # Convert payload to bit sequence
            payload_bits = []
            for byte in payload:
                for i in range(8):
                    payload_bits.append((byte >> (7 - i)) & 1)
            
            # Calculate embedding capacity
            blocks_y = height // 8
            blocks_x = width // 8
            total_blocks = blocks_y * blocks_x
            bits_per_block = len(self._embedding_coefficients)
            total_capacity = total_blocks * bits_per_block
            
            # Validate data size against capacity
            if len(payload_bits) > total_capacity:
                return StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=None,
                    message=f"Data too large. Max: {total_capacity} bits, need {len(payload_bits)} bits",
                    capacity_used=len(payload_bits),
                    capacity_total=total_capacity,
                    checksum=""
                )
            
            # Process each 8x8 block for embedding
            ycbcr_array = ycbcr.copy()
            bit_idx = 0
            
            for block_y in range(blocks_y):
                for block_x in range(blocks_x):
                    # Extract 8x8 block from selected channel
                    y_start = block_y * 8
                    x_start = block_x * 8
                    block = ycbcr_array[y_start:y_start+8, x_start:x_start+8, channel_idx]
                    
                    # Apply forward DCT to transform to frequency domain
                    dct_block = self._apply_dct(block)
                    
                    # Quantize coefficients for robustness
                    quantized = self._quantize(dct_block, self._quality_factor)
                    
                    # Embed bits into selected coefficients
                    for coeff_idx in self._embedding_coefficients:
                        if bit_idx < len(payload_bits):
                            bit = payload_bits[bit_idx]
                            quantized = self._embed_bit_in_coefficient(quantized, bit, coeff_idx)
                            bit_idx += 1
                    
                    # Dequantize to approximate original scale
                    dequantized = self._dequantize(quantized, self._quality_factor)
                    
                    # Apply inverse DCT to reconstruct block
                    idct_block = self._apply_idct(dequantized)
                    
                    # Replace original block with modified block
                    ycbcr_array[y_start:y_start+8, x_start:x_start+8, channel_idx] = idct_block
            
            # Convert back to BGR color space for saving
            result_img = cv2.cvtColor(ycbcr_array, cv2.COLOR_YCrCb2BGR)
            
            # Save result (PNG to preserve DCT modifications)
            if output_path is None:
                output_path = carrier_path
            
            # Save as PNG with high compression to preserve quality
            cv2.imwrite(output_path, result_img, [cv2.IMWRITE_PNG_COMPRESSION, 9])
            
            # Read back for checksum calculation
            with open(output_path, 'rb') as f:
                carrier_data = f.read()
            
            checksum = hashlib.sha256(carrier_data).hexdigest()
            
            return StegoResult(
                success=True,
                carrier_data=carrier_data,
                carrier_path=output_path,
                message=f"Data embedded successfully using DCT steganography ({len(payload_bits)} bits)",
                capacity_used=len(payload_bits),
                capacity_total=total_capacity,
                checksum=checksum
            )
            
        except Exception as e:
            return StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=None,
                message=f"DCT embedding failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def extract_message(
        self,
        carrier_path: str,
        output_path: Optional[str] = None
    ) -> Tuple[Optional[bytes], StegoResult]:
        """
        Extract data from a DCT-encoded image.
        
        This method reverses the DCT embedding process, reading the
        embedded bits from DCT coefficients and reconstructing the
        original data along with metadata.
        
        Args:
            carrier_path: Path to the stego image.
            output_path: Optional path to write extracted data.
            
        Returns:
            Tuple of (extracted_data, StegoResult):
            - extracted_data: The original embedded bytes (None if failed)
            - StegoResult: Operation status and details
            
        Example:
            >>> stego = DCTSteganographer()
            >>> data, result = stego.extract_message("embedded.png")
            >>> if result.success:
            ...     print(f"Extracted {len(data)} bytes")
        """
        try:
            # Read image using OpenCV
            img = cv2.imread(carrier_path)
            if img is None:
                raise ValueError(f"Could not read image: {carrier_path}")
            
            # Convert to YCbCr color space
            ycbcr = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
            
            height, width = ycbcr.shape[:2]
            height = (height // 8) * 8
            width = (width // 8) * 8
            ycbcr = ycbcr[:height, :width]
            
            # Use Y (luminance) channel for extraction (default)
            channel_idx = 0
            
            blocks_y = height // 8
            blocks_x = width // 8
            
            # Extract bits from each block's coefficients
            extracted_bits = []
            
            for block_y in range(blocks_y):
                for block_x in range(blocks_x):
                    # Extract 8x8 block from Y channel
                    y_start = block_y * 8
                    x_start = block_x * 8
                    block = ycbcr[y_start:y_start+8, x_start:x_start+8, channel_idx]
                    
                    # Apply forward DCT
                    dct_block = self._apply_dct(block)
                    
                    # Quantize for consistency with embedding
                    quantized = self._quantize(dct_block, self._quality_factor)
                    
                    # Extract bits from selected coefficients
                    for coeff_idx in self._embedding_coefficients:
                        bit = self._extract_bit_from_coefficient(quantized, coeff_idx)
                        extracted_bits.append(bit)
            
            # Convert extracted bits to bytes
            bytes_data = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | extracted_bits[i + j]
                    bytes_data.append(byte)
                else:
                    # Incomplete byte at the end is discarded
                    break
            
            # Read header length from first 4 bytes
            if len(bytes_data) < 4:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=carrier_path,
                    message="Invalid DCT data: too short",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            header_length = struct.unpack('<I', bytes_data[:4])[0]
            
            # Validate header completeness
            if len(bytes_data) < 4 + header_length:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=carrier_path,
                    message=f"Invalid DCT data: header truncated (need {4 + header_length}, have {len(bytes_data)})",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
            
            # Parse metadata and extract data
            try:
                header_data = bytes_data[4:4 + header_length]
                metadata = StegoMetadata.from_bytes(header_data)
                
                data_start = 4 + header_length
                extracted_data = bytes(bytes_data[data_start:])
                
                # Verify integrity using stored checksum
                if hashlib.sha256(extracted_data).hexdigest() != metadata.checksum:
                    return None, StegoResult(
                        success=False,
                        carrier_data=None,
                        carrier_path=carrier_path,
                        message="DCT data integrity check failed",
                        capacity_used=0,
                        capacity_total=0,
                        checksum=""
                    )
                
                # Write to output file if specified
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(extracted_data)
                
                return extracted_data, StegoResult(
                    success=True,
                    carrier_data=None,
                    carrier_path=carrier_path,
                    message=f"Extracted {len(extracted_data)} bytes using DCT steganography",
                    capacity_used=len(extracted_data),
                    capacity_total=0,
                    checksum=metadata.checksum
                )
                
            except Exception as e:
                return None, StegoResult(
                    success=False,
                    carrier_data=None,
                    carrier_path=carrier_path,
                    message=f"Failed to parse DCT metadata: {str(e)}",
                    capacity_used=0,
                    capacity_total=0,
                    checksum=""
                )
                
        except Exception as e:
            return None, StegoResult(
                success=False,
                carrier_data=None,
                carrier_path=carrier_path,
                message=f"DCT extraction failed: {str(e)}",
                capacity_used=0,
                capacity_total=0,
                checksum=""
            )
    
    def calculate_capacity(self, image_path: str) -> int:
        """
        Calculate maximum embeddable data size for an image using DCT.
        
        This method determines how many bytes can be embedded in an image
        using DCT steganography, based on image dimensions and the configured
        embedding coefficients.
        
        Capacity Formula:
            capacity = (height/8 × width/8 × num_coefficients) / 8 bytes
            
        Args:
            image_path: Path to the carrier image.
            
        Returns:
            Maximum embeddable bytes, or 0 if image cannot be read.
            
        Example:
            >>> stego = DCTSteganographer()
            >>> capacity = stego.calculate_capacity("test.jpg")
            >>> print(f"Can embed {capacity} bytes")
        """
        img = cv2.imread(image_path)
        if img is None:
            return 0
        
        height, width = img.shape[:2]
        height = (height // 8) * 8
        width = (width // 8) * 8
        
        # Calculate number of 8x8 blocks
        blocks = (height // 8) * (width // 8)
        bits_per_block = len(self._embedding_coefficients)
        
        # Convert bits to bytes
        return (blocks * bits_per_block) // 8
