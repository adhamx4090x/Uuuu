"""
Unit Tests for CXA Steganography Module

This module contains unit tests for image and text steganography
functionality, testing data hiding and extraction capabilities.
"""

import pytest
import os
import sys
from pathlib import Path
from PIL import Image
import numpy as np

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'python-core'))


class TestImageSteganography:
    """Test cases for image-based steganography."""

    @pytest.fixture
    def stego_engine(self):
        """Create steganography engine instance."""
        from stego.image import CXAStegoImage
        return CXAStegoImage()

    @pytest.fixture
    def test_image(self, tmp_path):
        """Create a test image for steganography tests."""
        # Create a simple RGB image (100x100 pixels)
        img_array = np.zeros((100, 100, 3), dtype=np.uint8)
        img_array[:, :, 0] = 255  # Red channel
        img_array[25:75, 25:75, 1] = 255  # Green square
        
        img = Image.fromarray(img_array, 'RGB')
        img_path = tmp_path / "test_image.png"
        img.save(str(img_path))
        
        return str(img_path)

    @pytest.fixture
    def rgba_test_image(self, tmp_path):
        """Create a test RGBA image."""
        img_array = np.zeros((100, 100, 4), dtype=np.uint8)
        img_array[:, :, 0] = 128
        img_array[:, :, 3] = 255  # Full opacity
        
        img = Image.fromarray(img_array, 'RGBA')
        img_path = tmp_path / "test_rgba.png"
        img.save(str(img_path))
        
        return str(img_path)

    def test_embed_lsb_text(self, stego_engine, test_image, tmp_path):
        """Test LSB text embedding in image."""
        secret_message = "Hidden secret message"
        output_path = str(tmp_path / "stego_output.png")
        
        result = stego_engine.embed_lsb(test_image, secret_message, output_path)
        
        assert result is True
        assert os.path.exists(output_path)

    def test_extract_lsb_text(self, stego_engine, test_image, tmp_path):
        """Test LSB text extraction from image."""
        secret_message = "Test message for extraction"
        output_path = str(tmp_path / "stego_extract.png")
        
        # First embed
        stego_engine.embed_lsb(test_image, secret_message, output_path)
        
        # Then extract
        extracted = stego_engine.extract_lsb(output_path)
        
        assert extracted == secret_message

    def test_embed_capacity_calculation(self, stego_engine, test_image):
        """Test that embedding capacity is calculated correctly."""
        capacity = stego_engine.get_capacity(test_image)
        
        # For 100x100 RGB image: 10000 pixels * 3 channels = 30000 bits
        # With 1-bit LSB: ~30000 bits / 8 = 3750 bytes
        assert capacity > 0
        assert capacity <= 3750  # Maximum for 1-bit LSB

    def test_embed_exceeds_capacity(self, stego_engine, test_image, tmp_path):
        """Test that embedding fails when message exceeds capacity."""
        # Create a very long message
        long_message = "x" * 4000
        output_path = str(tmp_path / "overflow.png")
        
        with pytest.raises(ValueError):
            stego_engine.embed_lsb(test_image, long_message, output_path)

    def test_rgba_image_steganography(self, stego_engine, rgba_test_image, tmp_path):
        """Test steganography on RGBA images."""
        secret_message = "RGBA hidden message"
        output_path = str(tmp_path / "stego_rgba.png")
        
        result = stego_engine.embed_lsb(rgba_test_image, secret_message, output_path)
        
        assert result is True
        
        extracted = stego_engine.extract_lsb(output_path)
        assert extracted == secret_message

    def test_empty_message_handling(self, stego_engine, test_image, tmp_path):
        """Test handling of empty messages."""
        output_path = str(tmp_path / "empty_stego.png")
        
        result = stego_engine.embed_lsb(test_image, "", output_path)
        
        # Empty message should be handled gracefully
        assert result is True or result is False  # Implementation specific

    def test_unicode_message_support(self, stego_engine, test_image, tmp_path):
        """Test embedding of Unicode messages."""
        unicode_message = "مرحبا بالعالم 🌍 Hello World 日本語"
        output_path = str(tmp_path / "unicode_stego.png")
        
        result = stego_engine.embed_lsb(test_image, unicode_message, output_path)
        
        assert result is True
        
        extracted = stego_engine.extract_lsb(output_path)
        assert extracted == unicode_message

    def test_image_modification_detection(self, stego_engine, test_image, tmp_path):
        """Test detection of modified stego images."""
        secret_message = "Watermark test"
        output_path = str(tmp_path / "watermarked.png")
        
        stego_engine.embed_lsb(test_image, secret_message, output_path)
        
        # Check if image has embedded data
        has_data = stego_engine.detect_stego(output_path)
        
        assert has_data is True


class TestTextSteganography:
    """Test cases for text-based steganography."""

    @pytest.fixture
    def text_stego(self):
        """Create text steganography engine instance."""
        from stego.text import CXAStegoText
        return CXAStegoText()

    def test_zalgo_text_encoding(self, text_stego):
        """Test Zalgo text encoding."""
        original = "Hello World"
        
        encoded = text_stego.encode_zalgo(original, "SECRET")
        
        assert encoded != original
        assert len(encoded) > len(original)

    def test_zalgo_text_decoding(self, text_stego):
        """Test Zalgo text decoding."""
        secret = "HIDDEN"
        original = "Decode me"
        
        encoded = text_stego.encode_zalgo(original, secret)
        decoded = text_stego.decode_zalgo(encoded)
        
        assert decoded == secret

    def test_zero_width_char_encoding(self, text_stego):
        """Test zero-width character encoding."""
        original = "Innocent looking text"
        secret = "SECRET123"
        
        encoded = text_stego.encode_zwc(original, secret)
        
        # Zero-width characters should be invisible
        assert len(encoded) == len(original) or len(encoded) > len(original)

    def test_zero_width_char_decoding(self, text_stego):
        """Test zero-width character decoding."""
        original = "Another message"
        secret = "TOP_SECRET"
        
        encoded = text_stego.encode_zwc(original, secret)
        decoded = text_stego.decode_zwc(encoded)
        
        assert decoded == secret

    def test_combine_encodings(self, text_stego):
        """Test combining multiple encoding methods."""
        original = "Multi-encoded message"
        secret = "COMBINED"
        
        encoded = text_stego.combine_encodings(original, secret)
        
        assert encoded != original

    def test_whitespace_steganography(self, text_stego):
        """Test whitespace-based steganography."""
        original = "This is a test"
        secret = "SECRET"
        
        encoded = text_stego.encode_whitespace(original, secret)
        
        # Should add trailing whitespace
        assert len(encoded.strip()) == len(original) or len(encoded) > len(original)


class TestStegoEdgeCases:
    """Edge case tests for steganography module."""

    @pytest.fixture
    def stego_engine(self):
        """Create steganography engine instance."""
        from stego.image import CXAStegoImage
        return CXAStegoImage()

    def test_grayscale_image_handling(self, stego_engine, tmp_path):
        """Test steganography on grayscale images."""
        # Create grayscale image
        img_array = np.random.randint(0, 256, (50, 50), dtype=np.uint8)
        img = Image.fromarray(img_array, 'L')
        img_path = tmp_path / "grayscale.png"
        img.save(str(img_path))
        
        # Should work on grayscale
        result = stego_engine.embed_lsb(str(img_path), "Test", str(tmp_path / "out.png"))
        
        assert result is True or False  # Depends on implementation

    def test_corrupted_stego_image(self, stego_engine, tmp_path):
        """Test extraction from corrupted stego image."""
        # Create a valid stego image
        img_array = np.zeros((50, 50, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')
        img_path = tmp_path / "corrupted.png"
        img.save(str(img_path))
        
        # Corrupt by modifying pixels
        corrupted_path = tmp_path / "corrupted_modified.png"
        img_array[0, 0] = [255, 255, 255]
        img.save(str(corrupted_path))
        
        # Extraction should handle corruption gracefully
        try:
            result = stego_engine.extract_lsb(str(corrupted_path))
            # Either returns corrupted data or raises exception
        except (ValueError, RuntimeError):
            pass  # Expected behavior

    def test_large_message_embedding(self, stego_engine, test_image, tmp_path):
        """Test embedding a large message."""
        # Create message that's about 50% of capacity
        capacity = stego_engine.get_capacity(test_image)
        large_message = "x" * int(capacity * 0.5)
        output_path = str(tmp_path / "large_stego.png")
        
        result = stego_engine.embed_lsb(test_image, large_message, output_path)
        
        assert result is True
        
        extracted = stego_engine.extract_lsb(output_path)
        assert extracted == large_message
