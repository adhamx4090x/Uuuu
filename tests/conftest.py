# CXA Test Configuration
# This file contains test settings and fixtures

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Test fixtures and configuration
pytest_plugins = ['pytest_asyncio']


@pytest.fixture(scope="session")
def project_root():
    """Return the project root directory."""
    return os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="session")
def python_core_path(project_root):
    """Return path to python-core directory."""
    return os.path.join(project_root, 'python-core')


@pytest.fixture(scope="session")
def python_gui_path(project_root):
    """Return path to python-gui directory."""
    return os.path.join(project_root, 'python-gui')


@pytest.fixture
def temp_directory(tmp_path):
    """Provide a temporary directory for test operations."""
    return tmp_path


@pytest.fixture
def sample_data(temp_directory):
    """Provide sample data for testing."""
    data_file = temp_directory / "sample.txt"
    data_file.write_text("Hello, World! This is test data for CXA encryption.")
    return data_file


@pytest.fixture
def sample_binary_data(temp_directory):
    """Provide sample binary data for testing."""
    binary_file = temp_directory / "sample.bin"
    binary_file.write_bytes(b'\x00\x01\x02\x03\x04\x05\xff\xfe\xfd')
    return binary_file
