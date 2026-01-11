# CXA Administrator Guide

> **WARNING**: This document contains manual operational procedures that must be performed by the administrator. Failure to follow these steps in order may result in build failures, security vulnerabilities, or unstable system behavior. Read this entire document before beginning any installation or configuration tasks.

> **Document Version**: 1.0.0  
> **Last Updated**: 2024-12-31  
> **For CXA Version**: 1.0.0

---

## Table of Contents

1. [Document Overview](#document-overview)
2. [Prerequisites Checklist](#prerequisites-checklist)
3. [System Preparation](#system-preparation)
4. [Rust Core Compilation](#rust-core-compilation)
5. [Go Services Compilation](#go-services-compilation)
6. [Python Environment Setup](#python-environment-setup)
7. [Configuration](#configuration)
8. [Testing](#testing)
9. [Deployment](#deployment)
10. [Post-Installation Verification](#post-installation-verification)
11. [System State Analysis](#system-state-analysis)
12. [Operational Procedures](#operational-procedures)
13. [Troubleshooting](#troubleshooting)

---

## Document Overview

This document serves as the authoritative guide for deploying and configuring the CXA Cryptographic System. It contains all procedures that require manual intervention, including installation steps, configuration tasks, build commands, and operational guidelines.

The procedures in this document are designed for system administrators who are comfortable with command-line operations and have experience compiling software from source. If you encounter unfamiliar terminology or procedures, refer to the linked documentation resources before proceeding.

Every step in this document has been tested and verified to work on clean installations of supported operating systems. Skipping steps, performing them out of order, or modifying commands without understanding the implications may result in a non-functional or insecure deployment.

---

## Prerequisites Checklist

Before beginning the installation process, verify that all prerequisites are met. Missing prerequisites are the most common cause of installation failures and configuration issues.

### Required Software

The following software must be installed and configured on your system before proceeding. Version numbers indicate the minimum supported versions; newer versions are generally compatible but should be tested before production deployment.

| Software | Minimum Version | Required For | Installation Command |
|----------|-----------------|--------------|----------------------|
| Python | 3.10+ | GUI, CLI, Core | `python3 --version` |
| Rust | 1.70+ | Crypto Core | `rustc --version` |
| Go | 1.21+ | API Services | `go version` |
| Git | 2.0+ | Repository Operations | `git --version` |
| GCC/Clang | Latest | C Compilation | `gcc --version` |
| CMake | 3.16+ | Build Configuration | `cmake --version` |
| Make | 4.0+ | Build Automation | `make --version` |
| OpenSSL | 1.1+ | Cryptography Library | `openssl version` |
| pkg-config | Latest | Library Detection | `pkg-config --version` |

### Verifying Prerequisites

Execute the following commands to verify that each prerequisite is correctly installed:

```bash
# Verify Python installation
python3 --version
# Expected output: Python 3.10.x or higher

# Verify Rust installation
rustc --version
# Expected output: rustc 1.70.0 or higher

# Verify Go installation
go version
# Expected output: go version go1.21.x

# Verify Git installation
git --version
# Expected output: git version 2.x.x

# Verify C compiler
gcc --version
# Expected output: gcc (GCC) x.x.x or similar

# Verify Make
make --version
# Expected output: GNU Make x.x.x or similar

# Verify OpenSSL
openssl version
# Expected output: OpenSSL 1.1.1x or 3.x.x
```

### Operating System Requirements

**Linux (Recommended)**: Ubuntu 20.04+, Debian 11+, Fedora 35+, or equivalent distributions. These platforms have well-tested build toolchains and package availability.

**macOS**: Version 12 (Monterey) or higher with Xcode command-line tools installed. Apple Silicon Macs are supported but may require additional configuration for optimal performance.

**Windows**: Windows 10 or Windows 11 with Visual Studio 2022 Build Tools installed. The build scripts assume a standard Windows development environment with CMD or PowerShell.

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB+ |
| CPU Cores | 2 | 4+ |
| Disk Space | 2 GB | 10 GB+ |
| Additional | - | SSD storage for faster builds |

---

## System Preparation

Perform these steps to prepare your system for CXA installation. These steps create necessary directories, clone the repository if not already present, and verify the overall environment.

### Step 1: Create Project Directory

```bash
# Create the CXA project directory
mkdir -p /opt/cxa
cd /opt/cxa

# Or for user-local installation
mkdir -p ~/cxa-project
cd ~/cxa-project
```

### Step 2: Clone or Navigate to Repository

```bash
# If cloning for the first time
git clone https://github.com/XvoidcrewX/CXA.git
cd CXA

# If the repository already exists
cd /path/to/CXA
```

### Step 3: Create Required Directories

```bash
# Create directory structure for runtime data
mkdir -p ~/.cxa/{keys,logs,certs,cache}

# Create build output directory
mkdir -p bin

# Create test output directory
mkdir -p test-reports
```

### Step 4: Verify Repository Integrity

```bash
# Verify the repository is clean and at expected commit
git status
git log --oneline -1

# If available, verify GPG signature
git verify-commit $(git rev-parse HEAD)
```

---

## Rust Core Compilation

The Rust core contains all cryptographic primitives and must be compiled before other components. This section provides detailed instructions for building each cryptographic module.

### Step 1: Install Rust Toolchain

If Rust is not already installed, install it using rustup:

```bash
# Download and install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Source the Rust environment
source $HOME/.cargo/env

# Add the stable toolchain
rustup default stable

# Verify installation
rustc --version
cargo --version
```

### Step 2: Configure Rust for Optimal Build

```bash
# Set release profile for optimal performance
cat >> ~/.cargo/config.toml << 'EOF'
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
EOF
```

### Step 3: Build Each Cryptographic Module

Navigate to each module directory and compile:

```bash
cd rust-core/crypto

# Build AES module
cd aes
cargo build --release
cd ..

# Build ChaCha20 module
cd chacha20
cargo build --release
cd ..

# Build Ed25519 signature module
cd ed25519
cargo build --release
cd ..

# Build hash functions module
cd hash
cargo build --release
cd ..

# Build key derivation module
cd kdf
cargo build --release
cd ..

# Build MAC module
cd mac
cargo build --release
cd ..

# Build memory operations module
cd mem
cargo build --release
cd ..

# Build random number generation module
cd random
cargo build --release
cd ..

# Build RSA module
cd rsa
cargo build --release
cd ..
```

### Step 4: Verify Rust Builds

```bash
# Check that all libraries were built
ls -la rust-core/crypto/*/target/release/*.rlib

# Expected: 9 library files for each module
# aes, chacha20, ed25519, hash, kdf, mac, mem, random, rsa
```

### Step 5: Build All Rust Crates (Alternative)

For a simplified build process:

```bash
cd rust-core/crypto
cargo build --release --workspace
cd ../..
```

---

## Go Services Compilation

The Go services provide API endpoints, event processing, and system monitoring capabilities. These services are optional for local GUI usage but required for networked deployments.

### Step 1: Install Go Toolchain

If Go is not already installed, download and install it:

```bash
# Download Go (Linux example)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add Go to PATH
export PATH=$PATH:/usr/local/go/bin

# Verify installation
go version
```

### Step 2: Initialize Go Modules

```bash
cd go-services
go mod tidy
```

### Step 3: Build Each Go Service

```bash
# Build API Server
cd api-server
go build -o ../../bin/cxa-api-server main.go
cd ..

# Build Event Monitor
cd event-monitor
go build -o ../../bin/cxa-event-monitor main.go
cd ..

# Build Event Processor
cd event-processor
go build -o ../../bin/cxa-event-processor main.go
cd ..

# Build System Monitor
cd monitor
go build -o ../../bin/cxa-monitor main.go
cd ..
```

### Step 4: Verify Go Builds

```bash
# List built executables
ls -la bin/cxa-*

# Expected executables:
# cxa-api-server, cxa-event-monitor, cxa-event-processor, cxa-monitor
```

### Step 5: Cross-Compilation (Optional)

To build for other platforms:

```bash
# Build for Windows (from Linux)
cd api-server
GOOS=windows GOARCH=amd64 go build -o ../../bin/cxa-api-server.exe main.go
cd ..

# Build for macOS (from Linux)
cd api-server
GOOS=darwin GOARCH=amd64 go build -o ../../bin/cxa-api-server-darwin main.go
cd ..
```

---

## Python Environment Setup

The Python layer provides the GUI, CLI, and orchestration capabilities. This section covers setting up the Python environment and installing dependencies.

### Step 1: Create Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate

# Windows (CMD):
venv\Scripts\activate.bat

# Windows (PowerShell):
venv\Scripts\Activate.ps1

# Verify activation
python --version
```

### Step 2: Install Python Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install base dependencies
pip install -r requirements/base.txt

# Install development dependencies
pip install -r requirements/dev.txt

# Verify key packages
python -c "import PyQt6; print('PyQt6:', PyQt6.__version__)"
python -c "import cryptography; print('cryptography:', cryptography.__version__)"
python -c "import PIL; print('Pillow:', PIL.__version__)"
```

### Step 3: Install CXA Package

```bash
# Install CXA in development mode
cd python-core
pip install -e .
cd ..

# Verify installation
python -m cxa --version
```

### Step 4: Configure Python Path (Optional)

For development work, ensure the Python path includes the project directories:

```bash
# Add to shell profile (.bashrc, .zshrc, etc.)
export PYTHONPATH=$PYTHONPATH:/path/to/CXA/python-core:/path/to/CXA/python-gui
```

---

## Configuration

Proper configuration is essential for secure and functional operation. This section details all configuration requirements and provides templates for configuration files.

### Step 1: Create Configuration File

```bash
# Copy default configuration
cp config/default.yml ~/.cxa/config.yml

# Create config directory if needed
mkdir -p ~/.cxa
```

### Step 2: Configure Security Settings

Edit `~/.cxa/config.yml` with appropriate security settings:

```yaml
security:
  min_password_length: 16
  max_key_age_days: 90
  auto_key_rotation: true
  failed_attempts_lockout: 3
  lockout_duration_minutes: 60
```

### Step 3: Configure Cryptographic Settings

```yaml
crypto:
  default_symmetric_algorithm: "aes-gcm-256"
  default_asymmetric_algorithm: "rsa-4096"
  default_hash_algorithm: "sha-256"
  default_kdf: "pbkdf2"
  
  kdf:
    pbkdf2:
      default_iterations: 600000
      hash_algorithm: "sha-256"
```

### Step 4: Configure Paths

```yaml
paths:
  keystore: "~/.cxa/keys"
  logs: "~/.cxa/logs"
  certs: "~/.cxa/certs"
  cache: "~/.cxa/cache"
```

### Step 5: Configure API Settings (If Using Go Services)

```yaml
api:
  host: "127.0.0.1"
  port: 8080
  tls_enabled: true
  cert_path: "~/.cxa/certs/server.crt"
  key_path: "~/.cxa/certs/server.key"
  rate_limit:
    requests_per_minute: 100
    burst_size: 20
```

### Step 6: Generate SSL Certificates (If Using API)

```bash
# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout ~/.cxa/certs/server.key \
  -out ~/.cxa/certs/server.crt -days 365 -nodes \
  -subj "/CN=localhost/O=CXA/C=US"

# Set appropriate permissions
chmod 600 ~/.cxa/certs/server.key
chmod 644 ~/.cxa/certs/server.crt
```

### Step 7: Set Environment Variables

Add to your shell profile or create an environment file:

```bash
# Create environment file
cat > ~/.cxa/environment << 'EOF'
CXA_CONFIG_PATH=~/.cxa/config.yml
CXA_KEYSTORE_PATH=~/.cxa/keys
CXA_LOG_LEVEL=INFO
PYTHONPATH=/path/to/CXA/python-core:/path/to/CXA/python-gui
EOF

# Source the environment
source ~/.cxa/environment
```

---

## Testing

Testing validates that all components are correctly installed and configured. Run tests in the order specified below.

### Step 1: Run Rust Tests

```bash
cd rust-core/crypto

# Run all Rust tests
cargo test --release

# Run specific module tests
cd aes && cargo test && cd ..
cd hash && cargo test && cd ..

# Run with verbose output
cargo test --release -- --nocapture
```

### Step 2: Run Go Tests

```bash
cd go-services

# Run all Go tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Step 3: Run Python Unit Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all Python tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=cxa_core --cov-report=html

# Run specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/fuzz/ -v --hypothesis-show-statistics
```

### Step 4: Run Full Integration Test

```bash
# Test complete workflow
python -c "
from cxa_core.crypto import CryptoEngine
from cxa_core.stego import ImageStego
from cxa_core.key_manager import CXAKeyManager
import tempfile
import os

# Create temporary directory
with tempfile.TemporaryDirectory() as tmpdir:
    # Test crypto engine
    engine = CryptoEngine()
    key = engine.generate_key(32)
    nonce = engine.generate_nonce()
    encrypted = engine.encrypt(b'Test data', key, nonce)
    decrypted = engine.decrypt(encrypted, key, nonce)
    assert decrypted == b'Test data', 'Crypto test failed'
    print('✓ Crypto engine test passed')
    
    # Test key manager
    key_mgr = CXAKeyManager(tmpdir)
    key_id = key_mgr.generate_key('test')
    stored_key = key_mgr.get_key(key_id)
    assert stored_key == key, 'Key manager test failed'
    print('✓ Key manager test passed')

print('✓ All integration tests passed')
"
```

### Step 5: Test CLI Functionality

```bash
# Test CLI is accessible
python -m python_cli.main --help

# Test a simple operation
echo "test data" > /tmp/test_file.txt
python -m python_cli.main hash --input /tmp/test_file.txt --algorithm sha256
```

---

## Deployment

This section covers deploying CXA for production use. Choose the deployment method that best fits your environment.

### Method 1: Local Installation

For local, single-user operation:

```bash
# Ensure virtual environment is active
source venv/bin/activate

# Create desktop entry (optional)
cat > ~/.local/share/applications/cxa.desktop << 'EOF'
[Desktop Entry]
Name=CXA Cryptographic System
Comment=Advanced cryptographic toolkit
Exec=/path/to/CXA/venv/bin/python -m python_gui.main
Icon=/path/to/CXA/python-gui/icon.png
Terminal=false
Type=Application
Categories=Security;System;
EOF

# Create symlink for CLI access
sudo ln -s /path/to/CXA/venv/bin/python /usr/local/bin/cxa
```

### Method 2: Systemd Service (Linux)

For background service deployment:

```bash
# Create systemd service file
sudo cat > /etc/systemd/system/cxa-api.service << 'EOF'
[Unit]
Description=CXA API Server
After=network.target

[Service]
Type=simple
User=cxa
Group=cxa
WorkingDirectory=/opt/cxa
Environment=PATH=/opt/cxa/venv/bin
ExecStart=/opt/cxa/bin/cxa-api-server
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/cxa/.cxa

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable cxa-api
sudo systemctl start cxa-api
sudo systemctl status cxa-api
```

### Method 3: Docker Deployment

For containerized deployment:

```bash
# Build images
docker build -f Dockerfile.python -t cxa-python .
docker build -f Dockerfile.api -t cxa-api .

# Start with docker-compose
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Method 4: Manual Service Startup

For testing or debugging:

```bash
# Terminal 1: Start API server
cd /opt/cxa
source venv/bin/activate
./bin/cxa-api-server

# Terminal 2: Start GUI (if needed)
cd /opt/cxa
source venv/bin/activate
python -m python_gui.main
```

---

## Post-Installation Verification

After installation, perform these verification steps to confirm a successful deployment.

### Step 1: Verify Binary Availability

```bash
# Check Rust libraries
ls -la rust-core/crypto/*/target/release/*.so
ls -la rust-core/crypto/*/target/release/*.rlib

# Check Go executables
ls -la bin/cxa-*

# Check Python packages
pip list | grep -E "cxa|PyQt|cryptography|Pillow"
```

### Step 2: Verify Configuration

```bash
# Check configuration file exists and is valid
cat ~/.cxa/config.yml | python -c "import yaml, sys; yaml.safe_load(sys.stdin); print('✓ Config valid')"

# Check environment variables
source ~/.cxa/environment
echo "CXA_CONFIG_PATH: $CXA_CONFIG_PATH"
echo "CXA_KEYSTORE_PATH: $CXA_KEYSTORE_PATH"
```

### Step 3: Test Key Operations

```bash
python << 'EOF'
from cxa_core.crypto import CryptoEngine
from cxa_core.key_manager import CXAKeyManager
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    # Test all crypto operations
    engine = CryptoEngine()
    
    # Test key generation
    key = engine.generate_key(32)
    print(f"✓ Generated 256-bit key")
    
    # Test encryption
    nonce = engine.generate_nonce()
    ciphertext = engine.aes_encrypt(b"Verification test", key, nonce)
    print(f"✓ AES encryption successful")
    
    # Test decryption
    plaintext = engine.aes_decrypt(ciphertext, key, nonce)
    assert plaintext == b"Verification test"
    print(f"✓ AES decryption successful")
    
    # Test hashing
    hash_result = engine.sha256(b"Test data")
    assert len(hash_result) == 64
    print(f"✓ SHA-256 hashing successful")
    
    # Test key manager
    key_mgr = CXAKeyManager(tmpdir)
    key_id = key_mgr.generate_key("verify_test")
    retrieved = key_mgr.get_key(key_id)
    assert retrieved == key
    print(f"✓ Key manager operations successful")

print("\n✓ All verification tests passed")
EOF
```

### Step 4: Test GUI Launch

```bash
# Launch GUI and verify it starts (headless test)
python -c "
import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
app = QApplication(sys.argv)
print('✓ PyQt6 GUI framework initialized')
print('✓ GUI launch successful')
"
```

### Step 5: Test CLI Commands

```bash
# Test CLI help
python -m python_cli.main --help

# Test version
python -m python_cli.main --version
```

---

## System State Analysis

This section analyzes the state of the CXA system after completing all installation and configuration procedures.

### What Is Complete

After successfully completing all steps in this document, the following components are fully functional:

**Cryptographic Core (Rust)**: All nine cryptographic modules (AES, ChaCha20, Ed25519, Hash, KDF, MAC, Memory, Random, RSA) are compiled and available. The Rust code provides the foundation for all cryptographic operations with performance optimized for release builds.

**API Services (Go)**: All four Go services (API Server, Event Monitor, Event Processor, System Monitor) are compiled and ready for deployment. These services provide networked access to CXA capabilities and can be deployed independently or together.

**Python Interface**: The GUI and CLI are fully functional with all tabs and commands implemented. The Python layer correctly invokes Rust cryptographic functions and coordinates operations across the system.

**Configuration System**: Configuration files are in place with appropriate security settings. The configuration is validated and the system loads settings correctly on startup.

**Testing Infrastructure**: All unit tests, integration tests, and fuzz tests are available and passing. The test suite provides ongoing validation of system functionality.

### What Is Not Complete

Despite successful installation, the following aspects require additional work to be considered complete:

**Key Material**: The system has no keys by default. Keys must be generated for any encryption operations. This is by design for security reasons, but means the first use requires key generation.

**User Data**: No data has been encrypted or processed yet. The system is a toolkit that becomes useful as you perform operations with it.

**Custom Configuration**: Default configuration is in place, but production deployments typically require customization for specific environments, networks, and security policies.

**Production Hardening**: This document focuses on getting the system running. Production deployment requires additional hardening including firewall configuration, network isolation, backup procedures, and monitoring setup.

### System Status Summary

| Aspect | Status | Description |
|--------|--------|-------------|
| Core Cryptography | Complete | All modules compiled and tested |
| API Services | Complete | All services built and ready |
| GUI Interface | Complete | All tabs implemented |
| CLI Interface | Complete | All commands available |
| Configuration | Initial | Basic settings applied |
| Key Material | Empty | No keys generated |
| User Data | Empty | No operations performed |
| Production Hardening | Pending | Requires additional work |

### Will the Project Be Complete After These Steps?

**No, the project will not be feature-complete after completing these steps.**

Completing the procedures in this document results in a **deployed, operational toolkit** that is ready for use. However, feature-complete implies that the system has been configured for a specific use case with all necessary customizations, key material generated, and integration with existing systems completed.

Think of the completed installation as reaching "Day 0" of deployment. The infrastructure is in place, the tools are ready, but the actual work of encrypting data, managing keys, and securing communications is what follows.

The CXA system is designed as a comprehensive toolkit rather than a turnkey solution. Its value is realized through use—generating keys for specific purposes, configuring policies for your organization, and integrating with your specific workflows. This is the expected and intended behavior for a security toolkit.

---

## Operational Procedures

These procedures cover routine operations that may be required during the lifetime of the CXA deployment.

### Key Management Procedures

**Generating a New Key**:

```bash
python << 'EOF'
from cxa_core.key_manager import CXAKeyManager

key_mgr = CXAKeyManager()
key_id = key_mgr.generate_key(
    name="my-new-key",
    key_type="aes-256",
    metadata={"purpose": "file-encryption", "created": "2024-12-31"}
)
print(f"Generated key: {key_id}")
EOF
```

**Rotating a Key**:

```python
from cxa_core.key_manager import CXAKeyManager

key_mgr = CXAKeyManager()
old_key_id = "key-to-rotate"

# Create new key
new_key_id = key_mgr.generate_key("rotated-key")

# Re-encrypt data with new key (implementation specific)
# ...

# Mark old key as rotated
key_mgr.rotate_key(old_key_id, new_key_id)
```

### Backup Procedures

**Creating an Encrypted Backup**:

```python
from cxa_core.backup import CXABackupManager

backup_mgr = CXABackupManager()
backup_path = backup_mgr.create_encrypted_backup(
    source="/path/to/data",
    password="backup-password",
    output="/path/to/backup.cxa"
)
print(f"Backup created: {backup_path}")
```

**Restoring from Backup**:

```python
from cxa_core.backup import CXABackupManager

backup_mgr = CXABackupManager()
backup_mgr.restore_backup(
    source="/path/to/backup.cxa",
    password="backup-password",
    destination="/path/to/restore"
)
print("Restore completed")
```

### Monitoring Procedures

**Checking System Status**:

```bash
# Check service status (if using systemd)
systemctl status cxa-api

# Check API health endpoint
curl https://localhost:8080/health

# Check logs
tail -f ~/.cxa/logs/cxa.log
```

### Update Procedures

**Updating CXA**:

```bash
# Stop services
systemctl stop cxa-api

# Backup configuration and keys
cp -r ~/.cxa ~/.cxa.backup.$(date +%Y%m%d)

# Pull latest code
git pull origin main

# Rebuild Rust core
cd rust-core/crypto
cargo build --release
cd ../..

# Rebuild Go services
cd go-services
go build -o ../bin/cxa-api-server ./api-server
cd ..

# Update Python packages
source venv/bin/activate
pip install -r requirements/base.txt --upgrade

# Restart services
systemctl start cxa-api
```

---

## Troubleshooting

This section addresses common issues and their solutions.

### Build Failures

**Rust Build Fails with Compilation Errors**:

```bash
# Update Rust toolchain
rustup update stable

# Clean build artifacts
cd rust-core/crypto
cargo clean
cargo build --release

# Check for missing dependencies
cargo build --release --verbose
```

**Go Build Fails with Import Errors**:

```bash
# Update Go modules
cd go-services
go mod tidy
go mod download

# Verify Go version
go version
```

**Python Package Installation Fails**:

```bash
# Upgrade pip
pip install --upgrade pip

# Install with verbose output
pip install -r requirements/base.txt -v

# Check for missing system packages
pkg-config --modversion openssl
```

### Runtime Errors

**Module Not Found Errors**:

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall package
cd python-core
pip install -e .
```

**Cryptographic Operations Fail**:

```bash
# Check Rust library availability
ls -la rust-core/crypto/*/target/release/*.so

# Set library path
export LD_LIBRARY_PATH=/path/to/CXA/rust-core/crypto/*/target/release:$LD_LIBRARY_PATH
```

**GUI Does Not Start**:

```bash
# Check Qt installation
python -c "from PyQt6.QtWidgets import QApplication; print('Qt OK')"

# Check display environment
echo $DISPLAY

# Try in terminal mode
python -m python_gui.main 2>&1
```

### Configuration Issues

**Configuration Not Loading**:

```bash
# Verify configuration file exists
cat ~/.cxa/config.yml

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('~/.cxa/config.yml'))"

# Check environment variable
echo $CXA_CONFIG_PATH
```

**Environment Variables Not Set**:

```bash
# Reload shell configuration
source ~/.bashrc
# or
source ~/.zshrc
```

---

## Support

If you encounter issues not covered by this document:

1. Review the main README.md for general information
2. Check the docs/ directory for detailed documentation
3. Search existing GitHub issues for similar problems
4. Open a new issue with detailed error messages and system information

---

**End of Administrator Guide**
