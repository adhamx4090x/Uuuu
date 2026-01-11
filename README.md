# CXA Cryptographic System

> Advanced, OpSec-conscious cryptographic toolkit for data protection, steganography, and secure key management.

[![License](https://img.shields.io/badge/License-MIT-001CFF.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-8FFF00)](https://www.python.org/downloads/)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21%2B-blue)](https://go.dev/)
[![Tests](https://img.shields.io/badge/Tests-Pytest-green)](tests/)

---

## Table of Contents

1. [Overview](#overview)
2. [Core Philosophy](#core-philosophy)
3. [Features](#features)
4. [Quick Start](#quick-start)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Documentation](#documentation)
8. [Support](#support)

---

## Overview

CXA is a **zero-trust**, **audit-ready** cryptographic application designed for users who demand **maximum confidentiality** and **operational security**. It integrates military-grade encryption, steganography, digital signatures, and tamper-resistant key management — all within a secure-by-default architecture.

This project represents a complete, multi-language cryptographic toolkit that combines the performance of Rust, the concurrency of Go, and the versatility of Python into a unified security solution suitable for personal encryption needs, enterprise data protection, and secure communications.

### Who This Is For

This document is for **regular users** who want to:
- Encrypt their files and messages securely
- Hide data inside images using steganography
- Manage cryptographic keys safely
- Sign and verify digital documents

**For project maintainers and administrators**, detailed operational documentation is available in [ADMIN_README.md](./ADMIN_README.md).

---

## Core Philosophy

CXA is built upon five foundational principles that guide all design decisions and implementation choices.

**No Telemetry** means that your data never leaves your machine. Unlike many modern applications that silently collect usage statistics, CXA operates completely offline and makes no network requests.

**No Auto-Updates** reflects the belief that security updates should be manually verified by you before deployment. With CXA, you control exactly what code runs on your system.

**No Cloud Dependencies** ensures that CXA operates entirely within your controlled environment. There are no external APIs to call, no cloud-based key management services.

**Transparent Security** means that all operations are auditable and verifiable. Every cryptographic operation, key access, and security event is logged.

**Zero-Trust Architecture** assumes that every component could be compromised and designs defenses accordingly.

---

## Features

### Encryption Capabilities

CXA implements a comprehensive set of encryption algorithms suitable for different use cases and security requirements.

- **Symmetric Encryption**: AES-GCM (128, 192, 256-bit) and ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048 and 4096-bit) for key exchange
- **Digital Signatures**: Ed25519 for fast and secure signing operations

### Key Management

- **Encrypted Keystore**: Keys are never stored in plaintext
- **Automatic Key Rotation**: Policies can be configured for regular key updates
- **Hardware Security Module Integration**: PKCS#11 support for HSMs

### Steganography

- **Image Steganography**: LSB embedding for PNG images
- **Text Steganography**: Zero-width character encoding and whitespace encoding

### Security Monitoring

- **Audit Logging**: Records every cryptographic operation and key access
- **Tamper Detection**: Monitors system integrity and detects unauthorized modifications
- **Intrusion Detection**: Identifies suspicious patterns such as brute-force attempts

---

## Quick Start

The fastest way to get started with CXA:

```bash
# Clone and enter the project directory
git clone https://github.com/XvoidcrewX/CXA.git
cd CXA

# Build everything (Linux/macOS/Windows)
./build_linux.sh all    # Linux and macOS with Bash
./build_macos.sh all    # macOS specific
build.bat all           # Windows

# Activate Python virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Launch the GUI
python -m python_gui.main

# Or use the CLI
python -m python_cli.main --help
```

That's it! You are now ready to use CXA for encryption, decryption, and secure key management.

---

## Installation

### Prerequisites

Before installing CXA, ensure your system meets the following requirements:

- **Python 3.10 or higher**
- **Rust toolchain** (version 1.70 or higher)
- **Go toolchain** (version 1.21 or higher)
- **Build tools**: gcc, make, cmake
- **System libraries**: libssl-dev, pkg-config (Linux)

### Installation Methods

#### Method 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/XvoidcrewX/CXA.git
cd CXA

# Build all components automatically
chmod +x build_linux.sh
./build_linux.sh all    # Builds Rust, Go, and Python components

# Or build selectively
./build_linux.sh rust   # Build Rust core only
./build_linux.sh go     # Build Go services only
./build_linux.sh python # Build Python package only

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Verify installation
python -m python_cli.main --version
```

#### Method 2: Docker Installation

For containerized deployment:

```bash
# Build and start all services
docker-compose up -d

# Access the CLI
docker exec -it cxa-python python -m python_cli.main --help
```

#### Method 3: Platform-Specific Build Scripts

The project includes dedicated build scripts for each platform:

| Platform | Build Command |
|----------|---------------|
| Linux | `./build_linux.sh all` |
| macOS | `./build_macos.sh all` |
| Windows | `build.bat all` |

For detailed build instructions, troubleshooting, or advanced configuration, please refer to [ADMIN_README.md](./ADMIN_README.md).

---

## Usage

### GUI Mode

The graphical user interface provides a point-and-click interface for all CXA operations. Launch it from the command line after installation:

```bash
python -m python_gui.main
```

The GUI organizes functionality into six tabs:
- **Dashboard**: System overview and quick actions
- **Encryption**: File and text encryption operations
- **Decryption**: Decrypting previously encrypted content
- **Key Management**: Generating, importing, and managing cryptographic keys
- **Backup**: Creating and restoring encrypted backups
- **Settings**: Configuring system preferences

### CLI Mode

The command-line interface provides scriptable access to CXA capabilities for automation and integration:

```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Encrypt a file
cxa encrypt --input secret.txt --output secret.enc --key key.bin

# Decrypt a file
cxa decrypt --input secret.enc --output secret.txt --key key.bin

# Generate a symmetric key
cxa generate-key --type aes-256 --output key.bin

# Generate a key pair
cxa generate-keypair --type rsa-4096 --public key.pub --private key.pem

# Sign a file
cxa sign --input document.pdf --output document.sig --key key.pem

# Verify a signature
cxa verify --input document.pdf --signature document.sig --key key.pub

# Hash a file
cxa hash --input document.pdf --algorithm sha256

# Hide data in image
cxa hide --input secret.txt --carrier image.png --output stego.png --password secret

# Extract hidden data
cxa reveal --input stego.png --output secret.txt --password secret
```

### Python API

For integration with other Python applications, CXA provides a direct API:

```python
from cxa_core.crypto import CryptoEngine, KeyType, SecurityLevel
from cxa_core.stego import ImageStego, TextStego

# Initialize engine with desired security level
engine = CryptoEngine(security_level=SecurityLevel.HIGH)

# Generate a symmetric key
key = engine.generate_key(KeyType.AES_256)

# Encrypt data
nonce = engine.generate_nonce()
result = engine.encrypt(b"Secret message", key, nonce)

# Decrypt data
decrypted = engine.decrypt(result.ciphertext, result.tag, key, result.nonce)

# Generate key pair for signatures
public_key, private_key = engine.generate_keypair(KeyType.ED25519)

# Sign data
signature = engine.sign(b"Data to sign", private_key)

# Verify signature
is_valid = engine.verify(b"Data to verify", signature, public_key)

# Hide data in image
stego = ImageStego()
result = stego.embed(b"Secret data", carrier_image, password="secure")
result.image.save("stego_image.png")

# Extract data from image
extracted = stego.extract(result.image, password="secure")
print(extracted.data)
```

---

## Documentation

### Additional Documentation

For more detailed information about CXA, please refer to the following resources:

| Document | Description |
|----------|-------------|
| [ADMIN_README.md](./ADMIN_README.md) | Detailed operational guide for project maintainers and administrators |
| [docs/api.md](./docs/api.md) | Detailed API reference |
| [docs/architecture.md](./docs/architecture.md) | System architecture details |
| [docs/deployment.md](./docs/deployment.md) | Production deployment instructions |
| [docs/security.md](./docs/security.md) | Security best practices |

### Security Considerations

CXA is designed for environments where security is paramount, but the tool itself is only as secure as the practices surrounding its use. Following these guidelines will help ensure that CXA provides the protection intended:

- **Always verify checksums** before running any downloaded code
- **Use strong passwords** for key derivation
- **Enable MFA** for API access if using the Go API services
- **Conduct regular security audits** including penetration testing

---

## Support

### Getting Help

- **Issues**: Open a GitHub issue for bugs or feature requests
- **Security**: See [docs/security.md](docs/security.md) for vulnerability reporting
- **Email**: voidcrew@cock.li for direct contact

---

**Remember**: Privacy isn't a feature. It's a practice.

Stay sharp. Stay skeptical. Never trust a tool more than your own judgment.
