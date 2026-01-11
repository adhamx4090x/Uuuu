# CXA Security Documentation

## Security Model

### Threat Model

The CXA Cryptographic System is designed to protect against the following threat categories:

**External Attackers**: Malicious actors attempting to intercept, modify, or steal sensitive data through network attacks or physical access to systems. CXA provides defense through military-grade encryption, secure key management, and comprehensive audit logging.

**Insider Threats**: Authorized users with malicious intent or negligence that could compromise security. CXA mitigates this through access controls, separation of duties, and comprehensive audit trails that track all user actions.

**Physical Attacks**: Attackers with physical access to computing hardware who may attempt memory extraction or hardware tampering. CXA provides secure memory management and tamper detection, though physical security remains a critical requirement.

**Software Attacks**: Malware, viruses, and exploit attempts targeting the cryptographic system. CXA employs defense-in-depth strategies including secure coding practices, input validation, and anti-tampering mechanisms.

### Security Properties

The CXA system guarantees several security properties through its cryptographic design:

**Confidentiality**: All sensitive data is encrypted using industry-standard algorithms with appropriate key sizes. AES-256-GCM provides 256-bit security, which is considered quantum-resistant for the foreseeable future.

**Integrity**: Authenticated encryption modes (GCM, Poly1305) ensure that any modification to ciphertext is detected. Digital signatures provide non-repudiation for critical operations.

**Authentication**: All cryptographic operations require appropriate authentication, whether through passwords, key material, or hardware tokens.

**Forward Secrecy**: Session keys are ephemeral and not stored long-term, ensuring that compromise of long-term keys does not expose previously encrypted communications.

## Cryptographic Algorithms

### Symmetric Encryption

#### AES-GCM (Default)

| Key Size | Security Level | Use Case |
|----------|----------------|----------|
| AES-128 | 128-bit | Standard security |
| AES-256 | 256-bit | High security |

AES-GCM provides authenticated encryption, combining confidentiality with integrity protection. The GCM mode uses a 12-byte nonce and 16-byte authentication tag.

#### ChaCha20-Poly1305

ChaCha20-Poly1305 is used as an alternative when hardware AES acceleration is unavailable. It provides the same 256-bit security level as AES-256 and is resistant to timing attacks.

### Asymmetric Encryption

#### RSA-OAEP

| Key Size | Security Level | Use Case |
|----------|----------------|----------|
| RSA-2048 | 112-bit | Standard security |
| RSA-4096 | 128-bit | High security |

RSA-OAEP (Optimal Asymmetric Encryption Padding) is used for key encryption and asymmetric operations.

#### Ed25519

Ed25519 provides fast, secure digital signatures with 128-bit security level. It is recommended for most signature use cases.

### Hash Functions

#### SHA-256 (Default)

SHA-256 produces a 256-bit hash and is suitable for most cryptographic hashing needs including integrity verification and HMAC.

#### SHA-512

SHA-512 provides a 512-bit hash for applications requiring higher collision resistance.

#### BLAKE3

BLAKE3 is a modern hash function that is significantly faster than SHA-256 while providing the same 256-bit security level.

### Key Derivation Functions

#### PBKDF2 (Default)

PBKDF2 (Password-Based Key Derivation Function 2) uses SHA-256 or SHA-512 with configurable iterations. Default: 600,000 iterations.

#### Argon2id (Recommended)

Argon2id provides resistance against GPU and ASIC attacks. Recommended parameters: 64MB memory, 3 iterations, 4 parallelism.

## Key Management

### Key Lifecycle

1. **Generation**: Keys are generated using cryptographically secure random number generators (CSPRNG). The system entropy source is checked for adequacy before key generation.

2. **Storage**: Master keys are encrypted using keys derived from user passwords. Operational keys are stored in an encrypted keystore protected by the master key.

3. **Usage**: Keys are loaded into secure memory during use and zeroized immediately after. Key usage is tracked for rotation decisions.

4. **Rotation**: Keys can be rotated manually or automatically based on configured policies. Old keys are retained for decryption of existing data.

5. **Destruction**: Keys are securely destroyed using multi-pass overwrite techniques. Destruction is logged with cryptographic proof.

### Keystore Architecture

```
Keystore
├── Master Key (encrypted with user password)
│   └── Key Entries
│       ├── Key ID 1
│       │   ├── Encrypted Key Material
│       │   ├── Metadata (algorithm, created, expires)
│       │   └── Access Control List
│       └── Key ID 2
│           └── ...
└── Audit Log (HMAC protected)
```

## Memory Security

### Secure Memory Allocation

CXA uses locked memory pages to prevent swapping to disk. Memory pages are marked as non pageable using platform-specific APIs:

- Linux: mlock() system call
- Windows: VirtualLock() API
- macOS: mlock() system call

### Memory Zeroization

All sensitive memory is zeroized using explicit overwrite operations:

```python
def secure_zero(data: bytearray) -> None:
    """Overwrite data with zeros."""
    for i in range(len(data)):
        data[i] = 0
```

### Buffer Protection

- Buffers are allocated with guard pages to detect overflow
- Stack canaries protect against buffer overflows
- ASLR (Address Space Layout Randomization) is enforced

## Audit System

### Logged Events

| Category | Events | Sensitivity |
|----------|--------|-------------|
| Authentication | Login, Logout, Failed attempts | Medium |
| Cryptographic | Encrypt, Decrypt, Sign, Verify | Low |
| Key Management | Create, Rotate, Destroy, Export | High |
| Configuration | Settings changes | Medium |
| Security | Tamper detection, Anomalies | Critical |

### Log Format

```json
{
    "timestamp": "2024-01-01T12:00:00Z",
    "event_type": "ENCRYPT",
    "user_id": "user123",
    "source_ip": "192.168.1.100",
    "operation": {
        "algorithm": "aes-gcm-256",
        "key_id": "key-abc123"
    },
    "outcome": "SUCCESS",
    "sanitized_details": "..."
}
```

### Log Protection

- Logs are append-only (no modification or deletion)
- HMAC signature protects log integrity
- Logs can be exported for compliance verification

## Input Validation

### Data Sanitization

All inputs undergo rigorous validation:

```python
def validate_input(data: bytes, max_length: int = 1024) -> bytes:
    # Check length
    if len(data) > max_length:
        raise ValidationError("Input too large")
    
    # Check for null bytes in string contexts
    if b'\x00' in data:
        raise ValidationError("Null bytes not allowed")
    
    # Validate encoding
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValidationError("Invalid encoding")
    
    return data
```

### Algorithm Selection

Algorithm selection is strictly controlled:

```python
ALLOWED_ALGORITHMS = {
    "symmetric": ["aes-gcm-128", "aes-gcm-256", "chacha20-poly1305"],
    "asymmetric": ["rsa-2048", "rsa-4096", "ed25519"],
    "hash": ["sha-256", "sha-512", "blake3"],
    "kdf": ["pbkdf2-sha256", "pbkdf2-sha512", "argon2id"]
}
```

## Secure Communication

### API Security

The Go-based API server implements:

- TLS 1.3 with strong cipher suites
- Certificate pinning for clients
- Rate limiting to prevent DoS attacks
- Request validation and sanitization
- Response encryption for sensitive data

### Cipher Suite Configuration

```go
tlsConfig := &tls.Config{
    MinVersion:               tls.VersionTLS13,
    CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
    PreferServerCipherSuites: true,
}
```

## Compliance Considerations

### FIPS 140-2

CXA is designed to support FIPS 140-2 compliance through:

- Use of validated cryptographic algorithms
- Separation of cryptographic and non-cryptographic modules
- Comprehensive audit logging
- Secure key management practices

### GDPR

For GDPR compliance, CXA provides:

- Data encryption at rest and in transit
- Secure data deletion capabilities
- Audit trails for data access
- Data portability through export features

### SOC 2

CXA supports SOC 2 requirements through:

- Access controls and authentication
- Change management procedures
- Risk management practices
- Comprehensive audit logging
- Incident response capabilities

## Security Best Practices

### For Users

1. **Use Strong Passwords**: Minimum 12 characters with mixed case, numbers, and symbols.

2. **Enable Key Rotation**: Configure automatic key rotation for sensitive data.

3. **Regular Backups**: Maintain encrypted backups of keystores.

4. **Monitor Audit Logs**: Review logs regularly for suspicious activity.

5. **Keep Software Updated**: Apply security patches promptly.

### For Administrators

1. **Network Isolation**: Deploy API servers in isolated network segments.

2. **Access Controls**: Implement least-privilege access for system administration.

3. **Hardware Security**: Consider HSM integration for master keys.

4. **Incident Response**: Develop and test incident response procedures.

5. **Regular Audits**: Conduct periodic security assessments.

## Security Contacts

For security issues, please contact:

- **Email**: voidcrew@cock.li
- **PGP Key**: See [public_key.txt](public_key.txt)
- **Session**: See [contacts.md](contacts.md)

**Note**: Do not post security issues publicly. Contact us directly for responsible disclosure.
