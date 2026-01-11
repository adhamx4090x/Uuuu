# CXA API Reference
# REST API documentation for the CXA Cryptographic System

## Base URL

All API endpoints are relative to:
- Production: `https://api.example.com/v1`
- Development: `https://localhost:8443/api/v1`

## Authentication

### API Key Authentication

Include your API key in the `Authorization` header:

```
Authorization: Bearer <your_api_key>
```

### Mutual TLS (mTLS)

For high-security deployments, client certificates can be used for authentication.

## Rate Limiting

| Tier | Requests/minute | Burst |
|------|-----------------|-------|
| Free | 60 | 10 |
| Basic | 300 | 50 |
| Professional | 1000 | 100 |
| Enterprise | 10000 | 1000 |

## Endpoints

### Health Check

#### GET /health

Check the overall health of the service.

**Response (200 OK):**
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "components": {
        "crypto": true,
        "keyManager": true,
        "auditLog": true
    },
    "uptime": "1h23m45s",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /ready

Check if the service is ready to accept requests.

**Response (200 OK):**
```json
{
    "status": "ready"
}
```

**Response (503 Service Unavailable):**
```json
{
    "status": "not_ready",
    "unready_components": ["keyManager"]
}
```

### Encryption

#### POST /encrypt

Encrypt data using the specified algorithm.

**Request:**
```json
{
    "plaintext": "string (base64 encoded)",
    "algorithm": "aes-256-gcm | chacha20-poly1305",
    "key_id": "string (optional)",
    "associated_data": "string (base64 encoded, optional)"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "ciphertext": "string (base64 encoded)",
    "tag": "string (base64 encoded)",
    "nonce": "string (base64 encoded)",
    "algorithm": "aes-256-gcm",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

**Error Response (400 Bad Request):**
```json
{
    "success": false,
    "error": "Invalid algorithm specified",
    "code": 400,
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### POST /decrypt

Decrypt data using the specified algorithm.

**Request:**
```json
{
    "ciphertext": "string (base64 encoded)",
    "tag": "string (base64 encoded)",
    "nonce": "string (base64 encoded)",
    "algorithm": "aes-256-gcm | chacha20-poly1305",
    "key_id": "string (optional)",
    "associated_data": "string (base64 encoded, optional)"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "plaintext": "string (base64 encoded)",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Hashing

#### POST /hash

Compute a cryptographic hash of the provided data.

**Request:**
```json
{
    "data": "string (base64 encoded)",
    "algorithm": "blake3 | sha-256 | sha-512 | sha3-256"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "hash": "string (hex encoded)",
    "algorithm": "blake3",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Key Management

#### POST /keys/generate

Generate a new cryptographic key.

**Request:**
```json
{
    "algorithm": "aes-256-gcm | aes-256-gcm | ed25519 | rsa-4096",
    "purpose": "encryption | signing | derivation",
    "expires_at": "2025-01-15T10:30:00Z (optional)",
    "max_uses": 1000 (optional)
}
```

**Response (201 Created):**
```json
{
    "success": true,
    "key_id": "uuid",
    "algorithm": "aes-256-gcm",
    "public_key": "string (base64 encoded, for asymmetric keys)",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /keys/list

List all available keys.

**Query Parameters:**
- `status`: Filter by key status (active, expired, revoked)
- `algorithm`: Filter by algorithm
- `limit`: Maximum results (default: 100)

**Response (200 OK):**
```json
{
    "success": true,
    "keys": [
        {
            "key_id": "uuid",
            "algorithm": "aes-256-gcm",
            "purpose": "encryption",
            "status": "active",
            "created_at": "2024-01-01T00:00:00Z",
            "expires_at": "2025-01-01T00:00:00Z",
            "use_count": 42
        }
    ],
    "total": 1,
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /keys/{key_id}

Get details for a specific key.

**Response (200 OK):**
```json
{
    "success": true,
    "key": {
        "key_id": "uuid",
        "algorithm": "aes-256-gcm",
        "purpose": "encryption",
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "expires_at": "2025-01-01T00:00:00Z",
        "use_count": 42,
        "metadata": {
            "description": "My encryption key"
        }
    },
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### DELETE /keys/{key_id}

Revoke and securely destroy a key.

**Response (200 OK):**
```json
{
    "success": true,
    "message": "Key revoked and scheduled for destruction",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### POST /keys/{key_id}/rotate

Rotate a key, creating a new version.

**Response (201 Created):**
```json
{
    "success": true,
    "new_key_id": "uuid",
    "old_key_id": "uuid",
    "message": "Key rotated successfully",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Key Derivation

#### POST /derive-key

Derive a key from a password or key material.

**Request:**
```json
{
    "password": "string (base64 encoded)",
    "salt": "string (base64 encoded)",
    "algorithm": "argon2id | scrypt | pbkdf2",
    "length": 32,
    "iterations": 3 (for argon2),
    "memory_cost": 65536 (for argon2/scrypt)
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "derived_key": "string (base64 encoded)",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Digital Signatures

#### POST /sign

Create a digital signature.

**Request:**
```json
{
    "data": "string (base64 encoded)",
    "key_id": "uuid",
    "algorithm": "ed25519 | rsa-4096"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "signature": "string (base64 encoded)",
    "algorithm": "ed25519",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### POST /verify

Verify a digital signature.

**Request:**
```json
{
    "data": "string (base64 encoded)",
    "signature": "string (base64 encoded)",
    "key_id": "uuid (optional)",
    "public_key": "string (base64 encoded, optional)",
    "algorithm": "ed25519 | rsa-4096"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "valid": true,
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Backup

#### POST /backup

Create an encrypted backup.

**Request (multipart/form-data):**
- `source`: File or directory path to backup
- `encryption_key_id`: Key to use for backup encryption
- `compression`: true | false (default: true)

**Response (201 Created):**
```json
{
    "success": true,
    "backup_id": "uuid",
    "size": 1048576,
    "compressed_size": 524288,
    "checksum": "sha256:abc123...",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /backup/{backup_id}

Get backup information.

**Response (200 OK):**
```json
{
    "success": true,
    "backup": {
        "backup_id": "uuid",
        "created_at": "2024-01-15T10:30:00Z",
        "size": 1048576,
        "status": "verified",
        "checksum": "sha256:abc123..."
    },
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### POST /backup/{backup_id}/restore

Restore from a backup.

**Request:**
```json
{
    "target_path": "/path/to/restore",
    "encryption_key_id": "uuid"
}
```

**Response (200 OK):**
```json
{
    "success": true,
    "restored_path": "/path/to/restore",
    "files_restored": 42,
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### DELETE /backup/{backup_id}

Delete a backup.

**Response (200 OK):**
```json
{
    "success": true,
    "message": "Backup deleted",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Steganography

#### POST /stego/embed

Embed data in a carrier file.

**Request (multipart/form-data):**
- `carrier`: Carrier file (image or text)
- `data`: Data to embed (base64 encoded)
- `method`: lsb | zerowidth (default: lsb for images, zerowidth for text)

**Response (200 OK):**
```json
{
    "success": true,
    "carrier_path": "/path/to/output",
    "capacity_used": 1024,
    "capacity_total": 65536,
    "checksum": "sha256:abc123...",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### POST /stego/extract

Extract data from a carrier file.

**Request (multipart/form-data):**
- `carrier`: Carrier file

**Response (200 OK):**
```json
{
    "success": true,
    "data": "string (base64 encoded)",
    "method": "lsb",
    "checksum": "sha256:abc123...",
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Audit

#### GET /audit/logs

Retrieve audit logs.

**Query Parameters:**
- `start_time`: Filter from this time
- `end_time`: Filter to this time
- `event_type`: Filter by event type
- `user_id`: Filter by user
- `limit`: Maximum results (default: 1000)

**Response (200 OK):**
```json
{
    "success": true,
    "logs": [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "ENCRYPT",
            "user_id": "uuid",
            "source_ip": "192.168.1.100",
            "operation": {
                "algorithm": "aes-256-gcm",
                "key_id": "uuid"
            },
            "outcome": "SUCCESS"
        }
    ],
    "total": 1,
    "request_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Metrics

#### GET /metrics

Get Prometheus-formatted metrics.

**Response (200 OK):**
```
# HELP cxa_requests_total Total HTTP requests
# TYPE cxa_requests_total counter
cxa_requests_total 1234

# HELP cxa_encrypt_ops_total Total encryption operations
# TYPE cxa_encrypt_ops_total counter
cxa_encrypt_ops_total 567

# HELP cxa_request_duration_seconds Request duration in seconds
# TYPE cxa_request_duration_seconds histogram
cxa_request_duration_seconds_bucket{le="0.005"} 100
cxa_request_duration_seconds_bucket{le="0.01"} 200
cxa_request_duration_seconds_bucket{le="0.025"} 500
cxa_request_duration_seconds_bucket{le="0.05"} 800
cxa_request_duration_seconds_bucket{le="0.1"} 1000
cxa_request_duration_seconds_bucket{le="0.25"} 1200
cxa_request_duration_seconds_bucket{le="0.5"} 1230
cxa_request_duration_seconds_bucket{le="1.0"} 1234
cxa_request_duration_seconds_bucket{le="+Inf"} 1234
cxa_request_duration_seconds_sum 12.34
cxa_request_duration_seconds_count 1234
```

## WebSocket API

### Connection

Connect to `wss://api.example.com/ws` with authentication:

```
Authorization: Bearer <your_api_key>
```

### Message Format

```json
{
    "type": "event",
    "payload": {
        "event_type": "ENCRYPT",
        "timestamp": "2024-01-15T10:30:00Z",
        "data": {...}
    }
}
```

### Subscriptions

Subscribe to specific event types:

```json
{
    "type": "subscribe",
    "channels": ["security_alerts", "key_events"]
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid or missing authentication |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## Versioning

The API uses URL versioning (`/v1`). Backward-incompatible changes will result in a new major version URL.
