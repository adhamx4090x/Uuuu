#!/bin/bash
set -e

# CXA Deployment Guide
# This document provides instructions for deploying CXA in various environments

echo "=========================================="
echo "CXA Cryptographic System - Deployment"
echo "=========================================="

# Table of Contents
echo ""
echo "Table of Contents:"
echo "1. Quick Start (Docker)"
echo "2. Manual Deployment"
echo "3. Kubernetes Deployment"
echo "4. Configuration"
echo "5. Security Hardening"
echo "6. Monitoring"
echo "7. Troubleshooting"

# Section 1: Quick Start with Docker
section1() {
    echo ""
    echo "=========================================="
    echo "1. Quick Start (Docker)"
    echo "=========================================="
    
    echo ""
    echo "Prerequisites:"
    echo "- Docker 20.10+"
    echo "- Docker Compose 2.0+"
    echo "- 2GB available RAM"
    echo "- 1GB available disk space"
    
    echo ""
    echo "Steps:"
    echo ""
    echo "1. Clone and build images:"
    echo "   git clone <repository>"
    echo "   docker-compose build"
    echo ""
    echo "2. Initialize configuration:"
    echo "   cp config/default.yml config/local.yml"
    echo "   # Edit config/local.yml with your settings"
    echo ""
    echo "3. Start services:"
    echo "   docker-compose up -d"
    echo ""
    echo "4. Verify deployment:"
    echo "   curl https://localhost:8443/health"
    echo ""
    echo "Expected output:"
    echo "   {\"status\":\"healthy\",\"components\":{\"crypto\":true,\"keyManager\":true}}"
}

# Section 2: Manual Deployment
section2() {
    echo ""
    echo "=========================================="
    echo "2. Manual Deployment"
    echo "=========================================="
    
    echo ""
    echo "2.1 Server Preparation"
    echo "----------------------"
    echo "Create dedicated user:"
    echo "   useradd -r -s /sbin/nologin cxa"
    echo ""
    echo "Create directories:"
    echo "   mkdir -p /var/lib/cxa/{keys,backups,logs}"
    echo "   chown -R cxa:cxa /var/lib/cxa"
    echo "   chmod 700 /var/lib/cxa/keys"
    
    echo ""
    echo "2.2 Install Dependencies"
    echo "------------------------"
    echo "Ubuntu/Debian:"
    echo "   apt-get update"
    echo "   apt-get install -y python3.11 python3-pip libssl-dev"
    echo ""
    echo "RHEL/CentOS:"
    echo "   yum install -y python3.11 openssl-devel"
    
    echo ""
    echo "2.3 Deploy Application"
    echo "----------------------"
    echo "Extract distribution:"
    echo "   tar -xzf cxa-linux-x86_64-*.tar.gz"
    echo "   cd cxa-linux-x86_64-*"
    echo ""
    echo "Install Python dependencies:"
    echo "   pip install -r requirements.txt"
    echo ""
    echo "Copy configuration:"
    echo "   cp config/default.yml /etc/cxa/config.yml"
    echo "   chmod 600 /etc/cxa/config.yml"
    echo ""
    echo "2.4 Configure Service"
    echo "---------------------"
    echo "Create systemd service (/etc/systemd/system/cxa-api.service):"
    cat << 'EOF'
[Unit]
Description=CXA Cryptographic API Server
After=network.target

[Service]
Type=simple
User=cxa
Group=cxa
WorkingDirectory=/opt/cxa
ExecStart=/opt/cxa/bin/api-server --config /etc/cxa/config.yml
Restart=always
RestartSec=10
Environment=CXA_KEY_DIR=/var/lib/cxa/keys
Environment=CXA_LOG_DIR=/var/lib/cxa/logs

[Install]
WantedBy=multi-user.target
EOF
    
    echo ""
    echo "Enable and start service:"
    echo "   systemctl daemon-reload"
    echo "   systemctl enable cxa-api"
    echo "   systemctl start cxa-api"
}

# Section 3: Kubernetes Deployment
section3() {
    echo ""
    echo "=========================================="
    echo "3. Kubernetes Deployment"
    echo "=========================================="
    
    echo ""
    echo "3.1 Namespace and Secrets"
    echo "-------------------------"
    cat << 'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: cxa-system
---
apiVersion: v1
kind: Secret
metadata:
  name: cxa-secrets
  namespace: cxa-system
type: Opaque
stringData:
  master-password: your-secure-password-here
EOF
    
    echo ""
    echo "3.2 Deployment"
    echo "--------------"
    cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cxa-api
  namespace: cxa-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cxa-api
  template:
    metadata:
      labels:
        app: cxa-api
    spec:
      containers:
      - name: cxa-api
        image: cxa/api:latest
        ports:
        - containerPort: 8443
        env:
        - name: CXA_KEY_DIR
          value: /keys
        - name: CXA_LOG_LEVEL
          value: info
        volumeMounts:
        - name: keys
          mountPath: /keys
        - name: logs
          mountPath: /var/log/cxa
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: keys
        emptyDir: {}
      - name: logs
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: cxa-api
  namespace: cxa-system
spec:
  selector:
    app: cxa-api
  ports:
  - port: 443
    targetPort: 8443
  type: ClusterIP
EOF
    
    echo ""
    echo "3.3 Apply to cluster:"
    echo "   kubectl apply -f k8s/"
    echo ""
    echo "3.4 Check status:"
    echo "   kubectl get pods -n cxa-system"
    echo "   kubectl logs -n cxa-system -l app=cxa-api"
}

# Section 4: Configuration
section4() {
    echo ""
    echo "=========================================="
    echo "4. Configuration"
    echo "=========================================="
    
    echo ""
    echo "4.1 Configuration File Structure"
    echo "---------------------------------"
    cat << 'EOF'
# CXA Configuration File
# All paths are relative to the application directory

crypto:
  # Default cryptographic algorithms
  default_symmetric: "aes-256-gcm"
  default_asymmetric: "rsa-4096"
  default_hash: "blake3"
  default_kdf: "argon2id"
  
  # Hardware acceleration
  hardware_acceleration: true
  
  # Secure memory settings
  secure_memory:
    enabled: true
    mlock: true
    wipe_pattern: "zero"

key_management:
  # Key storage configuration
  storage:
    path: "/var/lib/cxa/keys"
    encryption: "aes-256-gcm"
  
  # Key lifecycle
  max_key_age_days: 365
  auto_rotation: true
  rotation_threshold: 0.75  # Rotate at 75% of max age
  
  # Key derivation
  kdf:
    algorithm: "argon2id"
    memory_cost: 65536  # 64 MB
    time_cost: 3
    parallelism: 1

api:
  # API server configuration
  host: "0.0.0.0"
  port: 8443
  
  # TLS configuration
  tls:
    enabled: true
    cert: "/etc/cxa/tls/server.crt"
    key: "/etc/cxa/tls/server.key"
    min_version: "1.3"
  
  # Rate limiting
  rate_limit:
    requests_per_minute: 1000
    burst_size: 100
  
  # CORS
  cors:
    enabled: true
    origins:
      - "https://trusted-domain.com"

monitoring:
  # Logging configuration
  log:
    level: "info"
    format: "json"
    path: "/var/log/cxa"
  
  # Metrics
  metrics:
    enabled: true
    prometheus_port: 9090
  
  # Audit logging
  audit:
    enabled: true
    path: "/var/log/cxa/audit"
    retention_days: 90

backup:
  # Backup configuration
  storage:
    path: "/var/lib/cxa/backups"
    encryption: "aes-256-gcm"
  
  # Retention policy
  retention:
    daily: 7
    weekly: 4
    monthly: 12
EOF
}

# Section 5: Security Hardening
section5() {
    echo ""
    echo "=========================================="
    echo "5. Security Hardening"
    echo "=========================================="
    
    echo ""
    echo "5.1 System Hardening"
    echo "--------------------"
    echo "1. Enable firewall:"
    echo "   ufw allow 8443/tcp"
    echo "   ufw enable"
    echo ""
    echo "2. Disable unnecessary services:"
    echo "   systemctl disable --now avahi-daemon"
    echo "   systemctl disable --now cups"
    echo ""
    echo "3. Configure sysctl for security:"
    cat << 'EOF'
# /etc/sysctl.d/99-cxa-security.conf
kernel.randomize_va_space = 2
kernel.exec-shield = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
EOF
    
    echo ""
    echo "5.2 Application Security"
    echo "-----------------------"
    echo "1. Set restrictive permissions:"
    echo "   chmod 600 /etc/cxa/config.yml"
    echo "   chmod 600 /etc/cxa/tls/*.key"
    echo "   chmod 700 /var/lib/cxa/keys"
    echo ""
    echo "2. Use TLS 1.3 with strong cipher suites:"
    cat << 'EOF'
# Recommended TLS configuration
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
EOF
    
    echo ""
    echo "3. Enable audit logging:"
    echo "   auditctl -w /etc/cxa/ -p rwxa -k cxa-config"
}

# Section 6: Monitoring
section6() {
    echo ""
    echo "=========================================="
    echo "6. Monitoring"
    echo "=========================================="
    
    echo ""
    echo "6.1 Health Checks"
    echo "----------------"
    echo "API health endpoint:"
    echo "   curl https://localhost:8443/health"
    echo ""
    echo "Readiness check:"
    echo "   curl https://localhost:8443/ready"
    echo ""
    echo "Component status:"
    echo "   curl https://localhost:8443/api/v1/status"
    
    echo ""
    echo "6.2 Metrics (Prometheus format)"
    echo "-------------------------------"
    echo "Endpoint: https://localhost:8443/metrics"
    echo ""
    echo "Key metrics:"
    echo "   cxa_requests_total - Total HTTP requests"
    echo "   cxa_requests_active - Active requests"
    echo "   cxa_encrypt_ops_total - Total encryption operations"
    echo "   cxa_decrypt_ops_total - Total decryption operations"
    echo "   cxa_key_generations_total - Total key generations"
    echo "   cxa_errors_total - Total errors"
    
    echo ""
    echo "6.3 Alerting Rules (Prometheus)"
    echo "-------------------------------"
    cat << 'EOF'
groups:
- name: cxa-alerts
  rules:
  - alert: CXAHighErrorRate
    expr: rate(cxa_errors_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "CXA error rate high"
      
  - alert: CXAHighLatency
    expr: histogram_quantile(0.99, rate(cxa_request_duration_seconds_bucket[5m])) > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "CXA request latency high"
EOF
}

# Section 7: Troubleshooting
section7() {
    echo ""
    echo "=========================================="
    echo "7. Troubleshooting"
    echo "=========================================="
    
    echo ""
    echo "7.1 Common Issues"
    echo "-----------------"
    echo ""
    echo "Issue: Service fails to start"
    echo "Solutions:"
    echo "   1. Check logs: journalctl -u cxa-api -n 100"
    echo "   2. Verify configuration: /etc/cxa/config.yml"
    echo "   3. Check permissions: ls -la /var/lib/cxa/"
    echo ""
    echo "Issue: Cannot connect to API"
    echo "Solutions:"
    echo "   1. Verify service is running: systemctl status cxa-api"
    echo "   2. Check port: netstat -tlnp | grep 8443"
    echo "   3. Test locally: curl http://127.0.0.1:8443/health"
    echo ""
    echo "Issue: Encryption failures"
    echo "Solutions:"
    echo "   1. Check key status: cxa keys list"
    echo "   2. Verify key is not expired"
    echo "   3. Check audit logs for specific errors"
    
    echo ""
    echo "7.2 Log Locations"
    echo "-----------------"
    echo "   Application logs: /var/log/cxa/application.log"
    echo "   Audit logs: /var/log/cxa/audit/"
    echo "   System logs: journalctl -u cxa-api"
    
    echo ""
    echo "7.3 Recovery Procedures"
    echo "-----------------------"
    echo "   1. Lost master password - Data cannot be recovered"
    echo "   2. Corrupted keys - Restore from backup"
    echo "   3. Service won't start - Check configuration syntax"
    echo "   4. Performance issues - Check resource usage"
}

# Main
case "${1:-all}" in
    1|quick|docker)
        section1
        ;;
    2|manual)
        section2
        ;;
    3|k8s|kubernetes)
        section3
        ;;
    4|config|configuration)
        section4
        ;;
    5|security|hardening)
        section5
        ;;
    6|monitoring)
        section6
        ;;
    7|troubleshoot|troubleshooting)
        section7
        ;;
    all|"")
        section1
        section2
        section3
        section4
        section5
        section6
        section7
        ;;
    help|--help|-h)
        echo "Usage: $0 [section]"
        echo "Sections: quick, manual, k8s, config, security, monitoring, troubleshooting, all"
        ;;
    *)
        echo "Unknown section: $1"
        echo "Usage: $0 [section]"
        ;;
esac
