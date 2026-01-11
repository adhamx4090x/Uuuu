#!/usr/bin/env python3
"""
CXA Security Monitor Module

This module provides comprehensive security monitoring capabilities for the CXA
Cryptographic System. It tracks security events, detects anomalies, provides
alerts for potential security issues, and implements machine learning-based
threat detection for advanced security analysis.

The security monitoring system is designed to provide real-time visibility into
the security state of the cryptographic system while maintaining minimal
performance overhead. It implements multiple detection mechanisms including
rule-based thresholds, statistical anomaly detection, and machine learning
algorithms for identifying sophisticated threats.

Security Monitoring Features:
- Event logging and comprehensive audit trails
- Real-time anomaly detection with configurable thresholds
- Rate limiting to prevent brute force and abuse
- Alert management with escalation workflows
- Security metrics and statistical reporting
- Configurable alert handlers (console, file, custom)
- Machine learning-based threat detection
- Hybrid detection combining ML and rule-based analysis

Architecture:
The module is organized into several key components:

1. Event System:
   - SecurityEventType: Enumeration of all tracked event types
   - SecurityEvent: Data class representing individual events
   - SecurityLevel: Severity classification for events and alerts

2. Alert System:
   - SecurityAlert: Alert representation with lifecycle tracking
   - AlertStatus: Alert state management (NEW, ACKNOWLEDGED, INVESTIGATING, etc.)
   - IAlertHandler: Interface for alert handling strategies
   - ConsoleAlertHandler: Alerts printed to console
   - FileAlertHandler: Alerts written to log files

3. Detection Systems:
   - AnomalyDetector: Statistical anomaly detection based on event rates
   - RateLimiter: Request rate tracking and enforcement
   - MLThreatDetector: Machine learning-based threat detection
   - ThreatDetectionEngine: Hybrid ML + rule-based detection

4. Main Monitor:
   - CXASecurityMonitor: Central coordinator for all security monitoring

Author: CXA Development Team
Version: 1.0.0
"""

# ============================================================================
# Import Statements
# ============================================================================

# Standard library imports for system operations and utilities
import hashlib         # Hashing utilities for event fingerprinting
import json            # JSON serialization for event storage and transmission
import os              # Operating system functions for file operations
import queue           # Thread-safe queue for event processing
import threading       # Thread synchronization for concurrent processing
import time            # Time functions for timestamps and rate limiting
import uuid            # Unique identifier generation for events and alerts
from abc import ABC, abstractmethod  # Abstract base classes for interfaces
from dataclasses import dataclass, field, asdict  # Data class decorators
from datetime import datetime, timedelta  # Date/time handling with timezone support
from enum import Enum  # Enumeration types for constants
from pathlib import Path  # Object-oriented filesystem paths
from typing import Any, Callable, Dict, List, Optional, Tuple, Set  # Type hints
from collections import deque  # Double-ended queue for sliding window tracking
from statistics import mean, stdev  # Statistical functions for anomaly detection

# Third-party imports for machine learning (optional)
# These are imported conditionally as the ML components are optional
import numpy as np  # Numerical operations for ML feature processing


# ============================================================================
# Event Types and Enumerations
# ============================================================================

# Enumeration classes defining security event categories and severity levels
# These provide type-safe categorization for all security-relevant events


class SecurityEventType(Enum):
    """
    Enumeration of all security event types tracked by the monitoring system.
    
    This enumeration defines the categories of security events that can be
    logged and analyzed. Each event type represents a specific security-relevant
    occurrence in the cryptographic system.
    
    Event Categories:
    
    Authentication Events:
    Track user authentication attempts, successes, failures, and lockouts.
    These are critical for detecting brute force attacks and unauthorized
    access attempts.
    
    Key Management Events:
    Monitor the lifecycle of cryptographic keys including generation, usage,
    expiration, revocation, destruction, import, and export. These events
    help track key material handling and detect potential key compromise.
    
    Encryption Events:
    Record encryption and decryption operations including success and failure
    rates. These metrics help identify operational issues and potential
    attacks on cryptographic operations.
    
    Backup Events:
    Track backup creation, verification, restoration, and failures. These
    events are important for data integrity and disaster recovery procedures.
    
    System Events:
    Monitor system-level events like startup, shutdown, and configuration
    changes. These provide audit trails for system administration activities.
    
    Security Anomaly Events:
    Events generated by anomaly detection and threat analysis systems.
    These flag potential security issues requiring investigation.
    
    Example:
        >>> event_type = SecurityEventType.AUTH_FAILURE
        >>> print(event_type.value)
        'auth_failure'
    """
    
    # =========================================================================
    # Authentication Events
    # =========================================================================
    
    # Successful authentication event - logged when a user authenticates successfully
    AUTH_SUCCESS = "auth_success"
    
    # Failed authentication event - logged when authentication fails
    AUTH_FAILURE = "auth_failure"
    
    # Account lockout event - logged when an account is temporarily locked
    AUTH_LOCKOUT = "auth_lockout"
    
    # Password change event - logged when a password is changed
    AUTH_PASSWORD_CHANGE = "auth_password_change"
    
    # =========================================================================
    # Key Management Events
    # =========================================================================
    
    # Key generation event - logged when a new cryptographic key is created
    KEY_GENERATED = "key_generated"
    
    # Key usage event - logged when a key is used for cryptographic operations
    KEY_USED = "key_used"
    
    # Key expiration event - logged when a key reaches its expiration date
    KEY_EXPIRED = "key_expired"
    
    # Key revocation event - logged when a key is intentionally revoked
    KEY_REVOKED = "key_revoked"
    
    # Key destruction event - logged when a key is securely destroyed
    KEY_DESTROYED = "key_destroyed"
    
    # Key export event - logged when a key is exported from the system
    KEY_EXPORTED = "key_exported"
    
    # Key import event - logged when a key is imported into the system
    KEY_IMPORTED = "key_imported"
    
    # =========================================================================
    # Encryption Events
    # =========================================================================
    
    # Successful encryption event - logged when encryption completes successfully
    ENCRYPTION_SUCCESS = "encryption_success"
    
    # Encryption failure event - logged when encryption fails
    ENCRYPTION_FAILURE = "encryption_failure"
    
    # Successful decryption event - logged when decryption completes successfully
    DECRYPTION_SUCCESS = "decryption_success"
    
    # Decryption failure event - logged when decryption fails
    DECRYPTION_FAILURE = "decryption_failure"
    
    # =========================================================================
    # Backup Events
    # =========================================================================
    
    # Backup creation event - logged when a new backup is created
    BACKUP_CREATED = "backup_created"
    
    # Backup verification event - logged when a backup is verified
    BACKUP_VERIFIED = "backup_verified"
    
    # Backup restoration event - logged when data is restored from backup
    BACKUP_RESTORED = "backup_restored"
    
    # Backup failure event - logged when backup operations fail
    BACKUP_FAILED = "backup_failed"
    
    # =========================================================================
    # System Events
    # =========================================================================
    
    # System startup event - logged when the system or component starts
    SYSTEM_START = "system_start"
    
    # System shutdown event - logged when the system or component stops
    SYSTEM_STOP = "system_stop"
    
    # Configuration change event - logged when system configuration is modified
    CONFIG_CHANGED = "config_changed"
    
    # =========================================================================
    # Security Anomaly Events
    # =========================================================================
    
    # Anomaly detected event - logged when an anomaly is detected
    ANOMALY_DETECTED = "anomaly_detected"
    
    # Suspicious activity event - logged when suspicious patterns are observed
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # Rate limit exceeded event - logged when rate limits are triggered
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # Unauthorized access event - logged when unauthorized access is attempted
    UNAUTHORIZED_ACCESS = "unauthorized_access"


class SecurityLevel(Enum):
    """
    Enumeration of security severity levels for events and alerts.
    
    This enumeration defines the severity levels used to classify security
    events and alerts. Higher values indicate more severe security concerns
    requiring immediate attention.
    
    Severity Hierarchy:
    
    INFO (1):
    Informational events that do not indicate security issues. These are
    logged for audit purposes and operational visibility. Examples include
    successful operations, routine events, and status changes.
    
    LOW (2):
    Minor security events that warrant attention but do not indicate
    immediate threats. Examples include failed login attempts (first failure),
    configuration changes, and informational alerts.
    
    MEDIUM (3):
    Moderate security events that require review. These may indicate
    developing issues or attack attempts. Examples include repeated failed
    logins, encryption failures, and unusual access patterns.
    
    HIGH (4):
    Serious security events requiring prompt investigation. These indicate
    likely security issues or attacks in progress. Examples include account
    lockouts, significant anomalies, and potential data breaches.
    
    CRITICAL (5):
    Severe security events requiring immediate action. These indicate
    active security breaches or critical system issues. Examples include
    successful unauthorized access, key compromise indicators, and
    system integrity failures.
    
    Example:
        >>> level = SecurityLevel.HIGH
        >>> print(level.value)
        4
    """
    
    # Informational - no security impact
    INFO = 1
    
    # Low severity - minor concern
    LOW = 2
    
    # Medium severity - requires review
    MEDIUM = 3
    
    # High severity - requires investigation
    HIGH = 4
    
    # Critical severity - immediate action required
    CRITICAL = 5


class AlertStatus(Enum):
    """
    Enumeration of alert lifecycle states.
    
    This enumeration defines the possible states for security alerts as they
    progress through handling and resolution workflows.
    
    Lifecycle Flow:
    
    NEW (1):
    Initial state when an alert is first created. Alerts in this state
    have not yet been reviewed or acknowledged by security personnel.
    
    ACKNOWLEDGED (2):
    Alert has been reviewed and acknowledged by security personnel.
    The alert is recognized as valid and under investigation.
    
    INVESTIGATING (3):
    Active investigation is in progress. Security personnel are
    analyzing the alert and gathering additional information.
    
    RESOLVED (4):
    The issue has been addressed and the alert is resolved.
    The root cause has been identified and remediated.
    
    DISMISSED (5):
    The alert was determined to be false positive or non-actionable
    and has been dismissed without remediation.
    
    Example:
        >>> status = AlertStatus.INVESTIGATING
        >>> print(status.value)
        3
    """
    
    # Alert is new and unreviewed
    NEW = "new"
    
    # Alert has been acknowledged
    ACKNOWLEDGED = "acknowledged"
    
    # Alert is under active investigation
    INVESTIGATING = "investigating"
    
    # Alert has been resolved
    RESOLVED = "resolved"
    
    # Alert was dismissed
    DISMISSED = "dismissed"


# ============================================================================
# Event and Alert Data Classes
# ============================================================================

# Data structures for representing security events and alerts


@dataclass
class SecurityEvent:
    """
    Data class representing a single security event.
    
    This class encapsulates all information about a security event including
    its type, severity, source, and contextual details. Events are the
    fundamental unit of security monitoring.
    
    Attributes:
        event_id: Unique identifier for this event (UUID format)
        event_type: Classification of the event (e.g., AUTH_FAILURE)
        timestamp: When the event occurred (UTC timezone)
        source: Module or component that generated the event
        level: Security severity level of the event
        user_id: Associated user identifier (if applicable)
        session_id: Associated session identifier (if applicable)
        details: Additional event-specific information dictionary
        ip_address: Source IP address (if applicable)
    
    Example:
        >>> event = SecurityEvent.create(
        ...     event_type=SecurityEventType.AUTH_FAILURE,
        ...     source="auth_module",
        ...     level=SecurityLevel.LOW,
        ...     user_id="user123",
        ...     reason="Invalid password"
        ... )
        >>> print(event.event_id)
        '550e8400-e29b-41d4-a716-446655440000'
    """
    
    # Unique event identifier
    event_id: str
    
    # Type classification of the event
    event_type: SecurityEventType
    
    # When the event occurred
    timestamp: datetime
    
    # Source module/component
    source: str
    
    # Security severity level
    level: SecurityLevel
    
    # Associated user identifier (None if not applicable)
    user_id: Optional[str]
    
    # Associated session identifier (None if not applicable)
    session_id: Optional[str]
    
    # Additional event-specific details
    details: Dict[str, Any]
    
    # Source IP address (None if not applicable)
    ip_address: Optional[str]
    
    @classmethod
    def create(
        cls,
        event_type: SecurityEventType,
        source: str,
        level: SecurityLevel,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ) -> 'SecurityEvent':
        """
        Factory method to create a new SecurityEvent with auto-generated fields.
        
        This method provides a convenient way to create events with automatic
        UUID generation and timestamp creation. Additional details can be
        passed as keyword arguments.
        
        Args:
            event_type: Classification of the security event
            source: Module or component generating the event
            level: Security severity level
            user_id: Optional user identifier associated with the event
            session_id: Optional session identifier
            ip_address: Optional source IP address
            **kwargs: Additional event-specific details merged into details dict
        
        Returns:
            SecurityEvent: A new event instance with auto-generated fields
        """
        return cls(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.utcnow(),
            source=source,
            level=level,
            user_id=user_id,
            session_id=session_id,
            details=kwargs,
            ip_address=ip_address
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary representation.
        
        This method serializes the event to a dictionary suitable for
        JSON serialization or storage in databases.
        
        Returns:
            Dict containing all event fields with enum values converted to strings
        """
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'level': self.level.value,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'details': self.details,
            'ip_address': self.ip_address
        }
    
    def to_json(self) -> str:
        """
        Convert the event to a JSON string representation.
        
        Returns:
            JSON string representation of the event
        """
        return json.dumps(self.to_dict())


@dataclass
class SecurityAlert:
    """
    Data class representing a security alert requiring attention.
    
    This class encapsulates all information about a security alert including
    its title, description, severity, status, and lifecycle tracking. Alerts
    are generated from events that meet certain severity or anomaly criteria.
    
    Attributes:
        alert_id: Unique identifier for this alert (UUID format)
        event_id: ID of the triggering event
        title: Brief summary of the alert
        description: Detailed description of the alert
        level: Security severity level of the alert
        status: Current lifecycle state of the alert
        created_at: When the alert was created (UTC)
        acknowledged_at: When the alert was acknowledged (None if not yet)
        resolved_at: When the alert was resolved (None if not yet)
        assigned_to: Person or team assigned to handle the alert
        notes: List of investigation notes added over time
        related_events: List of event IDs related to this alert
    
    Example:
        >>> alert = SecurityAlert.from_event(
        ...     event=some_event,
        ...     title="Multiple Failed Logins",
        ...     description="5 failed login attempts from IP 192.168.1.100"
        ... )
        >>> print(alert.status.value)
        'new'
    """
    
    # Unique alert identifier
    alert_id: str
    
    # ID of the event that triggered this alert
    event_id: str
    
    # Brief alert title
    title: str
    
    # Detailed alert description
    description: str
    
    # Security severity level
    level: SecurityLevel
    
    # Current lifecycle status
    status: AlertStatus
    
    # When the alert was created
    created_at: datetime
    
    # When the alert was acknowledged (None if not acknowledged)
    acknowledged_at: Optional[datetime]
    
    # When the alert was resolved (None if not resolved)
    resolved_at: Optional[datetime]
    
    # Person or team assigned to handle the alert
    assigned_to: Optional[str]
    
    # List of investigation notes
    notes: List[str]
    
    # List of related event IDs
    related_events: List[str]
    
    @classmethod
    def from_event(cls, event: SecurityEvent, title: str, description: str) -> 'SecurityAlert':
        """
        Factory method to create an alert from a security event.
        
        This method creates an alert linked to a triggering event with
        automatic lifecycle field initialization.
        
        Args:
            event: The security event triggering this alert
            title: Brief summary title for the alert
            description: Detailed description of the alert
        
        Returns:
            SecurityAlert: A new alert instance linked to the event
        """
        return cls(
            alert_id=str(uuid.uuid4()),
            event_id=event.event_id,
            title=title,
            description=description,
            level=event.level,
            status=AlertStatus.NEW,
            created_at=datetime.utcnow(),
            acknowledged_at=None,
            resolved_at=None,
            assigned_to=None,
            notes=[],
            related_events=[event.event_id]
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the alert to a dictionary representation.
        
        Returns:
            Dict containing all alert fields with proper type conversions
        """
        return {
            'alert_id': self.alert_id,
            'event_id': self.event_id,
            'title': self.title,
            'description': self.description,
            'level': self.level.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'related_events': self.related_events
        }


# ============================================================================
# Alert Handler Interface and Implementations
# ============================================================================

# Abstract interface and concrete implementations for handling alerts


class IAlertHandler(ABC):
    """
    Abstract interface for security alert handlers.
    
    This interface defines the contract for alert handling strategies.
    Different handlers can implement different behaviors for processing
    and responding to security alerts.
    
    Implementations:
    - ConsoleAlertHandler: Prints alerts to console for development/debugging
    - FileAlertHandler: Writes alerts to log files for persistence
    - Custom handlers can integrate with SIEM systems, notification services, etc.
    
    Example:
        >>> handler: IAlertHandler = ConsoleAlertHandler()
        >>> handler.handle_alert(some_alert)
    """
    
    @abstractmethod
    def handle_alert(self, alert: SecurityAlert) -> None:
        """
        Process a security alert.
        
        Args:
            alert: The security alert to process
        """
        pass
    
    @abstractmethod
    def handle_event(self, event: SecurityEvent) -> Optional[SecurityAlert]:
        """
        Process an event and optionally create an alert.
        
        This method is called for each security event and can generate
        alerts based on event characteristics.
        
        Args:
            event: The security event to process
        
        Returns:
            SecurityAlert if an alert should be generated, None otherwise
        """
        pass


class ConsoleAlertHandler(IAlertHandler):
    """
    Alert handler that prints alerts to the console.
    
    This handler is primarily used for development, debugging, and
    testing environments where alerts need visible output but
    persistence is not required.
    
    Features:
    - Color-coded severity level indicators
    - Structured output format for readability
    - No external dependencies
    
    Limitations:
    - Alerts are not persisted
    - Output is only visible while console is active
    - Not suitable for production environments
    
    Example:
        >>> handler = ConsoleAlertHandler()
        >>> handler.handle_alert(alert)
        [HIGH] ALERT: Multiple Failed Login Attempts
          5 failed attempts from IP 192.168.1.100
          Alert ID: 550e8400-e29b-41d4-a716-446655440000
    """
    
    def handle_alert(self, alert: SecurityAlert) -> None:
        """
        Print the alert to console with formatted output.
        
        Args:
            alert: The security alert to display
        """
        # Map severity level to display string
        level_str = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][alert.level.value - 1]
        
        # Print formatted alert
        print(f"[{level_str}] ALERT: {alert.title}")
        print(f"  {alert.description}")
        print(f"  Alert ID: {alert.alert_id}")
        print()
    
    def handle_event(self, event: SecurityEvent) -> Optional[SecurityAlert]:
        """
        Check if an event should generate an alert and create one if needed.
        
        This implementation creates alerts for HIGH severity events and above.
        
        Args:
            event: The security event to evaluate
        
        Returns:
            SecurityAlert for high/critical events, None otherwise
        """
        # Generate alerts for high and critical severity events
        if event.level.value >= SecurityLevel.HIGH.value:
            return SecurityAlert.from_event(
                event,
                f"High severity event: {event.event_type.value}",
                f"Security event of high severity detected from {event.source}"
            )
        return None


class FileAlertHandler(IAlertHandler):
    """
    Alert handler that writes alerts to a log file.
    
    This handler provides persistent storage of alerts for production
    environments and audit compliance. Alerts are appended to a
    JSON Lines format file.
    
    Features:
    - Persistent storage of all alerts
    - JSON Lines format for easy parsing
    - Thread-safe file operations
    - Automatic directory creation
    
    Format:
    Each line is a JSON object representing one alert:
    {"alert_id": "...", "event_id": "...", "title": "...", ...}
    
    Example:
        >>> handler = FileAlertHandler("/var/log/cxa/alerts.log")
        >>> handler.handle_alert(alert)
        # Appends JSON line to /var/log/cxa/alerts.log
    """
    
    def __init__(self, log_path: str):
        """
        Initialize the file alert handler.
        
        Args:
            log_path: Path to the alert log file
        
        Raises:
            OSError: If parent directory cannot be created
        """
        self._log_path = Path(log_path)
        
        # Ensure parent directory exists
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread lock for file operations
        self._lock = threading.Lock()
    
    def handle_alert(self, alert: SecurityAlert) -> None:
        """
        Append the alert to the log file.
        
        Args:
            alert: The security alert to log
        """
        # Use thread lock for safe concurrent access
        with self._lock:
            with self._log_path.open('a') as f:
                f.write(alert.to_json() + "\n")
    
    def handle_event(self, event: SecurityEvent) -> Optional[SecurityAlert]:
        """
        Check if an event should generate an alert and create one if needed.
        
        Identical logic to ConsoleAlertHandler - creates alerts for
        HIGH severity events and above.
        
        Args:
            event: The security event to evaluate
        
        Returns:
            SecurityAlert for high/critical events, None otherwise
        """
        if event.level.value >= SecurityLevel.HIGH.value:
            return SecurityAlert.from_event(
                event,
                f"High severity event: {event.event_type.value}",
                f"Security event of high severity detected from {event.source}"
            )
        return None


# ============================================================================
# Anomaly Detection
# ============================================================================

class AnomalyDetector:
    """
    Statistical anomaly detector for security event patterns.
    
    This class monitors event occurrence rates over time windows and
    detects statistical anomalies that may indicate security issues.
    It uses a sliding window approach to track event frequencies
    and compares current rates against baseline expectations.
    
    Detection Method:
    The detector maintains a time-based window of recent events and
    calculates the event rate within that window. When the current
    rate exceeds a threshold multiple of the baseline rate, an
    anomaly alert is generated.
    
    Features:
    - Sliding window event rate tracking
    - Configurable time windows and thresholds
    - Baseline rate learning from observed data
    - Thread-safe operation
    
    Use Cases:
    - Detecting sudden spikes in failed login attempts
    - Identifying unusual encryption activity patterns
    - Monitoring for automated scanning or attacks
    
    Example:
        >>> detector = AnomalyDetector(window_seconds=300, threshold_multiplier=3.0)
        >>> alert = detector.record_event(SecurityEventType.AUTH_FAILURE)
        >>> if alert:
        ...     print(f"Anomaly detected: {alert.title}")
    """
    
    def __init__(self, window_seconds: int = 300, threshold_multiplier: float = 3.0):
        """
        Initialize the anomaly detector with detection parameters.
        
        Args:
            window_seconds: Time window size for rate calculation (default: 5 minutes)
            threshold_multiplier: Multiplier for baseline rate to trigger alert
                (default: 3.0, meaning 3x above baseline triggers alert)
        """
        # Detection parameters
        self._window_seconds = window_seconds
        self._threshold_multiplier = threshold_multiplier
        
        # Event tracking: maps event type to timestamps
        self._event_timestamps: Dict[str, List[datetime]] = {}
        
        # Baseline rates: maps event type to expected events per second
        self._baseline_rates: Dict[str, float] = {}
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
    
    def record_event(self, event_type: SecurityEventType) -> Optional[SecurityAlert]:
        """
        Record an event and check for rate anomalies.
        
        This method adds the current event to the tracking system and
        checks if the event rate has exceeded the anomaly threshold.
        
        Args:
            event_type: The type of event being recorded
        
        Returns:
            SecurityAlert if an anomaly is detected, None otherwise
        """
        with self._lock:
            event_key = event_type.value
            
            # Initialize tracking for new event types
            if event_key not in self._event_timestamps:
                self._event_timestamps[event_key] = []
            
            # Record current timestamp
            now = datetime.utcnow()
            self._event_timestamps[event_key].append(now)
            
            # Check for rate anomaly
            return self._check_rate_anomaly(event_key, now)
    
    def _check_rate_anomaly(self, event_key: str, now: datetime) -> Optional[SecurityAlert]:
        """
        Analyze event rate and detect anomalies.
        
        This internal method calculates the current event rate within
        the configured time window and compares it against the baseline.
        
        Args:
            event_key: The event type key to check
            now: Current timestamp for window calculation
        
        Returns:
            SecurityAlert if rate is anomalous, None otherwise
        """
        timestamps = self._event_timestamps[event_key]
        
        # Need sufficient history for meaningful analysis
        if len(timestamps) < 10:
            return None
        
        # Calculate events within the sliding window
        window_start = now - timedelta(seconds=self._window_seconds)
        recent_events = [t for t in timestamps if t > window_start]
        
        # Need minimum events in window for rate calculation
        if len(recent_events) < 5:
            return None
        
        # Get baseline rate (default to 1 event per second if not set)
        baseline = self._baseline_rates.get(event_key, 1.0)
        
        # Calculate current rate (events per second)
        current_rate = len(recent_events) / self._window_seconds
        
        # Calculate deviation from baseline
        if baseline > 0:
            deviation = (current_rate - baseline) / baseline
            
            # Check if deviation exceeds threshold
            if deviation > self._threshold_multiplier:
                return SecurityAlert(
                    alert_id=str(uuid.uuid4()),
                    event_id="",
                    title=f"Anomalous event rate: {event_key}",
                    description=f"Event rate {deviation:.1f}x above baseline",
                    level=SecurityLevel.HIGH,
                    status=AlertStatus.NEW,
                    created_at=now,
                    acknowledged_at=None,
                    resolved_at=None,
                    assigned_to=None,
                    notes=[],
                    related_events=[]
                )
        
        return None
    
    def update_baseline(self, event_type: SecurityEventType, rate: float) -> None:
        """
        Update the baseline event rate for an event type.
        
        This method allows external calibration of baseline rates based
        on observed normal activity patterns.
        
        Args:
            event_type: The event type to update
            rate: Expected events per second under normal conditions
        """
        with self._lock:
            self._baseline_rates[event_type.value] = rate


# ============================================================================
# Rate Limiter
# ============================================================================

class RateLimiter:
    """
    Rate limiter for preventing brute force attacks and abuse.
    
    This class tracks request rates from different identifiers (IP addresses,
    user IDs, etc.) and enforces configurable rate limits. When limits are
    exceeded, requests are blocked and can trigger security alerts.
    
    Features:
    - Per-identifier rate tracking
    - Configurable request limits and time windows
    - Thread-safe operation
    - Remaining request counts for API responses
    
    Use Cases:
    - Preventing brute force password attacks
    - Limiting API call frequency
    - Blocking aggressive automated scanning
    - Protecting against denial of service attacks
    
    Algorithm:
    Uses a sliding window approach with a deque to track request timestamps.
    Old requests outside the window are removed, and the current count
    determines if new requests are allowed.
    
    Example:
        >>> limiter = RateLimiter(max_requests=100, window_seconds=60)
        >>> allowed, remaining = limiter.is_allowed("192.168.1.100")
        >>> if not allowed:
        ...     print("Rate limit exceeded")
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Initialize the rate limiter with limits.
        
        Args:
            max_requests: Maximum requests allowed per time window
            window_seconds: Duration of each time window in seconds
        """
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        
        # Request history: maps identifier to timestamps
        self._request_history: Dict[str, deque] = {}
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if a request from the identifier is allowed.
        
        This method checks if the identifier has exceeded their rate limit
        within the current time window.
        
        Args:
            identifier: Unique identifier (IP address, user ID, etc.)
        
        Returns:
            Tuple of (allowed: bool, remaining_requests: int)
        """
        with self._lock:
            now = datetime.utcnow()
            
            # Initialize tracking for new identifiers
            if identifier not in self._request_history:
                self._request_history[identifier] = deque()
            
            # Remove expired requests from the window
            window_start = now - timedelta(seconds=self._window_seconds)
            while self._request_history[identifier] and \
                  self._request_history[identifier][0] < window_start:
                self._request_history[identifier].popleft()
            
            # Check if limit has been reached
            if len(self._request_history[identifier]) >= self._max_requests:
                return False, 0
            
            # Record this request
            self._request_history[identifier].append(now)
            
            # Calculate remaining requests
            remaining = self._max_requests - len(self._request_history[identifier])
            return True, remaining
    
    def get_remaining(self, identifier: str) -> int:
        """
        Get the number of remaining allowed requests.
        
        Args:
            identifier: The identifier to check
        
        Returns:
            Number of requests remaining in the current window
        """
        with self._lock:
            if identifier not in self._request_history:
                return self._max_requests
            
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=self._window_seconds)
            recent = [t for t in self._request_history[identifier] if t > window_start]
            
            return max(0, self._max_requests - len(recent))
    
    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for an identifier (e.g., after admin review).
        
        Args:
            identifier: The identifier to reset
        """
        with self._lock:
            if identifier in self._request_history:
                self._request_history[identifier].clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiter statistics.
        
        Returns:
            Dictionary with limiter configuration and statistics
        """
        with self._lock:
            return {
                'tracked_identifiers': len(self._request_history),
                'max_requests': self._max_requests,
                'window_seconds': self._window_seconds
            }


# ============================================================================
# Security Metrics
# ============================================================================

@dataclass
class SecurityMetrics:
    """
    Data class representing a snapshot of security metrics.
    
    This class encapsulates comprehensive security statistics at a point
    in time, including event counts, alert status, and system health.
    
    Attributes:
        timestamp: When these metrics were collected
        total_events: Total events processed since system start
        events_by_type: Count of events grouped by type
        events_by_level: Count of events grouped by severity
        active_alerts: Number of unresolved alerts
        new_alerts_24h: Alerts created in the last 24 hours
        rate_limiter_stats: Rate limiter statistics
        anomaly_count: Total anomalies detected
    """
    
    # When metrics were collected
    timestamp: datetime
    
    # Total events processed
    total_events: int
    
    # Events grouped by type
    events_by_type: Dict[str, int]
    
    # Events grouped by severity level
    events_by_level: Dict[str, int]
    
    # Number of unresolved alerts
    active_alerts: int
    
    # Alerts created in last 24 hours
    new_alerts_24h: int
    
    # Rate limiter statistics
    rate_limiter_stats: Dict[str, Any]
    
    # Total anomaly count
    anomaly_count: int
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metrics to dictionary format.
        
        Returns:
            Dictionary representation suitable for serialization
        """
        return {
            'timestamp': self.timestamp.isoformat(),
            'total_events': self.total_events,
            'events_by_type': {k.value: v for k, v in self.events_by_type.items()},
            'events_by_level': {k.name: v for k, v in self.events_by_level.items()},
            'active_alerts': self.active_alerts,
            'new_alerts_24h': self.new_alerts_24h,
            'rate_limiter_stats': self.rate_limiter_stats,
            'anomaly_count': self.anomaly_count
        }


# ============================================================================
# CXA Security Monitor - Main Class
# ============================================================================

class CXASecurityMonitor:
    """
    Comprehensive security monitoring system for the CXA Cryptographic System.
    
    This class provides the central coordinator for all security monitoring
    activities including event logging, anomaly detection, rate limiting,
    alert management, and metrics reporting. It implements a multi-threaded
    architecture for real-time processing without blocking main operations.
    
    Features:
    - Asynchronous event processing via queue
    - Comprehensive event logging and audit trails
    - Real-time anomaly detection
    - Configurable rate limiting
    - Alert lifecycle management
    - Security metrics and reporting
    - Configurable alert handlers (console, file, custom)
    - Event persistence to log files
    - Automatic cleanup of old data
    
    Architecture:
    
    Event Flow:
    1. Event created via log_event() or helper methods
    2. Event placed in asynchronous processing queue
    3. Background thread processes events:
       - Stores event in memory (up to max_events)
       - Updates statistics and counters
       - Checks for anomalies
       - Applies rate limiting
       - Notifies alert handlers
       - Writes to log file (if configured)
    
    Alert Flow:
    1. Anomaly or rule violation detected
    2. Alert created and added to alerts registry
    3. All registered alert handlers notified
    4. Alert can be acknowledged, investigated, resolved, or dismissed
    
    Thread Safety:
    - All public methods are thread-safe
    - Internal state protected by locks
    - Background processing uses daemon thread
    
    Example:
        >>> monitor = CXASecurityMonitor(log_dir="/var/log/cxa")
        >>> monitor.start()
        >>> monitor.log_event(SecurityEventType.AUTH_SUCCESS, "auth", SecurityLevel.INFO, user_id="user123")
        >>> alerts = monitor.get_active_alerts()
        >>> metrics = monitor.get_metrics()
        >>> monitor.stop()
    
    Author: CXA Development Team
    Version: 1.0.0
    """
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize the security monitor.
        
        Args:
            log_dir: Optional directory for event logs (None = in-memory only)
        """
        # Event queue for asynchronous processing
        self._event_queue: queue.Queue = queue.Queue()
        
        # Registered alert handlers
        self._alert_handlers: List[IAlertHandler] = []
        
        # Alert registry by ID
        self._alerts: Dict[str, SecurityAlert] = {}
        
        # Event storage
        self._events: List[SecurityEvent] = []
        
        # Statistics counters
        self._event_types: Dict[str, int] = {}
        self._event_levels: Dict[SecurityLevel, int] = {}
        
        # Detection components
        self._anomaly_detector = AnomalyDetector()
        self._rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        
        # Configuration
        self._log_dir = Path(log_dir) if log_dir else None
        self._max_events = 10000
        self._retention_days = 30
        
        # Threading
        self._running = False
        self._processor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Register default console handler
        self.register_alert_handler(ConsoleAlertHandler())
        
        # Configure file logging if directory specified
        if self._log_dir:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            self.register_alert_handler(FileAlertHandler(str(self._log_dir / "alerts.log")))
    
    def start(self) -> None:
        """
        Start the security monitor background processing thread.
        
        This method initializes the event processor thread that handles
        events from the queue. Must be called before logging events
        for full functionality.
        
        Side Effects:
            - Starts background processing thread
            - Logs SYSTEM_START event
        """
        if self._running:
            return
        
        self._running = True
        self._processor_thread = threading.Thread(target=self._process_events, daemon=True)
        self._processor_thread.start()
        
        # Log system start
        self.log_event(
            SecurityEventType.SYSTEM_START,
            "security_monitor",
            SecurityLevel.INFO,
            details={"version": "1.0.0"}
        )
    
    def stop(self) -> None:
        """
        Stop the security monitor background processing.
        
        This method signals the processor thread to stop and waits
        for it to finish. Pending events may not be processed.
        
        Side Effects:
            - Stops background processing thread
            - Logs SYSTEM_STOP event
        """
        if not self._running:
            return
        
        self._running = False
        
        if self._processor_thread:
            self._processor_thread.join(timeout=5)
        
        # Log system stop
        self.log_event(
            SecurityEventType.SYSTEM_STOP,
            "security_monitor",
            SecurityLevel.INFO
        )
    
    def _process_events(self) -> None:
        """
        Background thread function for processing events from the queue.
        
        This method runs in a separate thread and continuously processes
        events from the queue until stopped.
        """
        while self._running:
            try:
                event = self._event_queue.get(timeout=1)
                self._handle_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                # Log error but continue processing
                print(f"Error processing event: {e}")
    
    def _handle_event(self, event: SecurityEvent) -> None:
        """
        Process a single security event.
        
        This method handles all processing for an event including storage,
        statistics, anomaly detection, rate limiting, and alert generation.
        
        Args:
            event: The security event to process
        """
        with self._lock:
            # Store event
            self._events.append(event)
            
            # Trim old events if exceeding limit
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events:]
            
            # Update counters
            self._event_types[event.event_type.value] = \
                self._event_types.get(event.event_type.value, 0) + 1
            self._event_levels[event.level] = \
                self._event_levels.get(event.level, 0) + 1
        
        # Check for anomalies
        alert = self._anomaly_detector.record_event(event.event_type)
        if alert:
            self._add_alert(alert)
        
        # Check rate limiting for failure events
        if event.event_type in [
            SecurityEventType.AUTH_FAILURE,
            SecurityEventType.ENCRYPTION_FAILURE,
            SecurityEventType.DECRYPTION_FAILURE
        ]:
            if event.ip_address:
                allowed, remaining = self._rate_limiter.is_allowed(event.ip_address)
                if not allowed:
                    rate_limit_alert = SecurityAlert(
                        alert_id=str(uuid.uuid4()),
                        event_id=event.event_id,
                        title="Rate limit exceeded",
                        description=f"Too many failed operations from {event.ip_address}",
                        level=SecurityLevel.HIGH,
                        status=AlertStatus.NEW,
                        created_at=datetime.utcnow(),
                        acknowledged_at=None,
                        resolved_at=None,
                        assigned_to=None,
                        notes=[],
                        related_events=[event.event_id]
                    )
                    self._add_alert(rate_limit_alert)
        
        # Process through alert handlers
        for handler in self._alert_handlers:
            try:
                alert = handler.handle_event(event)
                if alert:
                    self._add_alert(alert)
            except Exception as e:
                print(f"Error in alert handler: {e}")
        
        # Write to file if configured
        if self._log_dir:
            self._write_event_to_file(event)
    
    def _write_event_to_file(self, event: SecurityEvent) -> None:
        """
        Write event to daily log file.
        
        Args:
            event: The event to log
        """
        try:
            date_str = event.timestamp.strftime("%Y-%m-%d")
            log_file = self._log_dir / f"events_{date_str}.log"
            
            with log_file.open('a') as f:
                f.write(event.to_json() + "\n")
        except Exception:
            pass
    
    def _add_alert(self, alert: SecurityAlert) -> None:
        """
        Add an alert and notify all handlers.
        
        Args:
            alert: The alert to add
        """
        with self._lock:
            self._alerts[alert.alert_id] = alert
        
        for handler in self._alert_handlers:
            try:
                handler.handle_alert(alert)
            except Exception as e:
                print(f"Error in alert handler: {e}")
    
    def log_event(
        self,
        event_type: SecurityEventType,
        source: str,
        level: SecurityLevel,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Log a security event for monitoring.
        
        This is the primary method for recording security events. Events
        are queued for asynchronous processing to avoid blocking the caller.
        
        Args:
            event_type: Type of security event
            source: Module or component generating the event
            level: Security severity level
            user_id: Optional associated user identifier
            session_id: Optional associated session identifier
            ip_address: Optional source IP address
            **kwargs: Additional event-specific details
        
        Returns:
            The generated event ID (UUID string)
        """
        # Create event
        event = SecurityEvent.create(
            event_type=event_type,
            source=source,
            level=level,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            **kwargs
        )
        
        # Queue for processing
        self._event_queue.put(event)
        
        return event.event_id
    
    def log_auth_success(
        self,
        user_id: str,
        source: str = "auth_module",
        **kwargs
    ) -> str:
        """
        Log a successful authentication event.
        
        Args:
            user_id: The authenticated user identifier
            source: Optional source module (default: auth_module)
            **kwargs: Additional event details
        
        Returns:
            The generated event ID
        """
        return self.log_event(
            SecurityEventType.AUTH_SUCCESS,
            source,
            SecurityLevel.INFO,
            user_id=user_id,
            **kwargs
        )
    
    def log_auth_failure(
        self,
        user_id: str,
        source: str = "auth_module",
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Log an authentication failure event.
        
        Args:
            user_id: The user who failed authentication
            source: Optional source module
            reason: Optional failure reason
            ip_address: Optional source IP address
            **kwargs: Additional event details
        
        Returns:
            The generated event ID
        """
        return self.log_event(
            SecurityEventType.AUTH_FAILURE,
            source,
            SecurityLevel.LOW,
            user_id=user_id,
            ip_address=ip_address,
            reason=reason,
            **kwargs
        )
    
    def log_encryption(
        self,
        success: bool,
        source: str = "encryption_module",
        **kwargs
    ) -> str:
        """
        Log an encryption operation event.
        
        Args:
            success: Whether the operation succeeded
            source: Optional source module
            **kwargs: Additional event details
        
        Returns:
            The generated event ID
        """
        event_type = SecurityEventType.ENCRYPTION_SUCCESS if success else SecurityEventType.ENCRYPTION_FAILURE
        level = SecurityLevel.INFO if success else SecurityLevel.MEDIUM
        
        return self.log_event(event_type, source, level, **kwargs)
    
    def log_decryption(
        self,
        success: bool,
        source: str = "decryption_module",
        **kwargs
    ) -> str:
        """
        Log a decryption operation event.
        
        Args:
            success: Whether the operation succeeded
            source: Optional source module
            **kwargs: Additional event details
        
        Returns:
            The generated event ID
        """
        event_type = SecurityEventType.DECRYPTION_SUCCESS if success else SecurityEventType.DECRYPTION_FAILURE
        level = SecurityLevel.INFO if success else SecurityLevel.MEDIUM
        
        return self.log_event(event_type, source, level, **kwargs)
    
    def log_key_operation(
        self,
        operation: str,
        key_id: str,
        source: str = "key_manager",
        **kwargs
    ) -> str:
        """
        Log a key management operation event.
        
        Args:
            operation: Operation type (generated, used, expired, revoked, destroyed, exported, imported)
            key_id: The key identifier
            source: Optional source module
            **kwargs: Additional event details
        
        Returns:
            The generated event ID
        """
        event_map = {
            'generated': SecurityEventType.KEY_GENERATED,
            'used': SecurityEventType.KEY_USED,
            'expired': SecurityEventType.KEY_EXPIRED,
            'revoked': SecurityEventType.KEY_REVOKED,
            'destroyed': SecurityEventType.KEY_DESTROYED,
            'exported': SecurityEventType.KEY_EXPORTED,
            'imported': SecurityEventType.KEY_IMPORTED
        }
        
        event_type = event_map.get(operation.lower())
        if not event_type:
            event_type = SecurityEventType.KEY_USED
        
        return self.log_event(event_type, source, SecurityLevel.INFO, **kwargs)
    
    def register_alert_handler(self, handler: IAlertHandler) -> None:
        """
        Register an alert handler for processing alerts.
        
        Args:
            handler: The alert handler implementation
        """
        with self._lock:
            self._alert_handlers.append(handler)
    
    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        level: Optional[SecurityLevel] = None,
        limit: int = 100
    ) -> List[SecurityAlert]:
        """
        Get alerts with optional filtering.
        
        Args:
            status: Filter by alert status (None = all)
            level: Filter by severity level (None = all)
            limit: Maximum number of alerts to return
        
        Returns:
            List of matching alerts (sorted by creation date, newest first)
        """
        with self._lock:
            alerts = list(self._alerts.values())
        
        # Apply filters
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if level:
            alerts = [a for a in alerts if a.level == level]
        
        # Sort and limit
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]
    
    def acknowledge_alert(self, alert_id: str, assigned_to: Optional[str] = None) -> bool:
        """
        Acknowledge an alert, assigning it for investigation.
        
        Args:
            alert_id: The alert to acknowledge
            assigned_to: Optional person/team assigned
        
        Returns:
            True if alert was found and acknowledged, False otherwise
        """
        with self._lock:
            if alert_id not in self._alerts:
                return False
            
            alert = self._alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
            alert.assigned_to = assigned_to
        
        return True
    
    def resolve_alert(self, alert_id: str, notes: Optional[str] = None) -> bool:
        """
        Resolve an alert after investigation and remediation.
        
        Args:
            alert_id: The alert to resolve
            notes: Optional resolution notes
        
        Returns:
            True if alert was found and resolved, False otherwise
        """
        with self._lock:
            if alert_id not in self._alerts:
                return False
            
            alert = self._alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            
            if notes:
                alert.notes.append(f"[{datetime.utcnow().isoformat()}] {notes}")
        
        return True
    
    def get_active_alerts(self) -> List[SecurityAlert]:
        """
        Get all active (unresolved) alerts.
        
        Returns:
            List of unresolved alerts
        """
        return self.get_alerts(status=AlertStatus.NEW)
    
    def get_events(
        self,
        event_type: Optional[SecurityEventType] = None,
        level: Optional[SecurityLevel] = None,
        source: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[SecurityEvent]:
        """
        Get events with optional filtering.
        
        Args:
            event_type: Filter by event type (None = all)
            level: Filter by severity level (None = all)
            source: Filter by source (None = all)
            since: Filter by timestamp (None = all)
            limit: Maximum events to return
        
        Returns:
            List of matching events (sorted by timestamp, newest first)
        """
        with self._lock:
            events = self._events.copy()
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if level:
            events = [e for e in events if e.level == level]
        
        if source:
            events = [e for e in events if e.source == source]
        
        if since:
            events = [e for e in events if e.timestamp >= since]
        
        # Sort and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
    
    def get_metrics(self) -> SecurityMetrics:
        """
        Get current security metrics snapshot.
        
        Returns:
            SecurityMetrics with current statistics
        """
        with self._lock:
            now = datetime.utcnow()
            day_ago = now - timedelta(days=1)
            
            new_alerts_24h = sum(
                1 for a in self._alerts.values()
                if a.created_at >= day_ago and a.status != AlertStatus.RESOLVED
            )
            
            return SecurityMetrics(
                timestamp=now,
                total_events=len(self._events),
                events_by_type=self._event_types.copy(),
                events_by_level=self._event_levels.copy(),
                active_alerts=len([a for a in self._alerts.values() 
                                  if a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]]),
                new_alerts_24h=new_alerts_24h,
                rate_limiter_stats=self._rate_limiter.get_stats(),
                anomaly_count=sum(
                    1 for e in self._events
                    if e.event_type == SecurityEventType.ANOMALY_DETECTED
                )
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive security statistics.
        
        Returns:
            Dictionary with event, alert, and system statistics
        """
        metrics = self.get_metrics()
        
        return {
            'events': {
                'total': metrics.total_events,
                'by_type': metrics.events_by_type,
                'by_level': {k.name: v for k, v in metrics.events_by_level.items()}
            },
            'alerts': {
                'active': metrics.active_alerts,
                'new_24h': metrics.new_alerts_24h
            },
            'rate_limiter': metrics.rate_limiter_stats,
            'anomalies': metrics.anomaly_count
        }
    
    def cleanup(self, retention_days: Optional[int] = None) -> Dict[str, int]:
        """
        Clean up old events and alerts exceeding retention period.
        
        Args:
            retention_days: Override for default retention period
        
        Returns:
            Dictionary with cleanup statistics (events_removed, alerts_removed)
        """
        if retention_days is None:
            retention_days = self._retention_days
        
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        
        stats = {'events_removed': 0, 'alerts_removed': 0}
        
        with self._lock:
            # Remove old events
            old_events = [e for e in self._events if e.timestamp < cutoff]
            self._events = [e for e in self._events if e.timestamp >= cutoff]
            stats['events_removed'] = len(old_events)
            
            # Remove old resolved alerts
            old_alerts = [
                a for a in self._alerts.values()
                if a.resolved_at and a.resolved_at < cutoff
            ]
            for alert in old_alerts:
                del self._alerts[alert.alert_id]
            stats['alerts_removed'] = len(old_alerts)
        
        return stats


# ============================================================================
# Machine Learning Threat Detection
# ============================================================================

class MLThreatDetector:
    """
    Machine Learning-based threat detection for security monitoring.
    
    This class uses unsupervised learning algorithms to detect anomalous
    patterns in security events that may indicate sophisticated threats
    not caught by rule-based detection.
    
    Supported Algorithms:
    
    Isolation Forest:
    - Excellent for high-dimensional anomaly detection
    - Works by isolating observations through random splits
    - Outliers are isolated quickly, normal points take longer
    - Fast training and inference
    - Good default choice for most scenarios
    
    One-Class SVM:
    - Learns a decision boundary around normal data
    - Good for detecting if a new sample is "normal" or not
    - More computationally expensive than Isolation Forest
    - Better for smaller datasets with clear boundaries
    
    Local Outlier Factor (LOF):
    - Measures local density deviation
    - Good for detecting outliers in datasets with varying densities
    - Excellent for detecting local anomalies
    
    Features Extracted:
    - Request rate (events per time window)
    - Time since last event
    - Event type distribution
    - Failed operation ratio
    - Session duration
    - Data volume patterns
    - Hour of day (cyclical encoding)
    - Day of week (cyclical encoding)
    - Weekend indicator
    - Authentication success rate
    - Encryption/decryption counts
    - Unique endpoints accessed
    - Geographic anomaly score
    - IP reputation score
    
    Security Applications:
    - Detecting brute force attacks (high failure rates)
    - Identifying automated scanning (unusual request patterns)
    - Finding unusual access patterns (time-based anomalies)
    - Flagging potential data exfiltration (high data volumes)
    - Detecting compromised accounts (behavior changes)
    
    Example:
        >>> detector = MLThreatDetector(algorithm="isolation_forest")
        >>> detector.train_baseline(historical_events)
        >>> result = detector.analyze_event(current_event_data)
        >>> if result['is_anomaly']:
        ...     print(f"Threat detected: {result['threat_score']:.2f}")
    
    Author: CXA Development Team
    Version: 2.0.0
    """
    
    def __init__(
        self,
        algorithm: str = "isolation_forest",
        contamination: float = 0.01,
        n_estimators: int = 100,
        random_state: int = 42
    ):
        """
        Initialize ML threat detector with algorithm and parameters.
        
        Args:
            algorithm: Detection algorithm ('isolation_forest', 'one_class_svm', 'lof')
            contamination: Expected proportion of outliers (0.0-0.5)
            n_estimators: Number of estimators for ensemble methods
            random_state: Random seed for reproducibility
        """
        self._algorithm = algorithm
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._random_state = random_state
        self._model = None
        self._is_trained = False
        self._feature_scale = None
        self._training_data = None
        
        # Initialize the model based on algorithm
        self._initialize_model()
    
    def _initialize_model(self) -> None:
        """
        Initialize the ML model based on configured algorithm.
        
        This method attempts to import scikit-learn and create the
        configured model. If scikit-learn is unavailable, the model
        remains None and statistical fallback is used.
        """
        try:
            import sklearn
        except ImportError:
            # scikit-learn not available, use statistical fallback
            self._model = None
            return
        
        if self._algorithm == "isolation_forest":
            # Isolation Forest: Good for high-dimensional anomaly detection
            # Works by isolating observations - random splits isolate outliers faster
            from sklearn.ensemble import IsolationForest
            self._model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=self._random_state,
                n_jobs=-1  # Use all CPU cores
            )
            
        elif self._algorithm == "one_class_svm":
            # One-Class SVM: Learns a decision boundary around normal data
            # Good for detecting if a new sample is "normal" or not
            from sklearn.svm import OneClassSVM
            self._model = OneClassSVM(
                kernel='rbf',  # Radial Basis Function kernel
                gamma='scale',  # Automatic gamma scaling
                nu=self._contamination  # Upper bound on fraction of outliers
            )
            
        elif self._algorithm == "lof":
            # Local Outlier Factor: Measures local density deviation
            # Good for detecting outliers in datasets with varying densities
            from sklearn.neighbors import LocalOutlierFactor
            self._model = LocalOutlierFactor(
                n_neighbors=20,  # Number of neighbors to compare
                contamination=self._contamination,
                novelty=True,  # Enable novelty detection mode
                n_jobs=-1
            )
            
        else:
            # Default to Isolation Forest
            from sklearn.ensemble import IsolationForest
            self._model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=self._random_state,
                n_jobs=-1
            )
    
    def _extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical features from event data for ML model input.
        
        This method converts raw event data into a fixed-length numerical
        feature vector suitable for ML model processing.
        
        Args:
            event_data: Dictionary of event features
        
        Returns:
            NumPy array of extracted features (17 dimensions)
        """
        features = []
        
        # Request rate (normalized to events per minute)
        request_rate = event_data.get('request_rate', 0)
        features.append(min(request_rate / 100, 10))  # Cap at 10x baseline
        
        # Time since last event (log-scaled, seconds)
        time_since = event_data.get('time_since_last_event', 0)
        features.append(np.log1p(time_since) / 10)  # Log scale, normalized
        
        # Failed operation ratio (0-1)
        failed_ratio = event_data.get('failed_ratio', 0)
        features.append(failed_ratio)
        
        # Session duration (log-scaled, minutes)
        session_duration = event_data.get('session_duration', 0)
        features.append(np.log1p(session_duration) / 10)
        
        # Data volume (log-scaled, bytes)
        data_volume = event_data.get('data_volume', 0)
        features.append(np.log1p(data_volume) / 20)
        
        # Event type diversity (Shannon entropy approximation)
        event_types = event_data.get('event_type_counts', {})
        if event_types:
            total = sum(event_types.values())
            diversity = len(event_types) / total if total > 0 else 0
        else:
            diversity = 0
        features.append(diversity)
        
        # Hour of day (0-23, cyclical encoding using sine and cosine)
        hour = event_data.get('hour_of_day', 12)
        features.append(np.sin(2 * np.pi * hour / 24))
        features.append(np.cos(2 * np.pi * hour / 24))
        
        # Day of week (0-6, cyclical encoding)
        dow = event_data.get('day_of_week', 0)
        features.append(np.sin(2 * np.pi * dow / 7))
        features.append(np.cos(2 * np.pi * dow / 7))
        
        # Is weekend (binary)
        is_weekend = event_data.get('is_weekend', False)
        features.append(1 if is_weekend else 0)
        
        # Authentication success rate (0-1)
        auth_success = event_data.get('auth_success_count', 0)
        auth_failure = event_data.get('auth_failure_count', 0)
        auth_total = auth_success + auth_failure
        auth_rate = auth_success / auth_total if auth_total > 0 else 1.0
        features.append(auth_rate)
        
        # Encryption operation count (normalized)
        encrypt_count = event_data.get('encryption_count', 0)
        features.append(min(encrypt_count / 50, 5))
        
        # Decryption operation count (normalized)
        decrypt_count = event_data.get('decryption_count', 0)
        features.append(min(decrypt_count / 50, 5))
        
        # Unique API endpoints accessed (normalized)
        unique_endpoints = event_data.get('unique_endpoints', 0)
        features.append(min(unique_endpoints / 20, 1))
        
        # Geographic anomaly score (0-1)
        geo_anomaly = event_data.get('geo_anomaly_score', 0)
        features.append(geo_anomaly)
        
        # IP reputation score (0-1, higher = more suspicious)
        ip_reputation = event_data.get('ip_reputation_score', 0)
        features.append(ip_reputation)
        
        return np.array(features, dtype=np.float64)
    
    def train_baseline(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the threat detection model on baseline "normal" data.
        
        This method fits the ML model to examples of normal behavior,
        allowing it to later detect deviations from this baseline.
        
        Args:
            training_data: List of event data dictionaries from normal operation
        
        Returns:
            Dictionary with training statistics
        
        Raises:
            ValueError: If insufficient training samples provided
        """
        if len(training_data) < 10:
            raise ValueError(f"Need at least 10 training samples, got {len(training_data)}")
        
        # Extract features from training data
        feature_vectors = []
        for event_data in training_data:
            features = self._extract_features(event_data)
            feature_vectors.append(features)
        
        X_train = np.array(feature_vectors)
        self._training_data = X_train
        
        # Store training data statistics for normalization
        self._feature_scale = {
            'mean': np.mean(X_train, axis=0),
            'std': np.std(X_train, axis=0) + 1e-6  # Avoid division by zero
        }
        
        # Normalize features using z-score normalization
        X_normalized = (X_train - self._feature_scale['mean']) / self._feature_scale['std']
        
        # Train the model if available
        if self._model is not None:
            self._model.fit(X_normalized)
            self._is_trained = True
            
            # Get training statistics
            predictions = self._model.predict(X_normalized)
            n_anomalies = np.sum(predictions == -1)
            anomaly_ratio = n_anomalies / len(predictions)
            
            return {
                'success': True,
                'samples_trained': len(training_data),
                'feature_dimensions': X_train.shape[1],
                'anomalies_in_training': n_anomalies,
                'anomaly_ratio': float(anomaly_ratio),
                'model_type': self._algorithm,
                'contamination': self._contamination
            }
        else:
            # Fallback: use statistical baseline
            self._is_trained = True
            return {
                'success': True,
                'samples_trained': len(training_data),
                'feature_dimensions': X_train.shape[1],
                'anomalies_in_training': 0,
                'anomaly_ratio': 0.0,
                'model_type': 'statistical_fallback',
                'note': 'scikit-learn not available, using statistical baseline'
            }
    
    def analyze_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single event for potential threats.
        
        Args:
            event_data: Event data dictionary to analyze
        
        Returns:
            Dictionary with analysis results including:
            - is_anomaly: bool indicating if event is anomalous
            - threat_score: float (0-1) indicating threat likelihood
            - anomaly_reasons: list of contributing factors
            - recommended_actions: suggested responses
            - confidence: analysis confidence level
        """
        if not self._is_trained:
            return {
                'is_anomaly': False,
                'threat_score': 0.0,
                'anomaly_reasons': ['Model not trained yet'],
                'recommended_actions': ['Train model with baseline data'],
                'confidence': 0.0
            }
        
        # Extract and normalize features
        features = self._extract_features(event_data)
        
        if self._feature_scale is not None:
            features_normalized = (features - self._feature_scale['mean']) / self._feature_scale['std']
        else:
            features_normalized = features
        
        # Analyze based on model type
        if self._model is not None:
            return self._analyze_with_model(features, features_normalized, event_data)
        else:
            return self._analyze_statistical(features, event_data)
    
    def _analyze_with_model(
        self,
        features: np.ndarray,
        features_normalized: np.ndarray,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze event using trained ML model.
        
        Args:
            features: Raw feature vector
            features_normalized: Normalized feature vector
            event_data: Original event data
        
        Returns:
            Analysis result dictionary
        """
        try:
            # Get anomaly prediction (-1 = anomaly, 1 = normal)
            prediction = self._model.predict(features_normalized.reshape(1, -1))[0]
            
            # Get anomaly score (lower = more anomalous for Isolation Forest)
            if hasattr(self._model, 'decision_function'):
                anomaly_score = self._model.decision_function(features_normalized.reshape(1, -1))[0]
                # Convert to 0-1 scale (1 = normal, 0 = anomaly)
                # Threshold at 0 based on sklearn convention
                threat_score = max(0, -anomaly_score / 10 + 1)
            else:
                threat_score = 0.5 if prediction == -1 else 0.0
            
            # Identify contributing factors
            anomaly_reasons = self._identify_anomaly_factors(features, event_data)
            
            # Generate recommendations
            recommended_actions = self._generate_recommendations(
                prediction == -1,
                threat_score,
                anomaly_reasons
            )
            
            return {
                'is_anomaly': prediction == -1,
                'threat_score': float(min(threat_score, 1.0)),
                'anomaly_reasons': anomaly_reasons,
                'recommended_actions': recommended_actions,
                'confidence': 0.85 if self._model is not None else 0.5
            }
            
        except Exception as e:
            return {
                'is_anomaly': False,
                'threat_score': 0.0,
                'anomaly_reasons': [f'Analysis error: {str(e)}'],
                'recommended_actions': ['Review logs manually'],
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _analyze_statistical(
        self,
        features: np.ndarray,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Fallback statistical analysis when ML library is unavailable.
        
        Uses simple threshold-based detection as a fallback.
        
        Args:
            features: Raw feature vector
            event_data: Original event data
        
        Returns:
            Analysis result dictionary
        """
        anomaly_reasons = []
        threat_score = 0.0
        
        # Check request rate
        request_rate = event_data.get('request_rate', 0)
        if request_rate > 100:
            anomaly_reasons.append(f'High request rate: {request_rate}/min')
            threat_score += 0.3
        
        # Check failed operation ratio
        failed_ratio = event_data.get('failed_ratio', 0)
        if failed_ratio > 0.5:
            anomaly_reasons.append(f'High failure rate: {failed_ratio*100:.1f}%')
            threat_score += 0.4
        
        # Check IP reputation
        ip_reputation = event_data.get('ip_reputation_score', 0)
        if ip_reputation > 0.7:
            anomaly_reasons.append('Suspicious IP reputation')
            threat_score += 0.3
        
        return {
            'is_anomaly': threat_score > 0.5,
            'threat_score': min(threat_score, 1.0),
            'anomaly_reasons': anomaly_reasons,
            'recommended_actions': self._generate_recommendations(
                threat_score > 0.5, threat_score, anomaly_reasons
            ),
            'confidence': 0.5,
            'method': 'statistical_fallback'
        }
    
    def _identify_anomaly_factors(
        self,
        features: np.ndarray,
        event_data: Dict[str, Any]
    ) -> List[str]:
        """
        Identify which features contributed to anomaly classification.
        
        Args:
            features: Raw feature values
            event_data: Original event data
        
        Returns:
            List of human-readable anomaly reasons
        """
        reasons = []
        
        # Feature names matching _extract_features order
        feature_names = [
            'request_rate', 'time_since_last', 'failed_ratio', 'session_duration',
            'data_volume', 'event_diversity', 'hour_sin', 'hour_cos',
            'dow_sin', 'dow_cos', 'is_weekend', 'auth_rate',
            'encryption_count', 'decryption_count', 'unique_endpoints',
            'geo_anomaly', 'ip_reputation'
        ]
        
        # Check for extreme values (z-score > 3)
        if self._feature_scale is not None:
            z_scores = np.abs(features - self._feature_scale['mean']) / self._feature_scale['std']
            outliers = z_scores > 3
            
            for i, (is_outlier, name) in enumerate(zip(outliers, feature_names)):
                if is_outlier:
                    reasons.append(f'Unusual {name}: {features[i]:.3f}')
        
        # Add context-specific checks
        failed_ratio = event_data.get('failed_ratio', 0)
        if failed_ratio > 0.3:
            reasons.append(f'High failure ratio: {failed_ratio:.2f}')
        
        ip_reputation = event_data.get('ip_reputation_score', 0)
        if ip_reputation > 0.5:
            reasons.append(f'Suspicious IP: reputation score {ip_reputation:.2f}')
        
        return reasons
    
    def _generate_recommendations(
        self,
        is_anomaly: bool,
        threat_score: float,
        anomaly_reasons: List[str]
    ) -> List[str]:
        """
        Generate recommended actions based on analysis results.
        
        Args:
            is_anomaly: Whether the event was classified as anomalous
            threat_score: Calculated threat score
            anomaly_reasons: List of anomaly contributing factors
        
        Returns:
            List of recommended actions
        """
        recommendations = []
        
        if not is_anomaly:
            recommendations.append('Continue normal monitoring')
            return recommendations
        
        # Threat level based responses
        if threat_score > 0.8:
            recommendations.append('CRITICAL: Immediate investigation required')
            recommendations.append('Consider temporarily blocking the source')
            recommendations.append('Notify security team immediately')
            
        elif threat_score > 0.6:
            recommendations.append('HIGH: Enhanced monitoring recommended')
            recommendations.append('Review recent activity from this source')
            recommendations.append('Consider additional authentication requirements')
            
        elif threat_score > 0.4:
            recommendations.append('MEDIUM: Log for review')
            recommendations.append('Monitor for follow-up activity')
            
        else:
            recommendations.append('LOW: Note in security logs')
        
        # Context-specific recommendations
        for reason in anomaly_reasons:
            if 'failure' in reason.lower():
                recommendations.append('Check for credential issues or brute force attempts')
            if 'request rate' in reason.lower():
                recommendations.append('Consider rate limiting or CAPTCHA')
            if 'IP' in reason.lower():
                recommendations.append('Review IP reputation and geolocation')
            if 'encryption' in reason.lower():
                recommendations.append('Verify encryption operation legitimacy')
        
        return recommendations
    
    def batch_analyze(
        self,
        events_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple events efficiently.
        
        Args:
            events_data: List of event data dictionaries
        
        Returns:
            List of analysis results
        """
        return [self.analyze_event(event) for event in events_data]
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the trained model.
        
        Returns:
            Dictionary with model information
        """
        return {
            'algorithm': self._algorithm,
            'is_trained': self._is_trained,
            'contamination': self._contamination,
            'n_estimators': self._n_estimators,
            'random_state': self._random_state,
            'feature_dimensions': 17 if self._training_data is None else self._training_data.shape[1]
        }
    
    def save_model(self, filepath: str) -> bool:
        """
        Save the trained model to disk.
        
        Args:
            filepath: Path to save model
        
        Returns:
            True if successful, False otherwise
        """
        try:
            import joblib
            
            model_data = {
                'model': self._model,
                'algorithm': self._algorithm,
                'contamination': self._contamination,
                'n_estimators': self._n_estimators,
                'random_state': self._random_state,
                'feature_scale': self._feature_scale,
                'is_trained': self._is_trained,
                'training_data': self._training_data
            }
            
            joblib.dump(model_data, filepath)
            return True
            
        except Exception as e:
            print(f"Failed to save model: {e}")
            return False
    
    def load_model(self, filepath: str) -> bool:
        """
        Load a trained model from disk.
        
        Args:
            filepath: Path to saved model
        
        Returns:
            True if successful, False otherwise
        """
        try:
            import joblib
            
            model_data = joblib.load(filepath)
            
            self._model = model_data['model']
            self._algorithm = model_data['algorithm']
            self._contamination = model_data['contamination']
            self._n_estimators = model_data['n_estimators']
            self._random_state = model_data['random_state']
            self._feature_scale = model_data['feature_scale']
            self._is_trained = model_data['is_trained']
            self._training_data = model_data.get('training_data')
            
            return True
            
        except Exception as e:
            print(f"Failed to load model: {e}")
            return False


class ThreatDetectionEngine:
    """
    High-level threat detection engine integrating ML with rule-based detection.
    
    This class combines ML-based anomaly detection with traditional
    rule-based detection for comprehensive security monitoring. The hybrid
    approach provides both sophisticated pattern recognition and deterministic
    rule enforcement.
    
    Features:
    - Hybrid detection (ML + rules)
    - Real-time event processing
    - Alert generation
    - Model management
    - Historical analysis
    
    Detection Strategy:
    
    ML-Based Detection:
    - Uses trained model to identify anomalous patterns
    - Good for detecting subtle, sophisticated attacks
    - Can identify novel attack patterns not covered by rules
    - May have higher false positive rate
    
    Rule-Based Detection:
    - Uses configurable thresholds for specific indicators
    - Deterministic behavior with clear logic
    - Good for known attack patterns (brute force, etc.)
    - Lower false positive rate
    
    Combined Analysis:
    The engine combines both analyses, taking the maximum threat score
    and union of anomaly factors for comprehensive detection.
    
    Example:
        >>> engine = ThreatDetectionEngine()
        >>> engine.train_baseline(historical_events)
        >>> result = engine.analyze_event("auth_failure", current_event)
        >>> if result['is_anomaly']:
        ...     engine.generate_alert(result)
    """
    
    def __init__(
        self,
        ml_algorithm: str = "isolation_forest",
        ml_contamination: float = 0.01
    ):
        """
        Initialize threat detection engine.
        
        Args:
            ml_algorithm: ML algorithm for anomaly detection
            ml_contamination: Expected anomaly rate in data
        """
        self._ml_detector = MLThreatDetector(
            algorithm=ml_algorithm,
            contamination=ml_contamination
        )
        
        # Rule-based thresholds (can be customized)
        self._thresholds = {
            'max_requests_per_minute': 100,
            'max_failed_ratio': 0.3,
            'max_session_duration_hours': 24,
            'max_data_volume_mb': 1000
        }
        
        # Event history for context
        self._event_history: deque = deque(maxlen=10000)
        self._lock = threading.Lock()
    
    def train_baseline(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the detection model on historical data.
        
        Args:
            training_data: List of historical event data
        
        Returns:
            Training result dictionary
        """
        return self._ml_detector.train_baseline(training_data)
    
    def analyze_event(
        self,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze a security event for potential threats.
        
        This method performs both ML-based and rule-based analysis,
        combining the results for comprehensive threat detection.
        
        Args:
            event_type: Type of security event
            event_data: Event data dictionary
        
        Returns:
            Analysis result with threat assessment including:
            - is_anomaly: Whether threat was detected
            - threat_score: Overall threat score (0-1)
            - anomaly_reasons: Contributing factors
            - recommended_actions: Suggested responses
            - ml_analysis: ML-specific results
            - rule_analysis: Rule-specific results
        """
        with self._lock:
            # Add to history
            self._event_history.append({
                'type': event_type,
                'data': event_data,
                'timestamp': datetime.utcnow()
            })
        
        # Get ML-based analysis
        ml_result = self._ml_detector.analyze_event(event_data)
        
        # Get rule-based analysis
        rule_result = self._analyze_rules(event_type, event_data)
        
        # Combine results - use maximum score
        combined_score = max(ml_result['threat_score'], rule_result['threat_score'])
        is_anomaly = ml_result['is_anomaly'] or rule_result['is_anomaly']
        
        # Combine anomaly reasons
        all_reasons = list(set(ml_result['anomaly_reasons'] + rule_result['anomaly_reasons']))
        
        # Combine recommendations
        all_actions = list(set(ml_result['recommended_actions'] + rule_result['recommended_actions']))
        
        return {
            'is_anomaly': is_anomaly,
            'threat_score': combined_score,
            'anomaly_reasons': all_reasons,
            'recommended_actions': all_actions,
            'ml_analysis': ml_result,
            'rule_analysis': rule_result,
            'confidence': min(ml_result['confidence'], rule_result.get('confidence', 1.0)),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _analyze_rules(
        self,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform rule-based threat analysis.
        
        Args:
            event_type: Type of event
            event_data: Event data
        
        Returns:
            Rule-based analysis result
        """
        anomaly_reasons = []
        threat_score = 0.0
        
        # Check request rate
        request_rate = event_data.get('request_rate', 0)
        if request_rate > self._thresholds['max_requests_per_minute']:
            anomaly_reasons.append(f'Request rate {request_rate} exceeds threshold {self._thresholds["max_requests_per_minute"]}')
            threat_score += min(request_rate / self._thresholds['max_requests_per_minute'] * 0.3, 0.5)
        
        # Check failed ratio
        failed_ratio = event_data.get('failed_ratio', 0)
        if failed_ratio > self._thresholds['max_failed_ratio']:
            anomaly_reasons.append(f'Failure ratio {failed_ratio:.2f} exceeds threshold {self._thresholds["max_failed_ratio"]}')
            threat_score += 0.4
        
        # Check data volume
        data_volume_mb = event_data.get('data_volume', 0) / (1024 * 1024)
        if data_volume_mb > self._thresholds['max_data_volume_mb']:
            anomaly_reasons.append(f'Data volume {data_volume_mb:.1f}MB exceeds threshold')
            threat_score += 0.3
        
        # Event-type specific rules
        if event_type == 'auth_failure':
            consecutive_failures = event_data.get('consecutive_failures', 0)
            if consecutive_failures >= 5:
                anomaly_reasons.append(f'{consecutive_failures} consecutive authentication failures')
                threat_score += 0.5
        
        return {
            'is_anomaly': threat_score > 0.3,
            'threat_score': min(threat_score, 1.0),
            'anomaly_reasons': anomaly_reasons,
            'recommended_actions': self._generate_rule_recommendations(anomaly_reasons),
            'confidence': 0.95
        }
    
    def _generate_rule_recommendations(self, reasons: List[str]) -> List[str]:
        """
        Generate recommendations based on rule violations.
        
        Args:
            reasons: List of rule violation reasons
        
        Returns:
            List of recommended actions
        """
        recommendations = []
        
        for reason in reasons:
            if 'Request rate' in reason:
                recommendations.append('Consider implementing rate limiting')
            if 'Failure ratio' in reason:
                recommendations.append('Check for brute force attacks')
            if 'consecutive authentication' in reason:
                recommendations.append('Consider temporary account lockout')
            if 'Data volume' in reason:
                recommendations.append('Review for potential data exfiltration')
        
        if not recommendations:
            recommendations.append('Review security logs')
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection engine statistics.
        
        Returns:
            Dictionary with engine statistics
        """
        return {
            'ml_detector': self._ml_detector.get_model_info(),
            'thresholds': self._thresholds,
            'event_history_size': len(self._event_history),
            'event_types_tracked': len(set(e['type'] for e in self._event_history))
        }
