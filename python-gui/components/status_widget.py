#!/usr/bin/env python3
"""
CXA Cryptographic System - Status Widget Component

This module provides a reusable widget for displaying system
status and health information.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QProgressBar
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from typing import Optional, Dict, Any
from enum import Enum


class StatusLevel(Enum):
    """Enumeration of status levels."""
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    INFO = "info"
    NEUTRAL = "neutral"


class StatusWidget(QWidget):
    """
    A widget for displaying status information with visual
    indicators for different status levels.
    """
    
    clicked = pyqtSignal()
    
    def __init__(
        self,
        title: str = "",
        message: str = "",
        level: StatusLevel = StatusLevel.NEUTRAL,
        parent: Optional[QWidget] = None
    ):
        """Initialize the status widget."""
        super().__init__(parent)
        self._level = level
        self._setup_ui()
        self.set_status(title, message, level)
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(15)
        
        # Status indicator
        self.indicator = QFrame()
        self.indicator.setFixedSize(QSize(16, 16))
        self.indicator.setStyleSheet(
            "border-radius: 8px;"
            "background-color: #9E9E9E;"
        )
        layout.addWidget(self.indicator)
        
        # Content layout
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(3)
        
        # Title
        self.title_label = QLabel()
        self.title_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        content_layout.addWidget(self.title_label)
        
        # Message
        self.message_label = QLabel()
        self.message_label.setFont(QFont("Segoe UI", 10))
        self.message_label.setWordWrap(True)
        content_layout.addWidget(self.message_label)
        
        layout.addLayout(content_layout)
        
        # Set frame style
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def set_status(
        self,
        title: str,
        message: str = "",
        level: StatusLevel = StatusLevel.NEUTRAL
    ):
        """Set the status information."""
        self._level = level
        self.title_label.setText(title)
        self.message_label.setText(message)
        self.message_label.setVisible(bool(message))
        
        # Update indicator color
        color = self._get_level_color(level)
        self.indicator.setStyleSheet(
            f"background-color: {color};"
            "border-radius: 8px;"
        )
        
        # Update background color based on level
        bg_color = self._get_level_background(level)
        self.setStyleSheet(
            f"StatusWidget {{ "
            f"background-color: {bg_color};"
            "border-radius: 8px;"
            "}}"
        )
        
    def set_progress(self, value: int, maximum: int = 100):
        """Set a progress value on the status."""
        if not hasattr(self, '_progress_bar'):
            # Create progress bar
            progress_layout = QVBoxLayout()
            self._progress_bar = QProgressBar()
            self._progress_bar.setRange(0, maximum)
            self._progress_bar.setValue(value)
            self._progress_bar.setTextVisible(False)
            self._progress_bar.setFixedHeight(6)
            
            # Add to layout after message
            layout = self.layout()
            content_layout = layout.itemAt(1).layout()
            content_layout.addWidget(self._progress_bar)
            
        self._progress_bar.setRange(0, maximum)
        self._progress_bar.setValue(value)
        
    def _get_level_color(self, level: StatusLevel) -> str:
        """Get the color for a status level."""
        colors = {
            StatusLevel.SUCCESS: "#4CAF50",  # Green
            StatusLevel.WARNING: "#FF9800",  # Orange
            StatusLevel.ERROR: "#F44336",    # Red
            StatusLevel.INFO: "#2196F3",     # Blue
            StatusLevel.NEUTRAL: "#9E9E9E",  # Gray
        }
        return colors.get(level, colors[StatusLevel.NEUTRAL])
        
    def _get_level_background(self, level: StatusLevel) -> str:
        """Get the background color for a status level."""
        colors = {
            StatusLevel.SUCCESS: "#E8F5E9",
            StatusLevel.WARNING: "#FFF3E0",
            StatusLevel.ERROR: "#FFEBEE",
            StatusLevel.INFO: "#E3F2FD",
            StatusLevel.NEUTRAL: "#FAFAFA",
        }
        return colors.get(level, colors[StatusLevel.NEUTRAL])
        
    def mousePressEvent(self, event):
        """Handle mouse press event."""
        self.clicked.emit()
        super().mousePressEvent(event)


class StatusPanel(QWidget):
    """
    A panel for displaying multiple status widgets.
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the status panel."""
        super().__init__(parent)
        self.statuses: Dict[str, StatusWidget] = {}
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(8)
        
        layout.addWidget(self.content_widget)
        
    def add_status(
        self,
        status_id: str,
        title: str,
        message: str = "",
        level: StatusLevel = StatusLevel.NEUTRAL
    ) -> StatusWidget:
        """Add a new status widget."""
        if status_id in self.statuses:
            self.statuses[status_id].set_status(title, message, level)
            return self.statuses[status_id]
            
        status = StatusWidget(title, message, level)
        self.statuses[status_id] = status
        self.content_layout.addWidget(status)
        return status
        
    def update_status(
        self,
        status_id: str,
        title: str,
        message: str = "",
        level: StatusLevel = StatusLevel.NEUTRAL
    ):
        """Update an existing status."""
        if status_id in self.statuses:
            self.statuses[status_id].set_status(title, message, level)
            
    def remove_status(self, status_id: str):
        """Remove a status widget."""
        if status_id in self.statuses:
            widget = self.statuses.pop(status_id)
            widget.deleteLater()
            
    def clear_all(self):
        """Clear all status widgets."""
        for widget in self.statuses.values():
            widget.deleteLater()
        self.statuses.clear()


class SystemHealthWidget(QWidget):
    """
    A widget for displaying overall system health status.
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the system health widget."""
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Health indicator
        indicator_layout = QVBoxLayout()
        indicator_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.health_indicator = QFrame()
        self.health_indicator.setFixedSize(QSize(80, 80))
        self.health_indicator.setStyleSheet(
            "border-radius: 40px;"
            "background-color: #4CAF50;"
        )
        indicator_layout.addWidget(self.health_indicator)
        
        self.health_label = QLabel("Good")
        self.health_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.health_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        indicator_layout.addWidget(self.health_label)
        
        layout.addLayout(indicator_layout)
        
        # Details section
        details_layout = QVBoxLayout()
        details_layout.setSpacing(8)
        
        self.status_items: Dict[str, StatusWidget] = {}
        
        items = [
            ("memory", "Memory Security", "Secure memory active"),
            ("keys", "Key Status", "All keys valid"),
            ("encryption", "Encryption", "Ready for operations"),
            ("network", "Network", "Connected"),
        ]
        
        for item_id, title, message in items:
            status = StatusWidget(title, message, StatusLevel.SUCCESS)
            self.status_items[item_id] = status
            details_layout.addWidget(status)
            
        layout.addLayout(details_layout)
        
    def set_health(self, level: StatusLevel, message: str = ""):
        """Set the overall health status."""
        color = self._get_indicator_color(level)
        self.health_indicator.setStyleSheet(
            f"border-radius: 40px;"
            f"background-color: {color};"
        )
        self.health_label.setText(level.name.capitalize())
        
    def _get_indicator_color(self, level: StatusLevel) -> str:
        """Get the indicator color for a status level."""
        colors = {
            StatusLevel.SUCCESS: "#4CAF50",
            StatusLevel.WARNING: "#FF9800",
            StatusLevel.ERROR: "#F44336",
            StatusLevel.INFO: "#2196F3",
            StatusLevel.NEUTRAL: "#9E9E9E",
        }
        return colors.get(level, colors[StatusLevel.NEUTRAL])
        
    def update_item(self, item_id: str, level: StatusLevel, message: str):
        """Update a status item."""
        if item_id in self.status_items:
            self.status_items[item_id].set_status(
                self.status_items[item_id].title_label.text(),
                message,
                level
            )
