#!/usr/bin/env python3
"""
CXA Cryptographic System - Key Widget Component

This module provides a reusable widget for displaying and managing
cryptographic keys in the UI.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QProgressBar, QToolTip
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor

from typing import Optional, Dict, Any
from datetime import datetime


class KeyWidget(QWidget):
    """
    A widget for displaying cryptographic key information
    with actions for common operations.
    """
    
    view_clicked = pyqtSignal(str)
    export_clicked = pyqtSignal(str)
    delete_clicked = pyqtSignal(str)
    
    def __init__(self, key_data: Dict[str, Any], parent: Optional[QWidget] = None):
        """Initialize the key widget."""
        super().__init__(parent)
        self.key_data = key_data
        self.key_id = key_data.get('id', '')
        self._setup_ui()
        self._setup_connections()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Key icon/status indicator
        self.status_indicator = QFrame()
        self.status_indicator.setFixedSize(QSize(12, 12))
        self.status_indicator.setStyleSheet(
            f"background-color: {self._get_status_color()};"
            f"border-radius: 6px;"
        )
        layout.addWidget(self.status_indicator)
        
        # Key info section
        info_layout = QVBoxLayout()
        
        # Key name
        self.key_name = QLabel(self.key_data.get('name', 'Unnamed Key'))
        self.key_name.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        info_layout.addWidget(self.key_name)
        
        # Key details
        details_text = f"{self.key_data.get('algorithm', 'Unknown')} | {self.key_data.get('type', 'Unknown')}"
        self.key_details = QLabel(details_text)
        self.key_details.setFont(QFont("Segoe UI", 10))
        self.key_details.setStyleSheet("color: #888888;")
        info_layout.addWidget(self.key_details)
        
        # Creation date
        created = self.key_data.get('created', '')
        if created:
            created_date = datetime.fromisoformat(created) if isinstance(created, str) else created
            self.creation_label = QLabel(f"Created: {created_date.strftime('%Y-%m-%d %H:%M')}")
            self.creation_label.setFont(QFont("Segoe UI", 9))
            self.creation_label.setStyleSheet("color: #666666;")
            info_layout.addWidget(self.creation_label)
        
        layout.addLayout(info_layout)
        
        # Spacer
        layout.addStretch()
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        
        self.view_btn = QPushButton("View")
        self.view_btn.setFixedSize(QSize(80, 30))
        button_layout.addWidget(self.view_btn)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.setFixedSize(QSize(80, 30))
        button_layout.addWidget(self.export_btn)
        
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setFixedSize(QSize(80, 30))
        button_layout.addWidget(self.delete_btn)
        
        layout.addLayout(button_layout)
        
        # Set frame style
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("KeyWidget { background-color: #2a2a2a; border-radius: 8px; }")
        
    def _setup_connections(self):
        """Setup signal connections."""
        self.view_btn.clicked.connect(lambda: self.view_clicked.emit(self.key_id))
        self.export_btn.clicked.connect(lambda: self.export_clicked.emit(self.key_id))
        self.delete_btn.clicked.connect(lambda: self.delete_clicked.emit(self.key_id))
        
    def _get_status_color(self) -> str:
        """Get the status indicator color based on key state."""
        status = self.key_data.get('status', 'active')
        if status == 'active':
            return '#4CAF50'  # Green
        elif status == 'expired':
            return '#FF9800'  # Orange
        elif status == 'revoked':
            return '#F44336'  # Red
        else:
            return '#9E9E9E'  # Gray
        
    def update_data(self, key_data: Dict[str, Any]):
        """Update the widget with new key data."""
        self.key_data = key_data
        self.key_id = key_data.get('id', '')
        self.key_name.setText(key_data.get('name', 'Unnamed Key'))
        
        details_text = f"{key_data.get('algorithm', 'Unknown')} | {key_data.get('type', 'Unknown')}"
        self.key_details.setText(details_text)
        
        self.status_indicator.setStyleSheet(
            f"background-color: {self._get_status_color()};"
            f"border-radius: 6px;"
        )


class KeyListWidget(QWidget):
    """
    A widget for displaying a list of cryptographic keys.
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the key list widget."""
        super().__init__(parent)
        self.keys: Dict[str, KeyWidget] = {}
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        self.scroll_area_contents = QWidget()
        self.list_layout = QVBoxLayout(self.scroll_area_contents)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(10)
        
        layout.addWidget(self.scroll_area_contents)
        
    def add_key(self, key_data: Dict[str, Any]) -> KeyWidget:
        """Add a key to the list."""
        key_id = key_data.get('id', '')
        key_widget = KeyWidget(key_data)
        self.keys[key_id] = key_widget
        self.list_layout.addWidget(key_widget)
        return key_widget
        
    def remove_key(self, key_id: str):
        """Remove a key from the list."""
        if key_id in self.keys:
            widget = self.keys.pop(key_id)
            widget.deleteLater()
            
    def clear(self):
        """Clear all keys from the list."""
        for widget in self.keys.values():
            widget.deleteLater()
        self.keys.clear()
        
    def update_key(self, key_id: str, key_data: Dict[str, Any]):
        """Update a key in the list."""
        if key_id in self.keys:
            self.keys[key_id].update_data(key_data)
