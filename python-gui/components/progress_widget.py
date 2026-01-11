#!/usr/bin/env python3
"""
CXA Cryptographic System - Progress Widget Component

This module provides a reusable widget for displaying operation
progress with detailed status information.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QPushButton, QFrame
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QFont

from typing import Optional, Callable
import time


class ProgressWidget(QWidget):
    """
    A widget for displaying operation progress with detailed
    status information and cancellation support.
    """
    
    cancelled = pyqtSignal()
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the progress widget."""
        super().__init__(parent)
        self._setup_ui()
        self._start_time = 0
        self._is_running = False
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        # Status layout
        status_layout = QHBoxLayout()
        
        # Operation label
        self.operation_label = QLabel("Ready")
        self.operation_label.setFont(QFont("Segoe UI", 10))
        status_layout.addWidget(self.operation_label)
        
        status_layout.addStretch()
        
        # Progress percentage
        self.percentage_label = QLabel("0%")
        self.percentage_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        status_layout.addWidget(self.percentage_label)
        
        layout.addLayout(status_layout)
        
        # Details layout
        details_layout = QHBoxLayout()
        
        # Time elapsed
        self.time_label = QLabel("Elapsed: 0:00")
        self.time_label.setFont(QFont("Segoe UI", 9))
        self.time_label.setStyleSheet("color: #888888;")
        details_layout.addWidget(self.time_label)
        
        details_layout.addStretch()
        
        # Speed
        self.speed_label = QLabel("")
        self.speed_label.setFont(QFont("Segoe UI", 9))
        self.speed_label.setStyleSheet("color: #888888;")
        details_layout.addWidget(self.speed_label)
        
        layout.addLayout(details_layout)
        
        # Cancel button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedSize(QSize(100, 30))
        self.cancel_btn.setEnabled(False)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Set frame style
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        
    def _setup_connections(self):
        """Setup signal connections."""
        self.cancel_btn.clicked.connect(self._on_cancel)
        
    def _on_cancel(self):
        """Handle cancel button click."""
        self.cancelled.emit()
        
    def start_operation(self, operation_name: str):
        """Start a new operation."""
        self._start_time = time.time()
        self._is_running = True
        self.operation_label.setText(operation_name)
        self.progress_bar.setValue(0)
        self.cancel_btn.setEnabled(True)
        
    def update_progress(self, value: int, message: str = ""):
        """Update the progress value."""
        self.progress_bar.setValue(value)
        self.percentage_label.setText(f"{value}%")
        
        if message:
            self.operation_label.setText(message)
            
        # Update elapsed time
        elapsed = time.time() - self._start_time
        self.time_label.setText(f"Elapsed: {self._format_time(elapsed)}")
        
    def update_speed(self, bytes_per_second: float):
        """Update the speed display."""
        if bytes_per_second > 0:
            self.speed_label.setText(f"{self._format_speed(bytes_per_second)}/s")
            
    def complete_operation(self, success: bool = True):
        """Complete the operation."""
        self._is_running = False
        self.progress_bar.setValue(100 if success else 0)
        self.cancel_btn.setEnabled(False)
        
        elapsed = time.time() - self._start_time
        self.time_label.setText(f"Total time: {self._format_time(elapsed)}")
        
        if success:
            self.operation_label.setText("Completed successfully")
        else:
            self.operation_label.setText("Operation failed")
            
    def set_range(self, minimum: int, maximum: int):
        """Set the progress range."""
        self.progress_bar.setRange(minimum, maximum)
        
    def reset(self):
        """Reset the progress widget."""
        self._is_running = False
        self.progress_bar.setValue(0)
        self.percentage_label.setText("0%")
        self.operation_label.setText("Ready")
        self.time_label.setText("Elapsed: 0:00")
        self.speed_label.setText("")
        self.cancel_btn.setEnabled(False)
        
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{int(seconds):d}:{int(seconds % 60):02d}"
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes:d}:{secs:02d}"
            
    def _format_speed(self, bytes_per_second: float) -> str:
        """Format speed in human-readable format."""
        if bytes_per_second >= 1_000_000:
            return f"{bytes_per_second / 1_000_000:.1f} MB"
        elif bytes_per_second >= 1_000:
            return f"{bytes_per_second / 1_000:.1f} KB"
        else:
            return f"{bytes_per_second:.1f} B"


class MultiProgressWidget(QWidget):
    """
    A widget for displaying multiple concurrent progress operations.
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the multi-progress widget."""
        super().__init__(parent)
        self.operations: dict[str, ProgressWidget] = {}
        self._setup_ui()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        self.operations_widget = QWidget()
        self.operations_layout = QVBoxLayout(self.operations_widget)
        self.operations_layout.setContentsMargins(0, 0, 0, 0)
        self.operations_layout.setSpacing(10)
        
        layout.addWidget(self.operations_widget)
        
    def add_operation(self, operation_id: str, operation_name: str) -> ProgressWidget:
        """Add a new progress operation."""
        if operation_id in self.operations:
            return self.operations[operation_id]
            
        progress = ProgressWidget()
        progress.start_operation(operation_name)
        self.operations[operation_id] = progress
        self.operations_layout.addWidget(progress)
        return progress
        
    def update_operation(self, operation_id: str, value: int, message: str = ""):
        """Update an operation's progress."""
        if operation_id in self.operations:
            self.operations[operation_id].update_progress(value, message)
            
    def complete_operation(self, operation_id: str, success: bool = True):
        """Complete an operation."""
        if operation_id in self.operations:
            self.operations[operation_id].complete_operation(success)
            
    def remove_operation(self, operation_id: str):
        """Remove an operation from the display."""
        if operation_id in self.operations:
            widget = self.operations.pop(operation_id)
            widget.deleteLater()
            
    def clear_all(self):
        """Clear all operations."""
        for widget in self.operations.values():
            widget.deleteLater()
        self.operations.clear()
