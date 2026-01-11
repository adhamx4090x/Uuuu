#!/usr/bin/env python3
"""
CXA Cryptographic System - Dashboard Tab

This module provides the dashboard interface for monitoring
system status, recent activities, and quick actions.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QFrame, QProgressBar,
    QScrollArea, QGroupBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon, QPixmap

from typing import Optional, Dict, Any
from datetime import datetime
import psutil


class DashboardTab(QWidget):
    """
    Dashboard tab providing system overview and quick access
    to common operations.
    """
    
    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize the dashboard tab."""
        super().__init__(parent)
        self.main_window = parent
        self._setup_ui()
        self._setup_connections()
        self._load_data()
        
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Welcome section
        welcome_group = QGroupBox("Welcome to CXA")
        welcome_layout = QVBoxLayout()
        
        welcome_title = QLabel("CXA Cryptographic System")
        welcome_title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        welcome_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        welcome_subtitle = QLabel("Secure your data with enterprise-grade cryptography")
        welcome_subtitle.setFont(QFont("Segoe UI", 12))
        welcome_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        welcome_layout.addWidget(welcome_title)
        welcome_layout.addWidget(welcome_subtitle)
        welcome_group.setLayout(welcome_layout)
        layout.addWidget(welcome_group)
        
        # Quick stats section
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(15)
        
        # System health card
        self.health_card = self._create_stat_card(
            "System Health", "Good", "#4CAF50", "System is operating normally"
        )
        stats_layout.addWidget(self.health_card)
        
        # Active keys card
        self.keys_card = self._create_stat_card(
            "Active Keys", "0", "#2196F3", "Cryptographic keys in use"
        )
        stats_layout.addWidget(self.keys_card)
        
        # Encrypted files card
        self.files_card = self._create_stat_card(
            "Encrypted Files", "0", "#FF9800", "Files encrypted this session"
        )
        stats_layout.addWidget(self.files_card)
        
        # Memory usage card
        self.memory_card = self._create_stat_card(
            "Memory Usage", "0%", "#9C27B0", "Secure memory consumption"
        )
        stats_layout.addWidget(self.memory_card)
        
        layout.addLayout(stats_layout)
        
        # Quick actions section
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(10)
        
        self.encrypt_btn = QPushButton("New Encryption")
        self.encrypt_btn.setMinimumSize(QSize(150, 50))
        actions_layout.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("New Decryption")
        self.decrypt_btn.setMinimumSize(QSize(150, 50))
        actions_layout.addWidget(self.decrypt_btn)
        
        self.keys_btn = QPushButton("Generate Keys")
        self.keys_btn.setMinimumSize(QSize(150, 50))
        actions_layout.addWidget(self.keys_btn)
        
        self.backup_btn = QPushButton("Create Backup")
        self.backup_btn.setMinimumSize(QSize(150, 50))
        actions_layout.addWidget(self.backup_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Recent activity section
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_list = QLabel("No recent activity")
        self.activity_list.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.activity_list.setWordWrap(True)
        
        activity_scroll = QScrollArea()
        activity_scroll.setWidget(self.activity_list)
        activity_scroll.setWidgetResizable(True)
        activity_scroll.setMaximumHeight(200)
        
        activity_layout.addWidget(activity_scroll)
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        # System info section
        info_group = QGroupBox("System Information")
        info_layout = QGridLayout()
        
        # Memory info
        self.memory_progress = QProgressBar()
        self.memory_progress.setRange(0, 100)
        self.memory_progress.setValue(0)
        
        info_layout.addWidget(QLabel("Secure Memory:"), 0, 0)
        info_layout.addWidget(self.memory_progress, 0, 1)
        
        # CPU info
        self.cpu_label = QLabel("0%")
        info_layout.addWidget(QLabel("CPU Usage:"), 1, 0)
        info_layout.addWidget(self.cpu_label, 1, 1)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        
    def _create_stat_card(self, title: str, value: str, color: str, tooltip: str) -> QFrame:
        """Create a statistics card widget."""
        card = QFrame()
        card.setFrameStyle(QFrame.Shape.StyledPanel)
        card.setToolTip(tooltip)
        
        card_layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 10))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"color: {color};")
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        
        return card
        
    def _setup_connections(self):
        """Setup signal connections."""
        self.encrypt_btn.clicked.connect(self._on_encrypt_clicked)
        self.decrypt_btn.clicked.connect(self._on_decrypt_clicked)
        self.keys_btn.clicked.connect(self._on_keys_clicked)
        self.backup_btn.clicked.connect(self._on_backup_clicked)
        
    def _on_encrypt_clicked(self):
        """Handle encrypt button click."""
        if self.main_window:
            self.main_window.tab_widget.setCurrentIndex(1)  # Encryption tab
            
    def _on_decrypt_clicked(self):
        """Handle decrypt button click."""
        if self.main_window:
            self.main_window.tab_widget.setCurrentIndex(2)  # Decryption tab
            
    def _on_keys_clicked(self):
        """Handle keys button click."""
        if self.main_window:
            self.main_window.tab_widget.setCurrentIndex(3)  # Key Management tab
            
    def _on_backup_clicked(self):
        """Handle backup button click."""
        if self.main_window:
            self.main_window.tab_widget.setCurrentIndex(4)  # Backup tab
            
    def _load_data(self):
        """Load dashboard data."""
        self._update_system_info()
        
    def _update_system_info(self):
        """Update system information displays."""
        try:
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_progress.setValue(memory.percent)
            
            # CPU usage
            cpu = psutil.cpu_percent()
            self.cpu_label.setText(f"{cpu}%")
            
        except Exception as e:
            print(f"Error updating system info: {e}")
            
    def refresh(self):
        """Refresh dashboard data."""
        self._load_data()
        self._update_system_info()
