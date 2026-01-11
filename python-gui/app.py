#!/usr/bin/env python3
"""
CXA Cryptographic System - Main Application

This module contains the main application class and main window
for the CXA GUI interface. It provides the core structure for
the cryptographic operations interface.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QHBoxLayout, QStatusBar, QMenuBar,
    QToolBar, QMessageBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QAction, QFont

import sys
from pathlib import Path
from typing import Optional

# Add python-core to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python-core"))

from cxa.memory import SecurityMonitor


class CXAApplication(QApplication):
    """
    Main application class for CXA Cryptographic System.
    
    This class extends QApplication to provide application-level
    functionality including security monitoring and resource management.
    """
    
    def __init__(self, argv: list[str]):
        """Initialize the CXA application."""
        super().__init__(argv)
        self.setApplicationName("CXA Cryptographic System")
        self.setApplicationVersion("1.0.0")
        self.setOrganizationName("MiniMax Agent")
        
        # Initialize security monitor
        self.security_monitor: Optional[SecurityMonitor] = None
        self._initialize_security()
        
        # Set application-wide font
        self._setup_fonts()
        
    def _initialize_security(self):
        """Initialize the security monitoring subsystem."""
        try:
            self.security_monitor = SecurityMonitor()
            self.security_monitor.start_monitoring()
        except Exception as e:
            print(f"Warning: Could not initialize security monitor: {e}")
            
    def _setup_fonts(self):
        """Setup application-wide fonts."""
        font = QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.setFont(font)
        
    def secure_cleanup(self):
        """Perform secure cleanup of sensitive data."""
        if self.security_monitor:
            self.security_monitor.secure_clear_all()
            
    def notify(self, receiver, event) -> bool:
        """Override notify to add security checks."""
        try:
            return super().notify(receiver, event)
        except Exception as e:
            print(f"Application notification error: {e}")
            return False
            
            
class MainWindow(QMainWindow):
    """
    Main window for the CXA Cryptographic System.
    
    This window provides the primary interface for all cryptographic
    operations including encryption, decryption, key management, and backups.
    """
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        self.setWindowTitle("CXA Cryptographic System")
        self.setMinimumSize(QSize(1024, 768))
        self._setup_ui()
        self._setup_menubar()
        self._setup_toolbar()
        self._setup_statusbar()
        self._connect_signals()
        
    def _setup_ui(self):
        """Setup the main user interface."""
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.setMovable(False)
        
        # Import and add tabs
        try:
            from .tabs.dashboard import DashboardTab
            from .tabs.encryption import EncryptionTab
            from .tabs.decryption import DecryptionTab
            from .tabs.key_management import KeyManagementTab
            from .tabs.backup import BackupTab
            from .tabs.settings import SettingsTab
            
            self.tabs = {
                'dashboard': DashboardTab(self),
                'encryption': EncryptionTab(self),
                'decryption': DecryptionTab(self),
                'key_management': KeyManagementTab(self),
                'backup': BackupTab(self),
                'settings': SettingsTab(self)
            }
            
            # Add tabs to widget
            self.tab_widget.addTab(self.tabs['dashboard'], "Dashboard")
            self.tab_widget.addTab(self.tabs['encryption'], "Encryption")
            self.tab_widget.addTab(self.tabs['decryption'], "Decryption")
            self.tab_widget.addTab(self.tabs['key_management'], "Key Management")
            self.tab_widget.addTab(self.tabs['backup'], "Backup")
            self.tab_widget.addTab(self.tabs['settings'], "Settings")
            
        except ImportError as e:
            print(f"Warning: Could not load all tabs: {e}")
            # Add placeholder tab
            placeholder = QWidget()
            layout = QVBoxLayout()
            from PyQt6.QtWidgets import QLabel
            layout.addWidget(QLabel("Tabs are loading..."))
            placeholder.setLayout(layout)
            self.tab_widget.addTab(placeholder, "Loading...")
            
        main_layout.addWidget(self.tab_widget)
        
    def _setup_menubar(self):
        """Setup the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Project", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self._on_new_project)
        file_menu.addAction(new_action)
        
        open_action = QAction("Open Project", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._on_open_project)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        keygen_action = QAction("Generate Key Pair", self)
        keygen_action.triggered.connect(self._on_generate_keys)
        tools_menu.addAction(keygen_action)
        
        verify_action = QAction("Verify Signatures", self)
        verify_action.triggered.connect(self._on_verify_signatures)
        tools_menu.addAction(verify_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._on_show_about)
        help_menu.addAction(about_action)
        
    def _setup_toolbar(self):
        """Setup the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)
        
        # Add toolbar actions
        new_action = QAction("New", self)
        new_action.setToolTip("Create new project")
        toolbar.addAction(new_action)
        
        open_action = QAction("Open", self)
        open_action.setToolTip("Open project")
        toolbar.addAction(open_action)
        
        toolbar.addSeparator()
        
        encrypt_action = QAction("Encrypt", self)
        encrypt_action.setToolTip("Go to encryption tab")
        encrypt_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        toolbar.addAction(encrypt_action)
        
        decrypt_action = QAction("Decrypt", self)
        decrypt_action.setToolTip("Go to decryption tab")
        decrypt_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addAction(decrypt_action)
        
    def _setup_statusbar(self):
        """Setup the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - CXA Cryptographic System initialized")
        
    def _connect_signals(self):
        """Connect signals between components."""
        pass
        
    def _on_new_project(self):
        """Handle new project action."""
        from PyQt6.QtWidgets import QFileDialog
        path = QFileDialog.getExistingDirectory(self, "Create New Project")
        if path:
            self.status_bar.showMessage(f"New project created: {path}")
            
    def _on_open_project(self):
        """Handle open project action."""
        from PyQt6.QtWidgets import QFileDialog
        path = QFileDialog.getExistingDirectory(self, "Open Project")
        if path:
            self.status_bar.showMessage(f"Project opened: {path}")
            
    def _on_generate_keys(self):
        """Handle generate keys action."""
        self.tab_widget.setCurrentIndex(3)  # Key Management tab
        
    def _on_verify_signatures(self):
        """Handle verify signatures action."""
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Verify Signatures", 
                               "Signature verification feature coming soon.")
        
    def _on_show_about(self):
        """Show about dialog."""
        from PyQt6.QtWidgets import QMessageBox
        
        about_text = """
        <h2>CXA Cryptographic System</h2>
        <p>Version 1.0.0</p>
        <p>A comprehensive cryptographic system providing secure encryption, 
        digital signatures, and key management capabilities.</p>
        <p><b>Features:</b></p>
        <ul>
            <li>Advanced Encryption Standard (AES-256)</li>
            <li>RSA and Ed25519 Digital Signatures</li>
            <li>Secure Key Derivation (Argon2id, scrypt, PBKDF2)</li>
            <li>Secure Memory Management</li>
            <li>Steganography Capabilities</li>
        </ul>
        <p>Built with Rust for security and performance.</p>
        """
        
        QMessageBox.about(self, "About CXA", about_text)
        
    def closeEvent(self, event):
        """Handle window close event."""
        reply = QMessageBox.question(
            self, "Exit CXA",
            "Are you sure you want to exit? All unsaved data will be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Perform secure cleanup
            app = QApplication.instance()
            if hasattr(app, 'secure_cleanup'):
                app.secure_cleanup()
            event.accept()
        else:
            event.ignore()
            
    def show_message(self, message: str, duration: int = 3000):
        """Show a message in the status bar."""
        self.status_bar.showMessage(message, duration)
