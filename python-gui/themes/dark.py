#!/usr/bin/env python3
"""
CXA Cryptographic System - Dark Theme

This module provides the dark theme stylesheet and application
function for the CXA GUI.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor


def get_dark_theme_stylesheet() -> str:
    """
    Get the complete dark theme stylesheet.
    
    Returns:
        str: The complete stylesheet for dark theme.
    """
    return """
    /* CXA Dark Theme Stylesheet */
    
    /* General Application Styles */
    QMainWindow, QWidget {
        background-color: #1a1a1a;
        color: #e0e0e0;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 10pt;
    }
    
    QLabel {
        color: #e0e0e0;
    }
    
    QMenuBar {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border-bottom: 1px solid #3d3d3d;
        padding: 4px;
    }
    
    QMenuBar::item {
        background-color: transparent;
        padding: 4px 12px;
        border-radius: 4px;
    }
    
    QMenuBar::item:selected {
        background-color: #3d3d3d;
    }
    
    QMenu {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 4px;
        padding: 4px;
    }
    
    QMenu::item {
        padding: 6px 20px;
        border-radius: 4px;
    }
    
    QMenu::item:selected {
        background-color: #4CAF50;
    }
    
    QMenu::separator {
        height: 1px;
        background-color: #3d3d3d;
        margin: 4px 0;
    }
    
    QToolBar {
        background-color: #2d2d2d;
        border-bottom: 1px solid #3d3d3d;
        padding: 4px;
        spacing: 8px;
    }
    
    QToolButton {
        background-color: transparent;
        color: #e0e0e0;
        padding: 6px 12px;
        border-radius: 4px;
    }
    
    QToolButton:hover {
        background-color: #3d3d3d;
    }
    
    QToolButton:pressed {
        background-color: #4d4d4d;
    }
    
    QStatusBar {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border-top: 1px solid #3d3d3d;
    }
    
    /* Group Box Styles */
    QGroupBox {
        font-weight: bold;
        border: 1px solid #3d3d3d;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 8px;
        background-color: #1f1f1f;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 6px;
        color: #4CAF50;
    }
    
    /* Button Styles */
    QPushButton {
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 500;
    }
    
    QPushButton:hover {
        background-color: #66BB6A;
    }
    
    QPushButton:pressed {
        background-color: #388E3C;
    }
    
    QPushButton:disabled {
        background-color: #555555;
        color: #888888;
    }
    
    QPushButton#secondary {
        background-color: #555555;
    }
    
    QPushButton#secondary:hover {
        background-color: #666666;
    }
    
    /* Input Styles */
    QLineEdit, QTextEdit, QPlainTextEdit {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 6px;
        padding: 8px;
        selection-background-color: #4CAF50;
        selection-color: white;
    }
    
    QLineEdit:focus, QTextEdit:focus {
        border-color: #4CAF50;
    }
    
    QLineEdit:placeholder-text {
        color: #666666;
    }
    
    /* Combo Box Styles */
    QComboBox {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 6px;
        padding: 8px 12px;
        min-width: 120px;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: right center;
        width: 24px;
        border-left: 1px solid #3d3d3d;
        border-top-right-radius: 6px;
        border-bottom-right-radius: 6px;
    }
    
    QComboBox::down-arrow {
        width: 12px;
        height: 12px;
        image: url(data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23e0e0e0'%3E%3Cpath d='M7 10l5 5 5-5z'/%3E%3C/svg%3E);
    }
    
    QComboBox:on {
        border-color: #4CAF50;
    }
    
    QComboBox QAbstractItemView {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 4px;
        selection-background-color: #4CAF50;
        selection-color: white;
    }
    
    /* Spin Box Styles */
    QSpinBox {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 6px;
        padding: 8px;
        min-width: 60px;
    }
    
    QSpinBox:focus {
        border-color: #4CAF50;
    }
    
    QSpinBox::up-button, QSpinBox::down-button {
        background-color: #3d3d3d;
        border-radius: 3px;
        width: 20px;
        margin: 2px;
    }
    
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {
        background-color: #4CAF50;
    }
    
    /* Progress Bar Styles */
    QProgressBar {
        background-color: #2d2d2d;
        border: 1px solid #3d3d3d;
        border-radius: 6px;
        text-align: center;
        color: #e0e0e0;
        height: 24px;
    }
    
    QProgressBar::chunk {
        background-color: #4CAF50;
        border-radius: 4px;
    }
    
    /* Check Box Styles */
    QCheckBox {
        color: #e0e0e0;
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 2px solid #3d3d3d;
        border-radius: 4px;
        background-color: #2d2d2d;
    }
    
    QCheckBox::indicator:checked {
        background-color: #4CAF50;
        border-color: #4CAF50;
        image: url(data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/%3E%3C/svg%3E);
    }
    
    QCheckBox::indicator:unchecked:hover {
        border-color: #4CAF50;
    }
    
    /* Radio Button Styles */
    QRadioButton {
        color: #e0e0e0;
        spacing: 8px;
    }
    
    QRadioButton::indicator {
        width: 18px;
        height: 18px;
        border: 2px solid #3d3d3d;
        border-radius: 9px;
        background-color: #2d2d2d;
    }
    
    QRadioButton::indicator:checked {
        border-color: #4CAF50;
        background-color: #4CAF50;
        image: url(data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Ccircle cx='12' cy='12' r='6'/%3E%3C/svg%3E);
    }
    
    QRadioButton::indicator:unchecked:hover {
        border-color: #4CAF50;
    }
    
    /* Tab Widget Styles */
    QTabWidget::pane {
        background-color: #1a1a1a;
        border: 1px solid #3d3d3d;
        border-radius: 8px;
        top: -1px;
    }
    
    QTabBar::tab {
        background-color: #2d2d2d;
        color: #e0e0e0;
        padding: 10px 20px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: #1a1a1a;
        color: #4CAF50;
        border-bottom: 2px solid #4CAF50;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #3d3d3d;
    }
    
    /* Table Widget Styles */
    QTableWidget {
        background-color: #1a1a1a;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 6px;
        gridline-color: #3d3d3d;
    }
    
    QTableWidget QHeaderView::section {
        background-color: #2d2d2d;
        color: #e0e0e0;
        padding: 8px;
        border: 1px solid #3d3d3d;
        font-weight: bold;
    }
    
    QTableWidget::item {
        padding: 8px;
        border: 1px solid #3d3d3d;
    }
    
    QTableWidget::item:selected {
        background-color: #4CAF50;
        color: white;
    }
    
    /* Scroll Area Styles */
    QScrollArea {
        background-color: #1a1a1a;
        border: none;
    }
    
    QScrollBar:vertical {
        background-color: #2d2d2d;
        width: 12px;
        border-radius: 6px;
        margin: 0;
    }
    
    QScrollBar::handle:vertical {
        background-color: #4d4d4d;
        min-height: 20px;
        border-radius: 5px;
        margin: 2px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #5d5d5d;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    
    QScrollBar:horizontal {
        background-color: #2d2d2d;
        height: 12px;
        border-radius: 6px;
        margin: 0;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #4d4d4d;
        min-width: 20px;
        border-radius: 5px;
        margin: 2px;
    }
    
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
    }
    
    /* Frame Styles */
    QFrame {
        background-color: transparent;
    }
    
    QFrame[frameShape="4"] {
        /* StyledPanel */
        background-color: #1f1f1f;
        border: 1px solid #3d3d3d;
        border-radius: 8px;
    }
    
    /* ToolTip Styles */
    QToolTip {
        background-color: #2d2d2d;
        color: #e0e0e0;
        border: 1px solid #3d3d3d;
        border-radius: 4px;
        padding: 6px;
    }
    
    /* Message Box Styles */
    QMessageBox {
        background-color: #1a1a1a;
    }
    
    QMessageBox QLabel {
        color: #e0e0e0;
    }
    
    /* Slider Styles */
    QSlider {
        background-color: transparent;
    }
    
    QSlider::groove:horizontal {
        background-color: #3d3d3d;
        height: 6px;
        border-radius: 3px;
    }
    
    QSlider::handle:horizontal {
        background-color: #4CAF50;
        width: 18px;
        height: 18px;
        margin: -6px 0;
        border-radius: 9px;
    }
    
    QSlider::sub-page:horizontal {
        background-color: #4CAF50;
        border-radius: 3px;
    }
    """


def apply_dark_theme(app: QApplication):
    """
    Apply the dark theme to the application.
    
    Args:
        app: The QApplication instance.
    """
    app.setStyle("Fusion")
    app.setStyleSheet(get_dark_theme_stylesheet())
    
    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#1a1a1a"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#2d2d2d"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#1f1f1f"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#2d2d2d"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#666666"))
    
    app.setPalette(palette)
