#!/usr/bin/env python3
"""
CXA Cryptographic System - Light Theme

This module provides the light theme stylesheet and application
function for the CXA GUI.

Author: MiniMax Agent
Version: 1.0.0
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor


def get_light_theme_stylesheet() -> str:
    """
    Get the complete light theme stylesheet.
    
    Returns:
        str: The complete stylesheet for light theme.
    """
    return """
    /* CXA Light Theme Stylesheet */
    
    /* General Application Styles */
    QMainWindow, QWidget {
        background-color: #f5f5f5;
        color: #333333;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 10pt;
    }
    
    QLabel {
        color: #333333;
    }
    
    QMenuBar {
        background-color: #ffffff;
        color: #333333;
        border-bottom: 1px solid #e0e0e0;
        padding: 4px;
    }
    
    QMenuBar::item {
        background-color: transparent;
        padding: 4px 12px;
        border-radius: 4px;
    }
    
    QMenuBar::item:selected {
        background-color: #e0e0e0;
    }
    
    QMenu {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        padding: 4px;
    }
    
    QMenu::item {
        padding: 6px 20px;
        border-radius: 4px;
    }
    
    QMenu::item:selected {
        background-color: #4CAF50;
        color: white;
    }
    
    QMenu::separator {
        height: 1px;
        background-color: #e0e0e0;
        margin: 4px 0;
    }
    
    QToolBar {
        background-color: #ffffff;
        border-bottom: 1px solid #e0e0e0;
        padding: 4px;
        spacing: 8px;
    }
    
    QToolButton {
        background-color: transparent;
        color: #333333;
        padding: 6px 12px;
        border-radius: 4px;
    }
    
    QToolButton:hover {
        background-color: #f0f0f0;
    }
    
    QToolButton:pressed {
        background-color: #e0e0e0;
    }
    
    QStatusBar {
        background-color: #ffffff;
        color: #333333;
        border-top: 1px solid #e0e0e0;
    }
    
    /* Group Box Styles */
    QGroupBox {
        font-weight: bold;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 8px;
        background-color: #ffffff;
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
        background-color: #cccccc;
        color: #888888;
    }
    
    QPushButton#secondary {
        background-color: #e0e0e0;
        color: #333333;
    }
    
    QPushButton#secondary:hover {
        background-color: #d0d0d0;
    }
    
    /* Input Styles */
    QLineEdit, QTextEdit, QPlainTextEdit {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        padding: 8px;
        selection-background-color: #4CAF50;
        selection-color: white;
    }
    
    QLineEdit:focus, QTextEdit:focus {
        border-color: #4CAF50;
    }
    
    QLineEdit:placeholder-text {
        color: #999999;
    }
    
    /* Combo Box Styles */
    QComboBox {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        padding: 8px 12px;
        min-width: 120px;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: right center;
        width: 24px;
        border-left: 1px solid #e0e0e0;
        border-top-right-radius: 6px;
        border-bottom-right-radius: 6px;
    }
    
    QComboBox::down-arrow {
        width: 12px;
        height: 12px;
        image: url(data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23333'%3E%3Cpath d='M7 10l5 5 5-5z'/%3E%3C/svg%3E);
    }
    
    QComboBox:on {
        border-color: #4CAF50;
    }
    
    QComboBox QAbstractItemView {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        selection-background-color: #4CAF50;
        selection-color: white;
    }
    
    /* Spin Box Styles */
    QSpinBox {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        padding: 8px;
        min-width: 60px;
    }
    
    QSpinBox:focus {
        border-color: #4CAF50;
    }
    
    QSpinBox::up-button, QSpinBox::down-button {
        background-color: #f0f0f0;
        border-radius: 3px;
        width: 20px;
        margin: 2px;
    }
    
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {
        background-color: #4CAF50;
        color: white;
    }
    
    /* Progress Bar Styles */
    QProgressBar {
        background-color: #f0f0f0;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        text-align: center;
        color: #333333;
        height: 24px;
    }
    
    QProgressBar::chunk {
        background-color: #4CAF50;
        border-radius: 4px;
    }
    
    /* Check Box Styles */
    QCheckBox {
        color: #333333;
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 2px solid #e0e0e0;
        border-radius: 4px;
        background-color: #ffffff;
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
        color: #333333;
        spacing: 8px;
    }
    
    QRadioButton::indicator {
        width: 18px;
        height: 18px;
        border: 2px solid #e0e0e0;
        border-radius: 9px;
        background-color: #ffffff;
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
        background-color: #f5f5f5;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        top: -1px;
    }
    
    QTabBar::tab {
        background-color: #ffffff;
        color: #333333;
        padding: 10px 20px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: #f5f5f5;
        color: #4CAF50;
        border-bottom: 2px solid #4CAF50;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #f0f0f0;
    }
    
    /* Table Widget Styles */
    QTableWidget {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        gridline-color: #e0e0e0;
    }
    
    QTableWidget QHeaderView::section {
        background-color: #f0f0f0;
        color: #333333;
        padding: 8px;
        border: 1px solid #e0e0e0;
        font-weight: bold;
    }
    
    QTableWidget::item {
        padding: 8px;
        border: 1px solid #e0e0e0;
    }
    
    QTableWidget::item:selected {
        background-color: #4CAF50;
        color: white;
    }
    
    /* Scroll Area Styles */
    QScrollArea {
        background-color: #f5f5f5;
        border: none;
    }
    
    QScrollBar:vertical {
        background-color: #f0f0f0;
        width: 12px;
        border-radius: 6px;
        margin: 0;
    }
    
    QScrollBar::handle:vertical {
        background-color: #c0c0c0;
        min-height: 20px;
        border-radius: 5px;
        margin: 2px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #a0a0a0;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    
    QScrollBar:horizontal {
        background-color: #f0f0f0;
        height: 12px;
        border-radius: 6px;
        margin: 0;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #c0c0c0;
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
        background-color: #ffffff;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
    }
    
    /* ToolTip Styles */
    QToolTip {
        background-color: #ffffff;
        color: #333333;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        padding: 6px;
    }
    
    /* Message Box Styles */
    QMessageBox {
        background-color: #f5f5f5;
    }
    
    QMessageBox QLabel {
        color: #333333;
    }
    
    /* Slider Styles */
    QSlider {
        background-color: transparent;
    }
    
    QSlider::groove:horizontal {
        background-color: #e0e0e0;
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


def apply_light_theme(app: QApplication):
    """
    Apply the light theme to the application.
    
    Args:
        app: The QApplication instance.
    """
    app.setStyle("Fusion")
    app.setStyleSheet(get_light_theme_stylesheet())
    
    # Set light palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#f5f5f5"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#333333"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#f5f5f5"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#333333"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#333333"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#4CAF50"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#999999"))
    
    app.setPalette(palette)
