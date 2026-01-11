#!/usr/bin/env python3
"""
CXA Cryptographic System - GUI Entry Point

This module serves as the entry point for the CXA GUI application.
It initializes the application and displays the main window.

Author: MiniMax Agent
Version: 1.0.0
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from app import CXAApplication
from themes.dark import apply_dark_theme


def main():
    """Main entry point for the CXA GUI application."""
    app = CXAApplication()
    apply_dark_theme(app)
    window = CXAApplication.MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
