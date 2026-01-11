#!/usr/bin/env python3
"""
CXA Project Comprehensive Verification Script
This script performs a detailed verification of all project components.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

class CXAVerifier:
    """Comprehensive project verification class."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'files_checked': 0,
            'files_valid': 0,
            'files_missing': 0,
            'files_errors': 0,
            'components': {},
            'errors': [],
            'warnings': []
        }
    
    def run_full_verification(self):
        """Run comprehensive verification."""
        print("=" * 80)
        print("CXA PROJECT COMPREHENSIVE VERIFICATION")
        print("=" * 80)
        print(f"\nProject Root: {self.project_root}")
        print(f"Verification Time: {self.results['timestamp']}\n")
        
        # Check all components
        self.check_root_files()
        self.check_python_components()
        self.check_rust_components()
        self.check_go_components()
        self.check_documentation()
        self.check_test_suite()
        self.check_configuration()
        
        # Generate summary
        self.print_summary()
        
        return self.results
    
    def check_file_exists(self, filepath: Path, description: str = "") -> bool:
        """Check if a file exists and is not empty."""
        self.results['files_checked'] += 1
        
        if not filepath.exists():
            self.results['files_missing'] += 1
            error_msg = f"MISSING: {filepath} ({description})"
            self.results['errors'].append(error_msg)
            print(f"  ❌ {error_msg}")
            return False
        
        if filepath.stat().st_size == 0:
            self.results['files_errors'] += 1
            error_msg = f"EMPTY: {filepath} ({description})"
            self.results['warnings'].append(error_msg)
            print(f"  ⚠️  {error_msg}")
            return True  # File exists but is empty
        
        self.results['files_valid'] += 1
        print(f"  ✓ {filepath.relative_to(self.project_root)}")
        return True
    
    def check_root_files(self):
        """Check root directory files."""
        print("\n" + "─" * 80)
        print("ROOT DIRECTORY FILES")
        print("─" * 80)
        
        root_files = [
            ("Cargo.toml", "Rust workspace configuration"),
            ("go.mod", "Go module configuration"),
            ("go.sum", "Go dependency checksums"),
            ("Makefile", "Build automation"),
            ("README.md", "Main documentation"),
            ("ADMIN_README.md", "Administrator guide"),
            ("docker-compose.yml", "Docker orchestration"),
            ("Dockerfile.python", "Python Docker image"),
            ("Dockerfile.api", "Go API Docker image"),
            ("build_linux.sh", "Linux build script"),
            ("build.bat", "Windows build script"),
        ]
        
        self.results['components']['root'] = {
            'total': len(root_files),
            'valid': 0,
            'missing': 0
        }
        
        for filename, description in root_files:
            filepath = self.project_root / filename
            if self.check_file_exists(filepath, description):
                self.results['components']['root']['valid'] += 1
            else:
                self.results['components']['root']['missing'] += 1
    
    def check_python_components(self):
        """Check Python components."""
        print("\n" + "─" * 80)
        print("PYTHON COMPONENTS")
        print("─" * 80)
        
        python_files = {
            'python-core': [
                ("__init__.py", "Core package init"),
                ("crypto/__init__.py", "Crypto package init"),
                ("crypto/engine.py", "Crypto engine"),
                ("cxa/__init__.py", "CXA package init"),
                ("cxa/engine.py", "Main engine"),
                ("cxa/backup.py", "Backup manager"),
                ("cxa/key_manager.py", "Key manager"),
                ("cxa/memory.py", "Memory security"),
                ("cxa/security_monitor.py", "Security monitor"),
                ("cxa/steganography.py", "Steganography"),
                ("stego/__init__.py", "Stego package init"),
                ("stego/image.py", "Image steganography"),
                ("stego/text.py", "Text steganography"),
            ],
            'python-cli': [
                ("main.py", "CLI entry point"),
            ],
            'python-gui': [
                ("__init__.py", "GUI package init"),
                ("main.py", "GUI entry point"),
                ("app.py", "Main application"),
                ("components/__init__.py", "Components init"),
                ("components/key_widget.py", "Key widget"),
                ("components/progress_widget.py", "Progress widget"),
                ("components/status_widget.py", "Status widget"),
                ("tabs/__init__.py", "Tabs init"),
                ("tabs/dashboard.py", "Dashboard tab"),
                ("tabs/encryption.py", "Encryption tab"),
                ("tabs/decryption.py", "Decryption tab"),
                ("tabs/key_management.py", "Key management tab"),
                ("tabs/backup.py", "Backup tab"),
                ("tabs/settings.py", "Settings tab"),
                ("themes/__init__.py", "Themes init"),
                ("themes/dark.py", "Dark theme"),
                ("themes/light.py", "Light theme"),
            ]
        }
        
        requirements_files = [
            ("requirements/base.txt", "Base dependencies"),
            ("requirements/dev.txt", "Development dependencies"),
        ]
        
        self.results['components']['python'] = {
            'subdirectories': list(python_files.keys()),
            'total_files': 0,
            'valid_files': 0,
            'missing_files': 0
        }
        
        for dir_name, files in python_files.items():
            print(f"\n📁 {dir_name}/")
            self.results['components']['python']['total_files'] += len(files)
            
            for filename, description in files:
                filepath = self.project_root / dir_name / filename
                if self.check_file_exists(filepath, description):
                    self.results['components']['python']['valid_files'] += 1
                else:
                    self.results['components']['python']['missing_files'] += 1
        
        print(f"\n📁 requirements/")
        for filename, description in requirements_files:
            filepath = self.project_root / filename
            if self.check_file_exists(filepath, description):
                self.results['components']['python']['valid_files'] += 1
            self.results['components']['python']['total_files'] += 1
    
    def check_rust_components(self):
        """Check Rust components."""
        print("\n" + "─" * 80)
        print("RUST COMPONENTS")
        print("─" * 80)
        
        rust_modules = [
            'aes',
            'chacha20',
            'ed25519',
            'hash',
            'kdf',
            'mac',
            'mem',
            'random',
            'rsa'
        ]
        
        self.results['components']['rust'] = {
            'modules': rust_modules,
            'total_files': 0,
            'valid_files': 0,
            'missing_files': 0
        }
        
        for module in rust_modules:
            module_path = self.project_root / 'rust-core' / 'crypto' / module
            print(f"\n⚙️  {module}/")
            
            # Check Cargo.toml
            cargo_path = module_path / 'Cargo.toml'
            if self.check_file_exists(cargo_path, f"{module} crate configuration"):
                self.results['components']['rust']['valid_files'] += 1
            self.results['components']['rust']['total_files'] += 1
            
            # Check lib.rs
            lib_path = module_path / 'src' / 'lib.rs'
            if self.check_file_exists(lib_path, f"{module} implementation"):
                self.results['components']['rust']['valid_files'] += 1
            self.results['components']['rust']['total_files'] += 1
    
    def check_go_components(self):
        """Check Go components."""
        print("\n" + "─" * 80)
        print("GO COMPONENTS")
        print("─" * 80)
        
        go_services = [
            ('api-server', 'API server'),
            ('event-monitor', 'Event monitoring'),
            ('event-processor', 'Event processing'),
            ('monitor', 'System monitor'),
        ]
        
        self.results['components']['go'] = {
            'services': [s[0] for s in go_services],
            'total_files': 0,
            'valid_files': 0,
            'missing_files': 0
        }
        
        for service_dir, description in go_services:
            service_path = self.project_root / 'go-services' / service_dir
            print(f"\n🔧 {service_dir}/")
            
            main_path = service_path / 'main.go'
            if self.check_file_exists(main_path, description):
                self.results['components']['go']['valid_files'] += 1
            self.results['components']['go']['total_files'] += 1
    
    def check_documentation(self):
        """Check documentation files."""
        print("\n" + "─" * 80)
        print("DOCUMENTATION")
        print("─" * 80)
        
        docs = [
            ('docs/api.md', 'API reference'),
            ('docs/architecture.md', 'Architecture docs'),
            ('docs/deployment.md', 'Deployment guide'),
            ('docs/security.md', 'Security documentation'),
        ]
        
        self.results['components']['docs'] = {
            'total': len(docs),
            'valid': 0,
            'missing': 0
        }
        
        for filepath, description in docs:
            path = self.project_root / filepath
            if self.check_file_exists(path, description):
                self.results['components']['docs']['valid'] += 1
            else:
                self.results['components']['docs']['missing'] += 1
    
    def check_test_suite(self):
        """Check test suite files."""
        print("\n" + "─" * 80)
        print("TEST SUITE")
        print("─" * 80)
        
        test_files = [
            ('tests/__init__.py', 'Tests package init'),
            ('tests/conftest.py', 'Pytest configuration'),
            ('tests/unit/__init__.py', 'Unit tests init'),
            ('tests/unit/test_crypto.py', 'Crypto unit tests'),
            ('tests/unit/test_steganography.py', 'Steganography unit tests'),
            ('tests/unit/test_backup.py', 'Backup unit tests'),
            ('tests/unit/test_security_monitor.py', 'Security monitor tests'),
            ('tests/unit/test_memory.py', 'Memory security tests'),
            ('tests/integration/__init__.py', 'Integration tests init'),
            ('tests/integration/test_complete_workflow.py', 'Integration tests'),
            ('tests/fuzz/__init__.py', 'Fuzz tests init'),
            ('tests/fuzz/test_crypto_fuzzing.py', 'Fuzz tests'),
        ]
        
        self.results['components']['tests'] = {
            'total': len(test_files),
            'valid': 0,
            'missing': 0
        }
        
        for filepath, description in test_files:
            path = self.project_root / filepath
            if self.check_file_exists(path, description):
                self.results['components']['tests']['valid'] += 1
            else:
                self.results['components']['tests']['missing'] += 1
    
    def check_configuration(self):
        """Check configuration files."""
        print("\n" + "─" * 80)
        print("CONFIGURATION")
        print("─" * 80)
        
        config_files = [
            ('config/default.yml', 'Default configuration'),
        ]
        
        self.results['components']['config'] = {
            'total': len(config_files),
            'valid': 0,
            'missing': 0
        }
        
        for filepath, description in config_files:
            path = self.project_root / filepath
            if self.check_file_exists(path, description):
                self.results['components']['config']['valid'] += 1
            else:
                self.results['components']['config']['missing'] += 1
    
    def print_summary(self):
        """Print verification summary."""
        print("\n" + "=" * 80)
        print("VERIFICATION SUMMARY")
        print("=" * 80)
        
        total = self.results['files_checked']
        valid = self.results['files_valid']
        missing = self.results['files_missing']
        errors = self.results['files_errors']
        
        print(f"\n📊 OVERALL STATISTICS:")
        print(f"   Total Files Checked: {total}")
        print(f"   ✓ Valid Files: {valid}")
        print(f"   ❌ Missing Files: {missing}")
        print(f"   ⚠️  Empty/Warning Files: {errors}")
        
        if total > 0:
            success_rate = (valid / total) * 100
            print(f"\n   Success Rate: {success_rate:.1f}%")
        
        print("\n" + "─" * 80)
        print("COMPONENT BREAKDOWN:")
        print("─" * 80)
        
        for component, data in self.results['components'].items():
            print(f"\n📦 {component.upper()}:")
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (int, str, list)):
                        print(f"   • {key}: {value}")
        
        if self.results['errors']:
            print("\n" + "─" * 80)
            print("ERRORS FOUND:")
            print("─" * 80)
            for error in self.results['errors']:
                print(f"   ❌ {error}")
        
        if self.results['warnings']:
            print("\n" + "─" * 80)
            print("WARNINGS:")
            print("─" * 80)
            for warning in self.results['warnings']:
                print(f"   ⚠️  {warning}")
        
        print("\n" + "=" * 80)
        if missing == 0 and errors == 0:
            print("✅ VERIFICATION COMPLETE - ALL FILES PRESENT AND VALID")
        elif missing == 0:
            print("⚠️  VERIFICATION COMPLETE - ALL FILES PRESENT (SOME EMPTY)")
        else:
            print("❌ VERIFICATION COMPLETE - MISSING FILES DETECTED")
        print("=" * 80)
        
        # Save results to JSON
        results_path = self.project_root / 'verification_results.json'
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n📄 Detailed results saved to: {results_path}")


def main():
    """Main entry point."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    
    verifier = CXAVerifier(project_root)
    results = verifier.run_full_verification()
    
    # Return appropriate exit code
    if results['files_missing'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
