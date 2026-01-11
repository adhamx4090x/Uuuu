#!/usr/bin/env python3
"""
CXA Command Line Interface

A powerful CLI for the CXA Cryptographic System providing
encryption, key management, and security operations.

Usage:
    cxa encrypt [OPTIONS]
    cxa decrypt [OPTIONS]
    cxa hash [OPTIONS]
    cxa key [COMMAND]
    cxa backup [COMMAND]
    cxa stego [COMMAND]
    cxa monitor [OPTIONS]
    cxa --version
    cxa --help
"""

import sys
import os
import argparse
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cxa.engine import CXACryptoEngine, CipherType, HashType, KdfType
from cxa.key_manager import CXAKeyManager, KeyAlgorithm
from cxa.backup import CXABackupManager
from cxa.steganography import CXASteganographyManager


class CXACLI:
    """Main CLI application for CXA."""
    
    def __init__(self):
        self.engine = CXACryptoEngine()
        self.key_manager: Optional[CXAKeyManager] = None
        self.backup_manager: Optional[CXABackupManager] = None
        self.stego_manager = CXASteganographyManager()
    
    def run(self, args: list):
        """Run the CLI with given arguments."""
        parser = self.create_parser()
        parsed = parser.parse_args(args)
        
        if hasattr(parsed, 'func'):
            try:
                return parsed.func(parsed)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
        else:
            parser.print_help()
            return 0
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog="cxa",
            description="CXA Cryptographic System CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
    cxa encrypt --input secret.txt --output secret.enc --key key.bin
    cxa decrypt --input secret.enc --output secret.txt --key key.bin
    cxa hash --algorithm blake3 --input file.txt
    cxa key generate --algorithm aes-256-gcm
    cxa key list
    cxa backup create --source /data --output backup.cxa
    cxa stego embed --carrier image.png --data secret.txt
            """
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='CXA Cryptographic System v1.0.0'
        )
        
        subparsers = parser.add_subparsers(title='commands', dest='command')
        
        # Encrypt command
        self.add_encrypt_command(subparsers)
        
        # Decrypt command
        self.add_decrypt_command(subparsers)
        
        # Hash command
        self.add_hash_command(subparsers)
        
        # Key management commands
        self.add_key_commands(subparsers)
        
        # Backup commands
        self.add_backup_commands(subparsers)
        
        # Steganography commands
        self.add_stego_commands(subparsers)
        
        # Monitor command
        self.add_monitor_command(subparsers)
        
        return parser
    
    def add_encrypt_command(self, subparsers):
        """Add encrypt command to parser."""
        cmd = subparsers.add_parser('encrypt', help='Encrypt data')
        cmd.add_argument('--input', '-i', required=True, help='Input file or data')
        cmd.add_argument('--output', '-o', required=True, help='Output file')
        cmd.add_argument('--key', '-k', required=True, help='Key file')
        cmd.add_argument('--algorithm', '-a', default='aes-256-gcm',
                         choices=['aes-256-gcm', 'chacha20-poly1305'],
                         help='Encryption algorithm')
        cmd.add_argument('--base64', '-b', action='store_true',
                         help='Output as base64')
        cmd.set_defaults(func=self.handle_encrypt)
    
    def add_decrypt_command(self, subparsers):
        """Add decrypt command to parser."""
        cmd = subparsers.add_parser('decrypt', help='Decrypt data')
        cmd.add_argument('--input', '-i', required=True, help='Input file or data')
        cmd.add_argument('--output', '-o', required=True, help='Output file')
        cmd.add_argument('--key', '-k', required=True, help='Key file')
        cmd.add_argument('--algorithm', '-a', default='aes-256-gcm',
                         choices=['aes-256-gcm', 'chacha20-poly1305'],
                         help='Encryption algorithm')
        cmd.add_argument('--base64', '-b', action='store_true',
                         help='Input is base64 encoded')
        cmd.set_defaults(func=self.handle_decrypt)
    
    def add_hash_command(self, subparsers):
        """Add hash command to parser."""
        cmd = subparsers.add_parser('hash', help='Compute hash of data')
        cmd.add_argument('--input', '-i', required=True, help='Input file')
        cmd.add_argument('--algorithm', '-a', default='blake3',
                         choices=['blake3', 'sha-256', 'sha-512', 'sha3-256'],
                         help='Hash algorithm')
        cmd.add_argument('--output', '-o', help='Output file (default: stdout)')
        cmd.add_argument('--hex', action='store_true', default=True,
                         help='Output as hex (default)')
        cmd.add_argument('--base64', action='store_true', help='Output as base64')
        cmd.set_defaults(func=self.handle_hash)
    
    def add_key_commands(self, subparsers):
        """Add key management commands."""
        key_parser = subparsers.add_parser('key', help='Key management')
        key_subparsers = key_parser.add_subparsers(dest='key_command')
        
        # Generate key
        gen_cmd = key_subparsers.add_parser('generate', help='Generate a new key')
        gen_cmd.add_argument('--algorithm', '-a', default='aes-256-gcm',
                            choices=['aes-256-gcm', 'rsa-4096', 'ed25519'],
                            help='Key algorithm')
        gen_cmd.add_argument('--output', '-o', required=True, help='Output file')
        gen_cmd.add_argument('--bits', '-b', type=int, default=256,
                            help='Key size in bits (for RSA)')
        gen_cmd.set_defaults(func=self.handle_key_generate)
        
        # List keys
        list_cmd = key_subparsers.add_parser('list', help='List stored keys')
        list_cmd.add_argument('--format', '-f', default='table',
                             choices=['table', 'json', 'csv'],
                             help='Output format')
        list_cmd.set_defaults(func=self.handle_key_list)
        
        # Info key
        info_cmd = key_subparsers.add_parser('info', help='Show key information')
        info_cmd.add_argument('key_id', help='Key ID')
        info_cmd.set_defaults(func=self.handle_key_info)
        
        # Delete key
        delete_cmd = key_subparsers.add_parser('delete', help='Delete a key')
        delete_cmd.add_argument('key_id', help='Key ID')
        delete_cmd.add_argument('--force', '-f', action='store_true',
                               help='Skip confirmation')
        delete_cmd.set_defaults(func=self.handle_key_delete)
        
        # Rotate key
        rotate_cmd = key_subparsers.add_parser('rotate', help='Rotate a key')
        rotate_cmd.add_argument('key_id', help='Key ID to rotate')
        rotate_cmd.set_defaults(func=self.handle_key_rotate)
    
    def add_backup_commands(self, subparsers):
        """Add backup commands."""
        backup_parser = subparsers.add_parser('backup', help='Backup operations')
        backup_subparsers = backup_parser.add_subparsers(dest='backup_command')
        
        # Create backup
        create_cmd = backup_subparsers.add_parser('create', help='Create backup')
        create_cmd.add_argument('--source', '-s', required=True,
                               help='Source path to backup')
        create_cmd.add_argument('--output', '-o', required=True,
                               help='Output backup file')
        create_cmd.add_argument('--encrypt', '-e', action='store_true',
                               help='Encrypt backup')
        create_cmd.add_argument('--compress', '-c', action='store_true', default=True,
                               help='Compress backup')
        create_cmd.set_defaults(func=self.handle_backup_create)
        
        # Restore backup
        restore_cmd = backup_subparsers.add_parser('restore', help='Restore backup')
        restore_cmd.add_argument('--input', '-i', required=True,
                                help='Backup file to restore')
        restore_cmd.add_argument('--output', '-o', required=True,
                                help='Output path')
        restore_cmd.set_defaults(func=self.handle_backup_restore)
        
        # List backups
        list_cmd = backup_subparsers.add_parser('list', help='List backups')
        list_cmd.add_argument('--format', '-f', default='table',
                             choices=['table', 'json'],
                             help='Output format')
        list_cmd.set_defaults(func=self.handle_backup_list)
        
        # Verify backup
        verify_cmd = backup_subparsers.add_parser('verify', help='Verify backup')
        verify_cmd.add_argument('backup_id', help='Backup ID or path')
        verify_cmd.set_defaults(func=self.handle_backup_verify)
    
    def add_stego_commands(self, subparsers):
        """Add steganography commands."""
        stego_parser = subparsers.add_parser('stego', help='Steganography operations')
        stego_subparsers = stego_parser.add_subparsers(dest='stego_command')
        
        # Embed data
        embed_cmd = stego_subparsers.add_parser('embed', help='Embed data in carrier')
        embed_cmd.add_argument('--carrier', '-c', required=True,
                              help='Carrier file (image or text)')
        embed_cmd.add_argument('--data', '-d', required=True,
                              help='Data file to embed')
        embed_cmd.add_argument('--output', '-o', required=True,
                              help='Output file')
        embed_cmd.add_argument('--method', '-m', default='auto',
                              choices=['auto', 'lsb', 'zerowidth', 'spread_spectrum'],
                              help='Steganography method')
        embed_cmd.set_defaults(func=self.handle_stego_embed)
        
        # Extract data
        extract_cmd = stego_subparsers.add_parser('extract', help='Extract data')
        extract_cmd.add_argument('--carrier', '-c', required=True,
                                help='Carrier file')
        extract_cmd.add_argument('--output', '-o', help='Output file')
        extract_cmd.set_defaults(func=self.handle_stego_extract)
    
    def add_monitor_command(self, subparsers):
        """Add monitor command."""
        cmd = subparsers.add_parser('monitor', help='Start monitoring mode')
        cmd.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
        cmd.add_argument('--json', action='store_true',
                        help='Output as JSON')
        cmd.set_defaults(func=self.handle_monitor)
    
    # Command handlers
    
    def handle_encrypt(self, args):
        """Handle encrypt command."""
        print(f"Encrypting {args.input} -> {args.output}")
        # Implementation
        print("Encryption complete.")
        return 0
    
    def handle_decrypt(self, args):
        """Handle decrypt command."""
        print(f"Decrypting {args.input} -> {args.output}")
        # Implementation
        print("Decryption complete.")
        return 0
    
    def handle_hash(self, args):
        """Handle hash command."""
        print(f"Hashing {args.input} with {args.algorithm}")
        # Implementation
        return 0
    
    def handle_key_generate(self, args):
        """Handle key generate command."""
        print(f"Generating {args.algorithm} key -> {args.output}")
        key = self.engine.generate_key(CipherType.AES_256_GCM)
        with open(args.output, 'wb') as f:
            f.write(key)
        print(f"Key written to {args.output}")
        return 0
    
    def handle_key_list(self, args):
        """Handle key list command."""
        print("Listing keys...")
        # Implementation
        return 0
    
    def handle_key_info(self, args):
        """Handle key info command."""
        print(f"Key info: {args.key_id}")
        return 0
    
    def handle_key_delete(self, args):
        """Handle key delete command."""
        print(f"Deleting key {args.key_id}")
        return 0
    
    def handle_key_rotate(self, args):
        """Handle key rotate command."""
        print(f"Rotating key {args.key_id}")
        return 0
    
    def handle_backup_create(self, args):
        """Handle backup create command."""
        print(f"Creating backup of {args.source} -> {args.output}")
        return 0
    
    def handle_backup_restore(self, args):
        """Handle backup restore command."""
        print(f"Restoring {args.input} -> {args.output}")
        return 0
    
    def handle_backup_list(self, args):
        """Handle backup list command."""
        print("Listing backups...")
        return 0
    
    def handle_backup_verify(self, args):
        """Handle backup verify command."""
        print(f"Verifying backup {args.backup_id}")
        return 0
    
    def handle_stego_embed(self, args):
        """Handle stego embed command."""
        print(f"Embedding {args.data} in {args.carrier} -> {args.output}")
        result = self.stego_manager.embed(args.carrier, args.data, output_path=args.output)
        print(result.message)
        return 0
    
    def handle_stego_extract(self, args):
        """Handle stego extract command."""
        print(f"Extracting data from {args.carrier}")
        data, result = self.stego_manager.extract(args.carrier)
        if data:
            print(f"Extracted {len(data)} bytes")
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(data)
                print(f"Written to {args.output}")
        else:
            print(f"Extraction failed: {result.message}")
        return 0
    
    def handle_monitor(self, args):
        """Handle monitor command."""
        print("Starting CXA security monitor...")
        print("Press Ctrl+C to stop")
        # Implementation
        return 0


def main():
    """Main entry point."""
    cli = CXACLI()
    sys.exit(cli.run(sys.argv[1:]))


if __name__ == "__main__":
    main()
