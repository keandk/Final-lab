#!/usr/bin/env python3
"""
MyFS: Encrypted File System
Main module that integrates all components and provides a CLI interface.
"""

import os
import sys
import getpass
import argparse
import time
from pathlib import Path

from myfs_constants import (
  MAGIC_NUMBER_DRI, MAGIC_NUMBER_METADATA
)
from myfs_formatter import format_new_volume
from myfs_security import MyFSSecurity
from myfs_connector import MyFSConnector
from myfs_formatter import MyFSFormatter
from myfs_hardware import get_machine_id_hash

# Default paths
DEFAULT_VOLUME_PATH = "myfs/MyFS.DRI"
DEFAULT_METADATA_PATH = "myfs/MyFS.METADATA"

class MyFS:
  def __init__(self, volume_path=DEFAULT_VOLUME_PATH, metadata_path=DEFAULT_METADATA_PATH):
    """Initialize MyFS with the given volume and metadata paths."""
    self.volume_path = volume_path
    self.metadata_path = metadata_path
    self.security = MyFSSecurity(volume_path, metadata_path)
    self.connector = MyFSConnector(volume_path, metadata_path)
    self.formatter = MyFSFormatter(volume_path, metadata_path)
    self.authenticated = False
    self.volume_password = None
    
  def check_files_exist(self):
    """Checks if the volume and metadata files exist."""
    return os.path.exists(self.volume_path) and os.path.exists(self.metadata_path)
    
  def create_volume(self, password):
    """Creates a new MyFS volume."""
    try:
      print("Creating volume...")
      success = self.formatter.format_volume(password)
      if success:
        print(f"Volume created successfully at {self.volume_path}.")
        print(f"Metadata file created at {self.metadata_path}.")
        
        # Create a backup of the clean application state
        print("Creating application backup for integrity protection...")
        self.security.create_backup()
        print("Backup created successfully.")
        
        return True
      print("Failed to create volume.")
      return False
    except Exception as e:
      print(f"Error creating volume: {str(e)}")
      return False
  
  def check_machine_id(self):
    """Verifies if the current machine is authorized to access the volume."""
    if not self.check_files_exist():
      print("Error: Volume or metadata file not found.")
      return False
      
    return self.security.verify_machine_id()
  
  def verify_self_integrity(self):
    """Verifies the integrity of the MyFS application by comparing file hashes with backup."""
    print("Verifying file integrity by comparing hash values...")
    is_valid, details = self.security.verify_self_integrity()
    
    if not is_valid:
      print("WARNING: Application integrity check failed!")
      print("Some files have been modified since the last backup.")
      
      # Print details about failed integrity checks
      for file_path, result in details.items():
        if isinstance(result, dict) and not result.get("is_valid", True):
          print(f"  - {file_path}: {result.get('reason', 'Unknown issue')}")
      
      # Try to repair
      print("Attempting automatic repair...")
      try:
        # This calls the self-repair functionality we added in security module
        # which will attempt to restore files from backup
        success, repair_message = self.security.self_repair.perform_self_repair()
        
        if success:
          print(f"Self-repair successful: {repair_message}")
          # Re-verify after repair
          is_valid, _ = self.security.verify_self_integrity()
          if is_valid:
            print("All files have been restored to their original state.")
            return True
          else:
            print("Some files still don't match their original hash values after repair attempt.")
            return False
        else:
          print(f"Self-repair failed: {repair_message}")
          return False
      except Exception as e:
        print(f"Error during self-repair: {str(e)}")
        return False
    
    print("Integrity verification complete: All files match their original hash values.")
    return True
  
  def authenticate(self, password=None):
    """Authenticates the user with the volume password and dynamic challenge."""
    if not self.check_files_exist():
      print("Error: Volume or metadata file not found.")
      return False
      
    # Check machine ID first
    if not self.check_machine_id():
      print("Error: This machine is not authorized to access the volume.")
      print("The volume can only be accessed from the machine that created it.")
      return False
      
    # Verify application integrity and attempt repair if needed
    if not self.verify_self_integrity():
      print("CRITICAL: Application integrity check failed and repair was not successful.")
      print("The application may be compromised. Exiting for security.")
      sys.exit(1)  # Exit for security if integrity verification fails
      
    # Generate dynamic challenge
    challenge, expected_answer = self.security.generate_dynamic_password()
    print(f"Dynamic challenge: {challenge}")
    answer = input("Your answer: ")
    
    if answer != expected_answer:
      print("Incorrect answer to dynamic challenge.")
      return False
      
    # Check volume password
    if password is None:
      password = getpass.getpass("Volume password: ")
      
    if not self.security.check_volume_password(password):
      print("Incorrect volume password.")
      return False
      
    # Initialize connector with password
    try:
      self.connector.initialize(password)
    except Exception as e:
      print(f"Failed to initialize system: {str(e)}")
      return False
      
    print("Authentication successful.")
    self.authenticated = True
    self.volume_password = password
    
    return True
  
  def change_volume_password(self):
    """Changes the volume password."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    old_password = self.volume_password
    new_password = getpass.getpass("New volume password: ")
    confirm_password = getpass.getpass("Confirm new password: ")
    
    if new_password != confirm_password:
      print("Passwords do not match.")
      return False
      
    try:
      self.security.change_volume_password(old_password, new_password)
      self.volume_password = new_password
      
      # Re-initialize connector with new password
      self.connector.initialize(new_password)
      
      print("Volume password changed successfully.")
      return True
    except Exception as e:
      print(f"Failed to change password: {str(e)}")
      return False
  
  def list_files(self, include_deleted=False):
    """Lists all files in the volume."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      files = self.connector.list_files(include_deleted)
      
      if not files:
        print("No files found in volume.")
        return True
        
      print(f"{'Index':<6} {'Filename':<30} {'Size':<12} {'Status':<10} {'Encrypted':<10}")
      print("-" * 70)
      
      for file_info in files:
        size_str = f"{file_info['size']:,} bytes"
        encrypted = "Yes" if file_info.get('is_encrypted', False) else "No"
        print(f"{file_info['index']:<6} {file_info['filename']:<30} {size_str:<12} {file_info['status']:<10} {encrypted:<10}")
        
      return True
    except Exception as e:
      print(f"Failed to list files: {str(e)}")
      return False
  
  def import_file(self, filepath, encrypt=False):
    """Imports a file into the volume."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    if not os.path.exists(filepath):
      print(f"Error: File not found: {filepath}")
      return False
      
    try:
      file_password = None
      if encrypt:
        file_password = getpass.getpass("File password: ")
        confirm_password = getpass.getpass("Confirm file password: ")
        
        if file_password != confirm_password:
          print("Passwords do not match.")
          return False
          
      print(f"Importing {filepath}...")
      file_index = self.connector.import_file(filepath, file_password)
      print(f"File imported successfully with index {file_index}.")
      return True
    except Exception as e:
      print(f"Failed to import file: {str(e)}")
      return False
  
  def export_file(self, file_index, export_path, use_original_path=False):
    """Exports a file from the volume."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      file_index = int(file_index)
      file_metadata = self.connector.metadata.get_file_metadata(file_index)
      
      file_password = None
      if file_metadata.get('is_encrypted', False):
        file_password = getpass.getpass("File password: ")
        
      print(f"Exporting file with index {file_index}...")
      exported_path = self.connector.export_file(
        file_index, export_path, file_password, use_original_path
      )
      print(f"File exported successfully to {exported_path}.")
      return True
    except Exception as e:
      print(f"Failed to export file: {str(e)}")
      return False
  
  def delete_file(self, file_index, permanent=False):
    """Deletes a file from the volume."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      file_index = int(file_index)
      
      if permanent:
        confirm = input("Are you sure you want to permanently delete this file? (y/n): ")
        if confirm.lower() != 'y':
          print("Operation cancelled.")
          return False
          
      print(f"Deleting file with index {file_index}...")
      self.connector.delete_file(file_index, permanent)
      print(f"File deleted {'permanently' if permanent else 'successfully'}.")
      return True
    except Exception as e:
      print(f"Failed to delete file: {str(e)}")
      return False
  
  def recover_file(self, file_index):
    """Recovers a deleted file."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      file_index = int(file_index)
      print(f"Recovering file with index {file_index}...")
      self.connector.recover_file(file_index)
      print("File recovered successfully.")
      return True
    except Exception as e:
      print(f"Failed to recover file: {str(e)}")
      return False
  
  def set_file_password(self, file_index):
    """Sets or changes a file's password."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      file_index = int(file_index)
      file_metadata = self.connector.metadata.get_file_metadata(file_index)
      
      if file_metadata.get('is_encrypted', False):
        print("This file is already encrypted.")
        action = input("Do you want to change the password or remove encryption? (change/remove): ")
        
        if action.lower() == 'change':
          old_password = getpass.getpass("Current file password: ")
          new_password = getpass.getpass("New file password: ")
          confirm_password = getpass.getpass("Confirm new password: ")
          
          if new_password != confirm_password:
            print("Passwords do not match.")
            return False
            
          print(f"Changing password for file with index {file_index}...")
          try:
            self.connector.set_file_password(file_index, new_password, old_password)
            print("File password changed successfully.")
          except Exception as e:
            print(f"Password change failed: {str(e)}")
            return False
        elif action.lower() == 'remove':
          old_password = getpass.getpass("Current file password: ")
          print(f"Removing encryption for file with index {file_index}...")
          try:
            self.connector.set_file_password(file_index, None, old_password)
            print("File encryption removed successfully.")
          except Exception as e:
            print(f"Encryption removal failed: {str(e)}")
            return False
        else:
          print("Invalid action. Operation cancelled.")
          return False
      else:
        new_password = getpass.getpass("File password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if new_password != confirm_password:
          print("Passwords do not match.")
          return False
          
        print(f"Encrypting file with index {file_index}...")
        self.connector.set_file_password(file_index, new_password)
        print("File encrypted successfully.")
        
      return True
    except Exception as e:
      print(f"Failed to set file password: {str(e)}")
      return False

  def verify_file_integrity(self, file_index):
    """Verifies the integrity of a file."""
    if not self.authenticated:
      print("Error: You must authenticate first.")
      return False
      
    try:
      file_index = int(file_index)
      print(f"Verifying integrity of file with index {file_index}...")
      is_valid, message = self.connector.verify_file_integrity(file_index)
      
      if is_valid:
        print("File integrity verified successfully.")
      else:
        print(f"File integrity check failed: {message}")
        
      return is_valid
    except Exception as e:
      print(f"Failed to verify file integrity: {str(e)}")
      return False

def parse_args():
  """Parse command line arguments."""
  parser = argparse.ArgumentParser(description="MyFS - Secure File Storage System")
  
  # Subparsers for different commands
  subparsers = parser.add_subparsers(dest="command", help="Command to execute")
  
  # Create volume
  create_parser = subparsers.add_parser("create", help="Create a new volume")
  create_parser.add_argument("-p", "--password", help="Volume password")
  
  # Change volume password
  passwd_parser = subparsers.add_parser("passwd", help="Change volume password")
  
  # List files
  list_parser = subparsers.add_parser("list", help="List files in volume")
  list_parser.add_argument("-d", "--deleted", action="store_true", help="Include deleted files")
  
  # Import file
  import_parser = subparsers.add_parser("import", help="Import a file into the volume")
  import_parser.add_argument("filepath", help="Path to file to import")
  import_parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file")
  
  # Export file
  export_parser = subparsers.add_parser("export", help="Export a file from the volume")
  export_parser.add_argument("index", help="Index of the file to export")
  export_parser.add_argument("exportpath", help="Path to export the file to")
  export_parser.add_argument("-o", "--original", action="store_true", help="Use original path")
  
  # Delete file
  delete_parser = subparsers.add_parser("delete", help="Delete a file from the volume")
  delete_parser.add_argument("index", help="Index of the file to delete")
  delete_parser.add_argument("-p", "--permanent", action="store_true", help="Delete permanently")
  
  # Recover file
  recover_parser = subparsers.add_parser("recover", help="Recover a deleted file")
  recover_parser.add_argument("index", help="Index of the file to recover")
  
  # Set file password
  setpass_parser = subparsers.add_parser("setpass", help="Set/change file password")
  setpass_parser.add_argument("index", help="Index of the file")
  
  # Verify file integrity
  verify_parser = subparsers.add_parser("verify", help="Verify file integrity")
  verify_parser.add_argument("index", help="Index of the file to verify")
  
  # Verify system integrity
  integrity_parser = subparsers.add_parser("integrity", help="Verify system integrity")
  
  # Create backup
  backup_parser = subparsers.add_parser("backup", help="Create/update system backup")
  
  # Interactive mode
  interactive_parser = subparsers.add_parser("interactive", help="Enter interactive mode")
  
  return parser.parse_args()

def interactive_mode(myfs):
  """Interactive mode for MyFS."""
  # Authenticate first
  if not myfs.authenticate():
    return False
    
  print("\nWelcome to MyFS Interactive Mode")
  print("Type 'help' for a list of commands, 'exit' to quit.")
  
  while True:
    cmd = input("\nMyFS> ").strip()
    
    if cmd == "exit" or cmd == "quit":
      return True
      
    elif cmd == "help":
      print("\nAvailable commands:")
      print("  list             - List all files")
      print("  list -d          - List all files including deleted")
      print("  import <path>    - Import a file")
      print("  import -e <path> - Import and encrypt a file")
      print("  export <idx> <path> - Export a file")
      print("  export -o <idx> <path> - Export to original path")
      print("  delete <idx>       - Delete a file (recoverable)")
      print("  delete -p <idx>    - Delete a file permanently")
      print("  recover <idx>      - Recover a deleted file")
      print("  setpass <idx>      - Set/change file password")
      print("  verify <idx>       - Verify file integrity")
      print("  passwd            - Change volume password")
      print("  integrity         - Verify system integrity")
      print("  backup            - Create/update system backup")
      print("  exit              - Exit interactive mode")
      
    elif cmd == "list" or cmd == "list -d":
      include_deleted = "-d" in cmd
      myfs.list_files(include_deleted)
      
    elif cmd.startswith("import "):
      parts = cmd.split(" ", 2)
      encrypt = False
      
      if parts[1] == "-e" and len(parts) > 2:
        encrypt = True
        filepath = parts[2]
      else:
        filepath = parts[1]
        
      myfs.import_file(filepath, encrypt)
      
    elif cmd.startswith("export "):
      parts = cmd.split(" ", 3)
      use_original = False
      
      if parts[1] == "-o" and len(parts) > 3:
        use_original = True
        idx = parts[2]
        export_path = parts[3]
      elif len(parts) > 2:
        idx = parts[1]
        export_path = parts[2]
      else:
        print("Invalid export command. Use: export [-o] <idx> <path>")
        continue
        
      myfs.export_file(idx, export_path, use_original)
      
    elif cmd.startswith("delete "):
      parts = cmd.split(" ")
      permanent = False
      
      if parts[1] == "-p" and len(parts) > 2:
        permanent = True
        idx = parts[2]
      else:
        idx = parts[1]
        
      myfs.delete_file(idx, permanent)
      
    elif cmd.startswith("recover "):
      parts = cmd.split(" ")
      idx = parts[1]
      myfs.recover_file(idx)
      
    elif cmd.startswith("setpass "):
      parts = cmd.split(" ")
      idx = parts[1]
      myfs.set_file_password(idx)
      
    elif cmd.startswith("verify "):
      parts = cmd.split(" ")
      idx = parts[1]
      myfs.verify_file_integrity(idx)
      
    elif cmd == "passwd":
      myfs.change_volume_password()
      
    elif cmd == "integrity":
      if myfs.verify_self_integrity():
        print("System integrity check passed.")
      
    elif cmd == "backup":
      try:
        print("Creating application backup...")
        if myfs.security.create_backup():
          print("System backup created/updated successfully.")
          return 0
        else:
          print("Failed to create system backup.")
          return 1
      except Exception as e:
        print(f"Error creating backup: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
      
    else:
      print("Unknown command. Type 'help' for a list of commands.")
  
  return True

def main():
  """Main entry point for MyFS."""
  args = parse_args()
  
  # Create MyFS instance
  myfs = MyFS()
  
  # If no command is provided, default to interactive mode
  if not args.command:
    return 0 if interactive_mode(myfs) else 1
  
  # Execute the requested command
  if args.command == "create":
    if args.password:
      password = args.password
    else:
      password = getpass.getpass("Volume password: ")
      confirm = getpass.getpass("Confirm password: ")
      if password != confirm:
        print("Passwords do not match.")
        return 1
    
    return 0 if myfs.create_volume(password) else 1
    
  elif args.command == "interactive":
    return 0 if interactive_mode(myfs) else 1
    
  elif args.command == "integrity":
    print("Running integrity verification...")
    if myfs.verify_self_integrity():
      print("RESULT: System integrity check passed. All files match their original hash values.")
      return 0
    else:
      print("RESULT: System integrity check failed. Some files could not be restored.")
      return 1
    
  elif args.command == "backup":
    try:
      print("Creating application backup...")
      if myfs.security.create_backup():
        print("System backup created/updated successfully.")
        return 0
      else:
        print("Failed to create system backup.")
        return 1
    except Exception as e:
      print(f"Error creating backup: {str(e)}")
      import traceback
      traceback.print_exc()
      return 1
  
  # For all other commands, authenticate first
  if not myfs.authenticate():
    return 1
    
  # Execute the command
  if args.command == "passwd":
    return 0 if myfs.change_volume_password() else 1
    
  elif args.command == "list":
    return 0 if myfs.list_files(args.deleted) else 1
    
  elif args.command == "import":
    return 0 if myfs.import_file(args.filepath, args.encrypt) else 1
    
  elif args.command == "export":
    return 0 if myfs.export_file(args.index, args.exportpath, args.original) else 1
    
  elif args.command == "delete":
    return 0 if myfs.delete_file(args.index, args.permanent) else 1
    
  elif args.command == "recover":
    return 0 if myfs.recover_file(args.index) else 1
    
  elif args.command == "setpass":
    return 0 if myfs.set_file_password(args.index) else 1
    
  elif args.command == "verify":
    return 0 if myfs.verify_file_integrity(args.index) else 1
    
  return 0

if __name__ == "__main__":
  sys.exit(main()) 