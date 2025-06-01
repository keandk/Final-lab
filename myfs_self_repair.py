"""
Self-repair module for MyFS.
Handles backup and restoration of application files to prevent tampering.
"""
import re
import os
import sys
import json
import shutil
import base64
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path
import hashlib

from myfs_utils import calculate_sha256
from myfs_constants import HASH_SIZE
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class MyFSSelfRepair:
  def __init__(self, volume_path):
    """Initialize the self-repair module."""
    self.volume_path = volume_path
    self.backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "myfs", ".backup")
    self.backup_manifest_path = os.path.join(self.backup_dir, "manifest.json")
    self.backup_archive_path = os.path.join(self.backup_dir, "myfs_backup.enc")
    self.key_file = os.path.join(os.path.dirname(__file__), "myfs", "MyFS.METADATA")
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(self.backup_dir):
      os.makedirs(self.backup_dir, exist_ok=True)
  
  def _get_all_app_files(self):
    """Get all Python files in the application."""
    app_files = []
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    for root, _, files in os.walk(app_dir):
      for file in files:
        if file.endswith('.py'):
          rel_path = os.path.relpath(os.path.join(root, file), app_dir)
          app_files.append(rel_path)
    
    return app_files
  
  def _read_key(self):
    """Read the encryption key from the key file."""
    try:
      with open(self.key_file, "rb") as f:
        key_data = f.read()
        # Extract the key used for backup (last 32 bytes)
        if len(key_data) >= 32:
          return key_data[-32:]
    except FileNotFoundError:
      # If key file doesn't exist, create a new one
      key = get_random_bytes(32)
      with open(self.key_file, "wb") as f:
        # Write some random data followed by the actual key
        f.write(get_random_bytes(64) + key)
      return key
    
    # If we couldn't extract a valid key, generate a new one
    key = get_random_bytes(32)
    with open(self.key_file, "wb") as f:
      f.write(get_random_bytes(64) + key)
    return key
  
  def create_backup(self, password=None):
    """Create an encrypted backup of all application files.
    Requires password for updating existing backup."""
    # If backup exists, require password for update
    if os.path.exists(self.backup_manifest_path):
        if not password:
            print("\nBackup update requires password verification.")
            password = input("Enter backup password: ").strip()
            if not password:
                raise ValueError("Password required to update existing backup")
        
        # Verify password against stored hash
        try:
            with open(self.backup_manifest_path, "r") as f:
                manifest = json.load(f)
                if "password_hash" not in manifest:
                    raise ValueError("Backup is not password protected")
                
                # Verify password
                if not self._verify_password(password, manifest["password_hash"]):
                    raise ValueError("Invalid password")
        except Exception as e:
            raise ValueError(f"Failed to verify backup password: {str(e)}")
    else:
        # For initial backup, ask user to set a password
        print("\nSetting up initial backup...")
        while True:
            password = input("Enter a password to protect the backup (or press Enter for default): ").strip()
            if not password:
                password = "initial"
                print("Using default password.")
                break
            confirm = input("Confirm password: ").strip()
            if password == confirm:
                break
            print("Passwords do not match. Please try again.")
    
    app_files = self._get_all_app_files()
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "files": {},
        "is_initial_backup": not os.path.exists(self.backup_manifest_path)
    }
    
    # Store password hash
    manifest["password_hash"] = self._hash_password(password)
    
    # Create a temporary zip file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip_file:
        temp_zip_path = temp_zip_file.name
    
    # Create zip file with all app files
    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in app_files:
            full_path = os.path.join(app_dir, file_path)
            file_stat = os.stat(full_path)
            
            with open(full_path, "rb") as f:
                file_content = f.read()
                file_hash = calculate_sha256(file_content)
                manifest["files"][file_path] = {
                    "hash": file_hash.hex(),
                    "size": file_stat.st_size,
                    "mod_time": file_stat.st_mtime
                }
            
            # Add file to zip
            zipf.write(full_path, file_path)
    
    # Read the zip file
    with open(temp_zip_path, "rb") as f:
        zip_data = f.read()
    
    # Encrypt the zip file
    key = self._read_key()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(zip_data, AES.block_size))
    
    # Create backup data
    backup_data = iv + encrypted_data
    
    # Save the encrypted backup
    with open(self.backup_archive_path, "wb") as f:
        f.write(backup_data)
    
    # Save the manifest
    with open(self.backup_manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    # Clean up
    os.unlink(temp_zip_path)
    
    print("Backup created successfully.")
    return True
  
  def verify_integrity(self):
    """Verify the integrity of all application files by comparing hash values."""
    if not os.path.exists(self.backup_manifest_path):
        # Create initial backup if none exists
        try:
            if self.create_backup():
                return True, {"status": "Initial backup created"}
        except Exception as e:
            return False, {"error": f"Failed to create initial backup: {str(e)}"}
        return False, {"error": "No backup manifest found"}
    
    try:
        with open(self.backup_manifest_path, "r") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return False, {"error": "Invalid backup manifest"}
    
    app_dir = os.path.dirname(os.path.abspath(__file__))
    integrity_results = {}
    all_valid = True
    modified_files = []
    
    # Check hash values
    for file_path, file_info in manifest["files"].items():
        full_path = os.path.join(app_dir, file_path)
        
        try:
            file_stat = os.stat(full_path)
            file_size = file_stat.st_size
            mod_time = file_stat.st_mtime
            
            with open(full_path, "rb") as f:
                file_content = f.read()
                actual_hash = calculate_sha256(file_content).hex()
            
            # Check all integrity metrics
            if (actual_hash != file_info["hash"] or 
                file_size != file_info["size"] or 
                abs(mod_time - file_info["mod_time"]) > 1):  # Allow 1 second difference for precision
                
                modified_files.append(file_path)
                reasons = []
                if actual_hash != file_info["hash"]:
                    reasons.append(f"Hash mismatch: expected {file_info['hash']}, got {actual_hash}")
                if file_size != file_info["size"]:
                    reasons.append(f"Size mismatch: expected {file_info['size']}, got {file_size}")
                if abs(mod_time - file_info["mod_time"]) > 1:
                    reasons.append(f"Modification time changed: expected {datetime.fromtimestamp(file_info['mod_time'])}, got {datetime.fromtimestamp(mod_time)}")
                
                integrity_results[file_path] = {
                    "is_valid": False,
                    "reason": "; ".join(reasons)
                }
                all_valid = False
            else:
                integrity_results[file_path] = {
                    "is_valid": True
                }
        except FileNotFoundError:
            modified_files.append(file_path)
            integrity_results[file_path] = {
                "is_valid": False,
                "reason": "File missing"
            }
            all_valid = False
    
    if not all_valid:
        print(f"\nFound {len(modified_files)} modified or missing files:")
        for file in modified_files:
            print(f"  - {file}: {integrity_results[file]['reason']}")
        
        print("\nOptions:")
        print("1. Update backup with current version (requires backup password)")
        print("2. Restore original files from backup")
        print("3. Exit without changes")
        
        while True:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == "1":
                password = input("Enter backup password: ").strip()
                try:
                    if self.create_backup(password):
                        # After updating backup, verify integrity again
                        is_valid, _ = self.verify_integrity()
                        if is_valid:
                            return True, {"status": "Backup updated with current version and verified"}
                        else:
                            return False, {"error": "Backup updated but integrity check still fails"}
                except ValueError as e:
                    return False, {"error": str(e)}
            elif choice == "2":
                print(f"\nAttempting to restore {len(modified_files)} files from backup...")
                success, message = self.restore_files(modified_files)
                if success:
                    # Verify integrity after restore
                    is_valid, _ = self.verify_integrity()
                    if is_valid:
                        print("Recovery completed successfully.")
                        return True, {"status": f"Self-repair completed: {len(modified_files)} files restored"}
                    else:
                        return False, {"error": "Files restored but integrity check still fails"}
                else:
                    print(f"Recovery failed: {message}")
                    return False, {"error": f"Failed to repair: {message}"}
            elif choice == "3":
                return False, {"error": "Operation cancelled by user"}
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    
    return all_valid, integrity_results
  
  def restore_files(self, files_to_restore=None):
    """Restore files from backup."""
    if not os.path.exists(self.backup_archive_path):
      return False, "Backup archive not found"
    
    try:
      # Read the encrypted backup
      with open(self.backup_archive_path, "rb") as f:
        encrypted_data = f.read()
      
      # Extract IV and encrypted data
      iv = encrypted_data[:16]
      encrypted_zip = encrypted_data[16:]
      
      # Decrypt the backup
      key = self._read_key()
      cipher = AES.new(key, AES.MODE_CBC, iv)
      zip_data = unpad(cipher.decrypt(encrypted_zip), AES.block_size)
      
      # Save to temporary file
      with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip_file:
        temp_zip_path = temp_zip_file.name
        temp_zip_file.write(zip_data)
      
      # Extract files
      app_dir = os.path.dirname(os.path.abspath(__file__))
      with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
        if files_to_restore is None:
          # Restore all files
          zipf.extractall(app_dir)
        else:
          # Restore only specified files
          for file_path in files_to_restore:
            try:
              zipf.extract(file_path, app_dir)
            except KeyError:
              pass  # File not in backup
      
      # Clean up
      os.unlink(temp_zip_path)
      
      return True, "Files restored successfully"
    except Exception as e:
      return False, f"Failed to restore files: {str(e)}"
  
  def perform_self_repair(self, password=None):
    """Perform self-repair if any hash values are different.
    Requires password if backup needs to be updated."""
    is_valid, results = self.verify_integrity()
    
    if is_valid:
        return True, "Integrity check passed, no repair needed"
    
    # Check if results is an error message
    if isinstance(results, dict) and "error" in results:
        # Handle the case where there's no backup yet
        if results["error"] == "No backup manifest found":
            # Create a backup first
            try:
                if self.create_backup(password):
                    return True, "Created initial backup"
            except ValueError as e:
                return False, str(e)
            return False, "Failed to create initial backup"
        return False, results["error"]
    
    # Get list of files that need repair
    files_to_restore = []
    if isinstance(results, dict):
        files_to_restore = [
            file_path for file_path, result in results.items() 
            if isinstance(result, dict) and not result.get("is_valid", True)
        ]
    
    if not files_to_restore:
        return True, "No files need repair"
    
    print(f"\nFound {len(files_to_restore)} modified files:")
    for file in files_to_restore:
        print(f"  - {file}")
    
    print("\nOptions:")
    print("1. Update backup with current version (requires backup password)")
    print("2. Restore original files from backup")
    print("3. Exit without changes")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            # Try to update backup
            if not password:
                password = input("Enter backup password: ").strip()
            try:
                # Force update the backup
                if self.create_backup(password):
                    # After updating backup, verify integrity again
                    is_valid, _ = self.verify_integrity()
                    if is_valid:
                        return True, "Backup updated with current version and verified"
                    else:
                        return False, "Backup updated but integrity check still fails"
            except ValueError as e:
                return False, str(e)
        elif choice == "2":
            # Restore the files
            print(f"\nAttempting to restore {len(files_to_restore)} files from backup...")
            success, message = self.restore_files(files_to_restore)
            if success:
                # Verify integrity after restore
                is_valid, _ = self.verify_integrity()
                if is_valid:
                    print("Recovery completed successfully.")
                    return True, f"Self-repair completed: {len(files_to_restore)} files restored"
                else:
                    return False, "Files restored but integrity check still fails"
            else:
                print(f"Recovery failed: {message}")
                return False, f"Failed to repair: {message}"
        elif choice == "3":
            return False, "Operation cancelled by user"
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

  def _verify_machine_id(self, current_machine_id):
    """Verify if the current machine is authorized to create backups."""
    if not os.path.exists(self.backup_manifest_path):
        return True  # Allow first backup creation
        
    try:
        with open(self.backup_manifest_path, "r") as f:
            manifest = json.load(f)
            
        # Check if machine ID matches the original backup
        return manifest["machine_id"] == current_machine_id.hex()
    except:
        return False 

  def _hash_password(self, password):
    """Hash a password using SHA-256 with salt."""
    salt = get_random_bytes(16)
    password_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256(salt + password_bytes)
    return {
        "hash": hash_obj.hexdigest(),
        "salt": base64.b64encode(salt).decode()
    }

  def _verify_password(self, password, stored_hash_info):
    """Verify a password against its stored hash."""
    salt = base64.b64decode(stored_hash_info["salt"])
    password_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256(salt + password_bytes)
    return hash_obj.hexdigest() == stored_hash_info["hash"] 