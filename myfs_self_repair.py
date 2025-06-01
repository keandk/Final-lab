"""
Self-repair module for MyFS.
Handles backup and restoration of application files to prevent tampering.
"""

import os
import sys
import json
import shutil
import base64
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path

from myfs_utils import calculate_sha256
from myfs_constants import HASH_SIZE
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class MyFSSelfRepair:
  def __init__(self, volume_path):
    """Initialize the self-repair module."""
    self.volume_path = volume_path
    self.backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".backup")
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
  
  def create_backup(self):
    """Create an encrypted backup of all application files."""
    app_files = self._get_all_app_files()
    app_dir = os.path.dirname(os.path.abspath(__file__))
    manifest = {
      "timestamp": datetime.now().isoformat(),
      "files": {}
    }
    
    # Create a temporary zip file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip_file:
      temp_zip_path = temp_zip_file.name
    
    # Create zip file with all app files
    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
      for file_path in app_files:
        full_path = os.path.join(app_dir, file_path)
        with open(full_path, "rb") as f:
          file_content = f.read()
          file_hash = calculate_sha256(file_content)
          manifest["files"][file_path] = file_hash.hex()
        
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
    
    # Save the encrypted backup
    with open(self.backup_archive_path, "wb") as f:
      f.write(iv + encrypted_data)
    
    # Save the manifest
    with open(self.backup_manifest_path, "w") as f:
      json.dump(manifest, f, indent=2)
    
    # Clean up
    os.unlink(temp_zip_path)
    
    return True
  
  def verify_integrity(self):
    """Verify the integrity of all application files by comparing hash values only."""
    if not os.path.exists(self.backup_manifest_path):
      # No backup exists, create one
      return False, {"error": "No backup manifest found, backup needed"}
    
    try:
      with open(self.backup_manifest_path, "r") as f:
        manifest = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
      return False, {"error": "Invalid backup manifest"}
    
    app_dir = os.path.dirname(os.path.abspath(__file__))
    integrity_results = {}
    all_valid = True
    modified_files = []
    
    # Only check hash values
    for file_path, expected_hash in manifest["files"].items():
      full_path = os.path.join(app_dir, file_path)
      
      try:
        with open(full_path, "rb") as f:
          file_content = f.read()
          actual_hash = calculate_sha256(file_content).hex()
          
          if actual_hash != expected_hash:
            modified_files.append(file_path)
            integrity_results[file_path] = {
              "is_valid": False,
              "reason": f"Hash mismatch: expected {expected_hash}, got {actual_hash}"
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
      print(f"Found {len(modified_files)} modified or missing files:")
      for file in modified_files:
        print(f"  - {file}: {integrity_results[file]['reason']}")
    
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
  
  def perform_self_repair(self):
    """Perform self-repair if any hash values are different."""
    is_valid, results = self.verify_integrity()
    
    if is_valid:
      return True, "Integrity check passed, no repair needed"
    
    # Check if results is an error message
    if isinstance(results, dict) and "error" in results:
      # Handle the case where there's no backup yet
      if results["error"] == "No backup manifest found, backup needed":
        # Create a backup first
        if self.create_backup():
          return True, "Created initial backup"
        else:
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
    
    print(f"Attempting to restore {len(files_to_restore)} files from backup...")
    
    # Restore the files
    success, message = self.restore_files(files_to_restore)
    if success:
      print("Recovery completed successfully.")
      return True, f"Self-repair completed: {len(files_to_restore)} files restored"
    else:
      print(f"Recovery failed: {message}")
      return False, f"Failed to repair: {message}" 