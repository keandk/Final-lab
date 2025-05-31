"""
Security module for MyFS.
Handles authentication, password verification, and machine ID checking.
"""

import os
import time
import random
import string
import hashlib
import struct
import socket
import inspect
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from myfs_constants import (
  MAGIC_NUMBER_DRI, DRI_MACHINE_NAME_LEN,
  SALT_SIZE, AES_IV_SIZE, HASH_SIZE, PBKDF2_ITERATIONS
)
from myfs_utils import (
  calculate_sha256, derive_key_pbkdf2, encrypt_aes_cbc, decrypt_aes_cbc,
  pack_str_fixed_len, unpack_fixed_len_str
)
from myfs_hardware import get_machine_id_hash
# Import the self-repair module
from myfs_self_repair import MyFSSelfRepair

class MyFSSecurity:
  def __init__(self, volume_path, metadata_path):
    self.volume_path = volume_path
    self.metadata_path = metadata_path
    self.volume_password_salt = None
    self.header_data = None
    # Initialize the self-repair module
    self.self_repair = MyFSSelfRepair(volume_path)
    
  def _read_volume_header(self):
    """Reads the volume header to get security-related data."""
    with open(self.volume_path, "rb") as f:
      # Check magic number
      magic = f.read(8)
      if magic != MAGIC_NUMBER_DRI:
        raise ValueError("Invalid MyFS volume file.")
      
      # Read volume UUID
      volume_id = f.read(16)
      
      # Read timestamp
      timestamp_bytes = f.read(8)
      creation_timestamp = struct.unpack("<q", timestamp_bytes)[0]
      
      # Read machine ID hash
      machine_id_hash = f.read(32)
      
      # Read machine name
      machine_name_bytes = f.read(DRI_MACHINE_NAME_LEN)
      machine_name = unpack_fixed_len_str(machine_name_bytes)
      
      # Read volume password salt
      volume_password_salt = f.read(16)
      self.volume_password_salt = volume_password_salt
      
      # Store header data
      self.header_data = {
        "volume_id": volume_id,
        "creation_timestamp": creation_timestamp,
        "machine_id_hash": machine_id_hash,
        "machine_name": machine_name,
        "volume_password_salt": volume_password_salt
      }
      
      return self.header_data

  def verify_machine_id(self):
    """Verifies if the current machine is the one that created the volume."""
    if not self.header_data:
      self._read_volume_header()
    
    # Get current machine ID hash
    current_machine_id_hash, _ = get_machine_id_hash()
    
    # Compare with stored machine ID hash
    return current_machine_id_hash == self.header_data["machine_id_hash"]

  def check_volume_password(self, password):
    """Checks if the volume password is correct by decrypting a test value."""
    if not self.header_data:
      self._read_volume_header()
    
    try:
      # Read metadata file header
      with open(self.metadata_path, "rb") as f:
        # Skip magic number and volume ID (8 + 16 bytes)
        f.seek(24)
        
        # Read stored salt
        metadata_salt = f.read(16)
        
        # Verify salt matches volume
        if metadata_salt != self.volume_password_salt:
          return False
        
        # Read metadata IV
        metadata_iv = f.read(16)
        
        # Read metadata size
        metadata_size_bytes = f.read(8)
        metadata_size = struct.unpack("<q", metadata_size_bytes)[0]
        
        # Skip checksum (32 bytes)
        f.seek(24 + 16 + 16 + 8 + 32)
        
        # Read a small portion of encrypted metadata to verify password
        test_data = f.read(64)  # Just need a small portion
      
      # Derive key from password
      key = derive_key_pbkdf2(password, self.volume_password_salt)
      
      # Try to decrypt test data
      cipher = AES.new(key, AES.MODE_CBC, metadata_iv)
      try:
        cipher.decrypt(test_data)
        return True
      except:
        return False
    except:
      return False

  def change_volume_password(self, old_password, new_password):
    """Changes the volume password."""
    if not self.header_data:
      self._read_volume_header()
    
    # Verify old password
    if not self.check_volume_password(old_password):
      raise ValueError("Incorrect old password.")
    
    # Read entire metadata file
    with open(self.metadata_path, "rb") as f:
      metadata_content = f.read()
    
    # Parse metadata
    # Skip header (24 + 16 + 16 + 8 + 32 = 96 bytes)
    header_size = 96
    metadata_iv = metadata_content[24+16:24+16+16]
    metadata_size_bytes = metadata_content[24+16+16:24+16+16+8]
    metadata_size = struct.unpack("<q", metadata_size_bytes)[0]
    
    # Extract encrypted metadata
    encrypted_metadata = metadata_content[header_size:header_size+metadata_size]
    
    # Derive old key
    old_key = derive_key_pbkdf2(old_password, self.volume_password_salt)
    
    # Decrypt metadata
    cipher = AES.new(old_key, AES.MODE_CBC, metadata_iv)
    padded_metadata = cipher.decrypt(encrypted_metadata)
    
    # Remove padding
    pad_len = padded_metadata[-1]
    metadata_bytes = padded_metadata[:-pad_len]
    
    # Generate new salt
    new_salt = get_random_bytes(SALT_SIZE)
    
    # Derive new key
    new_key = derive_key_pbkdf2(new_password, new_salt)
    
    # Generate new IV
    new_iv = get_random_bytes(AES_IV_SIZE)
    
    # Re-encrypt metadata
    cipher = AES.new(new_key, AES.MODE_CBC, new_iv)
    padded_metadata = metadata_bytes + bytes([16 - (len(metadata_bytes) % 16)] * (16 - (len(metadata_bytes) % 16)))
    encrypted_metadata = cipher.encrypt(padded_metadata)
    
    # Update volume header with new salt
    with open(self.volume_path, "rb+") as f:
      # Skip to salt position (8 + 16 + 8 + 32 + 64 = 128 bytes)
      f.seek(128)
      f.write(new_salt)
    
    # Create new metadata file
    with open(self.metadata_path, "wb") as f:
      # Write header
      f.write(metadata_content[:24])  # Magic + volume ID
      f.write(new_salt)  # New salt
      f.write(new_iv)  # New IV
      f.write(struct.pack("<q", len(encrypted_metadata)))  # New size
      
      # Calculate new header checksum
      header_data = metadata_content[:24] + new_salt + new_iv + struct.pack("<q", len(encrypted_metadata))
      header_checksum = calculate_sha256(header_data)
      f.write(header_checksum)
      
      # Write encrypted metadata
      f.write(encrypted_metadata)
      
      # Calculate and write overall checksum
      file_content = header_data + header_checksum + encrypted_metadata
      file_checksum = calculate_sha256(file_content)
      f.write(file_checksum)
    
    # Update stored data
    self.volume_password_salt = new_salt
    self.header_data["volume_password_salt"] = new_salt
    
    return True

  def generate_dynamic_password(self):
    """Generates a dynamic password challenge based on timestamp and volume data."""
    if not self.header_data:
      self._read_volume_header()
    
    # Seed with current time and volume creation time
    current_time = int(time.time())
    creation_time = self.header_data["creation_timestamp"]
    
    # Use XOR of times to seed random
    seed = current_time ^ creation_time
    random.seed(seed)
    
    # Generate a challenge (e.g., simple math operation with random numbers)
    a = random.randint(1, 100)
    b = random.randint(1, 100)
    op = random.choice(['+', '-', '*'])
    
    # Create challenge string
    challenge = f"What is {a} {op} {b}?"
    
    # Calculate expected answer
    if op == '+':
      answer = a + b
    elif op == '-':
      answer = a - b
    else:  # '*'
      answer = a * b
    
    return challenge, str(answer)

  def check_file_integrity(self, file_path):
    """Checks the integrity of a given file."""
    try:
      with open(file_path, "rb") as f:
        file_content = f.read()
      
      # Calculate hash
      file_hash = calculate_sha256(file_content)
      
      # For demonstration, we'll just return a simple check
      # In a real implementation, you'd compare against a known good hash
      # stored somewhere secure
      return True, file_hash.hex()
    except Exception as e:
      return False, str(e)

  def verify_self_integrity(self):
    """Verifies the integrity of the MyFS application itself by comparing hash values."""
    # Use the self-repair module to check integrity
    is_valid, integrity_results = self.self_repair.verify_integrity()
    
    # If integrity check failed but backup exists, perform self-repair
    if not is_valid:
      print("Starting automatic recovery process...")
      success, repair_message = self.self_repair.perform_self_repair()
      if success:
        print("Recovery process completed successfully.")
        # Re-verify after repair
        is_valid, integrity_results = self.self_repair.verify_integrity()
        if is_valid:
          print("All files now match their original hash values.")
      else:
        print(f"Recovery process failed: {repair_message}")
    else:
      print("All files match their original hash values.")
    
    return is_valid, integrity_results
  
  def create_backup(self):
    """Creates a backup of the application files for future self-repair."""
    return self.self_repair.create_backup() 