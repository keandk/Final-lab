"""
Metadata handling for MyFS.
Manages the encrypted metadata file (MyFS.METADATA) and its operations.
"""

import os
import json
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from myfs_constants import (
  MAGIC_NUMBER_METADATA, KEY_SUPPLEMENTAL_ENTRY_SIZE,
  SALT_SIZE, AES_IV_SIZE, HASH_SIZE
)
from myfs_utils import (
  calculate_sha256, derive_key_pbkdf2, encrypt_aes_cbc, decrypt_aes_cbc
)

class MyFSMetadata:
  def __init__(self, metadata_path):
    self.metadata_path = metadata_path
    self.metadata = {}
    self.header_data = None
    
  def _read_header(self):
    """Reads the metadata file header."""
    with open(self.metadata_path, "rb") as f:
      # Check magic number
      magic = f.read(8)
      if magic != MAGIC_NUMBER_METADATA:
        raise ValueError("Invalid MyFS metadata file.")
      
      # Read volume ID
      volume_id = f.read(16)
      
      # Read salt
      salt = f.read(16)
      
      # Read IV
      iv = f.read(16)
      
      # Read encrypted metadata size
      size_bytes = f.read(8)
      metadata_size = struct.unpack("<q", size_bytes)[0]
      
      # Read header checksum
      header_checksum = f.read(32)
      
      # Store header data
      self.header_data = {
        "volume_id": volume_id,
        "salt": salt,
        "iv": iv,
        "metadata_size": metadata_size,
        "header_checksum": header_checksum
      }
      
      return self.header_data
  
  def _verify_header_integrity(self):
    """Verifies the integrity of the metadata file header."""
    if not self.header_data:
      self._read_header()
    
    # Read header data for checksum verification
    with open(self.metadata_path, "rb") as f:
      # Read the header data: Magic (8) + Volume ID (16) + Salt (16) + IV (16) + Size (8)
      header_data_for_checksum = f.read(8 + 16 + 16 + 16 + 8)
      # Read the stored checksum
      stored_checksum = f.read(32)
    
    # Calculate checksum
    calculated_checksum = calculate_sha256(header_data_for_checksum)
    
    # Compare with stored checksum
    if calculated_checksum != stored_checksum:
      print(f"Header checksum mismatch: calculated {calculated_checksum.hex()}, stored {stored_checksum.hex()}")
    
    return calculated_checksum == stored_checksum
  
  def _verify_file_integrity(self):
    """Verifies the integrity of the entire metadata file."""
    if not self.header_data:
      self._read_header()
    
    # Read entire file except final checksum
    with open(self.metadata_path, "rb") as f:
      file_size = os.path.getsize(self.metadata_path)
      f.seek(0)
      file_content_for_checksum = f.read(file_size - HASH_SIZE)
      stored_checksum = f.read(HASH_SIZE)
    
    # Calculate checksum
    calculated_checksum = calculate_sha256(file_content_for_checksum)
    
    # Compare with stored checksum
    return calculated_checksum == stored_checksum
  
  def load(self, password):
    """Loads and decrypts the metadata."""
    if not self.header_data:
      self._read_header()
    
    # Verify header integrity
    if not self._verify_header_integrity():
      raise ValueError("Metadata file header integrity check failed.")
    
    # Verify overall file integrity
    if not self._verify_file_integrity():
      raise ValueError("Metadata file integrity check failed.")
    
    # Read encrypted metadata
    with open(self.metadata_path, "rb") as f:
      header_size = 8 + 16 + 16 + 16 + 8 + 32  # Magic + Volume ID + Salt + IV + Size + Header Checksum
      f.seek(header_size)
      encrypted_metadata = f.read(self.header_data["metadata_size"])
    
    # Derive key
    key = derive_key_pbkdf2(password, self.header_data["salt"])
    
    # Decrypt metadata
    try:
      decrypted_metadata = decrypt_aes_cbc(
        encrypted_metadata, key, self.header_data["iv"]
      )
      
      # Parse metadata
      # In our implementation, metadata is structured as KEY_SUPPLEMENTAL_ENTRY_SIZE-byte entries
      # for each file slot
      
      self.metadata = {}
      
      for i in range(len(decrypted_metadata) // KEY_SUPPLEMENTAL_ENTRY_SIZE):
        entry_start = i * KEY_SUPPLEMENTAL_ENTRY_SIZE
        entry_data = decrypted_metadata[entry_start:entry_start + KEY_SUPPLEMENTAL_ENTRY_SIZE]
        
        # Parse entry data
        if entry_data[0] == 0:  # First byte is zero for empty entries
          continue
        
        # Extract filename (255 bytes)
        filename_bytes = entry_data[:255]
        filename = ""
        for b in filename_bytes:
          if b == 0:
            break
          filename += chr(b)
        
        # Extract original path (512 bytes)
        path_bytes = entry_data[255:255+512]
        original_path = ""
        for b in path_bytes:
          if b == 0:
            break
          original_path += chr(b)
        
        # Extract password verifier (32 bytes)
        password_verifier = entry_data[255+512:255+512+32].hex()
        
        # Extract file checksum (32 bytes)
        file_checksum = entry_data[255+512+32:255+512+32+32].hex()
        
        # Store in metadata dictionary
        self.metadata[f"file_{i}"] = {
          "filename": filename,
          "original_path": original_path,
          "password_verifier": password_verifier,
          "file_checksum": file_checksum,
          "is_encrypted": not all(b == 0 for b in entry_data[255+512:255+512+32])
        }
      
      return self.metadata
    except Exception as e:
      import traceback
      print(f"Decryption error details: {str(e)}")
      print(f"Salt: {self.header_data['salt'].hex()}")
      print(f"IV: {self.header_data['iv'].hex()}")
      print(f"Metadata size: {self.header_data['metadata_size']}")
      traceback.print_exc()
      raise ValueError(f"Failed to decrypt metadata: {str(e)}")

  def save(self, password):
    """Encrypts and saves the metadata."""
    if not self.header_data:
      try:
        self._read_header()
      except:
        raise ValueError("Cannot save metadata without loading first.")
    
    # Prepare plaintext metadata
    plaintext_metadata = bytearray(KEY_SUPPLEMENTAL_ENTRY_SIZE * 100)  # Assuming max 100 entries
    
    for file_idx, file_data in self.metadata.items():
      if not file_idx.startswith("file_"):
        continue
      
      try:
        idx = int(file_idx.split("_")[1])
      except:
        continue
      
      if idx < 0 or idx >= 100:
        continue
      
      entry_start = idx * KEY_SUPPLEMENTAL_ENTRY_SIZE
      
      # Set non-zero byte to indicate entry is used
      plaintext_metadata[entry_start] = 1
      
      # Set filename
      filename_bytes = file_data.get("filename", "").encode("utf-8")
      filename_len = min(len(filename_bytes), 254)  # Leave room for null terminator
      plaintext_metadata[entry_start+1:entry_start+1+filename_len] = filename_bytes[:filename_len]
      
      # Set original path
      path_bytes = file_data.get("original_path", "").encode("utf-8")
      path_len = min(len(path_bytes), 511)  # Leave room for null terminator
      plaintext_metadata[entry_start+255:entry_start+255+path_len] = path_bytes[:path_len]
      
      # Set password verifier
      try:
        password_verifier = bytes.fromhex(file_data.get("password_verifier", ""))
        plaintext_metadata[entry_start+255+512:entry_start+255+512+32] = password_verifier
      except:
        pass  # Skip if invalid hex
      
      # Set file checksum
      try:
        file_checksum = bytes.fromhex(file_data.get("file_checksum", ""))
        plaintext_metadata[entry_start+255+512+32:entry_start+255+512+32+32] = file_checksum
      except:
        pass  # Skip if invalid hex
    
    # Derive key
    key = derive_key_pbkdf2(password, self.header_data["salt"])
    
    # Encrypt metadata
    encrypted_metadata = encrypt_aes_cbc(
      bytes(plaintext_metadata), key, self.header_data["iv"]
    )
    
    # Update header with new size
    self.header_data["metadata_size"] = len(encrypted_metadata)
    
    # Create header data
    header_data = bytearray()
    header_data.extend(MAGIC_NUMBER_METADATA)  # 8 bytes
    header_data.extend(self.header_data["volume_id"])  # 16 bytes
    header_data.extend(self.header_data["salt"])  # 16 bytes
    header_data.extend(self.header_data["iv"])  # 16 bytes
    header_data.extend(struct.pack("<q", len(encrypted_metadata)))  # 8 bytes
    
    # Calculate header checksum
    header_checksum = calculate_sha256(header_data)
    
    # Write to file
    with open(self.metadata_path, "wb") as f:
      # Write header and header checksum
      f.write(header_data)
      f.write(header_checksum)
      
      # Write encrypted metadata
      f.write(encrypted_metadata)
      
      # Calculate and write overall checksum
      file_content = header_data + header_checksum + encrypted_metadata
      file_checksum = calculate_sha256(file_content)
      f.write(file_checksum)
    
    return True

  def update_file_metadata(self, file_index, **kwargs):
    """Updates metadata for a specific file."""
    file_key = f"file_{file_index}"
    
    if file_key not in self.metadata:
      self.metadata[file_key] = {}
    
    # Update fields
    for key, value in kwargs.items():
      self.metadata[file_key][key] = value
    
    return True

  def get_file_metadata(self, file_index):
    """Gets metadata for a specific file."""
    file_key = f"file_{file_index}"
    return self.metadata.get(file_key, {})

  def delete_file_metadata(self, file_index, permanent=False):
    """Deletes metadata for a specific file."""
    file_key = f"file_{file_index}"
    
    if permanent and file_key in self.metadata:
      del self.metadata[file_key]
    elif file_key in self.metadata:
      # Mark as deleted but keep metadata
      self.metadata[file_key]["deleted"] = True
    
    return True 