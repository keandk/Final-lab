"""
File handling module for MyFS operations.
Manages file import, export, listing, and deletion.
"""

import os
import time
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct

from myfs_constants import (
  DRI_FT_ENTRY_SIZE, DRI_FT_ENTRY_COUNT, DRI_FT_FILENAME_HASH_LEN,
  KEY_FILENAME_LEN, KEY_ORIGINAL_PATH_LEN, KEY_PER_FILE_PW_VERIFIER_LEN,
  KEY_FILE_CONTENT_CHECKSUM_LEN, SALT_SIZE, AES_IV_SIZE
)
from myfs_utils import (
  calculate_sha256, derive_key_pbkdf2, encrypt_aes_cbc, decrypt_aes_cbc,
  pack_str_fixed_len, unpack_fixed_len_str
)

class FileStatus:
  EMPTY = 0
  ACTIVE = 1
  DELETED = 2  # Deleted but recoverable
  WIPED = 3    # Permanently deleted

class MyFSFileHandler:
  def __init__(self, volume_path, metadata_path):
    self.volume_path = volume_path
    self.metadata_path = metadata_path
    self.header_data = None
    self.volume_file = None
    self.metadata = None
    
  def _open_volume(self, mode="rb+"):
    """Opens the volume file for operations."""
    if self.volume_file:
      self.volume_file.close()
    self.volume_file = open(self.volume_path, mode)
    return self.volume_file
    
  def _close_volume(self):
    """Closes the volume file."""
    if self.volume_file:
      self.volume_file.close()
      self.volume_file = None
      
  def _read_volume_header(self):
    """Reads the volume header to get offsets and other metadata."""
    with open(self.volume_path, "rb") as f:
      # Skip magic number (8 bytes)
      f.seek(8)
      
      # Read volume UUID
      volume_id = f.read(16)
      
      # Read timestamp
      timestamp_bytes = f.read(8)
      creation_timestamp = struct.unpack("<q", timestamp_bytes)[0]
      
      # Skip machine ID hash (32 bytes) and machine name (64 bytes)
      f.seek(8 + 16 + 8 + 32 + 64)
      
      # Read volume password salt
      volume_password_salt = f.read(16)
      
      # Read file table offset
      file_table_offset_bytes = f.read(8)
      file_table_offset = struct.unpack("<q", file_table_offset_bytes)[0]
      
      # Read file table entry count and size
      ft_entry_count_bytes = f.read(4)
      ft_entry_count = struct.unpack("<i", ft_entry_count_bytes)[0]
      
      ft_entry_size_bytes = f.read(4)
      ft_entry_size = struct.unpack("<i", ft_entry_size_bytes)[0]
      
      # Read data region offset
      data_region_offset_bytes = f.read(8)
      data_region_offset = struct.unpack("<q", data_region_offset_bytes)[0]
      
      # Store header data
      self.header_data = {
        "volume_id": volume_id,
        "creation_timestamp": creation_timestamp,
        "volume_password_salt": volume_password_salt,
        "file_table_offset": file_table_offset,
        "ft_entry_count": ft_entry_count,
        "ft_entry_size": ft_entry_size,
        "data_region_offset": data_region_offset
      }
      
      return self.header_data

  def _read_metadata(self, password):
    """Reads and decrypts the metadata file."""
    # TODO: Implement metadata decryption 
    pass
    
  def _save_metadata(self, password):
    """Encrypts and saves the metadata file."""
    # TODO: Implement metadata encryption and saving
    pass
  
  def _get_file_table_entry(self, index):
    """Gets a file table entry at the specified index."""
    if not self.header_data:
      self._read_volume_header()
    
    file_table_offset = self.header_data["file_table_offset"]
    ft_entry_size = self.header_data["ft_entry_size"]
    
    with open(self.volume_path, "rb") as f:
      f.seek(file_table_offset + (index * ft_entry_size))
      entry_data = f.read(ft_entry_size)
      return entry_data
  
  def _update_file_table_entry(self, index, entry_data):
    """Updates a file table entry at the specified index."""
    if not self.header_data:
      self._read_volume_header()
    
    file_table_offset = self.header_data["file_table_offset"]
    ft_entry_size = self.header_data["ft_entry_size"]
    
    with open(self.volume_path, "rb+") as f:
      f.seek(file_table_offset + (index * ft_entry_size))
      f.write(entry_data)
  
  def _find_free_file_table_entry(self):
    """Finds a free file table entry for a new file."""
    if not self.header_data:
      self._read_volume_header()
    
    for i in range(self.header_data["ft_entry_count"]):
      entry_data = self._get_file_table_entry(i)
      status = entry_data[0]  # First byte is status
      if status == FileStatus.EMPTY:
        return i
        
    return None  # No free entry found
  
  def list_files(self, password, include_deleted=False):
    """Lists all files in the volume."""
    if not self.header_data:
      self._read_volume_header()
      
    # We need to read metadata to get filenames
    self._read_metadata(password)
    
    files = []
    for i in range(self.header_data["ft_entry_count"]):
      entry_data = self._get_file_table_entry(i)
      status = entry_data[0]  # First byte is status
      
      if status == FileStatus.ACTIVE or (include_deleted and status == FileStatus.DELETED):
        # Get filename from metadata
        filename = self.metadata.get(f"file_{i}", {}).get("filename", "Unknown")
        original_path = self.metadata.get(f"file_{i}", {}).get("original_path", "")
        
        # Unpack size and timestamps
        file_size_offset = 1 + DRI_FT_FILENAME_HASH_LEN
        file_size = struct.unpack("<q", entry_data[file_size_offset:file_size_offset+8])[0]
        
        encrypted_size_offset = file_size_offset + 8
        encrypted_size = struct.unpack("<q", entry_data[encrypted_size_offset:encrypted_size_offset+8])[0]
        
        creation_time_offset = encrypted_size_offset + 8
        creation_time = struct.unpack("<q", entry_data[creation_time_offset:creation_time_offset+8])[0]
        
        modification_time_offset = creation_time_offset + 8
        modification_time = struct.unpack("<q", entry_data[modification_time_offset:modification_time_offset+8])[0]
        
        files.append({
          "index": i,
          "filename": filename,
          "original_path": original_path,
          "size": file_size,
          "encrypted_size": encrypted_size,
          "creation_time": creation_time,
          "modification_time": modification_time,
          "status": "Active" if status == FileStatus.ACTIVE else "Deleted"
        })
    
    return files
  
  def import_file(self, filepath, password, file_password=None):
    """Imports a file into the volume with optional encryption."""
    if not self.header_data:
      self._read_volume_header()
      
    # Read metadata
    self._read_metadata(password)
    
    # Find filename and path
    filename = os.path.basename(filepath)
    original_path = os.path.abspath(filepath)
    
    # Calculate filename hash
    filename_hash = calculate_sha256(filename.encode("utf-8"))
    
    # Find free file table entry
    entry_index = self._find_free_file_table_entry()
    if entry_index is None:
      raise Exception("Volume is full, no free file table entries.")
    
    # Read file content
    with open(filepath, "rb") as f:
      file_content = f.read()
      
    # Calculate file checksum
    file_checksum = calculate_sha256(file_content)
    
    # Encrypt file if file_password is provided
    if file_password:
      # Generate salt and IV
      file_salt = get_random_bytes(SALT_SIZE)
      file_iv = get_random_bytes(AES_IV_SIZE)
      
      # Derive key
      file_key = derive_key_pbkdf2(file_password, file_salt)
      
      # Encrypt file
      encrypted_content = encrypt_aes_cbc(file_content, file_key, file_iv)
      
      # Generate password verifier (allows checking if password is correct without decrypting whole file)
      password_verifier = derive_key_pbkdf2(file_password, file_salt, dklen=KEY_PER_FILE_PW_VERIFIER_LEN)
    else:
      # Not encrypted
      encrypted_content = file_content
      file_salt = b"\x00" * SALT_SIZE
      file_iv = b"\x00" * AES_IV_SIZE
      password_verifier = b"\x00" * KEY_PER_FILE_PW_VERIFIER_LEN
    
    # Create file table entry
    entry_data = bytearray(DRI_FT_ENTRY_SIZE)
    
    # Set status to ACTIVE
    entry_data[0] = FileStatus.ACTIVE
    
    # Set filename hash
    entry_data[1:1+DRI_FT_FILENAME_HASH_LEN] = filename_hash
    
    # Set file size
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN, len(file_content))
    
    # Set encrypted data size
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+8, len(encrypted_content))
    
    # Set creation timestamp
    current_time = int(time.time())
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+16, current_time)
    
    # Set modification timestamp
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+24, current_time)
    
    # Append data to the end of the volume
    with open(self.volume_path, "rb+") as f:
      f.seek(0, 2)  # Seek to end of file
      data_offset = f.tell()
      
      # Write encrypted content
      f.write(encrypted_content)
    
    # Set data offset in entry
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+32, data_offset)
    
    # Set IV and salt placeholders
    iv_salt_offset = 1+DRI_FT_FILENAME_HASH_LEN+40
    entry_data[iv_salt_offset:iv_salt_offset+16] = file_iv
    entry_data[iv_salt_offset+16:iv_salt_offset+32] = file_salt
    
    # Update file table entry
    self._update_file_table_entry(entry_index, entry_data)
    
    # Update metadata
    self.metadata[f"file_{entry_index}"] = {
      "filename": filename,
      "original_path": original_path,
      "password_verifier": password_verifier.hex(),
      "file_checksum": file_checksum.hex(),
      "is_encrypted": bool(file_password)
    }
    
    # Save metadata
    self._save_metadata(password)
    
    return entry_index

  def export_file(self, file_index, export_path, volume_password, file_password=None, use_original_path=False):
    """Exports a file from the volume with optional decryption."""
    if not self.header_data:
      self._read_volume_header()
      
    # Read metadata
    self._read_metadata(volume_password)
    
    # Get file table entry
    entry_data = self._get_file_table_entry(file_index)
    status = entry_data[0]
    
    if status != FileStatus.ACTIVE:
      raise Exception("File not found or has been deleted.")
    
    # Get file metadata
    file_metadata = self.metadata.get(f"file_{file_index}", {})
    filename = file_metadata.get("filename", f"file_{file_index}")
    original_path = file_metadata.get("original_path", "")
    is_encrypted = file_metadata.get("is_encrypted", False)
    
    # Sanitize filename - remove control characters and other invalid characters
    filename = ''.join(c for c in filename if c.isprintable() and c not in '<>:"/\\|?*')
    if not filename:
        filename = f"file_{file_index}"
    
    # Determine export path
    if use_original_path and original_path:
      # Sanitize original path
      try:
        # Extract directory and filename from original path
        original_dir = os.path.dirname(original_path)
        original_filename = os.path.basename(original_path)
        
        # Sanitize filename in original path
        original_filename = ''.join(c for c in original_filename if c.isprintable() and c not in '<>:"/\\|?*')
        if not original_filename:
            original_filename = filename
            
        final_export_path = os.path.join(original_dir, original_filename)
        
        # Create directory structure if needed
        os.makedirs(os.path.dirname(final_export_path), exist_ok=True)
      except Exception:
        # Fallback to export_path if there's any issue with original_path
        if os.path.isdir(export_path):
          final_export_path = os.path.join(export_path, filename)
        else:
          final_export_path = export_path
    else:
      if os.path.isdir(export_path):
        final_export_path = os.path.join(export_path, filename)
      else:
        final_export_path = export_path
    
    # Get data offset
    data_offset_pos = 1 + DRI_FT_FILENAME_HASH_LEN + 32
    data_offset = struct.unpack("<q", entry_data[data_offset_pos:data_offset_pos+8])[0]
    
    # Get encrypted data size
    enc_size_pos = 1 + DRI_FT_FILENAME_HASH_LEN + 8
    encrypted_size = struct.unpack("<q", entry_data[enc_size_pos:enc_size_pos+8])[0]
    
    # Read data from volume
    with open(self.volume_path, "rb") as f:
      f.seek(data_offset)
      encrypted_data = f.read(encrypted_size)
    
    # Decrypt if necessary
    if is_encrypted:
      if not file_password:
        raise Exception("File is encrypted. Password required.")
      
      # Get IV and salt
      iv_salt_offset = 1 + DRI_FT_FILENAME_HASH_LEN + 40
      file_iv = entry_data[iv_salt_offset:iv_salt_offset+16]
      file_salt = entry_data[iv_salt_offset+16:iv_salt_offset+32]
      
      # Verify password
      password_verifier_expected = bytes.fromhex(file_metadata.get("password_verifier", ""))
      password_verifier_actual = derive_key_pbkdf2(file_password, file_salt, dklen=KEY_PER_FILE_PW_VERIFIER_LEN)
      
      if password_verifier_expected != password_verifier_actual:
        raise Exception("Incorrect file password.")
      
      # Derive key
      file_key = derive_key_pbkdf2(file_password, file_salt)
      
      # Decrypt
      file_data = decrypt_aes_cbc(encrypted_data, file_key, file_iv)
    else:
      file_data = encrypted_data
    
    # Verify file integrity
    file_checksum_expected = bytes.fromhex(file_metadata.get("file_checksum", ""))
    file_checksum_actual = calculate_sha256(file_data)
    
    if file_checksum_expected != file_checksum_actual:
      raise Exception("File integrity check failed. File may be corrupted.")
    
    # Write to file
    with open(final_export_path, "wb") as f:
      f.write(file_data)
    
    return final_export_path

  def delete_file(self, file_index, volume_password, permanent=False):
    """Deletes a file from the volume."""
    if not self.header_data:
      self._read_volume_header()
      
    # Read metadata
    self._read_metadata(volume_password)
    
    # Get file table entry
    entry_data = bytearray(self._get_file_table_entry(file_index))  # Convert to bytearray to make it mutable
    status = entry_data[0]
    
    if status != FileStatus.ACTIVE and status != FileStatus.DELETED:
      raise Exception("File not found or already permanently deleted.")
    
    # Update status
    if permanent:
      entry_data[0] = FileStatus.WIPED
      # Optionally wipe data region
      # Not implemented here for simplicity
    else:
      entry_data[0] = FileStatus.DELETED
    
    # Update file table entry
    self._update_file_table_entry(file_index, entry_data)
    
    # Update metadata
    if permanent:
      # Remove from metadata if permanent
      if f"file_{file_index}" in self.metadata:
        del self.metadata[f"file_{file_index}"]
    
    # Save metadata
    self._save_metadata(volume_password)
    
    return True

  def recover_file(self, file_index, volume_password):
    """Recovers a deleted file."""
    if not self.header_data:
      self._read_volume_header()
      
    # Read metadata
    self._read_metadata(volume_password)
    
    # Get file table entry
    entry_data = bytearray(self._get_file_table_entry(file_index))  # Convert to bytearray to make it mutable
    status = entry_data[0]
    
    if status != FileStatus.DELETED:
      raise Exception("File not found or cannot be recovered.")
    
    # Update status
    entry_data[0] = FileStatus.ACTIVE
    
    # Update file table entry
    self._update_file_table_entry(file_index, entry_data)
    
    # Save metadata
    self._save_metadata(volume_password)
    
    return True

  def set_file_password(self, file_index, volume_password, new_file_password, old_file_password=None):
    """Sets or changes a file's password and re-encrypts it."""
    if not self.header_data:
      self._read_volume_header()
      
    # Read metadata
    self._read_metadata(volume_password)
    
    # Get file table entry
    entry_data = bytearray(self._get_file_table_entry(file_index))  # Convert to bytearray to make it mutable
    status = entry_data[0]
    
    if status != FileStatus.ACTIVE:
      raise Exception("File not found or has been deleted.")
    
    # Get file metadata
    file_metadata = self.metadata.get(f"file_{file_index}", {})
    is_encrypted = file_metadata.get("is_encrypted", False)
    
    # Get data offset and size
    data_offset_pos = 1 + DRI_FT_FILENAME_HASH_LEN + 32
    data_offset = struct.unpack("<q", entry_data[data_offset_pos:data_offset_pos+8])[0]
    
    file_size_pos = 1 + DRI_FT_FILENAME_HASH_LEN
    file_size = struct.unpack("<q", entry_data[file_size_pos:file_size_pos+8])[0]
    
    enc_size_pos = 1 + DRI_FT_FILENAME_HASH_LEN + 8
    encrypted_size = struct.unpack("<q", entry_data[enc_size_pos:enc_size_pos+8])[0]
    
    # Read data from volume
    with open(self.volume_path, "rb") as f:
      f.seek(data_offset)
      encrypted_data = f.read(encrypted_size)
    
    # Get original file data
    if is_encrypted:
      # Verify old password is provided for encrypted files
      if old_file_password is None:
        raise Exception("Current password is required to change or remove encryption.")
        
      # Get IV and salt
      iv_salt_offset = 1 + DRI_FT_FILENAME_HASH_LEN + 40
      file_iv = entry_data[iv_salt_offset:iv_salt_offset+16]
      file_salt = entry_data[iv_salt_offset+16:iv_salt_offset+32]
      
      # Verify password
      password_verifier_expected = bytes.fromhex(file_metadata.get("password_verifier", ""))
      password_verifier_actual = derive_key_pbkdf2(old_file_password, file_salt, dklen=KEY_PER_FILE_PW_VERIFIER_LEN)
      
      if password_verifier_expected != password_verifier_actual:
        raise Exception("Incorrect file password.")
      
      # Derive key
      file_key = derive_key_pbkdf2(old_file_password, file_salt)
      
      # Decrypt
      file_data = decrypt_aes_cbc(encrypted_data, file_key, file_iv)
    else:
      file_data = encrypted_data
    
    # Re-encrypt with new password
    if new_file_password:
      # Generate new salt and IV for each encryption to ensure different ciphertext
      # even with the same content and password
      file_salt = get_random_bytes(SALT_SIZE)
      file_iv = get_random_bytes(AES_IV_SIZE)
      
      # Derive key
      file_key = derive_key_pbkdf2(new_file_password, file_salt)
      
      # Encrypt file
      encrypted_content = encrypt_aes_cbc(file_data, file_key, file_iv)
      
      # Generate password verifier
      password_verifier = derive_key_pbkdf2(new_file_password, file_salt, dklen=KEY_PER_FILE_PW_VERIFIER_LEN)
      
      is_encrypted = True
    else:
      # Remove encryption
      encrypted_content = file_data
      file_salt = b"\x00" * SALT_SIZE
      file_iv = b"\x00" * AES_IV_SIZE
      password_verifier = b"\x00" * KEY_PER_FILE_PW_VERIFIER_LEN
      
      is_encrypted = False
    
    # Append data to the end of the volume
    with open(self.volume_path, "rb+") as f:
      f.seek(0, 2)  # Seek to end of file
      data_offset = f.tell()
      
      # Write encrypted content
      f.write(encrypted_content)
    
    # Update file table entry
    # Set new data size
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+8, len(encrypted_content))
    
    # Set new data offset
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+32, data_offset)
    
    # Set new IV and salt
    iv_salt_offset = 1 + DRI_FT_FILENAME_HASH_LEN + 40
    entry_data[iv_salt_offset:iv_salt_offset+16] = file_iv
    entry_data[iv_salt_offset+16:iv_salt_offset+32] = file_salt
    
    # Update file table entry
    self._update_file_table_entry(file_index, entry_data)
    
    # Update metadata
    self.metadata[f"file_{file_index}"]["password_verifier"] = password_verifier.hex()
    self.metadata[f"file_{file_index}"]["is_encrypted"] = is_encrypted
    
    # Save metadata
    self._save_metadata(volume_password)
    
    return True 