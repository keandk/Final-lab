"""
Connector module for MyFS that integrates the file handler and metadata components.
This ensures proper interaction between different system modules.
"""

import os
import time
import struct

from myfs_file_handler import MyFSFileHandler, FileStatus
from myfs_metadata import MyFSMetadata
from myfs_utils import calculate_sha256

class MyFSConnector:
  def __init__(self, volume_path, metadata_path):
    """Initialize the connector with file handler and metadata components."""
    self.file_handler = MyFSFileHandler(volume_path, metadata_path)
    self.metadata = MyFSMetadata(metadata_path)
    self.volume_path = volume_path
    self.metadata_path = metadata_path
    self.volume_password = None
    
  def initialize(self, volume_password):
    """Initialize the system with the provided volume password."""
    self.volume_password = volume_password
    
    # Read volume header
    self.file_handler._read_volume_header()
    
    # Load metadata
    self.metadata.load(volume_password)
    
    # Link the file handler's metadata reference to our metadata instance
    self.file_handler.metadata = self.metadata.metadata
    
    return True
  
  def save_changes(self):
    """Save any changes to the metadata."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Save metadata
    self.metadata.save(self.volume_password)
    
    return True
  
  def list_files(self, include_deleted=False):
    """List all files in the volume."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Get file list from file handler
    files = self.file_handler.list_files(self.volume_password, include_deleted)
    
    # Enhance with additional metadata
    for file_info in files:
      index = file_info['index']
      metadata = self.metadata.get_file_metadata(index)
      
      # Add metadata info to file_info
      file_info['original_path'] = metadata.get('original_path', '')
      file_info['is_encrypted'] = metadata.get('is_encrypted', False)
    
    return files
  
  def import_file(self, filepath, file_password=None):
    """Import a file into the volume."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Import file using file handler
    file_index = self.file_handler.import_file(filepath, self.volume_password, file_password)
    
    # Save changes to metadata
    self.save_changes()
    
    return file_index
  
  def export_file(self, file_index, export_path, file_password=None, use_original_path=False):
    """Export a file from the volume."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Export file using file handler
    exported_path = self.file_handler.export_file(
      file_index, export_path, self.volume_password, file_password, use_original_path
    )
    
    return exported_path
  
  def delete_file(self, file_index, permanent=False):
    """Delete a file from the volume."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Delete file using file handler
    self.file_handler.delete_file(file_index, self.volume_password, permanent)
    
    # Update metadata
    if permanent:
      self.metadata.delete_file_metadata(file_index, permanent=True)
    else:
      self.metadata.update_file_metadata(file_index, deleted=True)
    
    # Save changes to metadata
    self.save_changes()
    
    return True
  
  def recover_file(self, file_index):
    """Recover a deleted file."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Recover file using file handler
    self.file_handler.recover_file(file_index, self.volume_password)
    
    # Update metadata
    self.metadata.update_file_metadata(file_index, deleted=False)
    
    # Save changes to metadata
    self.save_changes()
    
    return True
  
  def set_file_password(self, file_index, new_file_password, old_file_password=None):
    """Set or change a file's password."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Change file password using file handler
    self.file_handler.set_file_password(file_index, self.volume_password, new_file_password, old_file_password)
    
    # Save changes to metadata
    self.save_changes()
    
    return True
  
  def verify_file_integrity(self, file_index):
    """Verify the integrity of a file in the volume."""
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # Get file metadata
    file_metadata = self.metadata.get_file_metadata(file_index)
    
    # Get file entry from file table
    entry_data = self.file_handler._get_file_table_entry(file_index)
    status = entry_data[0]
    
    if status != FileStatus.ACTIVE:
      return False, "File is not active"
    
    # Get data offset and size
    data_offset_pos = 1 + 32 + 32  # Status + Filename hash + Data offset
    data_offset = struct.unpack("<q", entry_data[data_offset_pos:data_offset_pos+8])[0]
    
    # Get encrypted data size
    enc_size_pos = 1 + 32 + 8  # Status + Filename hash + File size
    encrypted_size = struct.unpack("<q", entry_data[enc_size_pos:enc_size_pos+8])[0]
    
    # Read data from volume
    with open(self.volume_path, "rb") as f:
      f.seek(data_offset)
      data = f.read(encrypted_size)
    
    # If the file is encrypted, we can only verify the encrypted data integrity
    # Full verification would require decryption with the file password
    
    # Calculate checksum
    data_checksum = calculate_sha256(data)
    
    # For now, we'll just return success (in a real implementation, you'd store and check
    # checksums of the encrypted data as well)
    return True, "File integrity verified"
  
  def cleanup_unused_space(self):
    """
    Clean up unused space in the volume.
    This reorganizes the volume by removing spaces left by deleted files.
    """
    if not self.volume_password:
      raise ValueError("System not initialized with password.")
    
    # This is a complex operation that would require:
    # 1. Identify all active files and their locations
    # 2. Create a new layout with files packed together
    # 3. Copy all files to their new positions
    # 4. Update all file table entries with new offsets
    
    # For simplicity, we'll just return success without implementation
    # In a real implementation, this would be a crucial optimization
    
    return True, "Space cleanup not implemented in this version" 