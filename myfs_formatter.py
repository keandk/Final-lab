"""
Core functionality for formatting MyFS volumes.
"""

import os
import struct
import time
import uuid
from Crypto.Cipher import AES

from myfs_constants import (
  MAGIC_NUMBER_DRI, MAGIC_NUMBER_METADATA,
  DRI_MACHINE_NAME_LEN, DRI_FT_ENTRY_COUNT, DRI_FT_ENTRY_SIZE,
  KEY_SUPPLEMENTAL_ENTRY_SIZE, SALT_SIZE, AES_IV_SIZE, HASH_SIZE
)
from myfs_utils import (
  calculate_sha256, derive_key_pbkdf2, encrypt_aes_cbc, pack_str_fixed_len
)
from myfs_hardware import get_hostname, get_machine_id_hash

class MyFSFormatter:
  def __init__(self, volume_path, metadata_path):
    """Initialize the formatter with volume and metadata paths."""
    self.volume_path = volume_path
    self.metadata_path = metadata_path
    
  def format_volume(self, password):
    """Format a new MyFS volume and metadata file."""
    return format_new_volume(self.volume_path, self.metadata_path, password)

def create_dri_header(volume_id_bytes, creation_timestamp, machine_id_hash_bytes, 
                     machine_name, volume_password_salt_bytes):
  """Creates the MyFS.DRI header bytes."""
  dri_header_buffer = bytearray()
  dri_header_buffer.extend(MAGIC_NUMBER_DRI)  # 8 bytes
  dri_header_buffer.extend(volume_id_bytes)  # 16 bytes
  dri_header_buffer.extend(
    struct.pack("<q", creation_timestamp)
  )  # 8 bytes (long long)
  dri_header_buffer.extend(machine_id_hash_bytes)  # 32 bytes
  dri_header_buffer.extend(
    pack_str_fixed_len(machine_name, DRI_MACHINE_NAME_LEN)
  )  # 64 bytes
  dri_header_buffer.extend(volume_password_salt_bytes)  # 16 bytes

  # Calculate offsets
  # Size of header fields written so far + checksum field itself (32 bytes)
  dri_header_fixed_part_size = len(dri_header_buffer) + HASH_SIZE
  file_table_offset_val = dri_header_fixed_part_size
  data_region_offset_val = file_table_offset_val + (
    DRI_FT_ENTRY_COUNT * DRI_FT_ENTRY_SIZE
  )

  dri_header_buffer.extend(
    struct.pack("<q", file_table_offset_val)
  )  # 8 bytes
  dri_header_buffer.extend(
    struct.pack("<i", DRI_FT_ENTRY_COUNT)
  )  # 4 bytes (int)
  dri_header_buffer.extend(
    struct.pack("<i", DRI_FT_ENTRY_SIZE)
  )  # 4 bytes (int)
  dri_header_buffer.extend(
    struct.pack("<q", data_region_offset_val)
  )  # 8 bytes

  # Calculate HeaderChecksum for MyFS.DRI (on buffer content BEFORE checksum field)
  dri_header_checksum = calculate_sha256(bytes(dri_header_buffer))
  dri_header_buffer.extend(dri_header_checksum)  # 32 bytes
  
  return dri_header_buffer

def create_key_header(volume_id_bytes, volume_password_salt_bytes, 
                     encrypted_metadata_iv_bytes, encrypted_metadata_size):
  """Creates the MyFS.METADATA header bytes."""
  key_header_buffer = bytearray()
  key_header_buffer.extend(MAGIC_NUMBER_METADATA)  # 8 bytes
  key_header_buffer.extend(volume_id_bytes)  # 16 bytes (link to DRI)
  key_header_buffer.extend(volume_password_salt_bytes)  # 16 bytes (same as DRI)
  key_header_buffer.extend(encrypted_metadata_iv_bytes)  # 16 bytes
  key_header_buffer.extend(
    struct.pack("<q", encrypted_metadata_size)
  )  # 8 bytes

  # Calculate HeaderChecksum for MyFS.METADATA (on buffer content BEFORE checksum field)
  key_header_checksum = calculate_sha256(bytes(key_header_buffer))
  key_header_buffer.extend(key_header_checksum)  # 32 bytes
  
  return key_header_buffer

def create_empty_supplemental_metadata():
  """Creates an empty supplemental metadata blob."""
  empty_supplemental_entry = bytearray(KEY_SUPPLEMENTAL_ENTRY_SIZE)
  
  plaintext_supplemental_metadata_blob_bytes = bytearray()
  for _ in range(DRI_FT_ENTRY_COUNT):
    plaintext_supplemental_metadata_blob_bytes.extend(empty_supplemental_entry)
    
  return plaintext_supplemental_metadata_blob_bytes

def format_new_volume(myfs_dri_filepath_str, myfs_metadata_filepath_str, volume_password_str):
  """
  Creates and formats a new MyFS.DRI volume and its corresponding MyFS.METADATA file.
  """
  print("Starting MyFS volume formatting...")

  # Validate inputs
  if not volume_password_str:
    print("Error: Volume password cannot be empty.")
    return False
  if os.path.exists(myfs_dri_filepath_str) or os.path.exists(myfs_metadata_filepath_str):
    print("Error: Target files already exist.")
    return False

  # 2. Gather Computer Information
  creation_timestamp = int(time.time())
  creating_machine_name = get_hostname()
  creating_machine_id_hash, raw_machine_id_str = get_machine_id_hash()
  
  if not raw_machine_id_str:
    print("Error: Failed to gather essential computer fingerprint components.")
    return False
    
  print(f"  Creating machine name: {creating_machine_name}")
  print(f"  Raw machine identifiers: {raw_machine_id_str}")
  print(f"  Machine ID Hash: {creating_machine_id_hash.hex()}")

  # 3. Generate Cryptographic Material for Volume Metadata Encryption
  volume_password_salt_bytes = os.urandom(SALT_SIZE)
  kek_metadata_bytes = derive_key_pbkdf2(
    volume_password_str, volume_password_salt_bytes
  )
  print(f"  Volume password salt: {volume_password_salt_bytes.hex()}")
  print(f"  Derived KEK for metadata: {kek_metadata_bytes.hex()}")

  # 4. Prepare and Write MyFS.DRI
  print(f"  Preparing MyFS.DRI at {myfs_dri_filepath_str}...")
  volume_id_bytes = uuid.uuid4().bytes

  # Create DRI header
  dri_header_buffer = create_dri_header(
    volume_id_bytes, creation_timestamp, creating_machine_id_hash,
    creating_machine_name, volume_password_salt_bytes
  )

  try:
    with open(myfs_dri_filepath_str, "wb") as f_dri:
      # Write Header
      f_dri.write(dri_header_buffer)
      print(f"    MyFS.DRI header written ({len(dri_header_buffer)} bytes).")

      # Initialize and Write File Table in MyFS.DRI
      empty_ft_entry = bytearray(DRI_FT_ENTRY_SIZE) # All zeros

      for i in range(DRI_FT_ENTRY_COUNT):
        f_dri.write(empty_ft_entry)
      print(
        f"    MyFS.DRI empty file table written ({DRI_FT_ENTRY_COUNT * DRI_FT_ENTRY_SIZE} bytes)."
      )
      # Data region is implicitly after this, initially empty.
  except IOError as e:
    print(f"Error writing MyFS.DRI file: {e}")
    return False

  # 5. Prepare and Write MyFS.METADATA (Removable Disk File)
  print(f"  Preparing MyFS.METADATA at {myfs_metadata_filepath_str}...")

  # Prepare Plaintext Supplemental Metadata Blob (all empty entries)
  plaintext_metadata = create_empty_supplemental_metadata()

  # Encrypt Supplemental Metadata Blob
  encrypted_iv = os.urandom(AES_IV_SIZE)
  encrypted_metadata = encrypt_aes_cbc(
    bytes(plaintext_metadata),
    kek_metadata_bytes,
    encrypted_iv
  )
  print(
    f"    Plaintext supplemental metadata size: {len(plaintext_metadata)}"
  )
  print(
    f"    Encrypted supplemental metadata size: {len(encrypted_metadata)}"
  )

  # Construct MyFS.METADATA Header
  metadata_header = create_key_header(
    volume_id_bytes, volume_password_salt_bytes,
    encrypted_iv, len(encrypted_metadata)
  )

  # Content for overall file checksum = METADATA Header + Encrypted Blob
  key_content_for_overall_checksum = (
    metadata_header + encrypted_metadata
  )
  key_file_overall_checksum = calculate_sha256(
    key_content_for_overall_checksum
  ) # 32 bytes

  try:
    with open(myfs_metadata_filepath_str, "wb") as f_metadata:
      f_metadata.write(metadata_header)
      f_metadata.write(encrypted_metadata)
      f_metadata.write(key_file_overall_checksum)
  except IOError as e:
    print(f"Error writing MyFS.METADATA: {e}")
    # Consider cleanup: if DRI was created but METADATA failed, should DRI be removed?
    # For simplicity here, not adding complex cleanup.
    return False

  print("Volume formatting completed successfully!")
  print(f"  MyFS.DRI created at: {myfs_dri_filepath_str}")
  print(f"  MyFS.METADATA created at: {myfs_metadata_filepath_str}")
  return True 