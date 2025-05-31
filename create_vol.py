"""
Main script for creating and formatting a new MyFS volume.
"""

import os
import sys
from myfs_formatter import format_new_volume

def create_test_dirs():
  """Creates test directories if they don't exist."""
  if not os.path.exists("test_volume"):
    os.makedirs("test_volume")
  if not os.path.exists("test_removable"):
    os.makedirs("test_removable")
    
def cleanup_test_files(dri_file, key_file):
  """Removes test files if they exist."""
  if os.path.exists(dri_file):
    os.remove(dri_file)
  if os.path.exists(key_file):
    os.remove(key_file)
    
def verify_sizes(dri_file, key_file):
  """Verifies and prints the sizes of created files."""
  from myfs_constants import DRI_FT_ENTRY_COUNT, DRI_FT_ENTRY_SIZE
  from myfs_constants import KEY_SUPPLEMENTAL_ENTRY_SIZE, HASH_SIZE
  from Crypto.Cipher import AES
  
  print("\nVerification (sizes):")
  if os.path.exists(dri_file):
    print(f"  MyFS.DRI size: {os.path.getsize(dri_file)} bytes")
  if os.path.exists(key_file):
    print(f"  MyFS.KEY size: {os.path.getsize(key_file)} bytes")

  # Expected DRI header size:
  # 8+16+8+32+64+16+8+4+4+8+32 = 200
  # Expected DRI file table size: 100 * 128 = 12800
  # Expected total DRI size: 200 + 12800 = 13000
  print(f"  Expected MyFS.DRI size: {200 + (DRI_FT_ENTRY_COUNT * DRI_FT_ENTRY_SIZE)}")

  # Expected KEY header size:
  # 8+16+16+16+8+32 = 96
  # Expected KEY supplemental blob (plaintext): 100 * 832 = 83200
  # After padding for AES, this will be slightly larger.
  # E.g., if 83200 % 16 != 0, it's padded to next multiple of 16.
  # 83200 is a multiple of 16. So, encrypted size should be 83200.
  # Expected total KEY size: 96 + 83200 + 32 = 83328
  expected_key_encrypted_blob_size = (
      (DRI_FT_ENTRY_COUNT * KEY_SUPPLEMENTAL_ENTRY_SIZE + AES.block_size - 1)
      // AES.block_size
  ) * AES.block_size
  print(f"  Expected MyFS.KEY size: {96 + expected_key_encrypted_blob_size + HASH_SIZE}")

def main():
  """Main function for creating and formatting a new MyFS volume."""
  if len(sys.argv) > 1 and sys.argv[1] == "--help":
    print("Usage: python create_vol.py [dri_file] [key_file] [password]")
    print("  If no arguments provided, creates test files with default values")
    return
    
  # Create test directories if they don't exist
  create_test_dirs()
  
  # Set default values
  dri_file = os.path.join("test_volume", "MyFS.DRI")
  key_file = os.path.join("test_removable", "MyFS.KEY")
  password = "1234567890"
  
  # Override with command line arguments if provided
  if len(sys.argv) >= 4:
    dri_file = sys.argv[1]
    key_file = sys.argv[2]
    password = sys.argv[3]
  
  # Clean up previous test files if they exist
  cleanup_test_files(dri_file, key_file)
  
  # Format the volume
  success = format_new_volume(dri_file, key_file, password)
  
  # Verify the results
  if success:
    verify_sizes(dri_file, key_file)

if __name__ == "__main__":
  main()