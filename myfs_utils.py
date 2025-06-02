"""
Utility functions for MyFS operations.
"""

import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

from myfs_constants import PBKDF2_ITERATIONS, AES_KEY_SIZE

def calculate_sha256(data_bytes):
  """Calculates SHA-256 hash of given bytes."""
  sha256 = hashlib.sha256()
  sha256.update(data_bytes)
  return sha256.digest()

def derive_key_pbkdf2(password_str, salt_bytes, dklen=AES_KEY_SIZE):
  """Derives a key using PBKDF2-HMAC-SHA256."""
  key = PBKDF2(
    password=password_str.encode("utf-8"),
    salt=salt_bytes,
    dkLen=dklen,
    count=PBKDF2_ITERATIONS,
    hmac_hash_module=SHA256,
  )
  return key

def encrypt_aes_cbc(plaintext_bytes, key_bytes, iv_bytes):
  """Encrypts plaintext using AES-256-CBC with PKCS#7 padding."""
  cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
  padded_plaintext = pad(plaintext_bytes, AES.block_size, style="pkcs7")
  ciphertext = cipher.encrypt(padded_plaintext)
  return ciphertext

def decrypt_aes_cbc(ciphertext_bytes, key_bytes, iv_bytes, debug=False):
  """Decrypts ciphertext using AES-256-CBC with PKCS#7 padding."""
  try:
    # Validate input parameters
    if len(key_bytes) != 32:  # AES-256 requires 32-byte key
      raise ValueError(f"Invalid key length: {len(key_bytes)}, expected 32 bytes")
    if len(iv_bytes) != 16:   # AES block size is 16 bytes
      raise ValueError(f"Invalid IV length: {len(iv_bytes)}, expected 16 bytes")
    if len(ciphertext_bytes) == 0:
      raise ValueError("Ciphertext is empty")
    if len(ciphertext_bytes) % 16 != 0:
      raise ValueError(f"Ciphertext length ({len(ciphertext_bytes)}) is not a multiple of 16 bytes")
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)
    
    # Attempt to unpad with error handling
    try:
      plaintext = unpad(padded_plaintext, AES.block_size, style="pkcs7")
      return plaintext
    except ValueError as padding_error:
      # Analyze the padding bytes for recovery
      last_byte = padded_plaintext[-1] if len(padded_plaintext) > 0 else 0
      
      if last_byte > 0 and last_byte <= 16:
        expected_padding_bytes = padded_plaintext[-last_byte:]
        is_valid_padding = all(b == last_byte for b in expected_padding_bytes)
        
        # Try to remove padding manually if it looks reasonable
        if last_byte <= len(padded_plaintext):
          manual_unpadded = padded_plaintext[:-last_byte]
          return manual_unpadded
      
      # If manual unpadding fails, return raw data
      return padded_plaintext
      
  except Exception as e:
    raise

def pack_str_fixed_len(s, length, encoding="utf-8"):
  """Packs a string into a fixed-length byte array, null-padded/truncated."""
  encoded_s = s.encode(encoding)
  if len(encoded_s) > length:
    return encoded_s[:length]
  return encoded_s + b"\x00" * (length - len(encoded_s))

def unpack_fixed_len_str(data_bytes, encoding="utf-8"):
  """Unpacks a fixed-length null-padded byte array into a string."""
  # Find the first null byte
  null_pos = data_bytes.find(b"\x00")
  if null_pos >= 0:
    # If found, only use bytes up to that position
    return data_bytes[:null_pos].decode(encoding)
  # Otherwise, use all bytes
  return data_bytes.decode(encoding) 