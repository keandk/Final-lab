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

def decrypt_aes_cbc(ciphertext_bytes, key_bytes, iv_bytes):
  """Decrypts ciphertext using AES-256-CBC with PKCS#7 padding."""
  cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
  padded_plaintext = cipher.decrypt(ciphertext_bytes)
  plaintext = unpad(padded_plaintext, AES.block_size, style="pkcs7")
  return plaintext

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