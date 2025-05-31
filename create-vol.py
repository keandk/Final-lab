import os
import json
import struct
import uuid
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Cấu hình
VOLUME_FILENAME = "MyFS.DRI"
METADATA_FILENAME = "metadata.enc"
MAX_FILES = 100
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 100_000

# Header format:
# 4 bytes magic "MFS1" -> để nhận diện file volume
# 16 bytes machine_id (UUID bytes) (MAC + padding)
# 4 bytes max_files (uint32) 
# 4 bytes reserved (padding)

"""Lấy MAC address máy tính tạo volume, padding đủ 16 bytes lưu trong header."""
def get_machine_id(): 
    mac = uuid.getnode()
    return mac.to_bytes(6, 'big') + b'\x00'*10  # padding 16 bytes total

def create_volume_header():
    magic = b'MFS1'
    machine_id = get_machine_id()
    max_files = MAX_FILES
    reserved = 0
    header = struct.pack(">4s16sII", magic, machine_id, max_files, reserved)
    return header
""""""
def create_empty_file_table():
    return b'\x00' * (MAX_FILES * 256)

def write_volume_file():
    header = create_volume_header()
    file_table = create_empty_file_table()
    with open(VOLUME_FILENAME, "wb") as f:
        f.write(header)
        f.write(file_table)
    print(f"Volume {VOLUME_FILENAME} đã được tạo.")

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_metadata(metadata_dict, password):
    data = json.dumps(metadata_dict).encode('utf-8')
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # padding PKCS7
    pad_len = 16 - (len(data) % 16)
    data_padded = data + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(data_padded)
    return salt + iv + ciphertext

def create_empty_metadata(password):
    metadata = {
        "files": [],  # rỗng
        "volume_password_set": True,
    }
    enc_data = encrypt_metadata(metadata, password)
    with open(METADATA_FILENAME, "wb") as f:
        f.write(enc_data)
    print(f"Metadata mã hóa rỗng đã được lưu vào {METADATA_FILENAME}.")

def main():
    print("=== Tạo volume MyFS.DRI mới ===")
    write_volume_file()

    password = getpass.getpass("Nhập mật khẩu truy cập volume: ")
    password_confirm = getpass.getpass("Xác nhận mật khẩu: ")
    if password != password_confirm:
        print("Mật khẩu không khớp, thoát.")
        return

    create_empty_metadata(password)
    print("Hoàn tất tạo volume và metadata mã hóa.")

if __name__ == "__main__":
    main()
