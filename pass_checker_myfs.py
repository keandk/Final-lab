import os
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 100_000
METADATA_FILENAME = "metadata.enc"

def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_metadata(metadata_dict, password):
    data = json.dumps(metadata_dict).encode('utf-8')
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = pad(data)
    ciphertext = cipher.encrypt(data_padded)
    return salt + iv + ciphertext

def decrypt_metadata(enc_data, password):
    salt = enc_data[:SALT_SIZE]
    iv = enc_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = enc_data[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = cipher.decrypt(ciphertext)
    data = unpad(data_padded)
    return json.loads(data.decode('utf-8'))

def load_metadata(password):
    try:
        with open(METADATA_FILENAME, "rb") as f:
            enc_data = f.read()
        metadata = decrypt_metadata(enc_data, password)
        return metadata
    except (ValueError, KeyError, json.JSONDecodeError):
        raise ValueError("Sai mật khẩu hoặc file metadata bị hỏng")

def save_metadata(metadata, password):
    enc_data = encrypt_metadata(metadata, password)
    with open(METADATA_FILENAME, "wb") as f:
        f.write(enc_data)

def change_volume_password(old_password, new_password):
    try:
        metadata = load_metadata(old_password)
    except ValueError:
        print("Mật khẩu cũ không đúng, đổi mật khẩu thất bại.")
        return False
    save_metadata(metadata, new_password)
    print("Đổi mật khẩu truy cập volume thành công.")
    return True

def check_password(password):
    try:
        _ = load_metadata(password)
        return True
    except ValueError:
        return False

# Ví dụ giao diện đơn giản:
if __name__ == "__main__":
    print("1. Kiểm tra mật khẩu")
    print("2. Đổi mật khẩu")
    choice = input("Chọn: ")
    if choice == "1":
        pw = input("Nhập mật khẩu kiểm tra: ")
        if check_password(pw):
            print("Mật khẩu đúng.")
        else:
            print("Mật khẩu sai.")
    elif choice == "2":
        old_pw = input("Nhập mật khẩu cũ: ")
        new_pw = input("Nhập mật khẩu mới: ")
        confirm_pw = input("Xác nhận mật khẩu mới: ")
        if new_pw != confirm_pw:
            print("Mật khẩu mới không khớp.")
        else:
            change_volume_password(old_pw, new_pw)