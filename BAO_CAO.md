# Báo Cáo Đồ Án MyFS - Hệ Thống Lưu Trữ Tập Tin An Toàn

GVHD: Thái Hùng Văn

Thành viên nhóm:

| Họ và Tên | MSSV |
| --- | --- |
| Nguyễn Thị Quỳnh Anh | 22520064 |
| Lưu Trung Kiên | 22520706 |

---

## **1. Tổng Quan**

**MyFS** là một hệ thống lưu trữ tập tin an toàn được thiết kế để lưu trữ dữ liệu trong một file MyFS.DRI (tương tự như file .ISO/.ZIP/.RAR) trên cloud disk, với metadata được mã hóa và lưu trữ trong file **MyFS.METADATA** trên removable disk. Hệ thống đảm bảo rằng cả hai disk phải được kết nối để có thể truy cập dữ liệu.

## 2. Tiêu Chí Thiết Kế

### 2.1. Bảo Mật Dữ Liệu (Ưu Tiên Cao Nhất)

- Mã hóa **AES-256-CBC** cho toàn bộ volume
- Mã hóa riêng cho từng tập tin với mật khẩu độc lập
- Xác thực máy tính thông qua Machine ID (WMI hoặc MAC address)
- Mật khẩu động (dynamic challenge)
- Không lưu trữ mật khẩu dưới dạng plaintext

### 2.2. Toàn Vẹn Dữ Liệu

- Kiểm tra hash cho từng tập tin
- Kiểm tra toàn vẹn hệ thống
- Tự động sao lưu và khôi phục
- Xác thực metadata

### 2.3. Phục Hồi Dữ Liệu

- Khôi phục tập tin đã xóa
- Tự động sửa chữa khi phát hiện thay đổi
- Sao lưu tự động với mật khẩu riêng

### 2.4. Giới Hạn Kỹ Thuật

- Tối đa 100 tập tin trong volume
- Không hỗ trợ hệ thống thư mục
- Kích thước tập tin tối đa: 4GB
- Tập tin > 100MB không yêu cầu bảo mật cao

## 3. Kiến Trúc Hệ Thống

### 3.1. Các Module Chính

1. **myfs.py**: Module chính, xử lý CLI và điều phối
2. **myfs_formatter.py**: Tạo và định dạng volume
3. **myfs_security.py**: Xử lý bảo mật và xác thực
4. **myfs_self_repair.py**: Tự động sửa chữa và sao lưu
5. **myfs_file_handler.py**: Xử lý tập tin
6. **myfs_metadata.py**: Quản lý metadata
7. **myfs_connector.py**: Kết nối các module
8. **myfs_hardware.py**: Xác định thông tin máy tính

### 3.2. Cấu Trúc Dữ Liệu

- **MyFS.DRI**: File volume chính
    - Header với thông tin máy tính
    - Bảng quản lý tập tin
    - Vùng dữ liệu được mã hóa
- **MyFS.METADATA**: File metadata
    - Thông tin xác thực
    - Metadata của các tập tin
    - Thông tin sao lưu

## 4. Các Chức Năng Đã Triển Khai

### 4.1. Quản Lý Volume

- Tạo và định dạng volume mới
- Thiết lập, kiểm tra và thay đổi mật khẩu volume
- Kiểm tra tính toàn vẹn volume

### 4.2. Quản Lý Tập Tin

- Liệt kê tập tin (bao gồm tập tin đã xóa)
- Import tập tin với metadata
- Export tập tin với tùy chọn đường dẫn gốc
- Xóa tập tin (có thể khôi phục)
- Xóa vĩnh viễn
- Khôi phục tập tin đã xóa (nếu xóa ở chế độ bình thường)

### 4.3. Bảo Mật

- Thiết lập mật khẩu và mã hóa AES-256-CBC cho volume
- Thiết lập và mã hóa riêng cho từng tập tin
- Xác thực máy tính
- Mật khẩu động
- Kiểm tra toàn vẹn hệ thống

### 4.4. Tự Động Sửa Chữa

- Phát hiện thay đổi hệ thống
- Tự động sao lưu
- Tự động khôi phục từ sao lưu
- Cập nhật sao lưu với phiên bản hiện tại

## 5. Cách Sử Dụng

### 5.1. Các Lệnh Cơ Bản

- Hiển thị trợ giúp `python myfs.py -h`
- Tạo volume mới `python myfs.py create`
- Liệt kê tập tin `python [myfs.py](http://myfs.py) list` hoặc `python myfs.py list -a`
- Import tập tin `python myfs.py import <đường_dẫn> [-e]`
- Export tập tin `python myfs.py export <index> <đường_dẫn> [-o]`
- Xóa tập tin `python myfs.py delete <index> [-p]`
- Khôi phục tập tin `python myfs.py recover <index>`
- Đặt mật khẩu tập tin `python myfs.py setpass <index>`
- Kiểm tra toàn vẹn `python myfs.py verify <index>`
- Kiểm tra toàn vẹn hệ thống `python myfs.py integrity`
- Tạo/cập nhật sao lưu `python myfs.py backup`
- Chế độ tương tác `python myfs.py interactive`

### 5.2. Chế Độ Tương Tác

- `list`: Liệt kê tập tin
- `list -d`: Liệt kê cả tập tin đã xóa
- `import <đường_dẫn>`: Import tập tin
- `import -e <đường_dẫn>`: Import và mã hóa
- `export <index> <đường_dẫn>`: Export tập tin
- `export -o <index> <đường_dẫn>`: Export về đường dẫn gốc
- `delete <index>`: Xóa tập tin
- `delete -p <index>`: Xóa vĩnh viễn
- `recover <index>`: Khôi phục tập tin
- `setpass <index>`: Đặt mật khẩu tập tin
- `verify <index>`: Kiểm tra toàn vẹn
- `passwd`: Đổi mật khẩu volume
- `integrity`: Kiểm tra toàn vẹn hệ thống
- `backup`: Tạo/cập nhật sao lưu
- `exit`: Thoát

## 6. Yêu Cầu Hệ Thống

- Python
- **pycryptodome** library
- Hệ điều hành: Windows/Linux/MacOS

## 7. Thuật Toán và Triển Khai

### 7.1. Mã Hóa và Bảo Mật

### 7.1.1. Mã Hóa AES

Hàm `encrypt_aes_cbc` và `decrypt_aes_cbc` thực hiện việc mã hóa và giải mã dữ liệu sử dụng thuật toán AES-256-CBC với padding PKCS#7. Các hàm này đảm bảo tính bảo mật cao cho dữ liệu được lưu trữ trong volume.

```python
# myfs_utils.py
def encrypt_aes_cbc(plaintext_bytes, key_bytes, iv_bytes):
    """Encrypts using AES-256-CBC with PKCS#7 padding."""    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_plaintext = pad(plaintext_bytes, AES.block_size, style="pkcs7")
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext
def decrypt_aes_cbc(ciphertext_bytes, key_bytes, iv_bytes):
    """Decrypts using AES-256-CBC with PKCS#7 padding."""    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(padded_plaintext, AES.block_size, style="pkcs7")
    return plaintext
```

### 7.1.2. Xác Thực Mật Khẩu Động

Hàm `generate_dynamic_password` tạo ra một thử thách động dựa trên thời gian hiện tại và thời gian tạo volume. Thử thách này yêu cầu người dùng thực hiện một phép tính đơn giản với các số ngẫu nhiên, tăng cường bảo mật cho quá trình xác thực.

```python
# myfs_security.py
def generate_dynamic_password(self):
    """Generates dynamic password challenge based on timestamp."""    
    if not self.header_data:
	      self._read_volume_header()
    current_time = int(time.time())
    creation_time = self.header_data["creation_timestamp"]
    seed = current_time ^ creation_time
    random.seed(seed)
    a = random.randint(1, 100)
    b = random.randint(1, 100)
    op = random.choice(['+', '-', '*'])
    challenge = f"What is {a} {op} {b}?"    
    if op == '+':
			  answer = a + b
    elif op == '-':
		    answer = a - b
    else: 
		    answer = a * b
    return challenge, str(answer)
```

### 7.1.3. Xác thực máy tính

Hàm `get_machine_id_hash` và `verify_machine_id` thực hiện việc xác thực máy tính thông qua việc tạo và kiểm tra hash của thông tin phần cứng. Điều này đảm bảo volume chỉ có thể được truy cập từ máy tính đã tạo ra nó.

```python
# myfs_hardware.py
def get_machine_id_hash():
    """Gets machine ID hash for identification."""    
    machine_id_str = get_hardware_identifiers_string()
    return calculate_sha256(machine_id_str.encode('utf-8')), machine_id_str
# myfs_security.py
def verify_machine_id(self):
    """Verifies if current machine matches volume creator."""    
    if not self.header_data:
        self._read_volume_header()
    current_machine_id_hash, _ = get_machine_id_hash()
    return current_machine_id_hash == self.header_data["machine_id_hash"]
```

### 7.2. Quản Lý Volume

### 7.2.1. Thiết lập và format volume (với mật khẩu volume)

Hàm `format_new_volume` thực hiện việc tạo và định dạng một volume MyFS mới, bao gồm việc tạo file MyFS.DRI và MyFS.METADATA. Quá trình này bao gồm việc xác thực đầu vào, thu thập thông tin máy tính, tạo các thành phần mã hóa, và ghi dữ liệu vào các file tương ứng.

```python
# myfs_formatter.py
def format_new_volume(myfs_dri_filepath_str, myfs_metadata_filepath_str, volume_password_str):
    """Creates and formats new MyFS volume."""    
    print("Starting MyFS volume formatting...")
    # Validate inputs    
    if not volume_password_str:
        print("Error: Volume password cannot be empty.")
        return False    
    if os.path.exists(myfs_dri_filepath_str) or os.path.exists(myfs_metadata_filepath_str):
		    print("Error: Target files already exist.")
        return False    
    # Get computer info    
    creation_timestamp = int(time.time())
    creating_machine_name = get_hostname()
    creating_machine_id_hash, raw_machine_id_str = get_machine_id_hash()
    if not raw_machine_id_str:
        print("Error: Failed to get computer fingerprint.")
        return False    
    # Generate crypto material   
    volume_password_salt_bytes = os.urandom(SALT_SIZE)
    kek_metadata_bytes = derive_key_pbkdf2(volume_password_str, volume_password_salt_bytes)
    # Create volume files    
    volume_id_bytes = uuid.uuid4().bytes    
    dri_header_buffer = create_dri_header(
	       volume_id_bytes, creation_timestamp, creating_machine_id_hash,
        creating_machine_name, volume_password_salt_bytes
    )
    try:
			   # Write MyFS.DRI        
		     with open(myfs_dri_filepath_str, "wb") as f_dri:
            f_dri.write(dri_header_buffer)
            empty_ft_entry = bytearray(DRI_FT_ENTRY_SIZE)
            for i in range(DRI_FT_ENTRY_COUNT):
                f_dri.write(empty_ft_entry)
    except IOError as e:
        print(f"Error writing MyFS.DRI: {e}")
        return False    
     # Write MyFS.METADATA    
     try:
        plaintext_metadata = create_empty_supplemental_metadata()
        encrypted_iv = os.urandom(AES_IV_SIZE)
        encrypted_metadata = encrypt_aes_cbc(
            bytes(plaintext_metadata),
            kek_metadata_bytes,
            encrypted_iv
        )
        metadata_header = create_key_header(
            volume_id_bytes, volume_password_salt_bytes,
            encrypted_iv, len(encrypted_metadata)
        )
        with open(myfs_metadata_filepath_str, "wb") as f_metadata:
            f_metadata.write(metadata_header)
            f_metadata.write(encrypted_metadata)
            f_metadata.write(calculate_sha256(metadata_header + encrypted_metadata))
    except IOError as e:
        print(f"Error writing MyFS.METADATA: {e}")
        return False    print("Volume formatting completed successfully!")
    print(f"  MyFS.DRI created at: {myfs_dri_filepath_str}")
    print(f"  MyFS.METADATA created at: {myfs_metadata_filepath_str}")
    return True
```

### 7.2.2. Thay đổi Mật Khẩu volume

Hàm `change_volume_password` cho phép thay đổi mật khẩu của volume, bao gồm việc xác thực mật khẩu cũ, giải mã metadata, tạo salt và IV mới, và mã hóa lại metadata với mật khẩu mới. Quá trình này đảm bảo tính bảo mật của dữ liệu trong volume.

```python
# myfs_security.py
def change_volume_password(self, old_password, new_password):
    """Changes volume password and re-encrypts metadata."""    
    if not self.header_data:
        self._read_volume_header()
    if not self.check_volume_password(old_password):
        raise ValueError("Incorrect old password.")
    # Read and parse metadata    
    with open(self.metadata_path, "rb") as f:
        metadata_content = f.read()
    header_size = 96    metadata_iv = metadata_content[24+16:24+16+16]
    metadata_size = struct.unpack("<q", metadata_content[24+16+16:24+16+16+8])[0]
    encrypted_metadata = metadata_content[header_size:header_size+metadata_size]
    # Decrypt metadata    
    old_key = derive_key_pbkdf2(old_password, self.volume_password_salt)
    cipher = AES.new(old_key, AES.MODE_CBC, metadata_iv)
    padded_metadata = cipher.decrypt(encrypted_metadata)
    metadata_bytes = padded_metadata[:-padded_metadata[-1]]
    # Generate new crypto material    
    new_salt = get_random_bytes(SALT_SIZE)
    new_iv = get_random_bytes(AES_IV_SIZE)
    new_key = derive_key_pbkdf2(new_password, new_salt)
    # Re-encrypt metadata    
    cipher = AES.new(new_key, AES.MODE_CBC, new_iv)
    padded_metadata = metadata_bytes + bytes([16 - (len(metadata_bytes) % 16)] * (16 - (len(metadata_bytes) % 16)))
    encrypted_metadata = cipher.encrypt(padded_metadata)
    # Update files    
    with open(self.volume_path, "rb+") as f:
        f.seek(128)
        f.write(new_salt)
    with open(self.metadata_path, "wb") as f:
        f.write(metadata_content[:24])
        f.write(new_salt)
        f.write(new_iv)
        f.write(struct.pack("<q", len(encrypted_metadata)))
        header_data = metadata_content[:24] + new_salt + new_iv + struct.pack("<q", len(encrypted_metadata))
        header_checksum = calculate_sha256(header_data)
        f.write(header_checksum)
        f.write(encrypted_metadata)
        f.write(calculate_sha256(header_data + header_checksum + encrypted_metadata))
    self.volume_password_salt = new_salt
    self.header_data["volume_password_salt"] = new_salt
    return True
```

### 7.2.3. Xác Thực Mật Khẩu

Hàm `check_volume_password` thực hiện việc xác thực mật khẩu volume bằng cách giải mã một phần nhỏ của metadata. Hàm này sử dụng salt được lưu trữ trong volume header và thử giải mã dữ liệu test để xác minh tính chính xác của mật khẩu.

```python
# myfs_security.py
def check_volume_password(self, password):
    """Verifies volume password by decrypting test data."""    
    if not self.header_data:
        self._read_volume_header()
    try:
        with open(self.metadata_path, "rb") as f:
            f.seek(24)
            metadata_salt = f.read(16)
            if metadata_salt != self.volume_password_salt:
                return False            metadata_iv = f.read(16)
            f.seek(24 + 16 + 16 + 8 + 32)
            test_data = f.read(64)
        key = derive_key_pbkdf2(password, self.volume_password_salt)
        cipher = AES.new(key, AES.MODE_CBC, metadata_iv)
        try:
            cipher.decrypt(test_data)
            return True        
        except:
			      return False    
			except:
        return False
```

### 7.3. Quản Lý Tập Tin

### 7.3.1. Liệt Kê Tập Tin

Hàm `list_files` hiển thị danh sách các tập tin trong volume, bao gồm thông tin về tên, kích thước, trạng thái và tình trạng mã hóa. Hàm này hỗ trợ tùy chọn hiển thị cả các tập tin đã bị xóa.

```python
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
```

### 7.3.2. Import và Export file

Hàm `import_file` và `export_file` thực hiện việc nhập và xuất tập tin vào/ra khỏi volume. Các hàm này hỗ trợ mã hóa tùy chọn cho từng tập tin, kiểm tra tính toàn vẹn, và xác thực mật khẩu khi cần thiết.

```python
# myfs_file_handler.py
def import_file(self, filepath, password, file_password=None):
    """Imports file with optional encryption."""    
    if not self.header_data:
        self._read_volume_header()
    self._read_metadata(password)
    filename = os.path.basename(filepath)
    original_path = os.path.abspath(filepath)
    filename_hash = calculate_sha256(filename.encode("utf-8"))
    entry_index = self._find_free_file_table_entry()
    if entry_index is None:
        raise Exception("Volume is full.")
    with open(filepath, "rb") as f:
        file_content = f.read()
    file_checksum = calculate_sha256(file_content)
    if file_password:
        file_salt = get_random_bytes(SALT_SIZE)
        file_iv = get_random_bytes(AES_IV_SIZE)
        file_key = derive_key_pbkdf2(file_password, file_salt)
        encrypted_content = encrypt_aes_cbc(file_content, file_key, file_iv)
        password_verifier = derive_key_pbkdf2(file_password, file_salt, dklen=KEY_PER_FILE_PW_VERIFIER_LEN)
    else:
        encrypted_content = file_content
        file_salt = b"\x00" * SALT_SIZE
        file_iv = b"\x00" * AES_IV_SIZE
        password_verifier = b"\x00" * KEY_PER_FILE_PW_VERIFIER_LEN
    entry_data = bytearray(DRI_FT_ENTRY_SIZE)
    entry_data[0] = FileStatus.ACTIVE
    entry_data[1:1+DRI_FT_FILENAME_HASH_LEN] = filename_hash
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN, len(file_content))
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+8, len(encrypted_content))
    current_time = int(time.time())
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+16, current_time)
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+24, current_time)
    with open(self.volume_path, "rb+") as f:
        f.seek(0, 2)
        data_offset = f.tell()
        f.write(encrypted_content)
    struct.pack_into("<q", entry_data, 1+DRI_FT_FILENAME_HASH_LEN+32, data_offset)
    iv_salt_offset = 1 + DRI_FT_FILENAME_HASH_LEN + 40    entry_data[iv_salt_offset:iv_salt_offset+16] = file_iv
    entry_data[iv_salt_offset+16:iv_salt_offset+32] = file_salt
    self._update_file_table_entry(entry_index, entry_data)
    self._update_file_metadata(entry_index, filename, original_path,
                              password_verifier, file_checksum, bool(file_password))
    return entry_index

def export_file(self, file_index, export_path, volume_password, file_password=None, use_original_path=False):
    """Exports file with optional decryption."""    
    if not self.header_data:
        self._read_volume_header()
    self._read_metadata(volume_password)
    entry_data = self._get_file_table_entry(file_index)
    file_metadata = self.metadata.get(f"file_{file_index}", {})
    if entry_data[0] != FileStatus.ACTIVE:
        raise Exception("File not found or deleted.")
        
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
```

### 7.3.3. Quản Lý Mật Khẩu Tập Tin

Hàm `set_file_password` cho phép thiết lập hoặc thay đổi mật khẩu cho một tập tin cụ thể. Hàm này xử lý việc giải mã dữ liệu cũ và mã hóa lại với mật khẩu mới, đồng thời cập nhật metadata tương ứng.

```python
# myfs_file_handler.py
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
```

### 7.3.4. Xóa và Khôi Phục Tập Tin

Hàm `delete_file` và `recover_file` thực hiện việc xóa và khôi phục tập tin trong volume. Hàm xóa hỗ trợ cả xóa thông thường (có thể khôi phục) và xóa vĩnh viễn, trong khi hàm khôi phục cho phép lấy lại các tập tin đã bị xóa thông thường.

```python
# myfs_file_handler.py
def delete_file(self, index: int, permanent: bool = False) -> bool:
    """Deletes file (recoverable or permanent)."""    
    try:
        metadata = self.get_file_metadata(index)
        if not metadata:
            return False        
        if permanent:
		        return self._permanent_delete(index)
        else:
            metadata.is_deleted = True            
            metadata.deleted_at = time.time()
		        return self._update_metadata(index, metadata)
    except Exception as e:
        print(f"Lỗi khi xóa: {str(e)}")
        return Falsedef recover_file(self, index: int) -> bool:
    """Recovers deleted file."""    
    try:
        metadata = self.get_file_metadata(index)
        if not metadata or not metadata.is_deleted:
            return False        
        metadata.is_deleted = False        
        metadata.deleted_at = None        
        return self._update_metadata(index, metadata)
    except Exception as e:
        print(f"Lỗi khi khôi phục: {str(e)}")
        return False
```

### 7.4. Tự Động Kiểm Tra và Khôi Phục

### 7.4.1. Kiểm Tra Tính Toàn Vẹn Hệ Thống

Hàm `verify_self_integrity` thực hiện việc kiểm tra tính toàn vẹn của toàn bộ hệ thống MyFS bằng cách so sánh hash của các file với bản sao lưu. Hàm này phát hiện các thay đổi không mong muốn và tự động khởi động quá trình khôi phục nếu cần thiết.

```python
# myfs.py
def verify_self_integrity(self):
    """Verifies the integrity of the MyFS application by comparing file hashes with backup."""
    print("Verifying file integrity by comparing hash values...")
    is_valid, details = self.security.verify_self_integrity()
    
    if not is_valid:
        print("WARNING: Application integrity check failed!")
        print("Some files have been modified since the last backup.")
        
        # Print details about failed integrity checks
        for file_path, result in details.items():
            if isinstance(result, dict) and not result.get("is_valid", True):
                print(f"  - {file_path}: {result.get('reason', 'Unknown issue')}")
        
        # Try to repair
        print("Attempting automatic repair...")
        try:
            success, repair_message = self.security.self_repair.perform_self_repair()
            
            if success:
                print(f"Self-repair successful: {repair_message}")
                # Re-verify after repair
                is_valid, _ = self.security.verify_self_integrity()
                if is_valid:
                    print("All files have been restored to their original state.")
                    return True
                else:
                    print("Some files still don't match their original hash values after repair attempt.")
                    return False
            else:
                print(f"Self-repair failed: {repair_message}")
                return False
        except Exception as e:
            print(f"Error during self-repair: {str(e)}")
            return False
    
    print("Integrity verification complete: All files match their original hash values.")
    return True
```

### 7.4.2. Tạo và Quản Lý Sao Lưu

Hàm `create_backup` thực hiện việc tạo và mã hóa bản sao lưu của toàn bộ hệ thống. Bản sao lưu được bảo vệ bằng mật khẩu riêng và được lưu trữ dưới dạng file nén đã mã hóa.

```python
# myfs_self_repair.py
def create_backup(self, password=None):
    """Create an encrypted backup of all application files."""
    # If backup exists, require password for update
    if os.path.exists(self.backup_manifest_path):
        if not password:
            print("\nBackup update requires password verification.")
            password = input("Enter backup password: ").strip()
            if not password:
                raise ValueError("Password required to update existing backup")
        
        # Verify password against stored hash
        try:
            with open(self.backup_manifest_path, "r") as f:
                manifest = json.load(f)
                if "password_hash" not in manifest:
                    raise ValueError("Backup is not password protected")
                
                # Verify password
                if not self._verify_password(password, manifest["password_hash"]):
                    raise ValueError("Invalid password")
        except Exception as e:
            raise ValueError(f"Failed to verify backup password: {str(e)}")
    
    # Get all application files
    app_files = self._get_all_app_files()
    app_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create manifest with file information
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "files": {},
        "is_initial_backup": not os.path.exists(self.backup_manifest_path)
    }
    
    # Store password hash
    manifest["password_hash"] = self._hash_password(password)
    
    # Create encrypted backup
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip_file:
        temp_zip_path = temp_zip_file.name
    
    # Create zip file with all app files
    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in app_files:
            full_path = os.path.join(app_dir, file_path)
            file_stat = os.stat(full_path)
            
            with open(full_path, "rb") as f:
                file_content = f.read()
                file_hash = calculate_sha256(file_content)
                manifest["files"][file_path] = {
                    "hash": file_hash.hex(),
                    "size": file_stat.st_size,
                    "mod_time": file_stat.st_mtime
                }
            
            # Add file to zip
            zipf.write(full_path, file_path)
    
    # Encrypt the backup
    with open(temp_zip_path, "rb") as f:
        zip_data = f.read()
    
    key = self._read_key()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(zip_data, AES.block_size))
    
    # Save encrypted backup and manifest
    with open(self.backup_archive_path, "wb") as f:
        f.write(iv + encrypted_data)
    
    with open(self.backup_manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    # Clean up
    os.unlink(temp_zip_path)
    
    print("Backup created successfully.")
    return True
```

### 7.4.3. Khôi Phục Tự Động

Hàm `perform_self_repair` thực hiện việc khôi phục hệ thống từ bản sao lưu khi phát hiện các thay đổi không mong muốn. Hàm này cung cấp nhiều tùy chọn khôi phục và đảm bảo tính toàn vẹn sau khi khôi phục.

```python
# myfs_self_repair.py
def perform_self_repair(self, password=None):
    """Perform self-repair if any hash values are different."""
    is_valid, results = self.verify_integrity()
    
    if is_valid:
        return True, "Integrity check passed, no repair needed"
    
    # Get list of files that need repair
    files_to_restore = []
    if isinstance(results, dict):
        files_to_restore = [
            file_path for file_path, result in results.items() 
            if isinstance(result, dict) and not result.get("is_valid", True)
        ]
    
    if not files_to_restore:
        return True, "No files need repair"
    
    print(f"\nFound {len(files_to_restore)} modified files:")
    for file in files_to_restore:
        print(f"  - {file}")
    
    print("\nOptions:")
    print("1. Update backup with current version (requires backup password)")
    print("2. Restore original files from backup")
    print("3. Exit without changes")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            # Try to update backup
            if not password:
                password = input("Enter backup password: ").strip()
            try:
                if self.create_backup(password):
                    is_valid, _ = self.verify_integrity()
                    if is_valid:
                        return True, "Backup updated with current version and verified"
                    else:
                        return False, "Backup updated but integrity check still fails"
            except ValueError as e:
                return False, str(e)
        elif choice == "2":
            # Restore the files
            print(f"\nAttempting to restore {len(files_to_restore)} files from backup...")
            success, message = self.restore_files(files_to_restore)
            if success:
                is_valid, _ = self.verify_integrity()
                if is_valid:
                    print("Recovery completed successfully.")
                    return True, f"Self-repair completed: {len(files_to_restore)} files restored"
                else:
                    return False, "Files restored but integrity check still fails"
            else:
                print(f"Recovery failed: {message}")
                return False, f"Failed to repair: {message}"
        elif choice == "3":
            return False, "Operation cancelled by user"
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
```

## 8. Kết Luận

MyFS đã đáp ứng đầy đủ các yêu cầu về bảo mật, toàn vẹn dữ liệu và khả năng phục hồi. Hệ thống cung cấp một giải pháp lưu trữ an toàn với các tính năng:
- Mã hóa mạnh mẽ
- Xác thực nhiều lớp
- Tự động sửa chữa
- Khôi phục dữ liệu
- Giao diện CLI dễ sử dụng