# Báo Cáo Đồ Án MyFS - Hệ Thống Lưu Trữ Tập Tin An Toàn

## 1. Tổng Quan

MyFS là một hệ thống lưu trữ tập tin an toàn được thiết kế để lưu trữ dữ liệu trong một file MyFS.DRI (tương tự như file .ISO/.ZIP/.RAR) trên cloud disk, với metadata được mã hóa và lưu trữ trong file MyFS.METADATA trên removable disk. Hệ thống đảm bảo rằng cả hai disk phải được kết nối để có thể truy cập dữ liệu.

## 2. Tiêu Chí Thiết Kế

### 2.1. Bảo Mật Dữ Liệu (Ưu Tiên Cao Nhất)
- Mã hóa AES cho toàn bộ volume
- Mã hóa riêng cho từng tập tin với mật khẩu độc lập
- Xác thực máy tính thông qua Machine ID
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
- Thay đổi mật khẩu volume
- Kiểm tra tính toàn vẹn volume

### 4.2. Quản Lý Tập Tin
- Liệt kê tập tin (bao gồm tập tin đã xóa)
- Import tập tin với metadata
- Export tập tin với tùy chọn đường dẫn gốc
- Xóa tập tin (có thể khôi phục)
- Xóa vĩnh viễn

### 4.3. Bảo Mật
- Mã hóa AES cho volume
- Mã hóa riêng cho từng tập tin
- Xác thực máy tính
- Mật khẩu động
- Kiểm tra toàn vẹn hệ thống

### 4.4. Tự Động Sửa Chữa
- Phát hiện thay đổi hệ thống
- Tự động sao lưu
- Khôi phục từ sao lưu
- Cập nhật sao lưu với phiên bản hiện tại

## 5. Cách Sử Dụng

### 5.1. Các Lệnh Cơ Bản
```bash
# Hiển thị trợ giúp
python myfs.py -h

# Tạo volume mới
python myfs.py create

# Liệt kê tập tin
python myfs.py list

# Import tập tin
python myfs.py import <đường_dẫn> [-e]

# Export tập tin
python myfs.py export <index> <đường_dẫn> [-o]

# Xóa tập tin
python myfs.py delete <index> [-p]

# Khôi phục tập tin
python myfs.py recover <index>

# Đặt mật khẩu tập tin
python myfs.py setpass <index>

# Kiểm tra toàn vẹn
python myfs.py verify <index>

# Kiểm tra toàn vẹn hệ thống
python myfs.py integrity

# Tạo/cập nhật sao lưu
python myfs.py backup

# Chế độ tương tác
python myfs.py interactive
```

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

## 6. Cài Đặt

1. Clone repository
2. Cài đặt các gói cần thiết:
```bash
pip install -r requirements.txt
```

## 7. Yêu Cầu Hệ Thống

- Python 3.6+
- pycryptodome
- Hệ điều hành: Windows/Linux/MacOS

## 8. Thuật Toán và Triển Khai

### 8.1. Mã Hóa và Bảo Mật

#### 8.1.1. Mã Hóa AES
```python
# myfs_security.py
def encrypt_data(self, data: bytes, key: bytes) -> bytes:
    """Mã hóa dữ liệu sử dụng AES-256-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext
```

#### 8.1.2. Xác Thực Mật Khẩu Động
```python
# myfs_security.py
def generate_challenge(self) -> str:
    """Tạo thử thách động dựa trên thời gian"""
    timestamp = int(time.time())
    challenge = hashlib.sha256(str(timestamp).encode()).hexdigest()[:8]
    return challenge

def verify_challenge(self, challenge: str, response: str) -> bool:
    """Xác thực phản hồi thử thách"""
    timestamp = int(time.time())
    valid_responses = []
    for t in range(timestamp - 2, timestamp + 3):
        valid = hashlib.sha256(str(t).encode()).hexdigest()[:8]
        valid_responses.append(valid)
    return response in valid_responses
```

### 8.2. Quản Lý Tập Tin

#### 8.2.1. Liệt Kê Tập Tin
```python
# myfs_file_handler.py
def list_files(self, show_deleted: bool = False) -> None:
    """Liệt kê danh sách các tập tin trong volume"""
    try:
        # Đọc bảng quản lý tập tin
        file_table = self._read_file_table()
        if not file_table:
            print("Volume trống")
            return
            
        # In header
        print("\n{:<5} {:<40} {:<10} {:<15} {:<10}".format(
            "STT", "Tên tập tin", "Kích thước", "Trạng thái", "Mã hóa"
        ))
        print("-" * 85)
        
        # In từng tập tin
        for idx, file_info in enumerate(file_table, 1):
            if not show_deleted and file_info.is_deleted:
                continue
                
            size_str = self._format_size(file_info.size)
            status = "Đã xóa" if file_info.is_deleted else "Hoạt động"
            encrypted = "Có" if file_info.is_encrypted else "Không"
            
            print("{:<5} {:<40} {:<10} {:<15} {:<10}".format(
                idx,
                file_info.name[:37] + "..." if len(file_info.name) > 37 else file_info.name,
                size_str,
                status,
                encrypted
            ))
            
        print(f"\nTổng số: {len(file_table)} tập tin")
    except Exception as e:
        print(f"Lỗi khi liệt kê: {str(e)}")
```

#### 8.2.2. Quản Lý Mật Khẩu Tập Tin
```python
# myfs_file_handler.py
def set_file_password(self, index: int, new_password: str = None) -> bool:
    """Đặt hoặc đổi mật khẩu cho tập tin"""
    try:
        # Lấy metadata
        metadata = self.get_file_metadata(index)
        if not metadata:
            return False
            
        # Đọc nội dung hiện tại
        content = self._read_from_volume(index)
        
        # Nếu đã mã hóa, giải mã trước
        if metadata.is_encrypted:
            content = self.decrypt_file_content(content, metadata.password)
            
        # Mã hóa lại với mật khẩu mới
        if new_password:
            content = self.encrypt_file_content(content, new_password)
            metadata.is_encrypted = True
            metadata.password = new_password
        else:
            metadata.is_encrypted = False
            metadata.password = None
            
        # Cập nhật vào volume
        return self._update_file_content(index, content, metadata)
    except Exception as e:
        print(f"Lỗi khi đặt mật khẩu: {str(e)}")
        return False
```

#### 8.2.3. Xóa và Khôi Phục Tập Tin
```python
# myfs_file_handler.py
def delete_file(self, index: int, permanent: bool = False) -> bool:
    """Xóa tập tin (có thể khôi phục hoặc vĩnh viễn)"""
    try:
        # Lấy metadata
        metadata = self.get_file_metadata(index)
        if not metadata:
            return False
            
        if permanent:
            # Xóa vĩnh viễn
            return self._permanent_delete(index)
        else:
            # Đánh dấu đã xóa
            metadata.is_deleted = True
            metadata.deleted_at = time.time()
            return self._update_metadata(index, metadata)
    except Exception as e:
        print(f"Lỗi khi xóa: {str(e)}")
        return False

def recover_file(self, index: int) -> bool:
    """Khôi phục tập tin đã xóa"""
    try:
        # Lấy metadata
        metadata = self.get_file_metadata(index)
        if not metadata or not metadata.is_deleted:
            return False
            
        # Khôi phục metadata
        metadata.is_deleted = False
        metadata.deleted_at = None
        return self._update_metadata(index, metadata)
    except Exception as e:
        print(f"Lỗi khi khôi phục: {str(e)}")
        return False
```

### 8.5. Quản Lý Mật Khẩu Volume

#### 8.5.1. Thiết Lập Mật Khẩu
```python
# myfs_security.py
def set_volume_password(self, new_password: str) -> bool:
    """Thiết lập mật khẩu mới cho volume"""
    try:
        # Tạo salt ngẫu nhiên
        salt = os.urandom(32)
        
        # Tạo hash mật khẩu
        password_hash = self._hash_password(new_password, salt)
        
        # Cập nhật metadata
        self.metadata.password_hash = password_hash
        self.metadata.password_salt = salt
        
        # Mã hóa lại toàn bộ volume
        return self._reencrypt_volume(new_password)
    except Exception as e:
        print(f"Lỗi khi đổi mật khẩu: {str(e)}")
        return False
```

#### 8.5.2. Xác Thực Mật Khẩu
```python
# myfs_security.py
def verify_volume_password(self, password: str) -> bool:
    """Xác thực mật khẩu volume"""
    try:
        # Lấy salt và hash từ metadata
        salt = self.metadata.password_salt
        stored_hash = self.metadata.password_hash
        
        # Tính hash mật khẩu nhập vào
        input_hash = self._hash_password(password, salt)
        
        # So sánh hash
        return input_hash == stored_hash
    except Exception:
        return False

def _hash_password(self, password: str, salt: bytes) -> bytes:
    """Tạo hash mật khẩu với salt"""
    # Sử dụng PBKDF2 với 100,000 vòng lặp
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000
    )
```

## 9. Kết Luận

MyFS đã đáp ứng đầy đủ các yêu cầu về bảo mật, toàn vẹn dữ liệu và khả năng phục hồi. Hệ thống cung cấp một giải pháp lưu trữ an toàn với các tính năng:
- Mã hóa mạnh mẽ
- Xác thực nhiều lớp
- Tự động sửa chữa
- Khôi phục dữ liệu
- Giao diện dễ sử dụng 