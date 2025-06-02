# Báo Cáo Đồ Án MyFS - Hệ Thống Lưu Trữ Tập Tin An Toàn

## **1. Tổng Quan**

**MyFS** là một hệ thống lưu trữ tập tin an toàn được thiết kế để lưu trữ dữ liệu trong một file MyFS.DRI (tương tự như file .ISO/.ZIP/.RAR) trên cloud disk, với metadata được mã hóa và lưu trữ trong file **MyFS.METADATA** trên removable disk. Hệ thống đảm bảo rằng cả hai disk phải được kết nối để có thể truy cập dữ liệu.


<video src="https://github.com/keandk/Final-lab/blob/main/final-lab-demo.mp4" controls></video>

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