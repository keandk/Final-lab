# MyFS - Secure File Storage System

MyFS is a secure file storage system that provides encryption, integrity verification, and automatic recovery capabilities.

## Features

### 1. Volume Management ✅
- Create and format encrypted volumes
- Change volume passwords
- Machine-specific access control

### 2. File Operations ✅
- List files (including deleted files)
- Import files into the volume
- Export files from the volume
- Delete files (with recovery option)
- Permanently delete files

### 3. Security Features ✅
- Volume-level encryption
- File-level encryption with individual passwords
- Dynamic challenge-response authentication
- Machine ID verification
- System integrity verification
- Automatic self-repair capabilities

### 4. Integrity Protection ✅
- File integrity verification
- System integrity checks
- Automatic backup creation
- Self-repair functionality with options to:
  - Update backup with current version
  - Restore from backup
  - Exit without changes

## Requirements Status

1. ✅ Create and format volume
   - Supports volume creation with password protection
   - Includes metadata file generation

2. ✅ Change/verify password
   - Volume password change functionality
   - Password verification with dynamic challenges

3. ✅ List files
   - Shows file index, name, size, status
   - Option to include deleted files

4. ✅ Set and change file password
   - Individual file encryption
   - Password change/removal options

5. ✅ Encryption
   - AES encryption for volume
   - Optional file-level encryption
   - Secure key management

6. ✅ Import/export
   - File import with optional encryption
   - File export with path options
   - Maintains file integrity

7. ✅ Delete/delete-perm
   - Soft delete with recovery option
   - Permanent deletion option
   - Secure file removal

8. ✅ Challenge
   - Dynamic challenge-response system
   - Time-based authentication
   - Machine verification

9. ✅ Check system origin
   - Machine ID verification
   - Hardware-based identification
   - Access control enforcement

10. ✅ Verify self integrity and recover automatically
    - System integrity verification
    - Automatic backup creation
    - Self-repair with multiple options:
      - Update backup with current version
      - Restore from backup
      - Exit without changes
    - Integrity verification after changes

## Usage

### Basic Commands

```bash
# show help 
python myfs.py -h
# Create a new volume
python myfs.py create

# List files
python myfs.py list

# Import a file
python myfs.py import <filepath> [-e]

# Export a file
python myfs.py export <index> <exportpath> [-o]

# Delete a file
python myfs.py delete <index> [-p]

# Recover a deleted file
python myfs.py recover <index>

# Set file password
python myfs.py setpass <index>

# Verify file integrity
python myfs.py verify <index>

# Check system integrity
python myfs.py integrity

# Create/update backup with its own password 
python myfs.py backup

# Interactive mode
python myfs.py interactive
```

### Interactive Mode

The interactive mode provides a command-line interface with the following commands:
- `list` - List all files
- `list -d` - List all files including deleted
- `import <path>` - Import a file
- `import -e <path>` - Import and encrypt a file
- `export <idx> <path>` - Export a file
- `export -o <idx> <path>` - Export to original path
- `delete <idx>` - Delete a file (recoverable)
- `delete -p <idx>` - Delete a file permanently
- `recover <idx>` - Recover a deleted file
- `setpass <idx>` - Set/change file password
- `verify <idx>` - Verify file integrity
- `passwd` - Change volume password
- `integrity` - Verify system integrity
- `backup` - Create/update system backup with its own password 
- `exit` - Exit interactive mode

## Security Features

### Volume Security
- AES encryption for volume data
- Password-based access control
- Machine-specific access restrictions

### File Security
- Optional file-level encryption
- Individual file passwords
- Secure file deletion

### System Security
- Integrity verification
- Automatic backup system
- Self-repair capabilities
- Machine ID verification

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install -r requirements.txt
```

## Dependencies

- Python 3.6+
- pycryptodome

## License

This project is licensed under the MIT License - see the LICENSE file for details.