# MyFS - Secure File Storage System

MyFS is a secure file storage system that stores files in an encrypted volume file (MyFS.DRI) with metadata stored in a separate encrypted file (MyFS.KEY). The system provides strong security features, data integrity checks, and file-level encryption.

## Features

- **Volume-level password protection**: The entire volume is protected with a master password
- **File-level encryption**: Individual files can be encrypted with their own passwords
- **Machine binding**: Volumes can only be accessed from the machine that created them
- **Dynamic password challenges**: Additional security through dynamic challenges
- **Secure file deletion**: Options for recoverable or permanent deletion
- **File integrity checking**: Ensures files remain uncorrupted
- **Self-integrity verification**: The application can detect tampering attempts
- **Original path preservation**: Files maintain knowledge of their original locations

## Requirements

- Python 3.6+
- PyCryptodome library

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/myfs.git
cd myfs
```

2. Create a virtual environment and install dependencies:
```
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install pycryptodome
```

## Usage

### Command Line Interface

MyFS provides a command-line interface with the following commands:

#### Create a new volume

```
python myfs.py create
```

#### List files in the volume

```
python myfs.py list
python myfs.py list --all  # Include deleted files
```

#### Import a file

```
python myfs.py import /path/to/file
python myfs.py import /path/to/file --encrypt  # With encryption
```

#### Export a file

```
python myfs.py export <file_index> /path/to/save
python myfs.py export <file_index> /path/to/save --original  # To original path
```

#### Delete a file

```
python myfs.py delete <file_index>
python myfs.py delete <file_index> --permanent  # Permanent deletion
```

#### Recover a deleted file

```
python myfs.py recover <file_index>
```

#### Set/change file password

```
python myfs.py password <file_index>
```

#### Change volume password

```
python myfs.py change-password
```

#### Verify file integrity

```
python myfs.py verify <file_index>
```

#### Interactive mode

```
python myfs.py interactive
```

### Custom Paths

By default, MyFS uses "MyFS.DRI" and "MyFS.KEY" in the current directory. You can specify custom paths:

```
python myfs.py --volume /path/to/volume.dri --metadata /path/to/metadata.key <command>
```

## Security Features

### Machine Binding

MyFS volumes are bound to the machine where they were created. This prevents unauthorized access if the volume file is copied to another machine.

### Dynamic Password Challenges

In addition to the volume password, MyFS requires solving a simple dynamic challenge that changes each time, adding an extra layer of security.

### File-Level Encryption

Files can be individually encrypted with different passwords, providing compartmentalized security within the volume.

### Self-Integrity Verification

MyFS verifies its own integrity on startup to detect tampering or modification of the application code.

## System Architecture

MyFS follows a modular design with the following components:

- `myfs.py` - Main entry point and CLI interface
- `myfs_constants.py` - Constants and configuration
- `myfs_formatter.py` - Volume creation and formatting
- `myfs_hardware.py` - Machine identification
- `myfs_utils.py` - Utility functions for cryptography and data handling
- `myfs_security.py` - Security and authentication functionality
- `myfs_file_handler.py` - File operations (import, export, delete)
- `myfs_metadata.py` - Metadata management
- `myfs_connector.py` - Integration between components

## File Format

### MyFS.DRI (Volume File)

The volume file contains:
- File header with magic number, machine ID, and other metadata
- File table with entries for each file
- Data region containing the actual file contents

### MyFS.KEY (Metadata File)

The metadata file contains:
- File header with magic number and encryption parameters
- Encrypted metadata for each file, including:
  - Original filename
  - Original path
  - Password verification data
  - File checksums

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- PyCryptodome for cryptographic operations
- Inspired by secure filesystem designs and cryptographic best practices