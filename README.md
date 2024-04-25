# "File Encryption and Decryption" Tool

## Overview

This Python script demonstrates a ransomware-like behavior by encrypting and decrypting files in a specified directory using AES-CTR encryption and RSA asymmetric key encryption.

## Requirements

- Python 3.x
- `cryptography` library

## Installation

### Python

Download and install Python from [python.org](https://www.python.org/downloads/).

### `cryptography` library

Install the `cryptography` library using pip:

```bash
pip install cryptography
```

## Configuration

The script uses a configuration dictionary to define settings for the encryption and decryption process. Here are the configuration options:

```python
CONFIG = {
    'smem_file': 'smem_unencrypted.txt',
    'private_key_file': 'private_key.pem',
    'public_key_file': 'public_key.pem',
    'encrypted_file_extension': '.encrypted',
    'target_directory': r'C:\Users\torfo\Desktop\test',
    'delete_files_after_encryption': True,
    'perform_smem_decryption': True 
}
```

- `smem_file`: File to store the unencrypted symmetric key.
- `private_key_file` & `public_key_file`: Files to store RSA private and public keys.
- `encrypted_file_extension`: Extension to append to encrypted files.
- `target_directory`: Directory containing the files to encrypt/decrypt.
- `delete_files_after_encryption`: Whether to delete the original files after encryption.
- `perform_smem_decryption`: Whether to perform symmetric key decryption after encryption.

## Usage

Run the script:

```bash
python ransomware.py
```

The script will perform the following steps:

1. Load or generate RSA key pair.
2. Generate or decrypt the symmetric key and save it to `smem-enc`.
3. Encrypt all `.txt` files in the `target_directory`.
4. Optionally, decrypt the encrypted files back to plaintext.
te:** Make sure to adjust the file paths and target list according to your requirements.  Change the dir_path variable to the target directory where your files are located.

## Disclaimer

This proof-of-concept code is provided for educational purposes only. Use this code responsibly and at your own risk. The author is not responsible for any misuse or illegal activities involving this code.

