# "File Encryption and Decryption" Tool

## Overview

This Python script demonstrates a file encryption and decryption tool using asymmetric and symmetric cryptography. The program performs the following tasks:

### Encryption on the Victim:

1. **Symmetric Key Generation**: Generates or loads a symmetric key (`smem`).
2. **RSA Key Pair Generation**: Generates or loads an RSA public-private key pair.
3. **Symmetric Key Encryption**: Encrypts the symmetric key (`smem`) using the RSA public key and saves it as `smem-enc`.
4. **File Encryption**: Encrypts files in a specified directory using the symmetric key (`smem`), appends a `.encrypted` extension to the filename, and deletes the original file.

### Decryption on the Victim:

1. **Symmetric Key Decryption**: Reads the encrypted symmetric key (`smem-enc`), decrypts it using the RSA private key to obtain `smem`.
2. **File Decryption**: Decrypts encrypted files in the specified directory using `smem` and deletes the encrypted files.

**Note:** Make sure to adjust the file paths and target list according to your requirements.  Change the dir_path variable to the target directory where your files are located.

## Disclaimer

This proof-of-concept code is provided for educational purposes only. Use this code responsibly and at your own risk. The author is not responsible for any misuse or illegal activities involving this code.

