# "File Encryption and Decryption" Tool

## Overview

This Python program demonstrates a simple file encryption and decryption tool using symmetric key cryptography. The program performs the following tasks:

1. Generates a random symmetric key (`smem`) in memory.
2. Encrypts `smem` and saves it to disk as `smem.enc`.
3. Reads a target list of files to be encrypted from `target_list.txt`.
4. Encrypts each file in the target list using `smem`, appends a `.enc` extension to the filename, and deletes the original file.
5. Clears `smem` from memory.
6. Decrypts the target list of files using `smem`.

The program is designed to work on both Windows and Linux systems and uses the PyCryptoDome library for encryption and decryption.

## Usage

1. Install the required library:

`pip install pycryptodome`


2. Create a file named `target_list.txt` containing the list of files you want to encrypt.

3. Run the `encrypt_decrypt.py` script:

`python encrypt_decrypt.py`


**Note:** Make sure to adjust the file paths and target list according to your requirements.

## Disclaimer

This proof-of-concept code is provided for educational purposes only. Use this code responsibly and at your own risk. The author is not responsible for any misuse or illegal activities involving this code.

