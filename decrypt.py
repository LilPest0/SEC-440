import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pickle

# Decrypt symmetric key using RSA private key
def decrypt_symmetric_key(encrypted_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(encrypted_key)
    return symmetric_key

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

# Decrypt smem.enc with private key
with open('private_key.pem', 'rb') as f:
    private_key = f.read()

with open('smem.enc', 'rb') as f:
    encrypted_smem = f.read()

smem = decrypt_symmetric_key(encrypted_smem, private_key)

# Read target list from a file
with open('target_list.txt', 'r') as f:
    target_list = f.readlines()

# Decrypt files in target list
for target_file in target_list:
    target_file = target_file.strip()  # Remove newline character
    encrypted_file = target_file + '.enc'
    if os.path.isfile(encrypted_file):
        decrypt_file(smem, encrypted_file)

print('Decryption completed.')

