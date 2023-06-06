import os
import subprocess
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
from random import SystemRandom

class VoidCrypt:
    
    def __init__(self):
        pass
    
    def load_entropy(self):
        source = os.urandom(256)
        for i in range(3):
          source += os.urandom(2 ** (21 + i))
        return source
        
    def generate_keys(self, source):
        keys = []
        for i in range(9):
            key_length = SystemRandom().randint(128, 256)
            random_bytes = [SystemRandom().choice(source) for _ in range(key_length) for _ in range(SystemRandom().randint(128, 256))]
            random_string = ''.join(str(byte) for byte in random_bytes)
            sha256_hash = hashlib.sha256()
            sha256_hash.update(random_string.encode())
            key = sha256_hash.digest()
            keys.append(key)
        return keys
    
    def shred_file(self, file_path):
        """shreds and removes the file after execution.

        Args:
            file_path: The path to the file to be shred.
        """
        subprocess.call(f'shred -zu -n 10 {file_path}', shell = True)
        
    def encrypt(self, filepath, key, iv, shred=False):
        """
        Encrypts a file using the AES encryption algorithm with the provided key and initialization vector (IV).

        Args:
            filepath: The path to the file to be encrypted.
            key: The encryption key, which can be generated using 'generate_keys(load_entropy())'
            iv: The initialization vector (IV), which can be generated using 'Random.new().read(16)'
            shred: If set to True, shreds the file after encryption. Defaults to False.
        """
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(filepath, 'rb') as infile:
            with open(filepath + '.enc', 'wb') as outfile:
                while True:
                    chunk = infile.read(65536)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - (len(chunk) % 16))
                    outfile.write(encryptor.encrypt(chunk))
        if shred:
            self.shred_file(filepath)

    def decrypt(self, filepath, key, iv, shred=False):
        """
        Decrypts a file that was encrypted using the AES encryption algorithm with the provided key and initialization vector (IV).

        Args:
            filepath: The path to the file to be encrypted.
            key: The decryption key
            iv: The initialization vector
            shred: If set to True, shreds the file after decryption. Defaults to False.
        """
        with open(filepath, 'rb') as infile:
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            with open(filepath[:-4], 'wb') as outfile:
                while True:
                    chunk = infile.read(65536)
                    if len(chunk) == 0:
                        break
                    decrypted_chunk = decryptor.decrypt(chunk)
                    outfile.write(decrypted_chunk)
        if shred:
            self.shred_file(filepath)
