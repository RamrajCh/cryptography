from Crypto.Cipher import AES
import os
 
def pad(data):
    """Add padding to the data if its length is not a multiple of 16 bytes."""
    padding_len = 16 - (len(data) % 16)
    return data + (chr(padding_len) * padding_len).encode()

def encrypt(key, data):
    """Encrypt the data using AES-128 in CBC mode with a random IV."""
    data = pad(data)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)

def unpad(data):
    """Remove padding from the data."""
    padding_len = data[-1]
    return data[:-padding_len]

def decrypt(key, data):
    """Decrypt the data using AES-128 in CBC mode."""
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data[AES.block_size:])
    return unpad(data)
