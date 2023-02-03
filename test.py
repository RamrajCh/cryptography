import unittest
import rsa
import os
from Crypto.Cipher import AES

from rsa_keys import generate_rsa_keys, save_rsa_keys
from aes_encrypt_decrypt import pad, unpad, encrypt as aes_encrypt, decrypt as aes_decrypt

class TestRsaKeysMethods(unittest.TestCase):
    
    def test_generate_rsa_keys(self):
        # Test for default key size
        public_key, private_key = generate_rsa_keys()
        self.assertEqual(public_key.n.bit_length(), 2048)
        self.assertEqual(private_key.n.bit_length(), 2048)
        
        # Test for key size = 1024
        public_key, private_key = generate_rsa_keys(1024)
        self.assertEqual(public_key.n.bit_length(), 1024)
        self.assertEqual(private_key.n.bit_length(), 1024)
        
        # Test for the type of keys returned
        public_key, private_key = generate_rsa_keys()
        self.assertIsInstance(public_key, rsa.PublicKey)
        self.assertIsInstance(private_key, rsa.PrivateKey)
        
    
    def test_save_rsa_keys(self):
        # generate RSA keys
        pub_key, priv_key = generate_rsa_keys()
        
        # save the keys
        filepath = 'keys'
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        save_rsa_keys(pub_key, priv_key, filepath)
        
        # load saved keys
        pub_key_file = os.path.join(filepath, "pubkey.pem")
        priv_key_file = os.path.join(filepath, "privkey.pem")
        
        with open(pub_key_file, 'rb') as f:
            loaded_pub_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(priv_key_file, 'rb') as f:
            loaded_priv_key = rsa.PrivateKey.load_pkcs1(f.read())
        
        # check if the keys are the same
        self.assertEqual(pub_key, loaded_pub_key)
        self.assertEqual(priv_key, loaded_priv_key)
        
        # remove the saved files
        os.remove(pub_key_file)
        os.remove(priv_key_file)
        os.rmdir(filepath)
        

class AESEncryptionTestCase(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(16)  # random AES-128 key
        
    def test_pad(self):
        data = b'Test data'
        padded_data = pad(data)
        self.assertEqual(len(padded_data) % 16, 0)
        
    def test_encrypt_decrypt(self):
        data = b'Test data'
        encrypted_data = aes_encrypt(self.key, data)
        decrypted_data = aes_decrypt(self.key, encrypted_data)
        self.assertEqual(data, decrypted_data)
    
    def test_file_encryption_decryption(self):
        # Encrypt the contents of the file
        with open("test_long_msg.txt", "rb") as f:
            data = f.read()
        encrypted_data = aes_encrypt(self.key, data)

        # Decrypt the encrypted data
        decrypted_data = aes_decrypt(self.key, encrypted_data)

        # Check if the decrypted data is equal to the original data
        self.assertEqual(decrypted_data, data)
        
    def test_unpad(self):
        data = b'Test data\x04\x04\x04\x04'
        unpadded_data = unpad(data)
        self.assertEqual(unpadded_data, b'Test data')
        
if __name__ == "__main__":
    unittest.main()