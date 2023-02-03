import socket
import rsa
import os

from exchange_rsa_keys import key_exchange_client
from aes_encrypt_decrypt import encrypt as aes_encrypt, decrypt as aes_decrypt

def client(privkey):
    host = socket.gethostname()
    port = 9297

    # exchange RSA public key with server
    server_pubkey = key_exchange_client( 
        client_pubkey_file="client_keys/pubkey.pem",
        server_host=host, 
        server_port=9960
    )
    
    client_socket = socket.socket()
    client_socket.connect((host, port))
    
    # send AES key encrypted by RSA public key of server
    aes_key = os.urandom(16)
    print(aes_key)
    encrypted_aes_key = rsa.encrypt(aes_key, server_pubkey)
    client_socket.send(encrypted_aes_key)
    
    # receive acknowledgement from server
    ack = client_socket.recv(1024)
    print(rsa.decrypt(ack, privkey).decode())

    message = input(" -> ")

    while message.lower().strip() != 'bye':
        # encrypt message by aes and send
        msg = aes_encrypt(aes_key, bytes(message, 'utf-8'))
        client_socket.send(msg)
        
        # receive message and decrypt with aes key
        data_decrypt = client_socket.recv(1024)
        data = aes_decrypt(aes_key, data_decrypt).decode()

        print('Received from server: ' + data)

        message = input(" -> ")

    client_socket.close()


if __name__ == '__main__':
    with open("client_keys/privkey.pem", 'rb') as f:
        client_privkey = rsa.PrivateKey.load_pkcs1(f.read())
    
    client(client_privkey)
    
    