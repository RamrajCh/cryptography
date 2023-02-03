import socket
import rsa

from exchange_rsa_keys import key_exchange_server
from aes_encrypt_decrypt import encrypt as aes_encrypt, decrypt as aes_decrypt

def server(privkey):
    host = socket.gethostname()
    port = 9297

    server_socket = socket.socket()
    server_socket.bind((host, port))
    
    # exchange RSA public key with server
    client_pubkey = key_exchange_server(
        server_pubkey_file="server_keys/pubkey.pem", 
        server_port=9960
    )
    
    server_socket.listen(2)
    conn, address = server_socket.accept()
    
    # Receive encrypted aes key from client and decrypt it
    encrypted_aes_key = conn.recv(1024)
    aes_key = rsa.decrypt(encrypted_aes_key, privkey)
    print(aes_key)
    
    # Acknowledge client of receiving AES key
    conn.send(rsa.encrypt("AES key received.".encode(), client_pubkey))
    
    while True:
        data_decrypt = conn.recv(1024)
        data = aes_decrypt(aes_key, data_decrypt).decode()
        
        if not data:
            break
        print("from connected user: " + str(data))
        data = input(' -> ')
        msg = aes_encrypt(aes_key, bytes(data, 'utf-8'))
        conn.send(msg)

    conn.close()

if __name__ == '__main__':
    with open("server_keys/privkey.pem", 'rb') as f:
        server_privkey = rsa.PrivateKey.load_pkcs1(f.read())
    
    server(server_privkey)