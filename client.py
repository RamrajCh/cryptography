import socket
import rsa

from exchange_rsa_keys import key_exchange_client

def client(privkey):
    host = socket.gethostname()
    port = 9990

    server_pubkey = key_exchange_client(
        client_privkey_file="client_keys/privkey.pem", 
        client_pubkey_file="client_keys/pubkey.pem",
        server_host=host, 
        server_port=16452
    )
    
    client_socket = socket.socket()
    client_socket.connect((host, port))
    

    message = input(" -> ")

    while message.lower().strip() != 'bye':
        msg = rsa.encrypt(message.encode(), server_pubkey)
        client_socket.send(msg)
        
        data_decrypt = client_socket.recv(1024)
        data = rsa.decrypt(data_decrypt, privkey).decode()
        
        print('Received from server: ' + data)

        message = input(" -> ")

    client_socket.close()


if __name__ == '__main__':
    with open("client_keys/privkey.pem", 'rb') as f:
        client_privkey = rsa.PrivateKey.load_pkcs1(f.read())
    
    client(client_privkey)
    
    