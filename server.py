import socket
import rsa

from exchange_rsa_keys import key_exchange_server

def server(privkey):
    host = socket.gethostname()
    port = 9990

    server_socket = socket.socket()
    server_socket.bind((host, port))
    
    client_pubkey = key_exchange_server(
        server_pubkey_file="server_keys/pubkey.pem", 
        server_port=16452
    )
    
    server_socket.listen(2)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))
    while True:
        data_decrypt = conn.recv(1024)
        data = rsa.decrypt(data_decrypt, privkey).decode()
        
        if not data:
            break
        print("from connected user: " + str(data))
        data = input(' -> ')
        msg = rsa.encrypt(data.encode(), client_pubkey)
        conn.send(msg)

    conn.close()

if __name__ == '__main__':
    with open("server_keys/privkey.pem", 'rb') as f:
        server_privkey = rsa.PrivateKey.load_pkcs1(f.read())
    
    server(server_privkey)