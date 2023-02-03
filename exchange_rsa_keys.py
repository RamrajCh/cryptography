import rsa
import socket

def key_exchange_client(client_pubkey_file, server_host, server_port):
    """
    Send client's public key to server and receive public key of server.

    Args:
        client_pubkey_file (str): path to client's public key PEM file.
        server_host (str): Server hostname
        server_port (int): Port where server is bind to.

    Returns:
        server_pubkey (rsa.PublicKey): RSA public key of server
    """
    with open(client_pubkey_file, 'rb') as f:
        client_pubkey = f.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        print("Connected to server.")

        # Send client's public key
        s.send(client_pubkey)
        print("Client public key sent.")

        # Receive the server's public key
        server_pubkey = rsa.PublicKey.load_pkcs1(s.recv(2048))
        print("Server public key received.")
        
        return server_pubkey

def key_exchange_server(server_pubkey_file, server_port):
    """
    Receive client's public key from client and send public key of server.

    Args:
        server_pubkey_file (str): path to server's public key PEM file.
        server_host (str): Server hostname
        server_port (int): Port where server is bind to.

    Returns:
        server_pubkey (rsa.PublicKey): RSA public key of server
    """
    
    # Load server's public key
    with open(server_pubkey_file, 'rb') as f:
        server_pubkey = f.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', server_port))
        s.listen()
        print("Server is listening.")
        conn, addr = s.accept()
        with conn:
            # Receive client's public key
            client_pubkey = rsa.PublicKey.load_pkcs1(conn.recv(2048))
            print("Client public key received.")

            # Send the encrypted public key to the client
            conn.send(server_pubkey)
            print("Server public key sent.")
            
            return client_pubkey
