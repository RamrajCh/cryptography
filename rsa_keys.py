import rsa
import os
import base64

def generate_rsa_keys(n_bits:int=2048) -> tuple:
    """
    Generate a pair of public and private keys for RSA encryption method.

    Args:
        n_bits (int, optional): 
            Key size in bits. Defaults to 2048.
    
    Returns:
        tuple: contains RSA public and private keys.
    """
    
    public_key, private_key = rsa.newkeys(nbits=n_bits)
    return (public_key, private_key)


def save_rsa_keys(pub_key:rsa.PublicKey, priv_key:rsa.PrivateKey, filepath:str) -> None:
    """
    Saves private key and public key in a given filepath.

    Args:
        pub_key (rsa.PublicKey): RSA public key
        priv_key (rsa.PrivateKey): RSA private key
        filepath (str): path to the file where the keys will be stored.
    """
    
    # Encode RSA keys in PEM format
    pub_key_pem = rsa.PublicKey.save_pkcs1(pub_key,format='PEM')
    priv_key_pem = rsa.PrivateKey.save_pkcs1(priv_key,format='PEM')
    
    # Save those PEM encoded keys to given filepath
    pub_key_file = os.path.join(filepath, "pubkey.pem")
    priv_key_file = os.path.join(filepath, "privkey.pem")
    
    with open(pub_key_file, 'wb') as f1:
        f1.write(pub_key_pem)
        
    with open(priv_key_file, 'wb') as f2:
        f2.write(priv_key_pem)
        

def generate_and_save_keys(n_bits:int=2048, filepath:str='.') -> None:
    """
    Generates RSA key-pairs and store them to given path

    Args:
        n_bits (int, optional): Key size in bits. Defaults to 2048.
        filepath (str, optional): path to the file where the keys will be stored. Defaults to '.'.
    """
    
    pub_key, priv_key = generate_rsa_keys(n_bits)
    save_rsa_keys(pub_key, priv_key, filepath)
    

if __name__ == "__main__":
    # Generate RSA key pairs for client and store them
    client_filepath = "client_keys"
    if not os.path.exists(client_filepath):
        os.makedirs(client_filepath)
    generate_and_save_keys(n_bits=2048, filepath=client_filepath)

    # Generate RSA key pairs for server and store them
    server_filepath = "server_keys"
    if not os.path.exists(server_filepath):
        os.makedirs(server_filepath)
    generate_and_save_keys(n_bits=2048, filepath=server_filepath)