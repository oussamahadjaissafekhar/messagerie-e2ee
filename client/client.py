# client/client.py

import socket
import os
from crypto.crypto_utils import (
    generate_rsa_keys,
    encrypt_message,
    decrypt_message,
)

HOST = '127.0.0.1'
PORT = 12345

def main():
    # Génération de clés (RSA et AES)
    priv, pub = generate_rsa_keys()
    aes_key = os.urandom(32)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"Connecté à {HOST}:{PORT}")

        while True:
            msg = input("→ Message à chiffrer : ")
            if msg.lower() == 'exit':
                break

            # Chiffrement AES
            ciphertext = encrypt_message(msg, aes_key)
            sock.sendall(ciphertext)

            # Réponse serveur (non chiffrée ici)
            response = sock.recv(1024)
            print("← Réponse brute :", response.decode())

if __name__ == "__main__":
    main()
