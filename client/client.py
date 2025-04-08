# client/client.py

import socket
import base64
import json
import os
from crypto.crypto_utils import (
    generate_rsa_keys,
    encrypt_message,
    decrypt_message,
    rsa_encrypt,
    rsa_decrypt
)

HOST = '127.0.0.1'
PORT = 12345
BUFFER_SIZE = 4096

def send_json(sock, data):
    msg = json.dumps(data).encode()
    sock.sendall(msg)

def recv_json(sock):
    data = sock.recv(BUFFER_SIZE)
    return json.loads(data.decode())

def main():
    name = input("Quel est ton nom d'utilisateur ? ")

    # Génération de la paire RSA
    priv_key, pub_key = generate_rsa_keys()
    pub_key_str = base64.b64encode(pub_key.save_pkcs1()).decode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"✅ Connecté au serveur sur {HOST}:{PORT}")

    # Envoi de la clé publique
    send_json(sock, {
        "action": "register",
        "name": name,
        "pubkey": pub_key_str
    })

    # Dictionnaire de clés publiques reçues
    known_pubkeys = {}

    while True:
        print("\n📨 Menu :")
        print(" 1. Envoyer un message")
        print(" 2. Récupérer la clé publique d’un client")
        print(" 3. Attendre un message")
        print(" 0. Quitter")
        choice = input("Choix : ")

        if choice == "0":
            break

        elif choice == "1":
            to = input("À qui veux-tu écrire ? ")
            if to not in known_pubkeys:
                print("❗ Clé publique inconnue. Utilise l'option 2 d'abord.")
                continue

            plaintext = input("Message : ")
            aes_key = os.urandom(32)

            encrypted_msg = encrypt_message(plaintext, aes_key)
            encrypted_key = rsa_encrypt(aes_key, known_pubkeys[to])
            
            send_json(sock, {
                "action": "message",
                "to": to,
                "from": name,
                "aes_key": base64.b64encode(encrypted_key).decode(),
                "msg": base64.b64encode(encrypted_msg).decode()
            })

        elif choice == "2":
            target = input("Nom du client : ")
            send_json(sock, {
                "action": "get_pubkey",
                "target": target
            })
            response = recv_json(sock)
            if "pubkey" in response:
                key_data = base64.b64decode(response["pubkey"])
                from Crypto.PublicKey import RSA
                rsa_key = RSA.import_key(key_data)
                known_pubkeys[target] = rsa_key
                print(f"🔑 Clé publique de {target} enregistrée.")
            else:
                print("❌ Client introuvable.")

        elif choice == "3":
            print("⏳ En attente d’un message...")
            msg_data = recv_json(sock)
            sender = msg_data["from"]
            encrypted_key = base64.b64decode(msg_data["aes_key"])
            encrypted_msg = base64.b64decode(msg_data["msg"])

            aes_key = rsa_decrypt(encrypted_key, priv_key)
            plaintext = decrypt_message(encrypted_msg, aes_key)

            print(f"\n💬 Nouveau message de {sender} : {plaintext}")

    sock.close()

if __name__ == "__main__":
    main()
