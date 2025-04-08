# tests/test_crypto.py

from crypto.crypto_utils import (
    generate_rsa_keys,
    serialize_public_key,
    load_public_key,
    encrypt_key_rsa,
    decrypt_key_rsa,
    encrypt_message,
    decrypt_message
)
import os

# Génération des clés RSA pour Alice et Bob
alice_private, alice_public = generate_rsa_keys()
bob_private, bob_public = generate_rsa_keys()

# Alice veut envoyer un message à Bob
print("🧠 Alice génère une clé AES pour la session")
aes_key = os.urandom(32)  # 256-bit AES

# 🔐 Alice chiffre la clé AES avec la clé publique de Bob
print("🔐 Alice chiffre la clé AES avec la clé publique de Bob")
bob_pub_bytes = serialize_public_key(bob_public)
bob_pub_loaded = load_public_key(bob_pub_bytes)
encrypted_key = encrypt_key_rsa(aes_key, bob_pub_loaded)

# 🧩 Bob déchiffre la clé AES avec sa clé privée
print("🔓 Bob déchiffre la clé AES avec sa clé privée")
decrypted_key = decrypt_key_rsa(encrypted_key, bob_private)

assert aes_key == decrypted_key, "❌ Erreur : la clé AES ne correspond pas !"
print("✅ Clé AES reçue intacte par Bob")

# 💬 Alice chiffre un message avec cette clé AES
message = "Salut Bob, c’est Alice !"
print("📤 Alice envoie :", message)
ciphertext = encrypt_message(message, aes_key)

# 📥 Bob déchiffre le message
decrypted_message = decrypt_message(ciphertext, decrypted_key)
print("📬 Bob reçoit :", decrypted_message)

assert message == decrypted_message, "❌ Erreur de déchiffrement"
print("✅ Communication sécurisée réussie 🎉")
