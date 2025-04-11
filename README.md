# Secure End-to-End Encrypted Chat System

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A secure chat application featuring end-to-end encryption (E2EE) using RSA for key exchange and AES-256 for message encryption.

## Features

- 🔒 End-to-end encryption (E2EE)
- 🔑 RSA-4096 for secure key exchange
- 🚀 AES-256-GCM for message encryption
- 💻 Tkinter GUI for both client and server
- 🖥️ Multi-client support using epoll (Linux)
- 📝 Server-side logging

## Requirements

- Python 3.8+
- Required packages:
  ```bash
  pip install cryptography

## 🚀 Lancement

```bash
# 🖥️ Lancer le serveur
make server

# 👤 Lancer un client (tu peux ouvrir plusieurs terminaux)
make client
