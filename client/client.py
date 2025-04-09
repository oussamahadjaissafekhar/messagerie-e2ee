import socket
import json
import threading
import os
from tkinter import *
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto.crypto_utils import (
    generate_rsa_keys,
    encrypt_message,
    decrypt_message,
    encrypt_key_rsa,
    decrypt_key_rsa
)

HOST = '0.0.0.0'
PORT = 12345
BUFFER_SIZE = 4096

class ChatClient:
    def __init__(self):
        self.root = Tk()
        self.root.withdraw()
        
        self.name = self.get_username_or_ip()
        if not self.name:
            self.root.destroy()
            return
            
        self.root.deiconify()
        self.root.title(f"Chat Sécurisé - {self.name}")
        
        # Génération des clés
        self.private_key, self.public_key = generate_rsa_keys()
        self.aes_keys = {}  # {destinataire: clé AES}
        
        self.connected_users = []
        self.current_recipient = None
        self.client_socket = None
        
        self.setup_ui()
        self.connect_to_server()
    
    def get_username_or_ip(self):
        """Fenêtre de connexion pour obtenir le nom d'utilisateur"""
        login_window = Toplevel(self.root)
        login_window.title("Connexion")
        login_window.geometry("300x150")
        login_window.resizable(False, False)
        
        Label(login_window, text="Entrez votre nom d'utilisateur:").pack(pady=10)
        
        username_entry = Entry(login_window)
        username_entry.pack(pady=5, padx=20, fill=X)
        username_entry.focus_set()
        
        result = []
        
        def on_submit():
            name = username_entry.get().strip()
            if name:
                result.append(name)
                login_window.destroy()
        
        Button(login_window, text="Connexion", command=on_submit).pack(pady=10)
        username_entry.bind('<Return>', lambda e: on_submit())
        
        login_window.protocol("WM_DELETE_WINDOW", lambda: [result.append(None), login_window.destroy()])
        self.root.wait_window(login_window)
        
        return result[0] if result else None

    def get_public_key_pem(self):
        """Retourne la clé publique au format PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def setup_ui(self):
        """Configure l'interface graphique"""
        # Frame utilisateurs
        user_frame = Frame(self.root)
        user_frame.pack(side=LEFT, fill=Y, padx=5, pady=5)
        
        Label(user_frame, text="Utilisateurs", font=('Arial', 12, 'bold')).pack()
        
        self.user_list = Listbox(user_frame, width=20, height=15)
        self.user_list.pack(fill=Y, expand=True)
        self.user_list.bind('<<ListboxSelect>>', self.select_user)
        
        # Frame principale
        main_frame = Frame(self.root)
        main_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=5, pady=5)
        
        # Zone de chat
        Label(main_frame, text="Conversation", font=('Arial', 12, 'bold')).pack()
        
        self.chat_display = scrolledtext.ScrolledText(main_frame, state='disabled')
        self.chat_display.pack(fill=BOTH, expand=True)
        
        # Zone de message
        msg_frame = Frame(main_frame)
        msg_frame.pack(fill=X, pady=5)
        
        Label(msg_frame, text="Message:").pack(side=LEFT)
        
        self.msg_entry = Entry(msg_frame)
        self.msg_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        self.msg_entry.bind("<Return>", self.send_message)
        
        Button(msg_frame, text="Envoyer", command=self.send_message).pack(side=RIGHT)
        
        # Barre de statut
        self.status_bar = Label(self.root, text="Non connecté", bd=1, relief=SUNKEN, anchor=W)
        self.status_bar.pack(side=BOTTOM, fill=X)

    def select_user(self, event):
        """Sélectionne un utilisateur pour le chat"""
        selection = self.user_list.curselection()
        if selection:
            self.current_recipient = self.user_list.get(selection[0])
            self.update_status(f"Destinataire: {self.current_recipient}")
            
            # Initier l'échange de clés si nécessaire
            if self.current_recipient not in self.aes_keys:
                self.init_key_exchange(self.current_recipient)

    def init_key_exchange(self, recipient):
        """Nouvelle méthode pour gérer l'échange de clés"""
        if recipient not in self.aes_keys:
            self.aes_keys[recipient] = os.urandom(32)
            key_request = {
                "action": "get_pubkey",
                "target": recipient,
                "from": self.name  # Ajout de l'expéditeur
            }
            self.client_socket.send(json.dumps(key_request).encode())
            self.display_message(f"[Système] Échange de clés initié avec {recipient}")

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            
            register_data = {
                "action": "register",
                "name": self.name,
                "pubkey": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            self.client_socket.send(json.dumps(register_data).encode())
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Connexion échouée: {str(e)}")
            self.root.destroy()

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                msg = json.loads(data.decode())
                
                if msg.get("action") == "userlist":
                    self.update_user_list(msg.get("users", []))
                
                elif msg.get("action") == "pubkey":
                    sender = msg.get("from")
                    if not sender:
                        continue
                        
                    try:
                        pubkey = serialization.load_pem_public_key(
                            msg.get("pubkey").encode(),
                            backend=default_backend()
                        )
                        if sender in self.aes_keys:
                            encrypted_key = encrypt_key_rsa(self.aes_keys[sender], pubkey)
                            key_msg = {
                                "action": "send_key",
                                "to": sender,
                                "from": self.name,
                                "key": encrypted_key.hex()
                            }
                            self.client_socket.send(json.dumps(key_msg).encode())
                    except Exception as e:
                        self.display_message(f"[Erreur] Clé publique invalide: {str(e)}")
                
                elif msg.get("action") == "send_key":
                    sender = msg.get("from")
                    if sender and sender in self.aes_keys:
                        self.display_message(f"[Erreur] Clé AES déjà existante pour {sender}")
                        continue
                        
                    try:
                        self.aes_keys[sender] = decrypt_key_rsa(
                            bytes.fromhex(msg.get("key")), 
                            self.private_key
                        )
                        self.display_message(f"[Système] Clé sécurisée établie avec {sender}")
                    except Exception as e:
                        self.display_message(f"[Erreur] Clé AES invalide: {str(e)}")
                
                elif msg.get("action") == "message":
                    sender = msg.get("from")
                    if sender in self.aes_keys:
                        try:
                            decrypted = decrypt_message(
                                bytes.fromhex(msg.get("content")),
                                self.aes_keys[sender]
                            )
                            self.display_message(f"{sender}: {decrypted}")
                        except Exception as e:
                            self.display_message(f"[Erreur] Impossible de déchiffrer: {str(e)}")
                    else:
                        self.display_message(f"[Système] Message chiffré reçu (clé manquante)")

            except Exception as e:
                print(f"Erreur: {str(e)}")
                break

    def send_message(self, event=None):
        """Envoie un message chiffré"""
        message = self.msg_entry.get()
        if message and self.current_recipient:
            try:
                # Vérifier si on a une clé AES
                if self.current_recipient not in self.aes_keys:
                    messagebox.showwarning("Attention", "Échange de clés en cours...")
                    return
                
                # Chiffrer le message
                encrypted_msg = encrypt_message(message, self.aes_keys[self.current_recipient])
                
                # Envoyer le message chiffré
                msg_data = {
                    "action": "message",
                    "to": self.current_recipient,
                    "from": self.name,
                    "content": encrypted_msg.hex()  # Convertir en hex pour JSON
                }
                self.client_socket.send(json.dumps(msg_data).encode())
                
                # Afficher localement
                self.display_message(f"Vous à {self.current_recipient}: {message}")
                self.msg_entry.delete(0, END)
                
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec d'envoi: {str(e)}")

    def display_message(self, message):
        """Affiche un message dans le chat"""
        self.chat_display.config(state='normal')
        self.chat_display.insert(END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(END)

    def update_user_list(self, users):
        """Met à jour la liste des utilisateurs connectés"""
        self.user_list.delete(0, END)
        for user in users:
            if user != self.name:
                self.user_list.insert(END, user)

    def update_status(self, message):
        """Met à jour la barre de statut"""
        self.status_bar.config(text=message)
        self.status_bar.update_idletasks()

    def on_closing(self):
        """Ferme proprement l'application"""
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    app = ChatClient()
    app.root.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.root.mainloop()