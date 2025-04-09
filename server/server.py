import socket
import select
import json
from tkinter import *
from tkinter import scrolledtext
import threading
from datetime import datetime

HOST = '0.0.0.0'
PORT = 12345
BUFFER_SIZE = 4096

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Serveur de Chat Sécurisé - Logs")
        
        # Configuration de la fenêtre
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Police fixe pour une meilleure lisibilité
        self.font = ('Courier New', 10)
        
        # Zone de logs
        self.log_frame = Frame(self.root)
        self.log_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        
        Label(self.log_frame, text="Journal d'activité du serveur", 
              font=('Arial', 12, 'bold')).pack()
        
        self.log_area = scrolledtext.ScrolledText(
            self.log_frame,
            wrap=WORD,
            width=80,
            height=25,
            font=self.font,
            bg='black',
            fg='white',
            insertbackground='white'
        )
        self.log_area.pack(fill=BOTH, expand=True)
        self.log_area.configure(state='disabled')
        
        # Boutons de contrôle
        control_frame = Frame(self.root)
        control_frame.pack(pady=5)
        
        Button(control_frame, text="Démarrer", command=self.start_server).pack(side=LEFT, padx=5)
        Button(control_frame, text="Arrêter", command=self.stop_server).pack(side=LEFT, padx=5)
        Button(control_frame, text="Effacer les logs", command=self.clear_logs).pack(side=LEFT, padx=5)
        
        # Variables serveur
        self.server_sock = None
        self.clients = {}
        self.clients_info = {}
        self.running = False
        self.epoll = None
        
    def log(self, message, message_type="info"):
        """Ajoute un message dans la zone de logs avec un style approprié"""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        
        # Couleurs selon le type de message
        colors = {
            "info": "white",
            "success": "green",
            "warning": "orange",
            "error": "red",
            "system": "cyan"
        }
        
        self.log_area.configure(state='normal')
        
        # Insertion avec la couleur appropriée
        self.log_area.insert(END, timestamp + " ", "timestamp")
        self.log_area.insert(END, message + "\n", message_type)
        
        self.log_area.configure(state='disabled')
        self.log_area.see(END)
        
        # Configuration des tags pour les couleurs
        self.log_area.tag_config("timestamp", foreground="gray")
        for msg_type, color in colors.items():
            self.log_area.tag_config(msg_type, foreground=color)
        
    def clear_logs(self):
        """Efface les logs"""
        self.log_area.configure(state='normal')
        self.log_area.delete(1.0, END)
        self.log_area.configure(state='disabled')
        
    def broadcast_userlist(self):
        """Diffuse la liste des utilisateurs connectés"""
        userlist = [info["name"] for info in self.clients_info.values()]
        message = json.dumps({
            "action": "userlist",
            "users": userlist
        }).encode()
        
        for fd in self.clients:
            try:
                self.clients[fd].sendall(message)
            except:
                continue

    def handle_message(self, fd, msg_bytes):
        """Gère les messages entrants"""
        try:
            msg = json.loads(msg_bytes.decode())
            action = msg.get("action")
            sender_name = self.clients_info.get(fd, {}).get("name")

            if action == "register":
                name = msg.get("name")
                pubkey = msg.get("pubkey")
                if not name or not pubkey:
                    return
                
                self.clients_info[fd] = {"name": name, "pubkey": pubkey}
                self.log(f"CONNEXION: {name} connecté", "system")
                self.log(f"CLÉ PUBLIQUE (extrait): {pubkey[:50]}...", "info")
                self.broadcast_userlist()

            elif action == "get_pubkey":
                target = msg.get("target")
                requester = sender_name
                if not target or not requester:
                    return
                
                self.log(f"DEMANDE CLÉ: {requester} demande la clé de {target}", "info")
                
                for target_fd, info in self.clients_info.items():
                    if info["name"] == target:
                        response = {
                            "action": "pubkey",
                            "from": target,
                            "pubkey": info["pubkey"]
                        }
                        self.clients[fd].sendall(json.dumps(response).encode())
                        self.log(f"ENVOI CLÉ: Clé de {target} envoyée à {requester}", "success")
                        return

            elif action == "send_key":
                recipient = msg.get("to")
                sender = sender_name
                encrypted_key = msg.get("key", "")
                if not recipient or not sender:
                    return
                
                self.log(f"CLÉ AES: {sender} -> {recipient}", "info")
                self.log(f"TAILLE: {len(encrypted_key)} caractères (chiffré RSA)", "info")
                self.log(f"CONTENU CHIFFRÉ:\n{encrypted_key[:100]}...", "info")
                
                for target_fd, info in self.clients_info.items():
                    if info["name"] == recipient:
                        msg["from"] = sender  
                        self.clients[target_fd].sendall(json.dumps(msg).encode())
                        self.log(f"TRANSFERT RÉUSSI: Clé AES envoyée à {recipient}", "success")
                        return

            elif action == "message":
                recipient = msg.get("to")
                sender = sender_name
                encrypted_content = msg.get("content", "")
                if not recipient or not sender:
                    return
                
                self.log(f"MESSAGE: {sender} -> {recipient}", "info")
                self.log(f"TAILLE: {len(encrypted_content)} caractères (chiffré AES)", "info")
                self.log(f"CONTENU CHIFFRÉ (base64):\n{encrypted_content[:100]}...", "info")
                
                for target_fd, info in self.clients_info.items():
                    if info["name"] == recipient:
                        msg["from"] = sender  
                        self.clients[target_fd].sendall(json.dumps(msg).encode())
                        self.log(f"TRANSFERT RÉUSSI: Message envoyé à {recipient}", "success")
                        return

        except json.JSONDecodeError:
            self.log("ERREUR: Message JSON invalide", "error")
            self.log(f"DONNÉES BRUTES:\n{msg_bytes[:100]}...", "warning")
        except Exception as e:
            self.log(f"ERREUR: {str(e)}", "error")

    def start_server(self):
        """Démarre le serveur"""
        if self.running:
            return
            
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((HOST, PORT))
            self.server_sock.listen(5)
            self.server_sock.setblocking(False)
            
            self.epoll = select.epoll()
            self.epoll.register(self.server_sock.fileno(), select.EPOLLIN)
            
            self.running = True
            threading.Thread(target=self.run_server, daemon=True).start()
            
            self.log("SERVEUR DÉMARRÉ sur {HOST}:{PORT}", "system")
            
        except Exception as e:
            self.log(f"ERREUR: Impossible de démarrer - {str(e)}", "error")
            self.running = False

    def run_server(self):
        """Boucle principale du serveur"""
        while self.running:
            try:
                events = self.epoll.poll(1)
                for fileno, event in events:
                    if fileno == self.server_sock.fileno():
                        client_sock, addr = self.server_sock.accept()
                        client_sock.setblocking(False)
                        fd = client_sock.fileno()
                        self.epoll.register(fd, select.EPOLLIN)
                        self.clients[fd] = client_sock
                        self.log(f"NOUVELLE CONNEXION: {addr[0]}:{addr[1]}", "system")

                    elif event & select.EPOLLIN:
                        sock = self.clients[fileno]
                        try:
                            data = sock.recv(BUFFER_SIZE)
                            if data:
                                self.handle_message(fileno, data)
                            else:
                                raise ConnectionError()
                        except:
                            name = self.clients_info.get(fileno, {}).get("name", "inconnu")
                            self.log(f"DÉCONNEXION: {name}", "system")
                            self.epoll.unregister(fileno)
                            sock.close()
                            self.clients.pop(fileno, None)
                            self.clients_info.pop(fileno, None)
                            self.broadcast_userlist()

            except Exception as e:
                self.log(f"ERREUR SERVEUR: {str(e)}", "error")

    def stop_server(self):
        """Arrête le serveur"""
        if not self.running:
            return
            
        self.running = False
        
        # Fermer toutes les connexions clients
        for fd, sock in self.clients.items():
            try:
                sock.close()
            except:
                pass
                
        if self.server_sock:
            self.server_sock.close()
            
        if self.epoll:
            self.epoll.close()
            
        self.clients.clear()
        self.clients_info.clear()
        
        self.log("SERVEUR ARRÊTÉ", "system")

    def on_closing(self):
        """Nettoyage à la fermeture"""
        self.stop_server()
        self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    app = ServerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()