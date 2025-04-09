import socket
import select
import json
import base64
from datetime import datetime

HOST = '0.0.0.0'
PORT = 12345
BUFFER_SIZE = 4096

clients = {}
clients_info = {}

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def broadcast_userlist():
    userlist = [info["name"] for info in clients_info.values()]
    message = json.dumps({
        "action": "userlist",
        "users": userlist
    }).encode()
    
    for fd in clients:
        try:
            clients[fd].sendall(message)
        except:
            continue

def handle_message(fd, msg_bytes):
    try:
        msg = json.loads(msg_bytes.decode())
        action = msg.get("action")
        sender_name = clients_info.get(fd, {}).get("name")

        if action == "register":
            name = msg.get("name")
            pubkey = msg.get("pubkey")
            if not name or not pubkey:
                return
                
            clients_info[fd] = {"name": name, "pubkey": pubkey}
            print(f"\n[{get_timestamp()}] [CONNEXION] {name} connecté")
            print(f"[PUBKEY] Clé publique (partielle): {pubkey[:50]}...")
            broadcast_userlist()

        elif action == "get_pubkey":
            target = msg.get("target")
            requester = sender_name
            if not target or not requester:
                return
                
            print(f"\n[{get_timestamp()}] [DEMANDE CLE] {requester} demande la clé publique de {target}")
            
            for target_fd, info in clients_info.items():
                if info["name"] == target:
                    response = {
                        "action": "pubkey",
                        "from": target,
                        "pubkey": info["pubkey"]
                    }
                    clients[fd].sendall(json.dumps(response).encode())
                    print(f"[ENVOI CLE] Clé publique de {target} envoyée à {requester}")
                    print(f"[DETAIL CLE] {info['pubkey'][:50]}...")
                    return

        elif action == "send_key":
            recipient = msg.get("to")
            sender = sender_name
            encrypted_key = msg.get("key", "")
            if not recipient or not sender:
                return
                
            print(f"\n[{get_timestamp()}] [ENVOI CLE AES] {sender} → {recipient}")
            print(f"[CLE CHIFFREE] (RSA) Taille: {len(encrypted_key)} caractères")
            print(f"[CONTENU] {encrypted_key[:50]}...")
            
            for target_fd, info in clients_info.items():
                if info["name"] == recipient:
                    msg["from"] = sender  
                    clients[target_fd].sendall(json.dumps(msg).encode())
                    print(f"[TRANSFERT REUSSI] Vers {recipient}")
                    return

        elif action == "message":
            recipient = msg.get("to")
            sender = sender_name
            encrypted_content = msg.get("content", "")
            if not recipient or not sender:
                return
                
            print(f"\n[{get_timestamp()}] [MESSAGE CHIFFRE] {sender} → {recipient}")
            print(f"[TAILLE] {len(encrypted_content)} caractères (base64)")
            print(f"[CONTENU CHIFFRE] {encrypted_content[:50]}...")
            print(f"[MODE] AES-256-CBC (IV inclus)")
            
            for target_fd, info in clients_info.items():
                if info["name"] == recipient:
                    msg["from"] = sender  
                    clients[target_fd].sendall(json.dumps(msg).encode())
                    print(f"[TRANSFERT REUSSI] Vers {recipient}")
                    return

    except json.JSONDecodeError:
        print(f"\n[{get_timestamp()}] [ERREUR] Message JSON invalide")
        print(f"[CONTENU BRUT] {msg_bytes[:100]}...")
    except Exception as e:
        print(f"\n[{get_timestamp()}] [ERREUR] {str(e)}")

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    server_sock.setblocking(False)

    print(f"\n🔐 Serveur de chat sécurisé démarré sur {HOST}:{PORT}")
    print("📝 Journalisation complète du trafic activée\n")

    epoll = select.epoll()
    epoll.register(server_sock.fileno(), select.EPOLLIN)

    try:
        while True:
            events = epoll.poll(1)
            for fileno, event in events:
                if fileno == server_sock.fileno():
                    client_sock, addr = server_sock.accept()
                    client_sock.setblocking(False)
                    fd = client_sock.fileno()
                    epoll.register(fd, select.EPOLLIN)
                    clients[fd] = client_sock
                    print(f"\n[{get_timestamp()}] [CONNEXION] Nouveau client depuis {addr}")

                elif event & select.EPOLLIN:
                    sock = clients[fileno]
                    try:
                        data = sock.recv(BUFFER_SIZE)
                        if data:
                            handle_message(fileno, data)
                        else:
                            raise ConnectionError()
                    except:
                        name = clients_info.get(fileno, {}).get("name", "inconnu")
                        print(f"\n[{get_timestamp()}] [DECONNEXION] {name} déconnecté")
                        epoll.unregister(fileno)
                        sock.close()
                        clients.pop(fileno, None)
                        clients_info.pop(fileno, None)
                        broadcast_userlist()

    finally:
        epoll.close()
        server_sock.close()
        print(f"\n[{get_timestamp()}] Serveur arrêté")

if __name__ == "__main__":
    main()