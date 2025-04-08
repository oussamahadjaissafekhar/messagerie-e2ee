# server/server.py

import socket
import select
import json

HOST = '0.0.0.0'
PORT = 12345
BUFFER_SIZE = 4096

clients = {}           # fd → socket
clients_info = {}      # fd → {'name': ..., 'pubkey': ...}

def handle_message(fd, msg_bytes):
    try:
        msg = json.loads(msg_bytes.decode())
        action = msg.get("action")

        if action == "register":
            name = msg.get("name")
            pubkey = msg.get("pubkey")
            clients_info[fd] = {"name": name, "pubkey": pubkey}
            print(f"🟢 Nouveau client : {name}")

        elif action == "get_pubkey":
            target = msg.get("target")
            for info in clients_info.values():
                if info["name"] == target:
                    response = json.dumps({
                        "action": "pubkey",
                        "target": target,
                        "pubkey": info["pubkey"]
                    }).encode()
                    clients[fd].sendall(response)
                    return
            clients[fd].sendall(b'{"error": "Client not found"}')

        elif action == "message":
            to = msg.get("to")
            for target_fd, info in clients_info.items():
                if info["name"] == to:
                    clients[target_fd].sendall(msg_bytes)
                    return
            clients[fd].sendall(b'{"error": "Recipient not found"}')

    except Exception as e:
        print(f"Erreur de parsing JSON: {e}")

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    server_sock.bind((HOST, PORT))
    server_sock.listen()

    print(f"🔐 Serveur E2EE en écoute sur {HOST}:{PORT}")

    epoll = select.epoll()
    epoll.register(server_sock.fileno(), select.EPOLLIN)

    try:
        while True:
            events = epoll.poll(1)
            for fileno, event in events:
                if fileno == server_sock.fileno():
                    client_sock, _ = server_sock.accept()
                    client_sock.setblocking(False)
                    epoll.register(client_sock.fileno(), select.EPOLLIN)
                    clients[client_sock.fileno()] = client_sock
                    print("📥 Nouvelle connexion")

                elif event & select.EPOLLIN:
                    sock = clients[fileno]
                    data = sock.recv(BUFFER_SIZE)
                    if data:
                        handle_message(fileno, data)
                    else:
                        print("❌ Client déconnecté")
                        epoll.unregister(fileno)
                        sock.close()
                        clients.pop(fileno, None)
                        clients_info.pop(fileno, None)

    finally:
        epoll.close()
        server_sock.close()

if __name__ == "__main__":
    main()
