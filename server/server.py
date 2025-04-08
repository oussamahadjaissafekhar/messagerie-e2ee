# server/server.py

import socket
import select

HOST = '0.0.0.0'
PORT = 12345
BUFFER_SIZE = 4096

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    server_sock.bind((HOST, PORT))
    server_sock.listen()

    print(f"Serveur lancé sur {HOST}:{PORT}")

    epoll = select.epoll()
    epoll.register(server_sock.fileno(), select.EPOLLIN)
    clients = {}

    try:
        while True:
            events = epoll.poll(1)
            for fileno, event in events:
                if fileno == server_sock.fileno():
                    client_sock, addr = server_sock.accept()
                    client_sock.setblocking(False)
                    epoll.register(client_sock.fileno(), select.EPOLLIN)
                    clients[client_sock.fileno()] = client_sock
                    print(f"Connexion : {addr}")
                elif event & select.EPOLLIN:
                    sock = clients[fileno]
                    data = sock.recv(BUFFER_SIZE)
                    if data:
                        print(f"Message chiffré reçu : {data.hex()[:60]}...")  # Affiche un bout
                        sock.sendall(b"Server a recu votre message chiffre.")
                    else:
                        epoll.unregister(fileno)
                        sock.close()
                        del clients[fileno]
    finally:
        epoll.unregister(server_sock.fileno())
        epoll.close()
        server_sock.close()

if __name__ == "__main__":
    main()
