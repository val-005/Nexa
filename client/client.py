import socket
import threading

def receive_message(client_socket: socket.socket) -> None:
    while True:
        reponse = client_socket.recv(1024).decode()
        print(f"{reponse.split(';')[0]}: {reponse.split(';')[1]}")

def main():
    host = "127.0.0.1"  # Adresse du serveur
    port = 8000         # Port du serveur

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
    except socket.error as e:
        print(f"Erreur de connexion au serveur: {e}")
        return

    pseudo = input("Entrez votre pseudo : ")
    registration_msg = f"register;client;{pseudo}"
    client_socket.send(registration_msg.encode())
    print("Connecté au serveur !")
    print("===========================================\n")

    t = threading.Thread(target=receive_message, args=(client_socket,))
    t.start()

    while True:
        msg = input("")
        if msg.lower() == 'quit':
            break

        recipient = input("Destinataire du message : ")
        msg_formaté = f"{pseudo};{msg};{recipient}"
        client_socket.send(msg_formaté.encode())
    
    client_socket.close()

if __name__ == "__main__":
    main()