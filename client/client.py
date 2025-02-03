import socket

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

    while True:
        print("\n------------ Menu ------------")
        print("Saisissez 'quit' pour quitter")
        msg = input("Entrez votre message : ")
        if msg.lower() == 'quit':
            break

        recipient = input("Destinataire du message : ")
        msg_formaté = f"{pseudo};{msg};{recipient}"
        client_socket.send(msg_formaté.encode())
        print("\nEnvoi du message...")

        reponse = client_socket.recv(1024).decode()
        print("---------------------------------")
        print(f"{reponse}")
        print("---------------------------------")
    
    client_socket.close()

if __name__ == "__main__":
    main()