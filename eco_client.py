import socket
import threading

class EchoClient:
    def __init__(self, host='127.0.0.1', port=65432):
        """
        Initializes the EchoClient.
        :param host: The server IP address to connect to.
        :param port: The server port number.
        """
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def receive_messages(self):
        """
        Runs in a separate thread to constantly listen for incoming messages.
        """
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                print("\n[Server] " + data.decode())
                print("Enter message to send (or 'exit' to quit): ", end="", flush=True)
            except:
                break

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # Pedir nombre de usuario
            name = input("Choose your name: ")
            self.client_socket.sendall(name.encode())  # enviar nombre al servidor

            # Hilo de escucha
            threading.Thread(target=self.receive_messages, daemon=True).start()

            while True:
                message = input("Enter message to send (or 'exit' to quit): ")
                if message.lower() == 'exit':
                    break
                self.client_socket.sendall(message.encode())
        except ConnectionRefusedError:
            print("Unable to connect to the server. Make sure it's running.")
        finally:
            self.stop()


    def stop(self):
        """
        Closes the client socket.
        """
        self.client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    client = EchoClient()
    client.start()

