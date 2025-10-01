import socket
import threading
import json
import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEBUG_WIRE = True  # Cambia a False cuando no quieras ver los paquetes


class EchoClient:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()

        self._x_priv = X25519PrivateKey.generate()
        self._x_pub = self._x_priv.public_key()
        self._aesgcm = None

    def _pub_b64(self):
        pub_bytes = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pub_bytes).decode()

    def _x_pub_b64(self):
        pub_bytes = self._x_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pub_bytes).decode()

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                if DEBUG_WIRE:
                    print("[wire←server raw]", data.decode('utf-8', errors='ignore'))

                packet = json.loads(data.decode('utf-8'))
                nonce = base64.b64decode(packet["nonce"])
                ct = base64.b64decode(packet["ct"])
                pt = self._aesgcm.decrypt(nonce, ct, associated_data=None)

                print("\n" + pt.decode('utf-8', errors='ignore'))
                print("Enter message to send (or 'exit' to quit): ", end="", flush=True)
            except:
                break

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            name = input("Choose your name: ").strip() or "anon"
            hello = {
                "name": name,
                "algo": "ed25519",
                "public_key": self._pub_b64(),
                "kx_pub": self._x_pub_b64()
            }
            self.client_socket.sendall(json.dumps(hello).encode('utf-8'))

            srv_reply = self.client_socket.recv(4096)
            reply = json.loads(srv_reply.decode('utf-8'))
            srv_kx_pub = base64.b64decode(reply["kx_pub"])
            peer = X25519PublicKey.from_public_bytes(srv_kx_pub)

            shared_secret = self._x_priv.exchange(peer)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"eco-chat-aesgcm"
            ).derive(shared_secret)
            self._aesgcm = AESGCM(aes_key)

            threading.Thread(target=self.receive_messages, daemon=True).start()

            while True:
                msg = input("Enter message to send (or 'exit' to quit): ")
                if msg.lower() == 'exit':
                    break

                sig = self._priv.sign(msg.encode('utf-8'))
                payload = {"msg": msg, "sig": base64.b64encode(sig).decode()}
                pt = json.dumps(payload).encode('utf-8')

                nonce = os.urandom(12)
                ct = self._aesgcm.encrypt(nonce, pt, associated_data=None)

                packet = {"nonce": base64.b64encode(nonce).decode(),
                          "ct": base64.b64encode(ct).decode()}
                if DEBUG_WIRE:
                    print("[wire→server]", packet)
                self.client_socket.sendall(json.dumps(packet).encode('utf-8'))

        except ConnectionRefusedError:
            print("Unable to connect to the server. Make sure it's running.")
        finally:
            self.stop()

    def stop(self):
        self.client_socket.close()
        print("Connection closed.")


if __name__ == "__main__":
    EchoClient().start()
