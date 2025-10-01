import socket
import threading
import re
import json
import base64
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

DEBUG_WIRE = True  # Cambia a False para apagarlo


class EchoServer:
    def __init__(self, name="Echo Server", host='127.0.0.1', port=65432, buffer=4096):
        self.name = name
        self.buffer = buffer
        self.host = host
        self.port = port

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"{self.name} started on {self.host}:{self.port}")

        self.clients = set()
        self.lock = threading.Lock()

        self.client_names = {}
        self.client_pubkeys = {}
        self.client_aes = {}
        self.fingerprints = {}

        self.bad_words = ["tonto", "idiota", "estupido", "Gonorrea", "Hijueputa", 
                          "Malparido", "Pirobo", "Marica", "Chimba", "Mierda", "Culo", 
                          "Carechimba", "Sapo hijueputa", "Mamón", "Güevón", "No joda", 
                          "Huevón", "Careverga", "Malnacido", "Perra", "Zorra", "Hueva", 
                          "Cabrón", "Ñero", "Caremonda", "Jueputa", "Bobo hijueputa", "Pendejo",
                          "Maldito", "Carechimba hp", "Chanda", "Tragahuevos", "Careculo"]
        self.bad_pattern = re.compile(r'(?i)\b(' + '|'.join(map(re.escape, self.bad_words)) + r')\b')

    def _mask(self, m):
        return '*' * len(m.group(0))

    def _recv_once(self, conn):
        return conn.recv(self.buffer)

    def handle_client(self, conn, addr):
        print(f"*** Nuevo cliente: {addr}")

        try:
            hello_raw = self._recv_once(conn)
            if not hello_raw:
                conn.close(); return
            hello = json.loads(hello_raw.decode('utf-8', errors='ignore'))

            name = (hello.get("name") or "").strip()
            ed_pub_b64 = hello.get("public_key")
            kx_pub_b64 = hello.get("kx_pub")

            ed_pub_bytes = base64.b64decode(ed_pub_b64)
            ed_pub = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)

            cli_kx_pub = X25519PublicKey.from_public_bytes(base64.b64decode(kx_pub_b64))
            srv_x_priv = X25519PrivateKey.generate()
            srv_x_pub = srv_x_priv.public_key()
            shared_secret = srv_x_priv.exchange(cli_kx_pub)

            aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"eco-chat-aesgcm").derive(shared_secret)
            aesgcm = AESGCM(aes_key)

            reply = {"kx_pub": base64.b64encode(
                srv_x_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode()}
            conn.sendall(json.dumps(reply).encode('utf-8'))

            fp = hashlib.sha256(ed_pub_bytes).hexdigest()[:8]

            with self.lock:
                self.clients.add(conn)
                self.client_names[conn] = name
                self.client_pubkeys[conn] = ed_pub
                self.client_aes[conn] = aesgcm
                self.fingerprints[conn] = fp

            print(f"*** {name} (ed25519:{fp}) se unió desde {addr}")

        except Exception as e:
            print(f"Error en handshake {addr}: {e}")
            conn.close(); return

        try:
            while True:
                data = self._recv_once(conn)
                if not data:
                    break

                if DEBUG_WIRE:
                    try:
                        print("[wire recv]", json.loads(data.decode('utf-8')))
                    except:
                        print("[wire recv raw]", data[:80])

                try:
                    packet = json.loads(data.decode('utf-8'))
                    nonce = base64.b64decode(packet["nonce"])
                    ct = base64.b64decode(packet["ct"])
                    aesgcm = self.client_aes[conn]
                    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
                except Exception as e:
                    print(f"[WARN] Descifrado falló: {e}")
                    continue

                try:
                    payload = json.loads(pt.decode('utf-8'))
                    msg = payload["msg"]
                    sig = base64.b64decode(payload["sig"])
                    self.client_pubkeys[conn].verify(sig, msg.encode('utf-8'))
                except (InvalidSignature, Exception):
                    print(f"[WARN] Firma inválida de {self.client_names.get(conn)}")
                    continue

                clean = self.bad_pattern.sub(self._mask, msg)
                out = f"[{self.client_names.get(conn)} ✓ {self.fingerprints.get(conn)}] {clean}"
                print(out)

                with self.lock:
                    for c in list(self.clients):
                        if c is conn:
                            continue
                        try:
                            aes = self.client_aes[c]
                            nonce2 = os.urandom(12)
                            ct2 = aes.encrypt(nonce2, out.encode('utf-8'), associated_data=None)
                            pkt2 = {
                                "nonce": base64.b64encode(nonce2).decode(),
                                "ct": base64.b64encode(ct2).decode()
                            }
                            if DEBUG_WIRE:
                                print("[wire send] to", self.client_names.get(c), ":", pkt2)
                            c.sendall(json.dumps(pkt2).encode('utf-8'))
                        except Exception:
                            pass
        finally:
            with self.lock:
                self.clients.discard(conn)
                self.client_names.pop(conn, None)
                self.client_pubkeys.pop(conn, None)
                self.client_aes.pop(conn, None)
                self.fingerprints.pop(conn, None)
            conn.close()
            print(f"*** Cliente salió {addr}")
            
    def start(self):
        print("Esperando conexiones...")
        try:
            while True:
                conn, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        try:
            self.server_socket.close()
        finally:
            with self.lock:
                for c in list(self.clients):
                    try:
                        c.close()
                    except:
                        pass
                self.clients.clear()
                self.client_names.clear()
                self.client_pubkeys.clear()
                self.client_aes.clear()
                self.fingerprints.clear()
            print("Server stopped.")



if __name__ == "__main__":
    EchoServer().start()
