import socket
import threading
import re  #busca reemplazar palabras por * , ignora mayusculas y evalua en forma de or 


class EchoServer:
    def __init__(self, name="Echo Server", host='127.0.0.1', port=65432, buffer=1024):
        self.name = name
        self.buffer = buffer
        self.host = host
        self.port = port
        self.client_names = {}  # en __init__

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"{self.name} started on {self.host}:{self.port}")

        # Estructuras para multicliente
        self.clients = set()            # sockets de clientes
        self.lock = threading.Lock()    # sincronizar acceso a self.clients
        
        #Aqui voy a implementar lo del bloqueo de palabras ofensivas 
        self.bad_words = ["tonto", "idiota", "estúpido"]  # aquí agregas las que quieras
        self.bad_pattern = re.compile(
            r'(?i)\b(' + '|'.join(map(re.escape, self.bad_words)) + r')\b'
        )

        def _mask(match):
            return '*' * len(match.group(0))
        self.mask_func = _mask

        
        

    def broadcast(self, data, sender_sock):
        """Envía 'data' a todos menos al emisor."""
        with self.lock:
            muertos = []
            for c in self.clients:
                if c is sender_sock:
                    continue
                try:
                    c.sendall(data)
                except:
                    muertos.append(c)
            for c in muertos:
                try: c.close()
                except: pass
                self.clients.discard(c)

    def handle_client(self, conn, addr):
        print(f"*** Nuevo cliente: {addr}")

        # 1) El cliente envía su nombre al conectarse
        try:
            name_raw = conn.recv(self.buffer)
            if not name_raw:
                conn.close()
                return
            name = name_raw.decode(errors="ignore").strip()
            if not name:
                name = f"{addr[0]}:{addr[1]}"
        except Exception:
            try: conn.close()
            except: pass
            return

        # 2) Registrar cliente y su nombre
        with self.lock:
            self.clients.add(conn)
            self.client_names[conn] = name
        print(f"*** {name} se unió desde {addr}")

        try:
            while True:
                data = conn.recv(self.buffer)
                if not data:
                    break

                # 3) Decodificar, limpiar y censurar
                raw_text = data.decode(errors='ignore').strip()
                if not raw_text:
                    continue  # ignora líneas vacías

                clean_text = self.bad_pattern.sub(self.mask_func, raw_text)

                # 4) Formatear y difundir (a todos menos al emisor)
                message = f"[{name}] {clean_text}"
                print(message)  # log en servidor
                self.broadcast(message.encode(), sender_sock=conn)

        finally:
            # 5) Limpieza
            with self.lock:
                self.clients.discard(conn)
                left_name = self.client_names.pop(conn, f"{addr[0]}:{addr[1]}")
            try:
                conn.close()
            except:
                pass
            print(f"*** {left_name} salió: {addr}")



    def start(self):
        print("Esperando conexiones...")
        try:
            while True:
                conn, addr = self.server_socket.accept()
                # Un hilo por cliente
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
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
                    try: c.close()
                    except: pass
                self.clients.clear()
            print("Server stopped.")

if __name__ == "__main__":
    EchoServer().start()
