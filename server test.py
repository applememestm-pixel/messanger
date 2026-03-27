#!/usr/bin/env python3
"""
Secure Chat Server - v4.5 (с поддержкой медиа)
"""

import socket
import ssl
import threading
import struct
import json
import uuid
import hashlib
import os
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_ssl_certificates(certfile="cert.pem", keyfile="key.pem"):
    """Генерация самоподписанных SSL сертификатов"""
    if os.path.exists(certfile) and os.path.exists(keyfile):
        print(f"✅ SSL сертификаты уже существуют: {certfile}, {keyfile}")
        return True

    try:
        print("🔐 Генерация SSL сертификатов...")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(keyfile, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Chat"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Chat Server"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.DNSName(u"127.0.0.1")]),
                           critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"✅ SSL сертификаты успешно созданы: {certfile}, {keyfile}")
        return True

    except Exception as e:
        print(f"❌ Ошибка генерации сертификатов: {e}")
        return False


class ChatServer:
    def __init__(self, host="0.0.0.0", port=5555, certfile="cert.pem", keyfile="key.pem"):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        self.clients: Dict[str, socket.socket] = {}
        self.public_keys: Dict[str, str] = {}
        self.users: Dict[str, Dict[str, str]] = {}
        self.sessions: Dict[str, str] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}

        self.lock = threading.Lock()
        self.messages_dir = "messages"
        os.makedirs(self.messages_dir, exist_ok=True)

        generate_ssl_certificates(certfile, keyfile)
        self.load_users()

    def load_users(self):
        try:
            if os.path.exists("users.json"):
                with open("users.json", "r", encoding="utf-8") as f:
                    self.users = json.load(f)
                print(f"📚 Загружено {len(self.users)} пользователей")
        except Exception as e:
            print(f"Ошибка загрузки пользователей: {e}")
            self.users = {}

    def save_users(self):
        try:
            with open("users.json", "w", encoding="utf-8") as f:
                json.dump(self.users, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения пользователей: {e}")

    def save_message(self, sender: str, recipient: str, data: dict, msg_type: str = "text"):
        """Сохранение зашифрованного сообщения"""
        filename = os.path.join(self.messages_dir, f"messages_{sender}_{recipient}.json")
        message_record = {
            "from": sender,
            "to": recipient,
            "type": msg_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        try:
            messages = []
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as f:
                    messages = json.load(f)
            messages.append(message_record)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(messages, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения сообщения: {e}")

    def send_json(self, sock: socket.socket, data: Dict[str, Any]) -> None:
        try:
            raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
            sock.sendall(struct.pack("!I", len(raw)))
            sock.sendall(raw)
        except Exception as e:
            print(f"Ошибка отправки: {e}")

    def recv_json(self, sock: socket.socket) -> Optional[Dict[str, Any]]:
        try:
            raw_len = self.recvall(sock, 4)
            if not raw_len:
                return None
            length = struct.unpack("!I", raw_len)[0]
            if length > 50 * 1024 * 1024:
                return None
            data = self.recvall(sock, length)
            if not data:
                return None
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"Ошибка получения: {e}")
            return None

    def recvall(self, sock: socket.socket, count: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < count:
            try:
                packet = sock.recv(count - len(buf))
                if not packet:
                    return None
                buf += packet
            except:
                return None
        return buf

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def broadcast(self, data: Dict[str, Any], exclude: Optional[str] = None) -> None:
        with self.lock:
            for name, conn in list(self.clients.items()):
                if name != exclude:
                    try:
                        self.send_json(conn, data)
                    except:
                        pass

    def get_users_list(self, exclude_name: Optional[str] = None) -> List[Dict[str, str]]:
        with self.lock:
            return [
                {"name": name, "public_key": pk}
                for name, pk in self.public_keys.items()
                if name != exclude_name
            ]

    def search_users(self, query: str) -> List[Dict[str, str]]:
        query = query.lower().strip()
        if not query:
            return self.get_users_list()
        with self.lock:
            results = []
            for name, pk in self.public_keys.items():
                if query in name.lower():
                    results.append({"name": name, "public_key": pk})
            return results

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        name = None
        try:
            msg = self.recv_json(conn)
            if not msg:
                return

            msg_type = msg.get("type")
            print(f"📨 [{addr}] {msg_type}")

            if msg_type == "register":
                name = msg.get("name")
                email = msg.get("email")
                password = msg.get("password")
                pubkey = msg.get("public_key")

                if not all([name, email, password, pubkey]):
                    self.send_json(conn, {"type": "register_error", "message": "Некорректные данные"})
                    conn.close()
                    return

                with self.lock:
                    if name in self.users:
                        self.send_json(conn, {"type": "register_error", "message": "Пользователь уже существует"})
                        conn.close()
                        return

                    self.users[name] = {
                        "email": email,
                        "password_hash": self.hash_password(password),
                        "public_key": pubkey
                    }
                    self.save_users()

                self.send_json(conn, {"type": "register_ok"})
                print(f"✅ Зарегистрирован: {name}")
                conn.close()
                return

            elif msg_type == "auth":
                name = msg.get("name")
                password = msg.get("password")
                pubkey = msg.get("public_key")

                if not all([name, password, pubkey]):
                    self.send_json(conn, {"type": "auth_error", "message": "Некорректные данные"})
                    conn.close()
                    return

                with self.lock:
                    user = self.users.get(name)

                    if not user:
                        print(f"📝 Авторегистрация: {name}")
                        self.users[name] = {
                            "email": f"{name}@local.com",
                            "password_hash": self.hash_password(password),
                            "public_key": pubkey
                        }
                        self.save_users()
                        user = self.users[name]

                    if self.hash_password(password) != user["password_hash"]:
                        self.send_json(conn, {"type": "auth_error", "message": "Неверный пароль"})
                        conn.close()
                        return

                    if name in self.clients:
                        self.send_json(conn, {"type": "auth_error", "message": "Пользователь уже подключён"})
                        conn.close()
                        return

                    session_token = str(uuid.uuid4())
                    self.sessions[session_token] = name
                    self.clients[name] = conn
                    self.public_keys[name] = pubkey
                    user["public_key"] = pubkey
                    self.save_users()

                self.send_json(conn, {"type": "auth_ok", "session_token": session_token})
                print(f"✅ {name} вошёл в чат ({addr})")

                users_list = self.get_users_list(exclude_name=name)
                self.send_json(conn, {"type": "users", "users": users_list})
                self.broadcast({"type": "join", "name": name, "public_key": pubkey}, exclude=name)

                while True:
                    msg = self.recv_json(conn)
                    if msg is None:
                        break

                    msg_type = msg.get("type")

                    if msg_type == "private":
                        target = msg.get("target")
                        data = msg.get("data")
                        media_type = msg.get("media_type", "text")

                        with self.lock:
                            self.save_message(name, target, data, media_type)

                            if target in self.clients:
                                self.send_json(self.clients[target], {
                                    "type": "private",
                                    "from": name,
                                    "data": data,
                                    "media_type": media_type
                                })
                            else:
                                self.send_json(conn, {
                                    "type": "error",
                                    "text": f"Пользователь {target} не в сети"
                                })

                    elif msg_type == "group_message":
                        group_id = msg.get("group_id")
                        data = msg.get("data")
                        media_type = msg.get("media_type", "text")

                        with self.lock:
                            group = self.groups.get(group_id)
                            if group and name in group["members"]:
                                for member in group["members"]:
                                    if member != name:
                                        self.save_message(name, member, data, f"group_{media_type}")

                                for member in group["members"]:
                                    if member != name and member in self.clients:
                                        self.send_json(self.clients[member], {
                                            "type": "group_message",
                                            "from": name,
                                            "group_id": group_id,
                                            "data": data,
                                            "media_type": media_type
                                        })
                                self.send_json(conn, {
                                    "type": "group_message",
                                    "from": name,
                                    "group_id": group_id,
                                    "data": data,
                                    "media_type": media_type
                                })

                    elif msg_type == "create_group":
                        group_name = msg.get("group_name")
                        members = msg.get("members", [])

                        if not group_name or not members:
                            self.send_json(conn, {"type": "error", "text": "Не указано имя группы"})
                            continue

                        if name not in members:
                            members.append(name)
                        members = list(set(members))
                        group_id = f"group_{len(self.groups) + 1}"

                        keys = {member: base64.b64encode(os.urandom(32)).decode() for member in members}

                        with self.lock:
                            self.groups[group_id] = {"name": group_name, "members": members, "keys": keys}

                        for member in members:
                            if member in self.clients:
                                self.send_json(self.clients[member], {
                                    "type": "group_created",
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "members": members,
                                    "keys": {member: keys[member]}
                                })

                        print(f"👥 Создана группа '{group_name}' (ID: {group_id}) с участниками: {members}")

                    elif msg_type == "search_user":
                        query = msg.get("query", "").strip()
                        results = self.search_users(query)
                        self.send_json(conn, {"type": "search_results", "results": results})

                    elif msg_type == "get_users":
                        users_list = self.get_users_list(exclude_name=name)
                        self.send_json(conn, {"type": "users", "users": users_list})

                    elif msg_type == "logout":
                        print(f"👋 {name} вышел из чата")
                        break

        except Exception as e:
            print(f"⚠️ Ошибка с клиентом {name or 'unknown'}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            with self.lock:
                if name and name in self.clients:
                    del self.clients[name]
                if name and name in self.public_keys:
                    del self.public_keys[name]
                for token in [t for t, u in self.sessions.items() if u == name]:
                    del self.sessions[token]

            if name:
                print(f"❌ {name} отключился")
                self.broadcast({"type": "leave", "name": name})
            try:
                conn.close()
            except:
                pass

    def start(self):
        if not (os.path.isfile(self.certfile) and os.path.isfile(self.keyfile)):
            print("❌ Ошибка: Файлы cert.pem и key.pem не найдены!")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)

        print("=" * 60)
        print("🚀 Secure Chat Server v4.5 (с поддержкой медиа)")
        print("=" * 60)
        print(f"📡 Адрес: {self.host}:{self.port}")
        print(f"🔒 SSL: {self.certfile}")
        print(f"📁 Пользователи: users.json")
        print(f"📁 Сообщения: {self.messages_dir}/")
        print("=" * 60)
        print("⏳ Ожидание подключений...\n")

        try:
            while True:
                try:
                    conn, addr = sock.accept()
                    print(f"📡 Новое соединение от {addr}")

                    try:
                        ssl_conn = context.wrap_socket(conn, server_side=True)
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(ssl_conn, addr),
                            daemon=True
                        )
                        client_thread.start()
                    except ssl.SSLError as e:
                        print(f"🔒 TLS ошибка с {addr}: {e}")
                        try:
                            conn.close()
                        except:
                            pass

                except socket.error as e:
                    print(f"⚠️ Ошибка сокета: {e}")

        except KeyboardInterrupt:
            print("\n\n🛑 Получен сигнал остановки...")
        finally:
            sock.close()
            print("✅ Сервер остановлен")


if __name__ == "__main__":
    print("Secure Chat Server v4.5")
    print("=" * 60)

    host = input("IP адрес (Enter = 0.0.0.0): ").strip() or "0.0.0.0"
    port_str = input("Порт (Enter = 5555): ").strip()
    port = int(port_str) if port_str else 5555
    certfile = input("SSL сертификат (Enter = cert.pem): ").strip() or "cert.pem"
    keyfile = input("SSL ключ (Enter = key.pem): ").strip() or "key.pem"

    print()

    server = ChatServer(host, port, certfile, keyfile)

    try:
        server.start()
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        import traceback

        traceback.print_exc()