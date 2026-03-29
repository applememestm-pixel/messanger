#!/usr/bin/env python3
"""
Secure Chat Client - v5.1 (с выбором цвета фона)
"""

import sys
import os
import ssl
import socket
import struct
import json
import base64
import uuid
import subprocess
import platform
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QTextBrowser, QLineEdit, QPushButton, QListWidget, QLabel,
    QMessageBox, QListWidgetItem, QInputDialog, QDialog, QDialogButtonBox,
    QScrollArea, QCheckBox, QSplitter, QFormLayout, QFileDialog
)
from PySide6.QtCore import Qt, Signal, QThread, QTimer, QUrl
from PySide6.QtGui import QFont, QTextCursor

from cryptography.hazmat.primitives.asymmetric import x25519, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

# WebRTC импорты
try:
    from aiortc import RTCPeerConnection, RTCSessionDescription, RTCIceCandidate
    from aiortc.contrib.media import MediaPlayer, MediaRecorder

    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    print("⚠️ aiortc не установлен. Звонки недоступны. Установите: pip install aiortc aioice av")


# ==================== ГЕНЕРАЦИЯ SSL СЕРТИФИКАТОВ ====================
def generate_ssl_certificates(certfile="cert.pem", keyfile="key.pem"):
    """Генерация самоподписанных SSL сертификатов"""
    if os.path.exists(certfile) and os.path.exists(keyfile):
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
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.DNSName(u"127.0.0.1")]),
                           critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"✅ SSL сертификаты успешно созданы")
        return True

    except Exception as e:
        print(f"❌ Ошибка генерации сертификатов: {e}")
        return False


class SimpleFormatter:
    @staticmethod
    def format_message(text: str) -> str:
        text = text.replace('\n', '<br>')
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text


class Crypto:
    @staticmethod
    def generate_x25519_keypair():
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return private, public

    @staticmethod
    def derive_shared_key(private, peer_public_bytes):
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private.exchange(peer_public)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data", backend=default_backend())
        return hkdf.derive(shared_secret)

    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> dict:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return {'nonce': base64.b64encode(nonce).decode(), 'ciphertext': base64.b64encode(ct).decode()}

    @staticmethod
    def decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')


class Message:
    def __init__(self, sender: str, text: str, timestamp=None, is_own: bool = False):
        self.sender = sender
        self.text = text
        self.is_own = is_own
        if timestamp and isinstance(timestamp, datetime):
            self.timestamp = timestamp
        else:
            self.timestamp = datetime.now()


class Chat:
    def __init__(self, chat_id: str, name: str, chat_type: str):
        self.id = chat_id
        self.name = name
        self.type = chat_type
        self.messages: List[Message] = []
        self.unread_count = 0
        self.shared_key: Optional[bytes] = None
        self.group_keys: Dict[str, str] = {}

    def add_message(self, sender: str, text: str, is_own: bool = False):
        self.messages.append(Message(sender, text, None, is_own))
        if not is_own:
            self.unread_count += 1

    def mark_read(self):
        self.unread_count = 0


class NetworkClient(QThread):
    connected = Signal()
    register_success = Signal()
    disconnected = Signal()
    error_occurred = Signal(str)
    message_received = Signal(str, str, dict)
    user_list_updated = Signal(list)
    user_joined = Signal(str, str)
    user_left = Signal(str)
    group_created = Signal(str, str, list, dict)
    search_results = Signal(list)

    # Сигналы для звонков
    call_incoming = Signal(str, str)  # caller, sdp
    call_accepted = Signal(str, str)  # caller, sdp
    call_ice_candidate = Signal(str, str)  # sender, candidate
    call_ended = Signal(str)  # from

    def __init__(self):
        super().__init__()
        self.sock = None
        self.running = False
        self.host = self.port = self.name = self.email = self.password = None
        self.pubkey_bytes = None
        self.mode = "auth"
        self.loop = None

        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect_to_server(self, host, port, name, email, password, pubkey_bytes, mode="auth"):
        self.host = host
        self.port = port
        self.name = name
        self.email = email
        self.password = password
        self.pubkey_bytes = pubkey_bytes
        self.mode = mode
        self.start()

    def run(self):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(15)
            raw_sock.connect((self.host, self.port))
            self.sock = self.context.wrap_socket(raw_sock, server_hostname=self.host)
            self.sock.settimeout(None)

            cmd = {
                "type": self.mode,
                "name": self.name,
                "password": self.password,
                "public_key": base64.b64encode(self.pubkey_bytes).decode(),
            }
            if self.mode == "register":
                cmd["email"] = self.email

            self._send_json(cmd)

            response = self._recv_json()
            if not response:
                self.error_occurred.emit("Нет ответа от сервера")
                return

            resp_type = response.get("type")

            if resp_type == "register_ok":
                print("✅ Регистрация прошла успешно")
                self.register_success.emit()
                return
            elif resp_type == "auth_ok":
                print("✅ Авторизация успешна")
                self.running = True
                self.connected.emit()

                while self.running:
                    msg = self._recv_json()
                    if msg is None:
                        break
                    self.process_message(msg)
            else:
                error_msg = response.get("message", "Ошибка авторизации")
                self.error_occurred.emit(error_msg)

        except Exception as e:
            self.error_occurred.emit(f"Ошибка подключения: {e}")
        finally:
            self.running = False
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
            self.disconnected.emit()

    def process_message(self, msg: dict):
        try:
            mtype = msg.get("type")
            if mtype == "users":
                self.user_list_updated.emit(msg["users"])
            elif mtype == "join":
                self.user_joined.emit(msg["name"], msg.get("public_key", ""))
            elif mtype == "leave":
                self.user_left.emit(msg["name"])
            elif mtype == "private":
                self.message_received.emit("private", msg["from"], msg["data"])
            elif mtype == "media_private":
                self.message_received.emit("media_private", msg["from"], msg["data"])
            elif mtype == "group_message":
                self.message_received.emit("group", msg["from"], {
                    "group_id": msg["group_id"],
                    "data": msg["data"]
                })
            elif mtype == "media_group":
                self.message_received.emit("media_group", msg["from"], {
                    "group_id": msg["group_id"],
                    "data": msg["data"]
                })
            elif mtype == "group_created":
                self.group_created.emit(msg["group_id"], msg["group_name"], msg["members"], msg.get("keys", {}))
            elif mtype == "search_results":
                self.search_results.emit(msg.get("results", []))
            # Обработка звонков
            elif mtype == "call_incoming":
                self.call_incoming.emit(msg["from"], msg.get("sdp", ""))
            elif mtype == "call_accepted":
                self.call_accepted.emit(msg["from"], msg.get("sdp", ""))
            elif mtype == "call_ice":
                self.call_ice_candidate.emit(msg["from"], msg.get("candidate", ""))
            elif mtype == "call_ended":
                self.call_ended.emit(msg.get("from", ""))
            elif mtype == "error":
                self.error_occurred.emit(msg.get("text", "Ошибка сервера"))
        except Exception as e:
            print(f"Ошибка обработки: {e}")

    def disconnect(self):
        self.running = False
        if self.sock:
            try:
                self._send_json({"type": "logout"})
            except:
                pass
            try:
                self.sock.close()
            except:
                pass

    def send_private(self, target: str, encrypted_data: dict):
        if self.running and self.sock:
            self._send_json({"type": "private", "target": target, "data": encrypted_data})

    # Методы для звонков
    async def start_call(self):
        self.pc = RTCPeerConnection()
        self.is_calling = True

        @self.pc.on("icecandidate")
        def on_ice_candidate(candidate):
            if candidate:
                self.ice_candidates.append({
                    "candidate": candidate.candidate,
                    "sdpMLineIndex": str(candidate.sdpMLineIndex),  # Конвертируем в строку
                    "sdpMid": candidate.sdpMid
                })

        # Убрали MediaPlayer - он вызывает ошибку
        self.pc.addTrack(None)  # Просто добавляем пустой трек

        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        sdp = self.pc.localDescription.sdp
        if self.crypto_key:
            encrypted = Crypto.encrypt(self.crypto_key, sdp)
            return json.dumps(encrypted)
        return sdp._send_json({"type": "call_start", "target": target, "sdp": sdp})

    def accept_call(self, caller: str, sdp: str):
        if self.running and self.sock:
            self._send_json({"type": "call_accept", "caller": caller, "sdp": sdp})

    def send_ice_candidate(self, target: str, candidate: str):
        if self.running and self.sock:
            self._send_json({"type": "call_ice", "target": target, "candidate": candidate})

    def end_call(self, target: str = None):
        if self.running and self.sock:
            self._send_json({"type": "call_end"})

    def _send_json(self, data: dict):
        try:
            data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.sock.sendall(struct.pack("!I", len(data_bytes)))
            self.sock.sendall(data_bytes)
        except:
            pass

    def _recv_json(self) -> Optional[dict]:
        try:
            raw_len = self._recvall(4)
            if not raw_len: return None
            length = struct.unpack("!I", raw_len)[0]
            if length > 50 * 1024 * 1024: return None
            data = self._recvall(length)
            if not data: return None
            return json.loads(data.decode('utf-8'))
        except:
            return None

    def _recvall(self, count: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < count:
            try:
                packet = self.sock.recv(count - len(buf))
                if not packet: return None
                buf += packet
            except:
                return None
        return buf


class CreateGroupDialog(QDialog):
    def __init__(self, users: List[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создать группу")
        self.setMinimumWidth(400)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Название группы:"))
        self.name_input = QLineEdit()
        layout.addWidget(self.name_input)
        layout.addWidget(QLabel("Выберите участников:"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        self.checkboxes = {}
        for u in sorted(users):
            cb = QCheckBox(u)
            self.checkboxes[u] = cb
            scroll_layout.addWidget(cb)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_data(self):
        group_name = self.name_input.text().strip()
        selected = [u for u, cb in self.checkboxes.items() if cb.isChecked()]
        return group_name, selected


class LoginDialog(QDialog):
    def __init__(self, saved_name="", saved_email=""):
        super().__init__()
        self.setWindowTitle("Авторизация / Регистрация")
        self.setFixedSize(350, 280)
        self.mode = "auth"
        self.result = None

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit(saved_name)
        self.email_edit = QLineEdit(saved_email)
        self.email_edit.hide()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        form.addRow("Имя пользователя:", self.name_edit)
        form.addRow("Email:", self.email_edit)
        form.addRow("Пароль:", self.password_edit)
        layout.addLayout(form)

        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color: red;")
        layout.addWidget(self.info_label)

        btn_layout = QHBoxLayout()
        self.submit_btn = QPushButton("Войти")
        self.switch_btn = QPushButton("Регистрация")
        btn_layout.addWidget(self.submit_btn)
        btn_layout.addWidget(self.switch_btn)
        layout.addLayout(btn_layout)

        self.submit_btn.clicked.connect(self.submit)
        self.switch_btn.clicked.connect(self.switch_mode)

    def switch_mode(self):
        self.mode = "register" if self.mode == "auth" else "auth"
        if self.mode == "auth":
            self.email_edit.hide()
            self.submit_btn.setText("Войти")
            self.switch_btn.setText("Регистрация")
            self.setWindowTitle("Авторизация")
        else:
            self.email_edit.show()
            self.submit_btn.setText("Зарегистрироваться")
            self.switch_btn.setText("Назад к входу")
            self.setWindowTitle("Регистрация")
        self.info_label.setText("")

    def submit(self):
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        password = self.password_edit.text()

        if not name or not password:
            self.info_label.setText("Заполните имя и пароль")
            return
        if self.mode == "register" and not email:
            self.info_label.setText("Укажите email для регистрации")
            return

        self.result = {"mode": self.mode, "name": name, "email": email, "password": password}
        self.accept()


class ChatWidget(QWidget):
    send_signal = Signal(str, str)
    send_media_signal = Signal(str, str, str)
    call_signal = Signal()  # Сигнал для звонка

    def __init__(self, chat: Chat, theme: str = "dark", parent=None):
        super().__init__(parent)
        self.chat = chat
        self.theme = theme
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header_layout = QHBoxLayout()
        icon = "💬" if self.chat.type == "private" else "👥" if self.chat.type == "group" else "📢"
        self.header = QLabel(f"{icon} {self.chat.name}")
        self.header.setObjectName("chatHeader")
        header_layout.addWidget(self.header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.messages_area = QTextBrowser()
        self.messages_area.setReadOnly(True)
        self.messages_area.setFont(QFont("Segoe UI", 10))
        self.messages_area.setObjectName("messagesArea")
        self.messages_area.anchorClicked.connect(self.on_link_clicked)
        layout.addWidget(self.messages_area)

        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Введите сообщение...")
        self.input_field.returnPressed.connect(self.on_send)
        self.input_field.setObjectName("inputField")

        self.send_button = QPushButton("Отправить")
        self.send_button.clicked.connect(self.on_send)
        self.send_button.setObjectName("sendButton")

        # Кнопка звонка (только для приватных чатов)
        self.call_button = QPushButton("📞")
        self.call_button.setFixedSize(40, 40)
        self.call_button.clicked.connect(self.on_call_clicked)
        self.call_button.setObjectName("callButton")
        if self.chat.type != "private":
            self.call_button.setEnabled(False)
            self.call_button.setToolTip("Звонки доступны только в приватных чатах")

        self.media_button = QPushButton("📎")
        self.media_button.setFixedSize(40, 40)
        self.media_button.clicked.connect(self.on_send_media)
        self.media_button.setObjectName("mediaButton")

        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.call_button)
        input_layout.addWidget(self.media_button)
        layout.addLayout(input_layout)

        self.apply_theme()
        self.refresh_messages()

    def on_link_clicked(self, url: QUrl):
        """Открытие файла по клику"""
        file_path = url.toLocalFile()
        if file_path and os.path.exists(file_path):
            try:
                if platform.system() == "Windows":
                    os.startfile(file_path)
                elif platform.system() == "Darwin":
                    subprocess.Popen(["open", file_path])
                else:
                    subprocess.Popen(["xdg-open", file_path])
            except Exception as e:
                print(f"Ошибка открытия файла: {e}")

    def on_call_clicked(self):
        """Клик по кнопке звонка"""
        self.call_signal.emit()

    def on_send_media(self):
        """Отправка медиа-файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл", "",
            "Все файлы (*.*);;Изображения (*.png *.jpg *.jpeg *.gif);;Видео (*.mp4 *.webm);;Аудио (*.mp3 *.wav)"
        )
        if file_path:
            ext = file_path.split('.')[-1].lower()
            if ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
                media_type = "image"
            elif ext in ['mp4', 'webm', 'avi', 'mov']:
                media_type = "video"
            elif ext in ['mp3', 'wav', 'm4a', 'flac']:
                media_type = "audio"
            else:
                media_type = "file"
            self.send_media_signal.emit(self.chat.id, file_path, media_type)

    def apply_theme(self):
        if self.theme == "dark":
            self.setStyleSheet("""
                QLabel#chatHeader {font-weight: bold; padding: 12px; background-color: #2D2D3A; color: #F3F4F6;}
                QTextBrowser#messagesArea {background-color: #1E1E2E; border: none; padding: 8px; color: #F3F4F6;}
                QLineEdit#inputField {background-color: #3A3A4A; border: none; border-radius: 20px; padding: 10px 16px; color: #F3F4F6;}
                QPushButton#sendButton, QPushButton#callButton, QPushButton#mediaButton {background-color: #7C3AED; border: none; border-radius: 20px; color: white; font-weight: bold;}
                QPushButton#sendButton {padding: 10px 20px;}
                QPushButton#callButton, QPushButton#mediaButton {padding: 10px; font-size: 16px;}
                QPushButton#sendButton:hover {background-color: #9F67FF;}
                QPushButton#callButton:hover {background-color: #9F67FF;}
                QPushButton#mediaButton:hover {background-color: #16A34A;}
                QPushButton#mediaButton {background-color: #22C55E;}
            """)
        else:
            self.setStyleSheet("""
                QLabel#chatHeader {font-weight: bold; padding: 12px; background-color: #FFFFFF; color: #1F2937; border-bottom: 1px solid #E5E7EB;}
                QTextBrowser#messagesArea {background-color: #F8F9FA; border: none; padding: 8px; color: #1F2937;}
                QLineEdit#inputField {background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 20px; padding: 10px 16px; color: #1F2937;}
                QPushButton#sendButton, QPushButton#callButton, QPushButton#mediaButton {background-color: #7C3AED; border: none; border-radius: 20px; color: white; font-weight: bold;}
                QPushButton#sendButton {padding: 10px 20px;}
                QPushButton#callButton, QPushButton#mediaButton {padding: 10px; font-size: 16px;}
                QPushButton#sendButton:hover {background-color: #9F67FF;}
                QPushButton#callButton:hover {background-color: #9F67FF;}
                QPushButton#mediaButton:hover {background-color: #16A34A;}
                QPushButton#mediaButton {background-color: #22C55E;}
            """)

    def update_theme(self, theme: str):
        self.theme = theme
        self.apply_theme()
        self.refresh_messages()

    def refresh_messages(self):
        self.messages_area.clear()
        for msg in self.chat.messages:
            self.add_message_display(msg)

    def add_message_display(self, msg: Message):
        timestamp = msg.timestamp.strftime("%H:%M:%S")
        sender = "Вы" if msg.is_own else msg.sender
        align = "right" if msg.is_own else "left"

        if self.theme == "dark":
            if msg.is_own:
                bg_color = "#2C3E66"
                text_color = "#FFFFFF"
            else:
                bg_color = "#3A3A4A"
                text_color = "#F3F4F6"
            time_color = "#6B7280"
        else:
            if msg.is_own:
                bg_color = "#E3F2FD"
                text_color = "#1F2937"
            else:
                bg_color = "#F3F4F6"
                text_color = "#1F2937"
            time_color = "#9CA3AF"

        # Проверяем, является ли сообщение ссылкой на файл
        if msg.text.startswith("📎"):
            file_path = msg.text.split(": ")[1] if ": " in msg.text else msg.text[2:]
            # Проверяем, существует ли файл
            if os.path.exists(file_path):
                file_url = QUrl.fromLocalFile(file_path).toString()
                formatted_text = f'<a href="{file_url}">{msg.text}</a>'
            else:
                formatted_text = SimpleFormatter.format_message(msg.text)
        else:
            formatted_text = SimpleFormatter.format_message(msg.text)

        html = f'''
        <div style="margin: 8px 0; text-align: {align};">
            <div style="display: inline-block; max-width: 70%; background-color: {bg_color}; border-radius: 12px; padding: 8px 12px;">
                <div style="color: {text_color}; font-size: 12px; font-weight: bold;">{sender}</div>
                <div style="color: {text_color};">{formatted_text}</div>
                <div style="color: {time_color}; font-size: 10px; margin-top: 4px;">{timestamp}</div>
            </div>
        </div>
        '''
        self.messages_area.insertHtml(html)

    def add_message(self, sender: str, text: str, is_own: bool = False):
        self.chat.add_message(sender, text, is_own)
        self.add_message_display(self.chat.messages[-1])

    def on_send(self):
        text = self.input_field.text().strip()
        if text:
            self.send_signal.emit(self.chat.id, text)
            self.input_field.clear()


class MainWindow(QMainWindow):
    # Палитра цветов для фона
    BACKGROUNDS = {
        "Чёрный": "#000000",
        "Белый": "#FFFFFF",
        "Серый": "#808080",
        "Тёмно-серый": "#2D2D3A",
        "Светло-серый": "#F3F4F6",
        "Синий": "#1E3A8A",
        "Зелёный": "#065F46",
        "Фиолетовый": "#5B21B6",
        "Красный": "#7F1D1D",
        "Оранжевый": "#92400E"
    }

    def __init__(self, network: NetworkClient, username: str, private_key):
        super().__init__()
        self.network = network
        self.username = username
        self.private_key = private_key

        self.users: Dict[str, str] = {}
        self.chats: Dict[str, Chat] = {}
        self.current_chat_id = None
        self.current_theme = "dark"
        self.pending_messages: Dict[str, list] = {}

        # Настройки фона
        self.current_bg = "Чёрный"
        self.load_background_setting()

        # Для звонков
        self.call_manager = None
        self.current_caller = None
        self.call_in_progress = False
        self.call_thread = None

        # Таймер автосохранения (каждые 5 минут)
        self.auto_save_timer = QTimer()
        self.auto_save_timer.timeout.connect(self.auto_save_all_chats)
        self.auto_save_timer.start(5 * 60 * 1000)

        # Таймер автоудаления
        self.auto_delete_timer = QTimer()
        self.auto_delete_timer.timeout.connect(self.auto_delete_old_messages)
        self.auto_delete_interval = 86400

        self.setup_ui()
        self.connect_signals()
        self.load_saved_messages()

        QTimer.singleShot(500, self.show_delete_interval_dialog)

        if "system" not in self.chats:
            self.chats["system"] = Chat("system", "📢 Система", "system")
        self.update_chat_list()
        self.add_system_message("Добро пожаловать в защищенный чат!")

        if not AIORTC_AVAILABLE:
            self.add_system_message(
                "⚠️ WebRTC не установлен. Звонки недоступны. Установите: pip install aiortc aioice av")

    # ==================== НАСТРОЙКИ ФОНА ====================
    def load_background_setting(self):
        """Загрузка настроек фона"""
        try:
            if os.path.exists("settings.json"):
                with open("settings.json", "r", encoding="utf-8") as f:
                    settings = json.load(f)
                    self.current_bg = settings.get("background", "Чёрный")
        except Exception as e:
            print(f"Ошибка загрузки настроек фона: {e}")
            self.current_bg = "Чёрный"

    def save_background_setting(self):
        """Сохранение настроек фона"""
        try:
            with open("settings.json", "w", encoding="utf-8") as f:
                json.dump({"background": self.current_bg}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения настроек фона: {e}")

    def choose_background(self):
        """Выбор цвета фона из палитры"""
        items = list(self.BACKGROUNDS.keys())
        item, ok = QInputDialog.getItem(
            self, "Выбор фона",
            "Выберите цвет фона:",
            items, items.index(self.current_bg), False
        )
        if ok:
            self.current_bg = item
            self.save_background_setting()
            self.apply_background()
            self.add_system_message(f"✅ Фон изменён на {item}")

    def apply_background(self):
        """Применение фонового цвета"""
        color = self.BACKGROUNDS.get(self.current_bg, "#000000")

        # Применяем фон через стили
        self.setStyleSheet(f"""
            QMainWindow, QWidget#centralWidget {{ background-color: {color}; }}
            QWidget#leftPanel {{ background-color: {color}; border-right: 1px solid #3A3A4A; }}
            QWidget#rightPanel {{ background-color: {color}; }}
            QLabel#nameLabel {{ color: {"#F3F4F6" if self.current_bg not in ["Белый", "Светло-серый"] else "#1F2937"}; font-weight: bold; font-size: 14px; padding: 8px; }}
            QLabel#chatsLabel, QLabel#usersLabel {{ color: {"#9CA3AF" if self.current_bg not in ["Белый", "Светло-серый"] else "#6B7280"}; font-weight: bold; padding: 8px 4px; }}
            QLabel#emptyChatLabel {{ color: {"#6B7280" if self.current_bg not in ["Белый", "Светло-серый"] else "#9CA3AF"}; font-size: 16px; }}
            QLineEdit#searchInput {{ background-color: {"#3A3A4A" if self.current_bg not in ["Белый", "Светло-серый"] else "#FFFFFF"}; border: {"none" if self.current_bg not in ["Белый", "Светло-серый"] else "1px solid #E5E7EB"}; border-radius: 20px; padding: 8px 12px; color: {"#F3F4F6" if self.current_bg not in ["Белый", "Светло-серый"] else "#1F2937"}; margin-bottom: 8px; }}
            QPushButton#btnSaved {{ background-color: #22C55E; color: white; font-weight: bold; padding: 8px; border-radius: 20px; border: none; }}
            QPushButton#btnSaved:hover {{ background-color: #16A34A; }}
            QPushButton#btnBg, QPushButton#btnTheme {{ background-color: {"#3A3A4A" if self.current_bg not in ["Белый", "Светло-серый"] else "#E5E7EB"}; color: {"#F3F4F6" if self.current_bg not in ["Белый", "Светло-серый"] else "#374151"}; border-radius: 20px; font-size: 16px; }}
            QPushButton#btnBg:hover, QPushButton#btnTheme:hover {{ background-color: {"#4A4A5A" if self.current_bg not in ["Белый", "Светло-серый"] else "#D1D5DB"}; }}
            QPushButton#btnCreateGroup {{ background-color: #7C3AED; border: none; border-radius: 20px; padding: 8px; color: white; margin-top: 8px; }}
            QPushButton#btnCreateGroup:hover {{ background-color: #9F67FF; }}
            QListWidget#chatList, QListWidget#userList {{ background-color: {"#2D2D3A" if self.current_bg not in ["Белый", "Светло-серый"] else "#FFFFFF"}; color: {"#F3F4F6" if self.current_bg not in ["Белый", "Светло-серый"] else "#1F2937"}; border: {"none" if self.current_bg not in ["Белый", "Светло-серый"] else "1px solid #E5E7EB"}; border-radius: 8px; padding: 4px; }}
            QListWidget#chatList::item, QListWidget#userList::item {{ padding: 8px; border-radius: 6px; }}
            QListWidget#chatList::item:hover, QListWidget#userList::item:hover {{ background-color: {"#3A3A4A" if self.current_bg not in ["Белый", "Светло-серый"] else "#F3F4F6"}; }}
            QListWidget#chatList::item:selected, QListWidget#userList::item:selected {{ background-color: #7C3AED; color: white; }}
            QWidget#chatStack {{ background-color: {color}; }}
            QStatusBar {{ background-color: {"#2D2D3A" if self.current_bg not in ["Белый", "Светло-серый"] else "#FFFFFF"}; color: {"#9CA3AF" if self.current_bg not in ["Белый", "Светло-серый"] else "#6B7280"}; }}
        """)

        # Обновляем цвета в чатах
        for i in range(self.chat_stack_layout.count()):
            widget = self.chat_stack_layout.itemAt(i).widget()
            if isinstance(widget, ChatWidget):
                widget.update_theme(self.current_theme)

    # ==================== АВТОСОХРАНЕНИЕ И АВТОУДАЛЕНИЕ ====================
    def show_delete_interval_dialog(self):
        items = ["Каждые 3 часа", "Каждый день", "Каждую неделю", "Отключить"]
        intervals = [10800, 86400, 604800, 0]

        item, ok = QInputDialog.getItem(
            self, "Интервал удаления",
            "Выберите интервал автоудаления старых сообщений:",
            items, 1, False
        )

        if ok:
            idx = items.index(item)
            self.auto_delete_interval = intervals[idx]
            if self.auto_delete_interval > 0:
                self.auto_delete_timer.start(self.auto_delete_interval * 1000)
                self.add_system_message(f"🗑️ Автоудаление установлено: {item}")
            else:
                self.add_system_message("🗑️ Автоудаление отключено")

    def auto_delete_old_messages(self):
        if self.auto_delete_interval == 0:
            return

        now = datetime.now()
        delete_before = now - timedelta(seconds=self.auto_delete_interval)

        total_deleted = 0
        for chat in self.chats.values():
            original_count = len(chat.messages)
            chat.messages = [msg for msg in chat.messages if msg.timestamp > delete_before]
            total_deleted += original_count - len(chat.messages)

        if total_deleted > 0:
            self.add_system_message(f"🗑️ Удалено {total_deleted} старых сообщений")
            if self.current_chat_id and self.current_chat_id in self.chats:
                self.switch_chat(self.current_chat_id)

    def auto_save_all_chats(self):
        saved_count = 0
        for chat_id, chat in self.chats.items():
            if chat.type == "private" and chat_id != "saved_messages":
                self.save_chat_to_file(chat_id, chat)
                saved_count += 1
        if saved_count > 0:
            self.add_system_message(f"💾 Автосохранено {saved_count} чатов")

    def save_chat_to_file(self, chat_id: str, chat: Chat):
        filename = f"chat_{chat_id.replace('private_', '')}.json"
        data = []
        for msg in chat.messages:
            data.append({
                "sender": msg.sender,
                "text": msg.text,
                "time": msg.timestamp.isoformat(),
                "is_own": msg.is_own
            })
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения {filename}: {e}")

    def load_chat_from_file(self, chat_id: str, chat: Chat):
        filename = f"chat_{chat_id.replace('private_', '')}.json"
        if os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for m in data:
                    try:
                        timestamp = datetime.fromisoformat(m.get("time", ""))
                    except:
                        timestamp = datetime.now()
                    msg = Message(
                        sender=m.get("sender", "Unknown"),
                        text=m.get("text", ""),
                        timestamp=timestamp,
                        is_own=m.get("is_own", False)
                    )
                    chat.messages.append(msg)
                print(f"📂 Загружено {len(chat.messages)} сообщений из {filename}")
            except Exception as e:
                print(f"Ошибка загрузки {filename}: {e}")

    # ==================== ЗВОНКИ ====================
    def start_call_to_user(self):
        """Начать звонок выбранному пользователю"""
        if not AIORTC_AVAILABLE:
            self.add_system_message("❌ WebRTC не установлен. Установите: pip install aiortc aioice av")
            return

        if not self.current_chat_id or self.current_chat_id == "saved_messages":
            self.add_system_message("❌ Выберите пользователя")
            return

        chat = self.chats[self.current_chat_id]
        if chat.type != "private":
            self.add_system_message("❌ Звонки только в приватных чатах")
            return

        if not chat.shared_key:
            self.add_system_message("❌ Нет ключа шифрования")
            return

        if self.call_in_progress:
            self.add_system_message("❌ Звонок уже в процессе")
            return

        self.call_manager = CallManager(crypto_key=chat.shared_key)
        self.call_in_progress = True
        self.add_system_message(f"📞 Начинаем звонок {chat.name}...")

        # Запускаем асинхронный звонок
        self.call_thread = threading.Thread(target=self._run_async_call, args=(chat.name,), daemon=True)
        self.call_thread.start()

    def _run_async_call(self, target: str):
        """Запуск асинхронного звонка в отдельном потоке"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self._async_start_call(target))
        except Exception as e:
            self.add_system_message(f"❌ Ошибка звонка: {e}")
            self.call_in_progress = False
        finally:
            loop.close()

    async def _async_start_call(self, target: str):
        """Асинхронный старт звонка"""
        try:
            sdp = await self.call_manager.start_call()
            self.network.start_call(target, sdp)

            # Отправляем ICE кандидаты
            while self.call_in_progress:
                candidates = self.call_manager.get_ice_candidates()
                for candidate in candidates:
                    encrypted_candidate = Crypto.encrypt(self.call_manager.crypto_key, json.dumps(candidate))
                    self.network.send_ice_candidate(target, json.dumps(encrypted_candidate))
                await asyncio.sleep(0.5)
        except Exception as e:
            self.add_system_message(f"❌ Ошибка: {e}")

    def on_call_incoming(self, caller: str, sdp: str):
        """Входящий звонок"""
        self.current_caller = caller
        reply = QMessageBox.question(
            self, "Входящий звонок",
            f"{caller} звонит вам. Ответить?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            chat_id = f"private_{caller}"
            if chat_id in self.chats and self.chats[chat_id].shared_key:
                self.call_manager = CallManager(crypto_key=self.chats[chat_id].shared_key)
                self.call_in_progress = True

                # Запускаем принятие звонка
                self.call_thread = threading.Thread(target=self._run_async_accept, args=(caller, sdp), daemon=True)
                self.call_thread.start()
            else:
                self.add_system_message("❌ Нет ключа шифрования")
        else:
            self.network.end_call(caller)

    def _run_async_accept(self, caller: str, sdp: str):
        """Запуск асинхронного принятия звонка"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self._async_accept_call(caller, sdp))
        except Exception as e:
            self.add_system_message(f"❌ Ошибка: {e}")
            self.call_in_progress = False
        finally:
            loop.close()

    async def _async_accept_call(self, caller: str, sdp: str):
        """Асинхронное принятие звонка"""
        try:
            sdp_response = await self.call_manager.start_call()
            await self.call_manager.handle_answer(sdp)
            self.network.accept_call(caller, sdp_response)
            self.add_system_message(f"✅ Звонок принят от {caller}")
        except Exception as e:
            self.add_system_message(f"❌ Ошибка: {e}")

    def on_call_accepted(self, caller: str, sdp: str):
        """Звонок принят собеседником"""
        self.add_system_message(f"✅ {caller} принял звонок")
        if self.call_manager:
            self.call_thread = threading.Thread(target=self._run_async_handle_answer, args=(sdp,), daemon=True)
            self.call_thread.start()

    def _run_async_handle_answer(self, sdp: str):
        """Асинхронная обработка ответа"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self.call_manager.handle_answer(sdp))
        except Exception as e:
            print(f"Ошибка обработки ответа: {e}")
        finally:
            loop.close()

    def on_ice_candidate(self, sender: str, candidate: str):
        """Получен ICE кандидат"""
        if self.call_manager and self.call_in_progress:
            self.call_thread = threading.Thread(target=self._run_async_add_ice, args=(candidate,), daemon=True)
            self.call_thread.start()

    def _run_async_add_ice(self, candidate: str):
        """Асинхронное добавление ICE кандидата"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self.call_manager.add_ice_candidate(candidate))
        except Exception as e:
            print(f"Ошибка добавления ICE: {e}")
        finally:
            loop.close()

    def on_call_ended(self, sender: str):
        """Звонок завершён"""
        self.add_system_message(f"📞 Звонок завершён{f' с {sender}' if sender else ''}")
        self.call_in_progress = False
        self.current_caller = None
        if self.call_manager:
            self.call_thread = threading.Thread(target=self._run_async_end_call, daemon=True)
            self.call_thread.start()

    def _run_async_end_call(self):
        """Асинхронное завершение звонка"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self.call_manager.end_call())
        except Exception as e:
            print(f"Ошибка завершения: {e}")
        finally:
            loop.close()
            self.call_manager = None

    # ==================== ОТПРАВКА МЕДИА И СООБЩЕНИЙ ====================
    def send_media(self, chat_id: str, file_path: str, media_type: str):
        """Отправка зашифрованного медиа (с поддержкой избранного)"""
        if chat_id not in self.chats:
            return

        chat = self.chats[chat_id]

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            file_b64 = base64.b64encode(file_data).decode()
            file_name = os.path.basename(file_path)
            ext = file_path.split('.')[-1].lower()
            local_file = f"media_{uuid.uuid4()}.{ext}"

            with open(local_file, 'wb') as f:
                f.write(file_data)

            if chat.type == "private":
                if chat_id == "saved_messages":
                    chat.add_message(self.username, f"📎 {media_type.upper()}: {local_file}", True)
                    self.save_saved_messages()
                else:
                    if not chat.shared_key:
                        self.add_system_message(f"❌ Нет ключа для {chat.name}")
                        return

                    encrypted = Crypto.encrypt(chat.shared_key, file_b64)
                    self.network._send_json({
                        "type": "private",
                        "target": chat.name,
                        "data": encrypted,
                        "media_type": media_type
                    })

                    chat.add_message(self.username, f"📎 {media_type.upper()}: {local_file}", True)
                    self.save_chat_to_file(chat_id, chat)

                if self.current_chat_id == chat_id:
                    self.switch_chat(chat_id)

            elif chat.type == "group":
                my_key_b64 = chat.group_keys.get(self.username)
                if not my_key_b64:
                    self.add_system_message("❌ Нет ключа для группы")
                    return
                key = base64.b64decode(my_key_b64)
                encrypted = Crypto.encrypt(key, file_b64)
                self.network._send_json({
                    "type": "group_message",
                    "group_id": chat.id,
                    "data": encrypted,
                    "media_type": media_type
                })
                chat.add_message(self.username, f"📎 {media_type.upper()}: {local_file}", True)
                if self.current_chat_id == chat_id:
                    self.switch_chat(chat_id)

        except Exception as e:
            self.add_system_message(f"❌ Ошибка отправки файла: {e}")

    def send_message(self, chat_id: str, text: str):
        """Отправка текстового сообщения (с поддержкой избранного)"""
        if chat_id not in self.chats:
            return
        chat = self.chats[chat_id]

        if chat.type == "private":
            if chat_id == "saved_messages":
                chat.add_message(self.username, text, True)
                self.save_saved_messages()
            else:
                target = chat.name
                if chat.shared_key:
                    encrypted = Crypto.encrypt(chat.shared_key, text)
                    self.network.send_private(target, encrypted)
                    chat.add_message(self.username, text, True)
                    self.save_chat_to_file(chat_id, chat)

            if self.current_chat_id == chat_id:
                self.switch_chat(chat_id)

        elif chat.type == "group":
            my_key_b64 = chat.group_keys.get(self.username)
            if my_key_b64:
                key = base64.b64decode(my_key_b64)
                encrypted = Crypto.encrypt(key, text)
                self.network._send_json({
                    "type": "group_message",
                    "group_id": chat.id,
                    "data": encrypted
                })
                chat.add_message(self.username, text, True)
                if self.current_chat_id == chat_id:
                    self.switch_chat(chat_id)

    def on_message_received(self, chat_type: str, sender: str, data: dict):
        if sender == self.username:
            return

        chat_id = f"private_{sender}"

        if chat_id not in self.chats or not self.chats[chat_id].shared_key:
            if chat_id not in self.pending_messages:
                self.pending_messages[chat_id] = []
            self.pending_messages[chat_id].append((sender, data))
            if self.network and self.network.running:
                self.network._send_json({"type": "get_users"})
            return

        chat = self.chats[chat_id]
        try:
            # Проверяем, зашифровано ли сообщение
            if isinstance(data, dict) and "nonce" in data and "ciphertext" in data:
                plaintext = Crypto.decrypt(chat.shared_key, data["nonce"], data["ciphertext"])
            else:
                plaintext = str(data)

            media_type = data.get("media_type", "text") if isinstance(data, dict) else "text"

            if media_type != "text":
                try:
                    file_data = base64.b64decode(plaintext)
                    if media_type == "image":
                        ext = "jpg"
                    elif media_type == "video":
                        ext = "mp4"
                    elif media_type == "audio":
                        ext = "mp3"
                    else:
                        ext = "bin"
                    local_file = f"media_{uuid.uuid4()}.{ext}"
                    with open(local_file, 'wb') as f:
                        f.write(file_data)
                    chat.add_message(sender, f"📎 {media_type.upper()}: {local_file}", False)
                except Exception as e:
                    print(f"Ошибка декодирования медиа: {e}")
                    chat.add_message(sender, plaintext, False)
            else:
                chat.add_message(sender, plaintext, False)

            if chat_id != "saved_messages":
                self.save_chat_to_file(chat_id, chat)

            if self.current_chat_id == chat_id:
                self.switch_chat(chat_id)
            else:
                self.update_chat_list()
        except Exception as e:
            print(f"⚠️ Ошибка расшифровки: {e}")
            self.add_system_message(f"⚠️ Ошибка расшифровки: {e}")

    def _process_pending_messages(self):
        for chat_id, msgs in list(self.pending_messages.items()):
            if chat_id in self.chats and self.chats[chat_id].shared_key:
                chat = self.chats[chat_id]
                for sender, data in msgs:
                    try:
                        if isinstance(data, dict) and "nonce" in data and "ciphertext" in data:
                            plaintext = Crypto.decrypt(chat.shared_key, data["nonce"], data["ciphertext"])
                        else:
                            plaintext = str(data)

                        media_type = data.get("media_type", "text") if isinstance(data, dict) else "text"

                        if media_type != "text":
                            try:
                                file_data = base64.b64decode(plaintext)
                                if media_type == "image":
                                    ext = "jpg"
                                elif media_type == "video":
                                    ext = "mp4"
                                elif media_type == "audio":
                                    ext = "mp3"
                                else:
                                    ext = "bin"
                                local_file = f"media_{uuid.uuid4()}.{ext}"
                                with open(local_file, 'wb') as f:
                                    f.write(file_data)
                                chat.add_message(sender, f"📎 {media_type.upper()}: {local_file}", False)
                            except:
                                chat.add_message(sender, plaintext, False)
                        else:
                            chat.add_message(sender, plaintext, False)
                    except Exception as e:
                        print(f"Ошибка обработки: {e}")

                if self.current_chat_id == chat_id:
                    self.switch_chat(chat_id)
                else:
                    self.update_chat_list()
                del self.pending_messages[chat_id]

    # ==================== UI ====================
    def setup_ui(self):
        self.setWindowTitle("Secure Chat")
        self.resize(1100, 700)

        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_panel.setObjectName("leftPanel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 8, 8)

        self.name_label = QLabel(f"👤 {self.username}")
        self.name_label.setObjectName("nameLabel")
        left_layout.addWidget(self.name_label)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔎 Поиск пользователя...")
        self.search_input.textChanged.connect(self.on_search_text_changed)
        self.search_input.setObjectName("searchInput")
        left_layout.addWidget(self.search_input)

        self.btn_saved = QPushButton("⭐ Избранное")
        self.btn_saved.setObjectName("btnSaved")
        self.btn_saved.clicked.connect(self.open_saved_messages)
        left_layout.addWidget(self.btn_saved)

        # Кнопка выбора фона
        self.btn_bg = QPushButton("🎨")
        self.btn_bg.setFixedSize(40, 40)
        self.btn_bg.setObjectName("btnBg")
        self.btn_bg.clicked.connect(self.choose_background)
        left_layout.addWidget(self.btn_bg)

        self.btn_theme = QPushButton("🌙")
        self.btn_theme.setFixedSize(40, 40)
        self.btn_theme.setObjectName("btnTheme")
        self.btn_theme.clicked.connect(self.toggle_theme)
        left_layout.addWidget(self.btn_theme)

        self.btn_create_group = QPushButton("➕ Создать группу")
        self.btn_create_group.setObjectName("btnCreateGroup")
        self.btn_create_group.clicked.connect(self.create_group)
        left_layout.addWidget(self.btn_create_group)

        left_layout.addWidget(QLabel("📋 Чаты"))
        self.chat_list = QListWidget()
        self.chat_list.setObjectName("chatList")
        self.chat_list.itemClicked.connect(self.chat_selected)
        left_layout.addWidget(self.chat_list)

        left_layout.addWidget(QLabel("👥 Пользователи"))
        self.user_list = QListWidget()
        self.user_list.setObjectName("userList")
        self.user_list.itemClicked.connect(self.user_clicked)
        left_layout.addWidget(self.user_list)

        splitter.addWidget(left_panel)

        right_panel = QWidget()
        right_panel.setObjectName("rightPanel")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.chat_stack = QWidget()
        self.chat_stack.setObjectName("chatStack")
        self.chat_stack_layout = QVBoxLayout(self.chat_stack)
        self.chat_stack_layout.setContentsMargins(0, 0, 0, 0)

        self.empty_chat_label = QLabel("💬 Выберите чат или пользователя")
        self.empty_chat_label.setObjectName("emptyChatLabel")
        self.empty_chat_label.setAlignment(Qt.AlignCenter)
        self.chat_stack_layout.addWidget(self.empty_chat_label)

        right_layout.addWidget(self.chat_stack)
        splitter.addWidget(right_panel)

        splitter.setSizes([320, 780])
        layout.addWidget(splitter)
        self.statusBar().showMessage("Подключено")

        self.apply_background()
        self.apply_theme()

    def on_search_text_changed(self, text: str):
        if not self.network or not self.network.running:
            return
        self.network._send_json({"type": "search_user", "query": text})

    def on_search_results(self, results: List[dict]):
        self.user_list.clear()
        for u in results:
            if u["name"] != self.username:
                self.user_list.addItem(u["name"])

    def apply_theme(self):
        if self.current_theme == "dark":
            # Дополнительные стили для тёмной темы поверх фона
            self.setStyleSheet(self.styleSheet() + """
                QLabel#chatHeader {font-weight: bold; padding: 12px; background-color: #2D2D3A; color: #F3F4F6;}
                QTextBrowser#messagesArea {background-color: #1E1E2E; border: none; padding: 8px; color: #F3F4F6;}
                QLineEdit#inputField {background-color: #3A3A4A; border: none; border-radius: 20px; padding: 10px 16px; color: #F3F4F6;}
                QPushButton#sendButton, QPushButton#callButton, QPushButton#mediaButton {background-color: #7C3AED; border: none; border-radius: 20px; color: white; font-weight: bold;}
                QPushButton#sendButton {padding: 10px 20px;}
                QPushButton#callButton, QPushButton#mediaButton {padding: 10px; font-size: 16px;}
                QPushButton#sendButton:hover {background-color: #9F67FF;}
                QPushButton#callButton:hover {background-color: #9F67FF;}
                QPushButton#mediaButton:hover {background-color: #16A34A;}
                QPushButton#mediaButton {background-color: #22C55E;}
            """)
        else:
            self.setStyleSheet(self.styleSheet() + """
                QLabel#chatHeader {font-weight: bold; padding: 12px; background-color: #FFFFFF; color: #1F2937; border-bottom: 1px solid #E5E7EB;}
                QTextBrowser#messagesArea {background-color: #F8F9FA; border: none; padding: 8px; color: #1F2937;}
                QLineEdit#inputField {background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 20px; padding: 10px 16px; color: #1F2937;}
                QPushButton#sendButton, QPushButton#callButton, QPushButton#mediaButton {background-color: #7C3AED; border: none; border-radius: 20px; color: white; font-weight: bold;}
                QPushButton#sendButton {padding: 10px 20px;}
                QPushButton#callButton, QPushButton#mediaButton {padding: 10px; font-size: 16px;}
                QPushButton#sendButton:hover {background-color: #9F67FF;}
                QPushButton#callButton:hover {background-color: #9F67FF;}
                QPushButton#mediaButton:hover {background-color: #16A34A;}
                QPushButton#mediaButton {background-color: #22C55E;}
            """)

        # Обновляем чаты
        for i in range(self.chat_stack_layout.count()):
            widget = self.chat_stack_layout.itemAt(i).widget()
            if isinstance(widget, ChatWidget):
                widget.update_theme(self.current_theme)

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.btn_theme.setText("☀️" if self.current_theme == "light" else "🌙")
        self.apply_theme()

    def connect_signals(self):
        self.network.user_list_updated.connect(self.on_user_list)
        self.network.user_joined.connect(self.on_user_joined)
        self.network.user_left.connect(self.on_user_left)
        self.network.message_received.connect(self.on_message_received)
        self.network.group_created.connect(self.on_group_created)
        self.network.error_occurred.connect(self.on_error)
        self.network.search_results.connect(self.on_search_results)

        # Сигналы звонков
        self.network.call_incoming.connect(self.on_call_incoming)
        self.network.call_accepted.connect(self.on_call_accepted)
        self.network.call_ice_candidate.connect(self.on_ice_candidate)
        self.network.call_ended.connect(self.on_call_ended)

    def on_user_list(self, users_data: List[dict]):
        print(f"[DEBUG] Получен users_list: {[u['name'] for u in users_data]}")
        self.users.clear()
        for u in users_data:
            self.users[u["name"]] = u["public_key"]

        for name in list(self.users.keys()):
            if name == self.username:
                continue
            chat_id = f"private_{name}"
            if chat_id not in self.chats:
                chat = Chat(chat_id, name, "private")
                chat.shared_key = self.compute_shared_key(name)
                self.load_chat_from_file(chat_id, chat)
                self.chats[chat_id] = chat
                print(f"🔗 Создан чат с {name}")

        self.update_chat_list()
        self._process_pending_messages()

    def on_user_joined(self, name: str, pubkey_b64: str):
        print(f"[DEBUG] Присоединился {name}")
        self.users[name] = pubkey_b64

        chat_id = f"private_{name}"
        if chat_id not in self.chats:
            chat = Chat(chat_id, name, "private")
            chat.shared_key = self.compute_shared_key(name)
            self.load_chat_from_file(chat_id, chat)
            self.chats[chat_id] = chat
            print(f"🔗 Создан чат с новым пользователем {name}")

        self.update_chat_list()
        self.add_system_message(f"🟢 {name} присоединился")

    def compute_shared_key(self, peer_name: str) -> Optional[bytes]:
        if peer_name == self.username:
            return b'\x00' * 32
        if peer_name not in self.users:
            print(f"⚠️ Нет публичного ключа для {peer_name}")
            return None
        try:
            peer_pub = base64.b64decode(self.users[peer_name])
            key = Crypto.derive_shared_key(self.private_key, peer_pub)
            print(f"✅ Ключ для {peer_name} успешно вычислен")
            return key
        except Exception as e:
            print(f"❌ Ошибка вычисления ключа для {peer_name}: {e}")
            return None

    def update_user_list(self):
        self.user_list.clear()
        for name in sorted(self.users.keys()):
            if name != self.username:
                self.user_list.addItem(name)

    def update_chat_list(self):
        self.chat_list.clear()

        if "system" in self.chats:
            item = QListWidgetItem("📢 Система")
            item.setData(Qt.UserRole, "system")
            if self.chats["system"].unread_count > 0:
                item.setText(f"📢 Система ({self.chats['system'].unread_count})")
            self.chat_list.addItem(item)

        if "saved_messages" in self.chats:
            item = QListWidgetItem("⭐ Избранное")
            item.setData(Qt.UserRole, "saved_messages")
            if self.chats["saved_messages"].unread_count > 0:
                item.setText(f"⭐ Избранное ({self.chats['saved_messages'].unread_count})")
            self.chat_list.addItem(item)

        for chat_id, chat in self.chats.items():
            if chat.type == "private" and chat_id not in ["saved_messages"]:
                item = QListWidgetItem(f"💬 {chat.name}")
                item.setData(Qt.UserRole, chat_id)
                if chat.unread_count > 0:
                    item.setText(f"💬 {chat.name} ({chat.unread_count})")
                self.chat_list.addItem(item)

        for chat_id, chat in self.chats.items():
            if chat.type == "group":
                item = QListWidgetItem(f"👥 {chat.name}")
                item.setData(Qt.UserRole, chat_id)
                if chat.unread_count > 0:
                    item.setText(f"👥 {chat.name} ({chat.unread_count})")
                self.chat_list.addItem(item)

    def user_clicked(self, item):
        name = item.text()
        if name == self.username:
            self.open_saved_messages()
            return
        chat_id = f"private_{name}"
        if chat_id not in self.chats:
            chat = Chat(chat_id, name, "private")
            chat.shared_key = self.compute_shared_key(name)
            self.load_chat_from_file(chat_id, chat)
            self.chats[chat_id] = chat
        self.switch_chat(chat_id)

    def open_saved_messages(self):
        chat_id = "saved_messages"
        if chat_id not in self.chats:
            chat = Chat(chat_id, "⭐ Избранное", "private")
            chat.shared_key = b'\x00' * 32
            self.load_chat_from_file(chat_id, chat)
            self.chats[chat_id] = chat
        self.switch_chat(chat_id)

    def load_saved_messages(self):
        if os.path.exists("saved_messages.json"):
            try:
                with open("saved_messages.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                chat = Chat("saved_messages", "⭐ Избранное", "private")
                chat.shared_key = b'\x00' * 32
                for m in data:
                    timestamp_str = m.get("time", "")
                    if timestamp_str and isinstance(timestamp_str, str):
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str)
                        except:
                            timestamp = datetime.now()
                    else:
                        timestamp = datetime.now()
                    msg = Message(
                        sender=m.get("sender", "Unknown"),
                        text=m.get("text", ""),
                        timestamp=timestamp,
                        is_own=m.get("is_own", False)
                    )
                    chat.messages.append(msg)
                self.chats["saved_messages"] = chat
            except:
                self.chats["saved_messages"] = Chat("saved_messages", "⭐ Избранное", "private")
                self.chats["saved_messages"].shared_key = b'\x00' * 32
        else:
            self.chats["saved_messages"] = Chat("saved_messages", "⭐ Избранное", "private")
            self.chats["saved_messages"].shared_key = b'\x00' * 32

    def save_saved_messages(self):
        if "saved_messages" not in self.chats:
            return
        data = []
        for msg in self.chats["saved_messages"].messages:
            data.append({
                "sender": msg.sender,
                "text": msg.text,
                "time": msg.timestamp.isoformat(),
                "is_own": msg.is_own
            })
        with open("saved_messages.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def switch_chat(self, chat_id: str):
        if chat_id not in self.chats:
            return
        self.current_chat_id = chat_id
        chat = self.chats[chat_id]
        chat.mark_read()
        self.update_chat_list()

        while self.chat_stack_layout.count():
            child = self.chat_stack_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        w = ChatWidget(chat, self.current_theme)
        w.send_signal.connect(self.send_message)
        w.send_media_signal.connect(self.send_media)
        w.call_signal.connect(self.start_call_to_user)
        self.chat_stack_layout.addWidget(w)
        self.setWindowTitle(f"Secure Chat - {chat.name}")

    def create_group(self):
        other_users = [u for u in self.users.keys() if u != self.username]
        if not other_users:
            QMessageBox.information(self, "Информация", "Нет других пользователей")
            return
        dialog = CreateGroupDialog(other_users, self)
        if dialog.exec() == QDialog.Accepted:
            group_name, members = dialog.get_data()
            if not group_name or not members:
                return
            if self.username not in members:
                members.append(self.username)
            self.network.create_group(group_name, members)

    def chat_selected(self, item):
        chat_id = item.data(Qt.UserRole)
        if chat_id:
            self.switch_chat(chat_id)

    def on_group_created(self, group_id: str, group_name: str, members: List[str], keys: dict):
        chat = Chat(group_id, f"👥 {group_name}", "group")
        chat.group_keys = keys
        self.chats[group_id] = chat
        self.update_chat_list()
        self.add_system_message(f"✅ Создана группа '{group_name}'")

    def on_error(self, msg: str):
        self.add_system_message(f"❌ {msg}")

    def on_user_left(self, name: str):
        if name in self.users:
            del self.users[name]
        self.update_user_list()
        self.add_system_message(f"🔴 {name} покинул чат")

    def add_system_message(self, text: str):
        if "system" not in self.chats:
            self.chats["system"] = Chat("system", "📢 Система", "system")
        self.chats["system"].add_message("Система", text, False)
        self.update_chat_list()
        if self.current_chat_id == "system":
            self.switch_chat("system")

    def closeEvent(self, event):
        self.auto_save_timer.stop()
        self.auto_delete_timer.stop()
        self.auto_save_all_chats()
        self.save_saved_messages()
        if self.call_in_progress and self.call_manager:
            self.network.end_call()
        if self.network:
            self.network.disconnect()
            self.network.wait(2000)
        event.accept()


class CallManager:
    """Управление WebRTC звонками с шифрованием"""

    def __init__(self, crypto_key: bytes = None):
        self.pc = None
        self.local_stream = None
        self.is_calling = False
        self.crypto_key = crypto_key
        self.ice_candidates = []
        self.loop = None

    async def start_call(self):
        """Начать звонок - создать offer"""
        if not AIORTC_AVAILABLE:
            raise Exception("aiortc не установлен")

        self.pc = RTCPeerConnection()
        self.is_calling = True

        @self.pc.on("icecandidate")
        def on_ice_candidate(candidate):
            if candidate:
                candidate_data = {
                    "candidate": candidate.candidate,
                    "sdpMLineIndex": candidate.sdpMLineIndex,
                    "sdpMid": candidate.sdpMid
                }
                self.ice_candidates.append(candidate_data)

        # Добавляем аудио трек
        try:
            self.local_stream = MediaPlayer("/dev/zero", format="f32le", options={"fsize": 3200})
            self.pc.addTrack(self.local_stream.audio)
        except Exception as e:
            print(f"⚠️ Не удалось добавить аудио: {e}")

        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # Шифруем SDP
        sdp = self.pc.localDescription.sdp
        if self.crypto_key:
            encrypted = Crypto.encrypt(self.crypto_key, sdp)
            return json.dumps(encrypted)
        return sdp

    async def handle_answer(self, sdp_data: str):
        """Обработать ответ от собеседника"""
        try:
            # Дешифруем SDP
            if self.crypto_key:
                data = json.loads(sdp_data)
                if "nonce" in data:
                    sdp = Crypto.decrypt(self.crypto_key, data["nonce"], data["ciphertext"])
                else:
                    sdp = sdp_data
            else:
                sdp = sdp_data

            answer = RTCSessionDescription(sdp=sdp, type="answer")
            await self.pc.setRemoteDescription(answer)
            return True
        except Exception as e:
            print(f"Ошибка обработки ответа: {e}")
            return False

    async def add_ice_candidate(self, candidate_data: str):
        """Добавить ICE кандидат"""
        try:
            # Дешифруем кандидат
            if self.crypto_key:
                data = json.loads(candidate_data)
                if "nonce" in data:
                    candidate_str = Crypto.decrypt(self.crypto_key, data["nonce"], data["ciphertext"])
                else:
                    candidate_str = candidate_data
            else:
                candidate_str = candidate_data

            candidate_dict = json.loads(candidate_str)
            candidate = RTCIceCandidate(
                candidate=candidate_dict["candidate"],
                sdpMLineIndex=candidate_dict["sdpMLineIndex"],
                sdpMid=candidate_dict["sdpMid"]
            )
            await self.pc.addIceCandidate(candidate)
            return True
        except Exception as e:
            print(f"Ошибка добавления ICE: {e}")
            return False

    async def end_call(self):
        """Завершить звонок"""
        self.is_calling = False
        if self.pc:
            await self.pc.close()
            self.pc = None
        self.ice_candidates = []

    def get_ice_candidates(self):
        """Получить накопленные ICE кандидаты"""
        return self.ice_candidates


class ClientApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)

        generate_ssl_certificates()

        self.private_key = None
        self.public_key_bytes = None
        self.user_info = {}
        self.config_file = "user_config.json"
        self.network = None
        self.main_window = None

        self._generate_keys()
        self.load_user_info()
        self.show_login_dialog()

    def _generate_keys(self):
        self.private_key, pub = Crypto.generate_x25519_keypair()
        self.public_key_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def load_user_info(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    self.user_info = json.load(f)
        except:
            self.user_info = {}

    def save_user_info(self):
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.user_info, f)
        except:
            pass

    def show_login_dialog(self):
        dlg = LoginDialog(self.user_info.get("name", ""), self.user_info.get("email", ""))
        if dlg.exec() == QDialog.Accepted:
            res = dlg.result
            self.user_info["name"] = res["name"]
            self.user_info["email"] = res.get("email", "")
            self.save_user_info()

            host, ok = QInputDialog.getText(None, "Подключение", "IP адрес сервера:", QLineEdit.Normal, "localhost")
            if not ok or not host:
                self.quit()
                return

            port, ok = QInputDialog.getInt(None, "Подключение", "Порт:", 5555, 1, 65535)
            if not ok:
                self.quit()
                return

            if res["mode"] == "register":
                self.register_user(host, port, res["name"], res["email"], res["password"])
            else:
                self.login_user(host, port, res["name"], res["password"])
        else:
            self.quit()

    def register_user(self, host, port, name, email, password):
        temp_network = NetworkClient()
        temp_network.register_success.connect(
            lambda: self._on_register_success(temp_network, host, port, name, password))
        temp_network.error_occurred.connect(lambda msg: self._on_temp_error(msg, temp_network))
        temp_network.connect_to_server(host, port, name, email, password, self.public_key_bytes, "register")

    def _on_register_success(self, temp_network, host, port, name, password):
        temp_network.disconnect()
        temp_network.deleteLater()
        self.login_user(host, port, name, password)

    def _on_temp_error(self, msg, temp_network):
        QMessageBox.critical(None, "Ошибка регистрации", msg)
        temp_network.deleteLater()
        self.show_login_dialog()

    def login_user(self, host, port, name, password):
        self.network = NetworkClient()
        self.network.connected.connect(self.on_connected)
        self.network.error_occurred.connect(self.on_error)
        self.network.disconnected.connect(self.on_disconnected)
        self.network.connect_to_server(host, port, name, "", password, self.public_key_bytes, "auth")

    def on_connected(self):
        self.main_window = MainWindow(self.network, self.user_info["name"], self.private_key)
        self.main_window.show()

    def on_error(self, msg):
        QMessageBox.critical(None, "Ошибка", msg)
        if self.network:
            self.network.wait(1500)
            self.network.deleteLater()
            self.network = None
        self.show_login_dialog()

    def on_disconnected(self):
        if self.main_window:
            self.main_window.close()
            self.main_window = None
        if self.network:
            self.network.wait(1500)
            self.network.deleteLater()
            self.network = None
        self.show_login_dialog()


if __name__ == "__main__":
    app = ClientApp(sys.argv)
    app.setStyle("Fusion")
    sys.exit(app.exec())
