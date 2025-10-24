import socket
import threading
import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = "127.0.0.1"
PORT = 5550

AES_KEY = b"0123456789abcdef"
HMAC_KEY = b"my_hmac_secret"

def encrypt_message(msg: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg, AES.block_size))
    mac = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + mac

def decrypt_message(data: bytes) -> bytes:
    iv = data[:16]
    mac_received = data[-32:]
    ciphertext = data[16:-32]
    mac_calc = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_calc):
        raise ValueError("HMAC verification failed")
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def send_encrypted(sock, msg: bytes):
    enc = encrypt_message(msg)
    sock.sendall(len(enc).to_bytes(4, "big") + enc)

def recv_encrypted(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet:
            return None
        data += packet
    return decrypt_message(data)

def receive_loop(sock):
    while True:
        try:
            msg = recv_encrypted(sock)
            if msg is None:
                break
            print(f"[Server] {msg.decode()}")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

def send_loop(sock):
    while True:
        msg = input("Enter message (or 'quit'): ")
        if msg.lower() == "quit":
            break
        send_encrypted(sock, msg.encode())

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[+] Connected to {HOST}:{PORT}")

    threading.Thread(target=receive_loop, args=(sock,), daemon=True).start()
    send_loop(sock)
    sock.close()

if __name__ == "__main__":
    main()