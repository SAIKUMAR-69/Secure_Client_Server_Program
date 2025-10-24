import socket
import threading
import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
#python client.py 127.0.0.1 5550

HOST = "0.0.0.0"
PORT = 5550

AES_KEY = b"0123456789abcdef"  # 16 bytes for AES-128
HMAC_KEY = b"my_hmac_secret"   # HMAC key

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

def client_receive_loop(conn, addr):
    while True:
        try:
            msg = recv_encrypted(conn)
            if msg is None:
                break
            print(f"\nClient says: {msg.decode()}")
        except Exception as e:
            print(f"[!] Error with {addr}: {e}")
            break
    conn.close()
    print(f"[-] Connection closed: {addr}")

def client_send_loop(conn, addr):
    while True:
        msg = input(f"Server message to {addr}: ")
        if msg.lower() == "quit":
            break
        try:
            send_encrypted(conn, msg.encode())
        except:
            break

def handle_client(conn, addr):
    threading.Thread(target=client_receive_loop, args=(conn, addr), daemon=True).start()
    threading.Thread(target=client_send_loop, args=(conn, addr), daemon=True).start()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        print(f"[+] Connected: {addr}")
        handle_client(conn, addr)

if __name__ == "__main__":
    main()