# Secure Client-Server Communication (AES-128-CBC + HMAC)

This project implements a **secure bidirectional TCP client-server communication system** using AES-128-CBC encryption and HMAC for message integrity. Both the client and server can send and receive encrypted messages in real time.

---

## 🛡️ Features

- **AES-128-CBC encryption** for confidentiality
- **HMAC-SHA256** for integrity verification
- **Bidirectional messaging** (both server and client can send messages)
- **Multi-threaded** communication
- **Secure key-based message exchange**

---

## 🧠 How It Works

Each message exchanged between the client and server is:
1. Encrypted using **AES-128-CBC** with a randomly generated IV.
2. The IV and ciphertext are combined and authenticated with an **HMAC**.
3. The receiver verifies the HMAC before decrypting the message.

This ensures that messages are confidential and tamper-proof.

---

## 🧰 Requirements

Install dependencies before running the code:

```bash
pip install pycryptodome
```

---

## 🚀 Running the Server

1. Open a terminal and run the server:

```bash
python server.py
```

You should see:
```
[*] Server listening on 0.0.0.0:5550
```

---

## 💬 Running the Client

1. In another terminal (or machine), run the client:

```bash
python client.py 127.0.0.1 5550
```

2. You’ll see:
```
[+] Connected to 127.0.0.1:5550
```

3. Type messages and press **Enter** to send.
4. Type `quit` to exit.

---

## 🔄 Communication Flow

```
Client  --->  [Encrypt + HMAC]  --->  Server
Server  --->  [Encrypt + HMAC]  --->  Client
```

- Each message includes:
  - 16-byte IV
  - AES-encrypted ciphertext
  - 32-byte HMAC for verification

---

## 📁 File Structure

```
Secure_Client_Server_Program/
├── client.py        # Client-side code
├── server.py        # Server-side code
└── README.md        # Documentation (this file)
```

---

## ⚠️ Notes

- Ensure both **client** and **server** use the **same AES and HMAC keys**.
- You can change the port and IP address if needed.
- Always keep your encryption keys secret.

---

## 🧩 Example Interaction

```
Server: [*] Server listening on 0.0.0.0:5550
Client: [+] Connected to 127.0.0.1:5550

Client → Server: Hello Server!
Server → Client: Hello Client!
```

---

## 👨‍💻 Author

Developed by **Saikumar**  
For educational and security learning purposes.
