---
marp: true
title: Cybersecurity with Python Tools
theme: gaia
paginate: true
---

# Cybersecurity with Python Tools

- [octaflop/cyberpython](https://github.com/octaflop/cyberpython)
- ![](./cyberpython_github_repo_qr.png) 

---


# Introduction 🔰

<!-- eta: 3min -->

- Importance of cybersecurity
- Why Python is popular for cybersecurity
<!-- joke: "Why did the hacker cross the road? Because that's where the security was weakest!" -->

---

# Python Basics for Cybersecurity 🐍


<!-- eta: 5min -->

- Key Python libraries: `requests`, `socket`, `scrapy`, `cryptography`
- Setting up a Python environment
- `python3.12 -m venv venv && source venv/bin/activate`
- 
<!-- tip: "Think of virtual environments as your personal cybersecurity lab coats." -->

---

# Network Security Tools 🛜

<!-- eta: 8min -->

## Port Scanning with Python

```python
import socket

def scan_ports(host):
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()

scan_ports('127.0.0.1')
```

<!-- Joke: "Port scanning is like knocking on doors to see if anyone's home... but less creepy." -->

---

## Implementing a Simple Packet Sniffer

- Use scapy to capture and analyze network packets.
- Reference: [GitHub repository](https://github.com/hposton/python-for-cybersecurity/blob/840769d04d2228803fd7493cdaf52c348b5db775/Part_8/8.2_Network_Sniffing/NetworkCredentialSniffing.py#L4) for Python cybersecurity scripts

---


# Web Application Security 🌐

<!-- eta: 8min -->

* Web scraping with beautifulsoup, scrapy, scrapyd; etc
* SQL injection detection: sqlmap
* XSS vuln scanner

---


# Cryptography in Python 🔐

<!-- eta: 8min -->

## Encryption and Decryption using PyCrypto

```python
from Crypto.Cipher import AES
import base64

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

key = b'Sixteen byte key'
message = "Secret Message"
print(encrypt_message(key, message))

```

---

# Demo 🎡

<!-- eta: 14min -->

## Encrypting and decrypting with python

```python
import hashlib
import socket
from cryptography.fernet import Fernet

def hash_password(password):
    # Hash a password using SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()
    print(f"Hashed Password: {hashed}")

def check_open_ports(host, ports):
    # Check if specified ports are open on the given host
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
    print(f"Open Ports on {host}: {open_ports}")

def encrypt_decrypt_message(message):
    # Generate a key for encryption
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    
    # Encrypt the message
    encrypted_message = cipher_suite.encrypt(message.encode())
    print(f"Encrypted Message: {encrypted_message}")
    
    # Decrypt the message
    decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
    print(f"Decrypted Message: {decrypted_message}")

def main():
    # Demonstrate password hashing
    password = "securepassword123"
    hash_password(password)
    
    # Demonstrate checking open ports
    host = "localhost"
    ports = [22, 80, 443, 8080]
    check_open_ports(host, ports)
    
    # Demonstrate encryption and decryption
    message = "Hello, Cybersecurity!"
    encrypt_decrypt_message(message)

if __name__ == "__main__":
    main()
```

---

# Resources

## Long-Form Resources for Further Learning

- [Black Hat Python](https://nostarch.com/black-hat-python2E) 💰
- [Violent Python](https://github.com/tanc7/hacking-books/blob/master/Violent%20Python%20-%20A%20Cookbook%20for%20Hackers,%20Forensic%20Analysts,%20Penetration%20Testers%20and%20Security%20Engineers.pdf) 📖


---

## GitHub repositories for further exploration

- [PeterMosmans/security-scripts](https://github.com/PeterMosmans/security-scripts)


<!-- Joke: "Remember, in cybersecurity, the only thing more important than Python is coffee!" -->

---

## This Repo:


- [octaflop/cyberpython](https://github.com/octaflop/cyberpython)
- ![](./cyberpython_github_repo_qr.png)