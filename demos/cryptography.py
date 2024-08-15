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

