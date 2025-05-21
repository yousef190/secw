import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# مفتاح التشفير (16 بايت)
KEY = b'234567890abcdef1234567890abcdef1'  # الآن طوله 32 بايت

def encrypt_file(input_file_path, output_file_path):
    cipher = AES.new(KEY, AES.MODE_CFB)
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(plaintext)
    with open(output_file_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)  # نخزن الـ IV في أول الملف

def decrypt_file(input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f:
        iv = f.read(16)  # أول 16 بايت هما الـ IV
        ciphertext = f.read()
    cipher = AES.new(KEY, AES.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

# توقيع الملف
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_file(file_path):
    try:
        with open("private_key.pem", "rb") as key_file:
            key_data = key_file.read()
            private_key = RSA.import_key(key_data)
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")

    with open(file_path, "rb") as f:
        file_data = f.read()

    h = SHA256.new(file_data)
    signature = pkcs1_15.new(private_key).sign(h)

    with open(file_path + ".sig", "wb") as sig_file:
        sig_file.write(signature)

# التحقق من التوقيع
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_signature(file_path, signature_path):
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = RSA.import_key(key_file.read())

        with open(file_path, "rb") as f:
            file_data = f.read()
        h = SHA256.new(file_data)

        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        print("Verification error:", str(e))
        return False

