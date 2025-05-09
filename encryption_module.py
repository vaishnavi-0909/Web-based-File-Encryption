import os
import hashlib
from Crypto.Cipher import AES
import qrcode
import cv2

# Function to hash the passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).digest()

# Function to encrypt data using AES-GCM
def encrypt_data(aes_key, data):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

# Function to generate a QR code from data
def generate_qr(data, output_path):
    qr = qrcode.make(data)
    qr.save(output_path)

# Function to read QR code from a file
def read_qr(qr_path):
    image = cv2.imread(qr_path)
    if image is None:
        return None
    detector = cv2.QCodeDetector()
    data, _, _ = detector.detectAndDecode(image)
    return data

# Function to derive AES key from passkey (hashing twice)
def derive_key_from_passkey(passkey):
    hashed_passkey = hash_passkey(passkey)
    aes_key = hash_passkey(hashed_passkey.hex())  # Derive AES key
    return aes_key
