import cv2
from Crypto.Cipher import AES

def decrypt_data(aes_key, encrypted_data):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Function to read QR code using OpenCV
def read_qr(qr_path):
    image = cv2.imread(qr_path)
    if image is None:
        print(f"❌ Failed to load image from path: {qr_path}")
        return None
    detector = cv2.QRCodeDetector()  # Corrected this line
    data, _, _ = detector.detectAndDecode(image)
    if data:
        return data
    else:
        print("Failed to decode QR code!")
        return None
