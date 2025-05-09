# Web-based-File-Encryption
A secure and user-friendly web application for encrypting and decrypting files using AES-GCM encryption combined with QR code-based multi-factor authentication.

This project ensures your sensitive files are protected with strong encryption, while also leveraging QR codes to add an extra layer of security. Users can easily encrypt any supported file format, generate QR codes for secure key exchange, and later decrypt files by scanning the codes and verifying the passkey — all within a clean, browser-based interface.

 Workflow- 
  1. Encryption: User uploads a file and provides a strong passkey.--->AES-GCM is used to encrypt the file securely.--->Two QR codes are generated:--->One contains the path to the encrypted file.----->One contains the AES key and hashed passkey.

  2. Decryption: User uploads both QR codes and re-enters the original passkey.--->If passkey verification is successful, the file is decrypted.

Features:-  AES-GCM encryption for data integrity and security.
            Passkey strength validation with a retry mechanism.
            QR-based multi-factor authentication.
            Streamlit-powered web interface.

Supports: .txt, .jpg, .jpeg, .png, .pdf.

