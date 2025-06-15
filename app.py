import streamlit as st
import tempfile
import os
import time
import re
from encryption_module import encrypt_data, generate_qr, derive_key_from_passkey, hash_passkey
from decryption_process import decrypt_data, read_qr

st.title("Secure File Encryption and Decryption")
st.write("Encrypt and decrypt files securely using AES-GCM encryption and QR code-based multi-factor authentication.")

# Track action change to reset decryption attempts
option = st.selectbox("Choose an action", ["Encrypt", "Decrypt"])

if 'last_action' not in st.session_state:
    st.session_state.last_action = option
elif st.session_state.last_action != option:
    st.session_state.attempts = 0
    st.session_state.lock_time = 0
    st.session_state.last_action = option

if option == "Encrypt":
    st.header("File Encryption")
    uploaded_file = st.file_uploader("Upload a file to encrypt", type=["txt", "jpg", "jpeg", "png", "pdf"])
    passkey = st.text_input("Enter a passkey (10-20 characters, must include letters, digits, and special characters):", type="password")

    def is_strong_passkey(passkey):
        return (
            len(passkey) >= 10 and len(passkey) <= 20 and
            re.search(r'[A-Za-z]', passkey) and
            re.search(r'\d', passkey) and
            re.search(r'[^A-Za-z0-9]', passkey)
        )

    if st.button("Encrypt File"):
        if not uploaded_file:
            st.error("❌ Please upload a file to encrypt.")
        elif not is_strong_passkey(passkey):
            st.error("❌ Passkey must be 10–20 characters and include letters, digits, and special characters.")
        else:
            try:
                aes_key = derive_key_from_passkey(passkey)
                file_data = uploaded_file.read()
                encrypted_data = encrypt_data(aes_key, file_data)

                with tempfile.NamedTemporaryFile(delete=False) as enc_file:
                    enc_file.write(encrypted_data)
                    encrypted_file_path = enc_file.name

                encrypted_qr_path = encrypted_file_path + ".png"
                generate_qr(encrypted_file_path, encrypted_qr_path)

                passkey_qr_path = "passkey_qr.png"
                generate_qr(hash_passkey(passkey).hex() + "|" + aes_key.hex(), passkey_qr_path)

                st.session_state.encrypted_qr_path = encrypted_qr_path
                st.session_state.passkey_qr_path = passkey_qr_path

                st.success("File encrypted successfully! Please download the QR codes below.")

            except Exception as e:
                st.error(f"Error: {str(e)}")

    if 'encrypted_qr_path' in st.session_state and 'passkey_qr_path' in st.session_state:
        st.download_button("Download Encrypted File QR Code", open(st.session_state.encrypted_qr_path, "rb").read(), file_name="encrypted_file_qr.png")
        st.download_button("Download Passkey QR Code", open(st.session_state.passkey_qr_path, "rb").read(), file_name="passkey_qr.png")

elif option == "Decrypt":
    st.header("File Decryption")
    qr_file = st.file_uploader("Upload the QR code for the encrypted file", type=["png", "jpg"])
    qr_passkey = st.file_uploader("Upload the QR code for the passkey", type=["png", "jpg"])
    passkey_input = st.text_input("Enter the passkey used during encryption:", type="password")

    if 'attempts' not in st.session_state:
        st.session_state.attempts = 0
    if 'lock_time' not in st.session_state:
        st.session_state.lock_time = 0

    if st.button("Decrypt File"):
        current_time = time.time()

        if st.session_state.attempts >= 3:
            if current_time - st.session_state.lock_time < 60:
                st.warning("⏳ Too many failed attempts. Please wait 1 minute before retrying.")
                st.stop()
            else:
                st.session_state.attempts = 0

        def is_strong_passkey(passkey):
            return (
                len(passkey) >= 8 and
                re.search(r'[A-Za-z]', passkey) and
                re.search(r'\d', passkey) and
                re.search(r'[^A-Za-z0-9]', passkey)
            )

        if not is_strong_passkey(passkey_input):
            st.error("❌ Passkey must be at least 8 characters and include letters, digits, and special characters.")
            st.stop()

        if not qr_file or not qr_passkey:
            st.error("❌ Please upload both QR codes.")
            st.stop()

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as file_temp:
                file_temp.write(qr_file.read())
                encrypted_file_qr = file_temp.name

            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as passkey_temp:
                passkey_temp.write(qr_passkey.read())
                passkey_qr = passkey_temp.name

            encrypted_file_path = read_qr(encrypted_file_qr)
            passkey_data = read_qr(passkey_qr)

            if not encrypted_file_path or not passkey_data:
                st.error("❌ Invalid QR code data!")
                st.stop()

            stored_passkey, stored_aes_key = passkey_data.split("|")
            aes_key = bytes.fromhex(stored_aes_key)

            if hash_passkey(passkey_input).hex() == stored_passkey:
                with open(encrypted_file_path, "rb") as enc_file:
                    encrypted_data = enc_file.read()

                decrypted_data = decrypt_data(aes_key, encrypted_data)

                decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
                with open(decrypted_file_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)

                st.session_state.attempts = 0
                st.success("✅ Decryption successful!")
                with open(decrypted_file_path, "rb") as file:
                    st.download_button("Download Decrypted File", file.read(), file_name="decrypted_output")

            else:
                st.session_state.attempts += 1
                if st.session_state.attempts >= 3:
                    st.session_state.lock_time = time.time()
                    st.error("❌ Too many incorrect attempts. Locked for 1 minute.")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.attempts}")

        except Exception as e:
            st.error(f"❌ Decryption failed: {str(e)}")
