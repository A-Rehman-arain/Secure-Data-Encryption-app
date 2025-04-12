

import streamlit as st
import hashlib
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the encryption key from .env file
key = os.getenv("FERNET_KEY")
if not key:
    raise ValueError("FERNET_KEY is not set in the .env file")

# Create cipher using the key
cipher = Fernet(key)

# ----------------- Helper Functions -----------------

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ----------------- Session State Setup -----------------

if 'users' not in st.session_state:
    st.session_state.users = {}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'page' not in st.session_state:
    st.session_state.page = "login"

# ----------------- Pages -----------------

def login_page():
    st.title("🔑 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = st.session_state.users.get(username)
        if user and user["password"] == hash_text(password):
            st.session_state.current_user = username
            st.success(f"✅ Welcome, {username}!")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")

    st.info("Don't have an account?")
    if st.button("Go to Signup"):
        st.session_state.page = "signup"

def signup_page():
    st.title("📝 Signup")

    new_username = st.text_input("Choose Username")
    new_password = st.text_input("Choose Password", type="password")

    if st.button("Sign Up"):
        if new_username in st.session_state.users:
            st.error("❌ Username already exists!")
        elif not new_username or not new_password:
            st.error("⚠️ Please fill in all fields.")
        else:
            st.session_state.users[new_username] = {
                "password": hash_text(new_password),
                "data": {}
            }
            st.success("✅ Account created!")
            st.session_state.page = "login"
            st.rerun()

    st.info("Already have an account?")
    if st.button("Go to Login"):
        st.session_state.page = "login"

def main_app():
    user = st.session_state.current_user
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.title("🔒 Secure Data Encryption System")
        st.write(f"Welcome, **{user}**!")

    elif choice == "Store Data":
        st.subheader("📂 Store Data")

        label = st.text_input("Enter label for your data:")
        user_data = st.text_area("Enter data to encrypt:")
        passkey = st.text_input("Set a passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey and label:
                encrypted_text = encrypt_data(user_data)
                hashed_passkey = hash_text(passkey)

                st.session_state.users[user]["data"][label] = {
                    "encrypted": encrypted_text,
                    "passkey_hash": hashed_passkey
                }
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("⚠️ All fields are required.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Data")

        labels = list(st.session_state.users[user]["data"].keys())
        if not labels:
            st.info("No data stored yet.")
            return

        selected_label = st.selectbox("Select label:", labels)
        passkey_input = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if selected_label and passkey_input:
                encrypted_entry = st.session_state.users[user]["data"][selected_label]
                hashed_input = hash_text(passkey_input)

                if hashed_input == encrypted_entry["passkey_hash"]:
                    try:
                        decrypted_text = decrypt_data(encrypted_entry["encrypted"])
                        st.success(f"✅ Decrypted Data:\n\n{decrypted_text}")
                        st.session_state.failed_attempts = 0
                    except:
                        st.error("❌ Decryption failed! Data may be corrupted.")
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")

                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. You have been logged out.")
                        st.session_state.current_user = None
                        st.session_state.failed_attempts = 0
                        st.rerun()
            else:
                st.error("⚠️ Please enter a passkey.")

    elif choice == "Logout":
        st.session_state.current_user = None
        st.success("🔓 Logged out successfully.")
        st.rerun()

# ----------------- App Router -----------------

if st.session_state.current_user:
    main_app()
elif st.session_state.page == "signup":
    signup_page()
else:
    login_page()

                    