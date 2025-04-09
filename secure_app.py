import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🔑 Utilities
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def generate_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

# 📦 Initialize session state
if "users" not in st.session_state:
    st.session_state.users = {}  # username: {password, cipher, stored_data}

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# 🔐 Auth Functions
def register_user(username, password):
    if username in st.session_state.users:
        return False
    st.session_state.users[username] = {
        "password": hash_text(password),
        "cipher": generate_cipher(),
        "stored_data": []
    }
    return True

def login_user(username, password):
    user = st.session_state.users.get(username)
    if user and user["password"] == hash_text(password):
        st.session_state.current_user = username
        st.session_state.failed_attempts = 0
        return True
    return False

# 🧠 Encryption Functions
def encrypt_data(text, cipher):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, user_data):
    hashed = hash_text(passkey)
    for record in user_data:
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return record["cipher"].decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# 📲 Streamlit UI
st.title("🔒 Multi-User Secure Data System")

# Sidebar Navigation
menu = ["Home", "Sign Up", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# 🏠 Home Page
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Securely **store and retrieve** data with multi-user authentication.")

# 🆕 Sign Up
elif choice == "Sign Up":
    st.subheader("🆕 Create an Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Sign Up"):
        if register_user(new_user, new_pass):
            st.success("✅ Account created! You can now log in.")
        else:
            st.error("❌ Username already exists.")

# 🔑 Login
elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_user(username, password):
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid credentials")

# 📥 Store Data
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📥 Store Your Data")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                user = st.session_state.users[st.session_state.current_user]
                encrypted = encrypt_data(user_data, user["cipher"])
                hashed = hash_text(passkey)
                user["stored_data"].append({
                    "encrypted_text": encrypted,
                    "passkey": hashed,
                    "cipher": user["cipher"]
                })
                st.success("✅ Data encrypted and saved!")
                st.code(encrypted)
            else:
                st.error("⚠️ Both fields are required!")

# 📤 Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login first.")
    elif st.session_state.failed_attempts >= 3:
        st.warning("❌ Too many failed attempts. Please login again.")
        st.session_state.current_user = None
        st.rerun()
    else:
        st.subheader("📤 Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Text:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                user = st.session_state.users[st.session_state.current_user]
                decrypted = decrypt_data(encrypted_text, passkey, user["stored_data"])
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted)
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect! Attempts left: {attempts_left}")
            else:
                st.error("⚠️ Both fields are required!")

# 🚪 Logout
elif choice == "Logout":
    if st.session_state.current_user:
        st.success(f"👋 Logged out {st.session_state.current_user}")
    st.session_state.current_user = None
