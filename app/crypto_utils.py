from cryptography.fernet import Fernet
import os
import hmac
import hashlib

# In real systems, store this in environment variables
SECRET_KEY = os.environ.get("TRUSTLEASE_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = Fernet.generate_key().decode()

fernet = Fernet(SECRET_KEY.encode())

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

def generate_hmac(data: str, key: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()