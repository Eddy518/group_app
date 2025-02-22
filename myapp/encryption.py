from cryptography.fernet import Fernet
import os
from base64 import b64encode, b64decode
from dotenv import load_dotenv

load_dotenv()


class MessageEncryption:
    def __init__(self):
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)

    def _get_or_create_key(self):
        # Try to get key from environment variable
        key = os.getenv("MESSAGE_ENCRYPTION_KEY")

        if not key:
            # Generate a new key if none exists
            key = Fernet.generate_key()
            print("\nWARNING: No encryption key found in .env file!")
            print("Add the following line to your .env file:")
            print(f"MESSAGE_ENCRYPTION_KEY={key.decode()}\n")
            return key

        try:
            # Validate the key
            Fernet(key.encode() if isinstance(key, str) else key)
            return key.encode() if isinstance(key, str) else key
        except Exception:
            # If key is invalid, generate a new one
            new_key = Fernet.generate_key()
            print("\nWARNING: Invalid encryption key in .env file!")
            print("Add the following line to your .env file:")
            print(f"MESSAGE_ENCRYPTION_KEY={new_key.decode()}\n")
            return new_key

    def encrypt_message(self, message: str) -> str:
        """Encrypt a message"""
        if not message:
            return message
        encrypted = self.fernet.encrypt(message.encode())
        return b64encode(encrypted).decode()

    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a message"""
        if not encrypted_message:
            return encrypted_message
        try:
            decrypted = self.fernet.decrypt(b64decode(encrypted_message))
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "**Message could not be decrypted**"
