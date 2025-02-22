# myapp/utils.py
import re
from myapp import db
from cryptography.fernet import Fernet
import os
from base64 import b64encode, b64decode
from dotenv import load_dotenv

load_dotenv()


def handle_points(message, sender_id, User):
    """Parse messages for @username++ and award points"""
    pattern = r"@(\w+)\+\+"
    matches = re.finditer(pattern, message)
    recipients = []

    for match in matches:
        username = match.group(1)
        recipient = User.query.filter_by(username=username).first()

        if recipient and recipient.id != sender_id:
            recipient.points += 1
            recipients.append(
                {"username": recipient.username, "new_points": recipient.points}
            )

            try:
                db.session.commit()
            except:
                db.session.rollback()
                return []

    return recipients


class MessageEncryption:
    def __init__(self):
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)

    def _get_or_create_key(self):
        key = os.getenv("MESSAGE_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key()
            print(f"\nGenerated new encryption key: {key.decode()}\n")
        return key.encode() if isinstance(key, str) else key

    def encrypt(self, message: str) -> str:
        if not message:
            return message
        return self.fernet.encrypt(message.encode()).decode()

    def decrypt(self, encrypted_message: str) -> str:
        if not encrypted_message:
            return encrypted_message
        try:
            return self.fernet.decrypt(encrypted_message.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "**Message could not be decrypted**"
