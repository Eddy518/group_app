from cryptography.fernet import Fernet


def generate_encryption_key():
    key = Fernet.generate_key()
    print("\nGenerated encryption key:")
    print(f"MESSAGE_ENCRYPTION_KEY={key.decode()}\n")
    print("Add this line to your .env file")


if __name__ == "__main__":
    generate_encryption_key()
