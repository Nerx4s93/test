from cryptography.fernet import Fernet

def generate_key(path="secret.key"):
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    print(f"Ключ сохранён в {path}")
    print(f"Ключ (base64): {key.decode()}")

if __name__ == "__main__":
    generate_key()