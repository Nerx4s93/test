# crypto_tool.py
from cryptography.fernet import Fernet
import sys

def load_key(path="secret.key"):
    with open(path, "rb") as f:
        return f.read()

def encrypt_text(text: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(text.encode("utf-8"))

def decrypt_text(token: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode("utf-8")

def encrypt_file(in_path: str, out_path: str, key: bytes):
    f = Fernet(key)
    with open(in_path, "rb") as fin:
        data = fin.read()
    with open(out_path, "wb") as fout:
        fout.write(f.encrypt(data))
    print(f"Файл зашифрован → {out_path}")

def decrypt_file(in_path: str, out_path: str, key: bytes):
    f = Fernet(key)
    with open(in_path, "rb") as fin:
        data = fin.read()
    with open(out_path, "wb") as fout:
        fout.write(f.decrypt(data))
    print(f"Файл расшифрован → {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python crypto_tool.py enc-text 'строка'")
        print("  python crypto_tool.py dec-text <base64>")
        print("  python crypto_tool.py enc-file input.txt output.enc")
        print("  python crypto_tool.py dec-file input.enc output.txt")
        sys.exit(1)

    cmd = sys.argv[1]
    key = load_key()

    if cmd == "enc-text":
        token = encrypt_text(sys.argv[2], key)
        print(token.decode())

    elif cmd == "dec-text":
        print(decrypt_text(sys.argv[2].encode(), key))

    elif cmd == "enc-file":
        encrypt_file(sys.argv[2], sys.argv[3], key)

    elif cmd == "dec-file":
        decrypt_file(sys.argv[2], sys.argv[3], key)

    else:
        print("Неизвестная команда:", cmd)