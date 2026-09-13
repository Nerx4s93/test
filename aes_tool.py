#!/usr/bin/env python3
"""
AES-256-CBC утилита, совместимая с C++ DecryptAES256 (CryptoAPI).

Формат входных/выходных данных:
  - key : hex-строка, 64 символа (32 байта)
  - iv  : hex-строка, 32 символа (16 байт)
  - data: hex-строка (по умолчанию) или --raw для чтения из файла / stdin

Использование:
  # Сгенерировать ключ и IV
  python aes_tool.py genkey

  # Зашифровать строку (текст -> hex-шифротекст в stdout)
  python aes_tool.py encrypt --key <hex> --iv <hex> --text "Hello"

  # Расшифровать hex-шифротекст
  python aes_tool.py decrypt --key <hex> --iv <hex> --hex <hex_ct>

  # Работа с файлами:
  #   --in  — откуда читать (файл),
  #   --out — куда писать (файл).
  #   Формат вывода управляется флагом --format {auto,hex,raw}.
  #     encrypt, auto: файл -> raw, stdout -> hex
  #     decrypt, auto: всегда raw (как есть), hex-фолбэк для stdout
  python aes_tool.py encrypt --key <hex> --iv <hex> --in plain.txt --out ct.bin
  python aes_tool.py decrypt --key <hex> --iv <hex> --in ct.bin    --out plain.txt

  # Явно задать формат вывода:
  python aes_tool.py encrypt --key <hex> --iv <hex> --in plain.txt --out ct.hex --format hex
  python aes_tool.py decrypt --key <hex> --iv <hex> --in ct.bin  --format hex
  python aes_tool.py encrypt --key <hex> --iv <hex> --text "Hi" --format raw | xxd

  # Пайпы: stdin -> stdout
  cat plain.txt | python aes_tool.py encrypt --key <hex> --iv <hex> > ct.hex
  cat ct.bin    | python aes_tool.py decrypt --key <hex> --iv <hex> --format raw
"""

import argparse
import secrets
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY_SIZE = 32  # AES-256


# ---------- Валидация ----------

def parse_hex(value: str, expected_bytes: int, name: str) -> bytes:
    """Преобразует hex-строку в байты с проверкой длины."""
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        sys.exit(f"[-] {name}: не является корректной hex-строкой")
    if len(raw) != expected_bytes:
        sys.exit(f"[-] {name}: ожидалось {expected_bytes} байт "
                 f"({expected_bytes*2} hex-символов), получено {len(raw)}")
    return raw


# ---------- Крипто-операции ----------

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC с PKCS#7-паддингом (как CryptEncrypt в CryptoAPI)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC со снятием PKCS#7-паддинга (как CryptDecrypt(..., TRUE, ...))."""
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        sys.exit(f"[-] Шифротекст должен быть кратен {BLOCK_SIZE} байтам "
                 f"(получено {len(ciphertext)})")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except ValueError:
        sys.exit("[-] Ошибка снятия паддинга: неверный ключ, IV или повреждённые данные")


def generate_key_hex() -> str:
    return secrets.token_hex(KEY_SIZE)


def generate_iv_hex() -> str:
    return secrets.token_hex(BLOCK_SIZE)


# ---------- CLI ----------

def read_input_bytes(args) -> bytes:
    """Возвращает входные данные в виде байт (для шифрования)."""
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.infile is not None:
        with open(args.infile, "rb") as f:
            return f.read()
    if sys.stdin.isatty():
        sys.exit("[-] Укажите --text, --in или передайте данные через stdin")
    return sys.stdin.buffer.read()


def read_ciphertext_bytes(args) -> bytes:
    """Возвращает шифротекст в виде байт (для расшифровки)."""
    if args.hex is not None:
        try:
            return bytes.fromhex(args.hex)
        except ValueError:
            sys.exit("[-] --hex: некорректная hex-строка")
    if args.infile is not None:
        # Файл может быть как бинарным шифротекстом, так и текстовым hex-файлом.
        with open(args.infile, "rb") as f:
            raw = f.read()
        stripped = raw.strip()
        if stripped and all(c in b"0123456789abcdefABCDEF \r\n\t" for c in stripped):
            try:
                return bytes.fromhex(stripped.decode("ascii"))
            except ValueError:
                pass
        return raw
    if sys.stdin.isatty():
        sys.exit("[-] Укажите --hex, --in или передайте данные через stdin")
    return sys.stdin.buffer.read()


def write_output(data: bytes, args, as_hex: bool):
    """Пишет результат в файл или stdout (hex или raw)."""
    if args.outfile:
        if as_hex:
            with open(args.outfile, "w", encoding="ascii") as f:
                f.write(data.hex())
        else:
            with open(args.outfile, "wb") as f:
                f.write(data)
        return

    # stdout
    if as_hex:
        print(data.hex())
    else:
        try:
            sys.stdout.write(data.decode("utf-8"))
            if not data.endswith(b"\n"):
                sys.stdout.write("\n")
        except UnicodeDecodeError:
            # не текст — выведем hex
            print(data.hex())


def resolve_format(args, command: str) -> str:
    """
    Определяет фактический формат вывода: 'hex' или 'raw'.

    Приоритет:
      1) явные устаревшие флаги --raw-output / --hex-output (для совместимости),
      2) --format {auto,hex,raw},
      3) значение 'auto' по умолчанию, зависящее от команды и наличия --out.
    """
    # 1) старые флаги
    if getattr(args, "raw_output", False) and getattr(args, "hex_output", False):
        sys.exit("[-] Нельзя одновременно указывать --raw-output и --hex-output")
    if getattr(args, "raw_output", False):
        return "raw"
    if getattr(args, "hex_output", False):
        return "hex"

    # 2) --format
    fmt = getattr(args, "format", "auto")
    if fmt in ("hex", "raw"):
        return fmt

    # 3) auto
    if command == "encrypt":
        # файл -> raw, stdout -> hex
        return "raw" if args.outfile else "hex"
    if command == "decrypt":
        # по умолчанию пишем как есть
        return "raw"
    return "raw"


def cmd_genkey(_args):
    key = generate_key_hex()
    iv = generate_iv_hex()
    print(f"KEY = {key}")
    print(f"IV  = {iv}")


def cmd_encrypt(args):
    key = parse_hex(args.key, KEY_SIZE, "key")
    iv = parse_hex(args.iv, BLOCK_SIZE, "iv")
    plaintext = read_input_bytes(args)
    ct = encrypt(plaintext, key, iv)
    fmt = resolve_format(args, "encrypt")
    write_output(ct, args, as_hex=(fmt == "hex"))


def cmd_decrypt(args):
    key = parse_hex(args.key, KEY_SIZE, "key")
    iv = parse_hex(args.iv, BLOCK_SIZE, "iv")
    ct = read_ciphertext_bytes(args)
    pt = decrypt(ct, key, iv)
    fmt = resolve_format(args, "decrypt")
    write_output(pt, args, as_hex=(fmt == "hex"))


def add_format_args(sp):
    """Общие флаги формата вывода для encrypt/decrypt."""
    sp.add_argument(
        "--format",
        choices=("auto", "hex", "raw"),
        default="auto",
        help="формат вывода: auto (по умолчанию), hex или raw (бинарь)",
    )
    # Устаревшие алиасы — сохранены для обратной совместимости.
    sp.add_argument("--raw-output", action="store_true",
                    help="алиас --format raw")
    sp.add_argument("--hex-output", action="store_true",
                    help="алиас --format hex")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AES-256-CBC шифрование/расшифровка (совместимо с CryptoAPI)"
    )
    sub = p.add_subparsers(dest="command", required=True)

    # genkey
    sp = sub.add_parser("genkey", help="сгенерировать ключ и IV")
    sp.set_defaults(func=cmd_genkey)

    # encrypt
    sp = sub.add_parser("encrypt", help="зашифровать данные")
    sp.add_argument("--key", required=True, help="ключ, 64 hex-символа")
    sp.add_argument("--iv", required=True, help="IV, 32 hex-символа")
    sp.add_argument("--text", help="открытый текст (строка)")
    sp.add_argument("--in", dest="infile",
                    help="файл с открытым текстом (бинарный/текстовый)")
    sp.add_argument("--out", dest="outfile",
                    help="файл для шифротекста")
    add_format_args(sp)
    sp.set_defaults(func=cmd_encrypt)

    # decrypt
    sp = sub.add_parser("decrypt", help="расшифровать данные")
    sp.add_argument("--key", required=True, help="ключ, 64 hex-символа")
    sp.add_argument("--iv", required=True, help="IV, 32 hex-символа")
    sp.add_argument("--hex", dest="hex", help="шифротекст как hex-строка")
    sp.add_argument("--in", dest="infile",
                    help="файл с шифротекстом (бинарь или hex-текст)")
    sp.add_argument("--out", dest="outfile",
                    help="файл для открытого текста")
    add_format_args(sp)
    sp.set_defaults(func=cmd_decrypt)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()