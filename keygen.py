import secrets

def generate_key_hex() -> str:
    return secrets.token_hex(32)

def generate_iv_hex() -> str:
    return secrets.token_hex(16)

if __name__ == "__main__":
    key_hex = generate_key_hex()
    iv_hex  = generate_iv_hex()
    print("KEY:", key_hex, f"({len(key_hex)} hex chars, {len(key_hex)//2} bytes)")
    print("IV :", iv_hex,  f"({len(iv_hex)} hex chars, {len(iv_hex)//2} bytes)")