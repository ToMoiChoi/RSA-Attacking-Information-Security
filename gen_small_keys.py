"""
Script tạo cặp khóa RSA nhỏ (64-bit n) và mã hóa file demo.txt
để tấn công Trial Division / Wiener có thể phá được.

Output:
  - public_key.pem   (PKCS#8 SubjectPublicKeyInfo)
  - private_key.pem  (PKCS#8 PrivateKeyInfo - simplified)
  - encrypt_file.bin (ciphertext dạng nhị phân)
"""
import random, math, os, base64, struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Toán học RSA ────────────────────────────────────────
def miller_rabin(n, k=20):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p

def mod_inv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1: return None
    return x % m

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

# ─── ASN.1 DER helpers ──────────────────────────────────
def der_integer(n):
    """Encode an integer as DER INTEGER."""
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b'\x00'
    if b[0] & 0x80:          # nếu bit đầu = 1 thì thêm 0x00 phía trước
        b = b'\x00' + b
    return b'\x02' + der_length(len(b)) + b

def der_length(l):
    if l < 0x80:
        return bytes([l])
    enc = l.to_bytes((l.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(enc)]) + enc

def der_sequence(*items):
    body = b''.join(items)
    return b'\x30' + der_length(len(body)) + body

def der_bitstring(content):
    body = b'\x00' + content       # 0 unused bits
    return b'\x03' + der_length(len(body)) + body

def der_null():
    return b'\x05\x00'

def der_oid_rsa():
    """OID 1.2.840.113549.1.1.1 (rsaEncryption)"""
    return b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'

def make_public_key_pem(e, n):
    """Tạo SubjectPublicKeyInfo PEM (PKCS#8 public key)."""
    rsa_pub = der_sequence(der_integer(n), der_integer(e))
    algo_id = der_sequence(der_oid_rsa(), der_null())
    spki = der_sequence(algo_id, der_bitstring(rsa_pub))
    b64 = base64.encodebytes(spki).decode('ascii').strip()
    return f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"

def make_private_key_pem(n, e, d, p, q):
    """Tạo PKCS#1 RSAPrivateKey wrapped in PKCS#8 PrivateKeyInfo."""
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inv(q, p)
    rsa_priv = der_sequence(
        der_integer(0),     # version
        der_integer(n),
        der_integer(e),
        der_integer(d),
        der_integer(p),
        der_integer(q),
        der_integer(dp),
        der_integer(dq),
        der_integer(qinv),
    )
    algo_id = der_sequence(der_oid_rsa(), der_null())
    # Wrap in PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
    octet_priv = b'\x04' + der_length(len(rsa_priv)) + rsa_priv
    pkcs8 = der_sequence(der_integer(0), algo_id, octet_priv)
    b64 = base64.encodebytes(pkcs8).decode('ascii').strip()
    return f"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n"


# ─── Main ────────────────────────────────────────────────
def main():
    KEY_BITS = 16   # n sẽ khoảng 16-bit → dễ dàng bị phân tích thừa số

    print(f"Đang tạo khóa RSA {KEY_BITS}-bit...")
    p = gen_prime(KEY_BITS // 2)    # 32-bit prime
    q = gen_prime(KEY_BITS // 2)    # 32-bit prime
    while p == q:
        q = gen_prime(KEY_BITS // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = mod_inv(e, phi)

    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {n}  ({n.bit_length()} bit)")
    print(f"  e = {e}")
    print(f"  d = {d}")

    # ── Mã hóa file demo.txt (Block mode) ──
    demo_path = os.path.join(SCRIPT_DIR, "demo.txt")
    with open(demo_path, "r", encoding="utf-8") as f:
        plaintext = f.read().strip()
    print(f"\n  Plaintext: \"{plaintext}\"")

    c_bytes_len = (n.bit_length() + 7) // 8
    
    ciphertext_bytes = b''
    m_check_list = []
    
    # Mã hóa từng byte (kích thước block plaintext = 1 byte, vì n 16-bit > 255)
    for byte_val in plaintext.encode('utf-8'):
        c_block = pow(byte_val, e, n)
        ciphertext_bytes += c_block.to_bytes(c_bytes_len, 'big')
        
        # Kiểm tra giải mã
        m_block_check = pow(c_block, d, n)
        m_check_list.append(m_block_check)
        assert m_block_check == byte_val, f"Lỗi giải mã block! {m_block_check} != {byte_val}"

    c_int = int.from_bytes(ciphertext_bytes, 'big')
    print(f"  C (integer ghép) = {c_int}")
    print(f"  ✅ Giải mã đúng: {''.join(chr(b) for b in m_check_list)}")

    # ── Ghi file ──
    pub_pem = make_public_key_pem(e, n)
    priv_pem = make_private_key_pem(n, e, d, p, q)

    pub_path = os.path.join(SCRIPT_DIR, "public_key.pem")
    priv_path = os.path.join(SCRIPT_DIR, "private_key.pem")
    bin_path = os.path.join(SCRIPT_DIR, "encrypt_file.bin")

    with open(pub_path, "w") as f:
        f.write(pub_pem)
    print(f"\n  → Đã ghi {pub_path} ({os.path.getsize(pub_path)} bytes)")

    with open(priv_path, "w") as f:
        f.write(priv_pem)
    print(f"  → Đã ghi {priv_path} ({os.path.getsize(priv_path)} bytes)")

    # Ghi ciphertext dạng binary (chứa tất cả các block)
    with open(bin_path, "wb") as f:
        f.write(ciphertext_bytes)
    print(f"  → Đã ghi {bin_path} ({os.path.getsize(bin_path)} bytes)")

    print(f"\n✅ Hoàn tất! Key {KEY_BITS}-bit, tấn công Trial Division sẽ phá được.")

if __name__ == "__main__":
    main()
