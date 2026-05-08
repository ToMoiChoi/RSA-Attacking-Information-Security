import random, math, os, base64

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
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b'\x00'
    if b[0] & 0x80:
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
    body = b'\x00' + content
    return b'\x03' + der_length(len(body)) + body

def der_null():
    return b'\x05\x00'

def der_oid_rsa():
    return b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'

def make_public_key_pem(e, n):
    rsa_pub = der_sequence(der_integer(n), der_integer(e))
    algo_id = der_sequence(der_oid_rsa(), der_null())
    spki = der_sequence(algo_id, der_bitstring(rsa_pub))
    b64 = base64.encodebytes(spki).decode('ascii').strip()
    return f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"

def make_private_key_pem(n, e, d, p, q):
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inv(q, p)
    rsa_priv = der_sequence(
        der_integer(0), der_integer(n), der_integer(e), der_integer(d),
        der_integer(p), der_integer(q), der_integer(dp), der_integer(dq),
        der_integer(qinv)
    )
    algo_id = der_sequence(der_oid_rsa(), der_null())
    octet_priv = b'\x04' + der_length(len(rsa_priv)) + rsa_priv
    pkcs8 = der_sequence(der_integer(0), algo_id, octet_priv)
    b64 = base64.encodebytes(pkcs8).decode('ascii').strip()
    return f"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n"

# ─── Main ────────────────────────────────────────────────
def main():
    KEY_BITS = 16   # n 16-bit -> Trial division VÀ Wiener đều phá được

    print(f"Đang tạo khóa RSA {KEY_BITS}-bit (vulnerable to Wiener's Attack)...")
    
    import decimal
    decimal.getcontext().prec = 350

    while True:
        # Chọn p, q sao cho q < p < 2q
        while True:
            p = gen_prime(KEY_BITS // 2)
            q = gen_prime(KEY_BITS // 2)
            if q > p:
                p, q = q, p
            if p < 2 * q:
                break

        n = p * q
        phi = (p - 1) * (q - 1)
        
        n_dec = decimal.Decimal(n)
        n_root_4 = n_dec ** decimal.Decimal('0.25')
        max_d = int(decimal.Decimal('0.3333333333333333') * n_root_4)
        
        # Nếu max_d quá nhỏ (<3), thử lại cặp p, q khác
        if max_d < 3:
            continue

        valid_d_found = False
        # Thử tìm d trong khoảng cho phép
        for d_candidate in range(3, max_d + 1):
            if math.gcd(d_candidate, phi) == 1:
                e = mod_inv(d_candidate, phi)
                if e is not None:
                    d = d_candidate
                    valid_d_found = True
                    break
        
        if valid_d_found:
            break
        # Nếu không tìm được d nào hợp lệ, quay lại tạo p, q mới

    print(f"  n = {n}  ({n.bit_length()} bit)")
    print(f"  e = {e}  ({e.bit_length()} bit)")
    print(f"  d = {d}  ({d.bit_length()} bit - RẤT NHỎ!)")

    # ── Mã hóa file demo.txt (Block mode) ──
    demo_path = os.path.join(SCRIPT_DIR, "demo.txt")
    with open(demo_path, "r", encoding="utf-8") as f:
        plaintext = f.read().strip()
    print(f"\n  Plaintext: \"{plaintext}\"")

    c_bytes_len = (n.bit_length() + 7) // 8
    
    ciphertext_bytes = b''
    m_check_list = []
    
    for byte_val in plaintext.encode('utf-8'):
        c_block = pow(byte_val, e, n)
        ciphertext_bytes += c_block.to_bytes(c_bytes_len, 'big')
        m_block_check = pow(c_block, d, n)
        m_check_list.append(m_block_check)
        assert m_block_check == byte_val, f"Lỗi giải mã block! {m_block_check} != {byte_val}"

    print(f"  ✅ Giải mã đúng: {''.join(chr(b) for b in m_check_list)}")

    # ── Ghi file ──
    pub_pem = make_public_key_pem(e, n)
    priv_pem = make_private_key_pem(n, e, d, p, q)

    pub_path = os.path.join(SCRIPT_DIR, "public_key.pem")
    priv_path = os.path.join(SCRIPT_DIR, "private_key.pem")
    bin_path = os.path.join(SCRIPT_DIR, "encrypt_file.bin")

    with open(pub_path, "w") as f:
        f.write(pub_pem)
    with open(priv_path, "w") as f:
        f.write(priv_pem)
    with open(bin_path, "wb") as f:
        f.write(ciphertext_bytes)

    print(f"\n✅ Hoàn tất! Key {KEY_BITS}-bit (d={d.bit_length()} bit). Tấn công Wiener sẽ thành công.")

if __name__ == "__main__":
    main()
