# attack_ui.py
# Tkinter UI for RSA Attack Simulation

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import attack_src
import math
import os
import struct
import base64

# Constants
BRUTE_FORCE_LIMIT = 1000000

# Default file paths (same directory as script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PUBLIC_KEY_FILE  = os.path.join(SCRIPT_DIR, "public_key.txt")
DEFAULT_CIPHERTEXT_FILE  = os.path.join(SCRIPT_DIR, "ciphertext.txt")
DEFAULT_PEM_FILE         = os.path.join(SCRIPT_DIR, "public_key.pem")
DEFAULT_BIN_FILE         = os.path.join(SCRIPT_DIR, "encrypt_file.bin")

# ─────────────────────────────────────────────
# ASN.1 helpers – parse SubjectPublicKeyInfo PEM
# ─────────────────────────────────────────────
def _asn1_length(der, idx):
    """Return (length, next_idx) from a DER-encoded length field."""
    b = der[idx]
    if b < 0x80:
        return b, idx + 1
    num_bytes = b & 0x7F
    length = int.from_bytes(der[idx+1 : idx+1+num_bytes], 'big')
    return length, idx + 1 + num_bytes

def parse_pem_public_key(pem_text):
    """
    Minimal parser for PKCS#8 SubjectPublicKeyInfo PEM  (RSAPublicKey inside).
    Returns (n, e) as integers, or raises ValueError.
    """
    lines = [l.strip() for l in pem_text.strip().splitlines()
             if not l.strip().startswith('-----')]
    der = base64.b64decode(''.join(lines))

    idx = 0
    # SEQUENCE (outer)
    if der[idx] != 0x30:
        raise ValueError("Expected SEQUENCE at start of DER")
    _, idx = _asn1_length(der, idx + 1)

    # SEQUENCE (AlgorithmIdentifier) – skip it
    if der[idx] != 0x30:
        raise ValueError("Expected AlgorithmIdentifier SEQUENCE")
    alg_len, idx2 = _asn1_length(der, idx + 1)
    idx = idx2 + alg_len

    # BIT STRING (public key bits)
    if der[idx] != 0x03:
        raise ValueError("Expected BIT STRING")
    _, idx = _asn1_length(der, idx + 1)
    idx += 1  # skip 'unused bits' byte (0x00)

    # SEQUENCE (RSAPublicKey)
    if der[idx] != 0x30:
        raise ValueError("Expected RSAPublicKey SEQUENCE")
    _, idx = _asn1_length(der, idx + 1)

    # INTEGER n
    if der[idx] != 0x02:
        raise ValueError("Expected INTEGER for n")
    n_len, idx = _asn1_length(der, idx + 1)
    n = int.from_bytes(der[idx : idx + n_len], 'big')
    idx += n_len

    # INTEGER e
    if der[idx] != 0x02:
        raise ValueError("Expected INTEGER for e")
    e_len, idx = _asn1_length(der, idx + 1)
    e = int.from_bytes(der[idx : idx + e_len], 'big')

    return n, e


# ─────────────────────────────────────────────
# BIN file helpers
# ─────────────────────────────────────────────
def bin_to_int(path):
    """Read a .bin file and return its content as a big-endian integer."""
    with open(path, 'rb') as f:
        raw = f.read()
    return int.from_bytes(raw, 'big'), raw


def int_to_text(value):
    """Try to convert a decrypted integer back to readable UTF-8 text."""
    try:
        byte_len = (value.bit_length() + 7) // 8
        return value.to_bytes(byte_len, 'big').decode('utf-8', errors='replace')
    except Exception:
        return str(value)


def decrypt_block_cipher(d, n, raw_bytes, block_size):
    """
    Decrypt a .bin file that was created by encrypting *each block* of
    `block_size` bytes separately with RSA.
    Returns the decoded text or None if block_size doesn't fit evenly.
    """
    if len(raw_bytes) % block_size != 0:
        return None
    result = b''
    for i in range(0, len(raw_bytes), block_size):
        c_block = int.from_bytes(raw_bytes[i : i + block_size], 'big')
        m_block = pow(c_block, d, n)
        # m fits in block_size bytes
        m_bytes = m_block.to_bytes(block_size, 'big').lstrip(b'\x00')
        result += m_bytes
    try:
        return result.decode('utf-8')
    except Exception:
        return result.decode('latin-1', errors='replace')


# ─────────────────────────────────────────────
# Load helpers for UI
# ─────────────────────────────────────────────
def load_from_files():
    """Reads public_key.txt and ciphertext.txt, fills e, n, c entries."""
    pub_path = DEFAULT_PUBLIC_KEY_FILE
    if not os.path.exists(pub_path):
        pub_path = filedialog.askopenfilename(
            title="Chọn file khóa công khai",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not pub_path:
            return

    e_val = n_val = None
    try:
        with open(pub_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("e="):
                    e_val = line.split("=", 1)[1].strip()
                elif line.startswith("n="):
                    n_val = line.split("=", 1)[1].strip()
    except Exception as ex:
        messagebox.showerror("Lỗi", f"Không thể đọc file khóa công khai:\n{ex}")
        return

    if e_val is None or n_val is None:
        messagebox.showerror("Lỗi", "File khóa công khai không hợp lệ.\nCần có dòng 'e=...' và 'n=...'.")
        return

    ciph_path = DEFAULT_CIPHERTEXT_FILE
    if not os.path.exists(ciph_path):
        ciph_path = filedialog.askopenfilename(
            title="Chọn file bản mã",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not ciph_path:
            return

    c_val = None
    try:
        with open(ciph_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("c="):
                    c_val = line.split("=", 1)[1].strip()
    except Exception as ex:
        messagebox.showerror("Lỗi", f"Không thể đọc file bản mã:\n{ex}")
        return

    if c_val is None:
        messagebox.showerror("Lỗi", "File bản mã không hợp lệ.\nCần có dòng 'c=...'.")
        return

    entry_e.delete(0, tk.END); entry_e.insert(0, e_val)
    entry_n.delete(0, tk.END); entry_n.insert(0, n_val)
    entry_c.delete(0, tk.END); entry_c.insert(0, c_val)
    entry_mode.set("integer")

    messagebox.showinfo("Thành công",
        f"Đã tải:\n  e = {e_val}\n  n = {n_val}\n  c = {c_val}")


def load_from_pem_bin():
    """
    Parse public_key.pem → (n, e)  AND  read encrypt_file.bin → c (integer).
    Fills the entry widgets so the user can then run any attack.
    """
    # --- PEM ---
    pem_path = DEFAULT_PEM_FILE
    if not os.path.exists(pem_path):
        pem_path = filedialog.askopenfilename(
            title="Chọn file khóa công khai (.pem)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if not pem_path:
            return

    try:
        with open(pem_path, "r") as f:
            pem_text = f.read()
        n_val, e_val = parse_pem_public_key(pem_text)
    except Exception as ex:
        messagebox.showerror("Lỗi PEM", f"Không thể đọc file PEM:\n{ex}")
        return

    # --- BIN ---
    bin_path = DEFAULT_BIN_FILE
    if not os.path.exists(bin_path):
        bin_path = filedialog.askopenfilename(
            title="Chọn file bản mã nhị phân (.bin)",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if not bin_path:
            return

    try:
        c_int, raw_bytes = bin_to_int(bin_path)
    except Exception as ex:
        messagebox.showerror("Lỗi BIN", f"Không thể đọc file BIN:\n{ex}")
        return

    entry_e.delete(0, tk.END); entry_e.insert(0, str(e_val))
    entry_n.delete(0, tk.END); entry_n.insert(0, str(n_val))
    entry_c.delete(0, tk.END); entry_c.insert(0, str(c_int))
    entry_mode.set("bin_single")       # The whole file is ONE ciphertext block
    _bin_raw_bytes.clear()
    _bin_raw_bytes.append(raw_bytes)   # Store raw bytes for block-mode decryption

    messagebox.showinfo("Đã tải PEM + BIN",
        f"PEM → n ({n_val.bit_length()} bit), e = {e_val}\n"
        f"BIN → c ({c_int.bit_length()} bit)\n\n"
        f"Lưu ý: n là {n_val.bit_length()}-bit — các tấn công thông thường\n"
        f"(Trial Division / Wiener) sẽ THẤT BẠI như thiết kế.")


# ─────────────────────────────────────────────
# State for binary block mode
# ─────────────────────────────────────────────
_bin_raw_bytes = []   # list of one element: raw bytes from .bin file
entry_mode = None     # tk.StringVar set after root is created


# ─────────────────────────────────────────────
# Input validation
# ─────────────────────────────────────────────
def validate_input(value_str, name):
    if not value_str:
        messagebox.showerror("Lỗi Nhập Liệu", f"Vui lòng nhập giá trị cho '{name}'.")
        return None
    try:
        value_int = int(value_str)
        if value_int < 0:
            raise ValueError("Giá trị không được là số âm.")
        if value_int == 0 and name != "c (Bản mã)":
            raise ValueError("Giá trị phải là số nguyên dương (ngoại trừ C có thể là 0).")
        return value_int
    except ValueError as e:
        messagebox.showerror("Lỗi Nhập Liệu", f"Giá trị không hợp lệ cho '{name}':\n{value_str}\n{e}")
        return None


# ─────────────────────────────────────────────
# Post-attack: try to decode plaintext as text
# ─────────────────────────────────────────────
def _try_decode_plaintext(result_dict, n, d):
    """
    Attempts to decode the decrypted integer M back to human-readable text.
    Also tries block-mode if a .bin file was loaded.
    Appends decoded text to result_dict.
    """
    m = result_dict.get('decrypted_message')
    if m is None:
        return

    # 1. Direct integer → text
    text_direct = int_to_text(m)
    result_dict['decrypted_text'] = text_direct

    # 2. If raw bytes from a .bin file exist, try block-decryption
    if _bin_raw_bytes and d is not None:
        raw = _bin_raw_bytes[0]
        for blk in (4, 2, 1, 8, 16):
            decoded = decrypt_block_cipher(d, n, raw, blk)
            if decoded:
                result_dict['decrypted_text_block'] = decoded
                break


# ─────────────────────────────────────────────
# Attack runners
# ─────────────────────────────────────────────
def run_factorization_attack():
    e_str = entry_e.get()
    n_str = entry_n.get()
    c_str = entry_c.get()

    e = validate_input(e_str, "e (Số mũ công khai)")
    n = validate_input(n_str, "n (Modulus)")
    c = validate_input(c_str, "c (Bản mã)")
    if None in [e, n, c]:
        return
    if c >= n:
        messagebox.showerror("Lỗi Nhập Liệu", f"Bản mã (c={c}) phải nhỏ hơn modulus (n={n}).")
        return

    disable_buttons()
    progress_bar.start(10)
    root.update()

    result = attack_src.factorize_attack(e, n, c)
    if result['success']:
        _try_decode_plaintext(result, n, result.get('d'))

    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()
    display_results(result)


def run_wiener_attack():
    e_str = entry_e.get()
    n_str = entry_n.get()
    c_str = entry_c.get()

    e = validate_input(e_str, "e (Số mũ công khai)")
    n = validate_input(n_str, "n (Modulus)")
    c = validate_input(c_str, "c (Bản mã)")
    if None in [e, n, c]:
        return
    if c >= n:
        messagebox.showerror("Lỗi Nhập Liệu", f"Bản mã (c={c}) phải nhỏ hơn modulus (n={n}).")
        return

    disable_buttons()
    progress_bar.start(10)
    root.update()

    result = attack_src.wiener_attack(e, n, c)
    if result['success']:
        _try_decode_plaintext(result, n, result.get('d'))

    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()
    display_results(result)


def run_brute_force_attack():
    e_str = entry_e.get()
    n_str = entry_n.get()
    c_str = entry_c.get()

    e = validate_input(e_str, "e (Số mũ công khai)")
    n = validate_input(n_str, "n (Modulus)")
    c = validate_input(c_str, "c (Bản mã)")
    if None in [e, n, c]:
        return
    if c >= n:
        messagebox.showerror("Lỗi Nhập Liệu", f"Bản mã (c={c}) phải nhỏ hơn modulus (n={n}).")
        return

    limit = BRUTE_FORCE_LIMIT
    confirm = messagebox.askokcancel(
        "Xác nhận Brute-Force",
        f"Tấn công Brute-Force sẽ thử tìm bản rõ M từ 0 đến {limit}.\n"
        f"Việc này có thể mất thời gian.\n\nBạn có muốn tiếp tục?",
        icon='warning'
    )
    if not confirm:
        return

    disable_buttons()
    progress_bar.start(10)
    root.update()

    result = attack_src.brute_force_message_attack(e, n, c, limit=limit)
    if result['success']:
        _try_decode_plaintext(result, n, None)

    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()
    display_results(result)


# ─────────────────────────────────────────────
# Results display
# ─────────────────────────────────────────────
def display_results(result_dict):
    text_results.config(state='normal')
    text_results.delete('1.0', tk.END)

    text_results.insert(tk.END, f"--- Kết quả [{result_dict['attack_type']}] ---\n")
    text_results.insert(tk.END, f"Thời gian: {result_dict['time_taken']:.4f} giây\n")
    text_results.insert(tk.END,
        f"Trạng thái: {'✅ THÀNH CÔNG' if result_dict['success'] else '❌ THẤT BẠI'}\n")
    text_results.insert(tk.END, f"Thông báo: {result_dict['message']}\n")

    if result_dict['success']:
        text_results.insert(tk.END, "\n--- Chi tiết phục hồi ---\n")
        if result_dict['attack_type'] in (
                "Factorization (Trial Division)", "Wiener's Attack (Small d)"):
            for key, label in [('p', 'p'), ('q', 'q'),
                                ('phi', 'phi(n)'),
                                ('phi_candidate', 'phi(n) candidate'),
                                ('k', 'k (convergent)'),
                                ('d', 'd (khóa bí mật)')]:
                if result_dict.get(key) is not None:
                    text_results.insert(tk.END, f"  {label} = {result_dict[key]}\n")

        if result_dict.get('decrypted_message') is not None:
            text_results.insert(tk.END,
                f"\nBản rõ (số nguyên M) = {result_dict['decrypted_message']}\n")

        # ── New: show decoded text ──────────────────────────
        text_direct = result_dict.get('decrypted_text')
        text_block  = result_dict.get('decrypted_text_block')

        if text_block:
            text_results.insert(tk.END, "\n┌─ Nội dung giải mã (block mode) ─────────────────\n")
            text_results.insert(tk.END, f"│  {text_block}\n")
            text_results.insert(tk.END, "└──────────────────────────────────────────────────\n")
        elif text_direct:
            text_results.insert(tk.END, "\n┌─ Nội dung giải mã (integer→text) ───────────────\n")
            text_results.insert(tk.END, f"│  {text_direct}\n")
            text_results.insert(tk.END, "└──────────────────────────────────────────────────\n")

    # Brute-force extra info
    if result_dict['attack_type'] == "Brute-Force (Message)":
        if result_dict.get('limit_tested') is not None:
            text_results.insert(tk.END, f"Giới hạn thử M: {result_dict['limit_tested']}\n")

    text_results.insert(tk.END, "─" * 50 + "\n")
    text_results.config(state='disabled')


# ─────────────────────────────────────────────
# Button helpers
# ─────────────────────────────────────────────
def disable_buttons():
    btn_factor.config(state='disabled', text="Đang chạy...")
    btn_wiener.config(state='disabled', text="Đang chạy...")
    btn_brute_force.config(state='disabled', text="Đang chạy...")

def enable_buttons():
    btn_factor.config(state='normal', text="Tấn công Phân tích Thừa số")
    btn_wiener.config(state='normal', text="Tấn công Wiener (d nhỏ)")
    btn_brute_force.config(state='normal', text="Tấn công Brute-Force (Bản rõ)")


# ─────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────
root = tk.Tk()
root.title("Mô Phỏng Tấn Công RSA")
root.geometry("750x820")
root.resizable(False, False)

entry_mode = tk.StringVar(value="integer")   # "integer" | "bin_single"

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(expand=True, fill='both')

# ── Input frame ──────────────────────────────
input_frame = ttk.LabelFrame(
    main_frame, text="Nhập Tham Số RSA Công Khai và Bản Mã", padding="10")
input_frame.pack(fill='x', pady=5)
input_frame.columnconfigure(1, weight=1)

ttk.Label(input_frame, text="e (Số mũ công khai):").grid(
    row=0, column=0, padx=5, pady=4, sticky='w')
entry_e = ttk.Entry(input_frame, width=65)
entry_e.grid(row=0, column=1, padx=5, pady=4, sticky='ew')

ttk.Label(input_frame, text="n (Modulus):").grid(
    row=1, column=0, padx=5, pady=4, sticky='w')
entry_n = ttk.Entry(input_frame, width=65)
entry_n.grid(row=1, column=1, padx=5, pady=4, sticky='ew')

ttk.Label(input_frame, text="c (Bản mã):").grid(
    row=2, column=0, padx=5, pady=4, sticky='w')
entry_c = ttk.Entry(input_frame, width=65)
entry_c.grid(row=2, column=1, padx=5, pady=4, sticky='ew')

# ── Load buttons ─────────────────────────────
load_frame = ttk.Frame(input_frame)
load_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=8, sticky='ew')
load_frame.columnconfigure(0, weight=1)
load_frame.columnconfigure(1, weight=1)

btn_load_txt = ttk.Button(
    load_frame,
    text="📄  Tải TXT  (public_key.txt + ciphertext.txt)",
    command=load_from_files)
btn_load_txt.grid(row=0, column=0, padx=4, sticky='ew')

btn_load_pem = ttk.Button(
    load_frame,
    text="🔑  Tải PEM + BIN  (public_key.pem + encrypt_file.bin)",
    command=load_from_pem_bin)
btn_load_pem.grid(row=0, column=1, padx=4, sticky='ew')

# ── Attack buttons ───────────────────────────
attack_frame = ttk.Frame(main_frame, padding="5")
attack_frame.pack(fill='x', pady=8)
for col in range(3):
    attack_frame.columnconfigure(col, weight=1)

btn_factor = ttk.Button(
    attack_frame, text="Tấn công Phân tích Thừa số",
    command=run_factorization_attack)
btn_factor.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

btn_wiener = ttk.Button(
    attack_frame, text="Tấn công Wiener (d nhỏ)",
    command=run_wiener_attack)
btn_wiener.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

btn_brute_force = ttk.Button(
    attack_frame, text="Tấn công Brute-Force (Bản rõ)",
    command=run_brute_force_attack)
btn_brute_force.grid(row=0, column=2, padx=5, pady=5, sticky='ew')

# ── Progress bar ─────────────────────────────
progress_bar = ttk.Progressbar(main_frame, mode='indeterminate', length=600)
progress_bar.pack(pady=6)

# ── Info banner ──────────────────────────────
info_text = (
    "ℹ️  Chế độ TXT (n nhỏ): tấn công Phân tích Thừa số thường THÀNH CÔNG và giải mã được văn bản.\n"
    "ℹ️  Chế độ PEM+BIN (n 1024-bit): tấn công THẤT BẠI – minh họa bảo mật RSA thực tế."
)
info_label = ttk.Label(main_frame, text=info_text, wraplength=700,
                       foreground='#555555', font=('Segoe UI', 8))
info_label.pack(pady=(0, 4))

# ── Results frame ────────────────────────────
results_frame = ttk.LabelFrame(main_frame, text="Kết Quả Tấn Công", padding="10")
results_frame.pack(expand=True, fill='both', pady=5)

text_results = scrolledtext.ScrolledText(
    results_frame, wrap='word', height=22, state='disabled',
    font=('Courier New', 9))
text_results.pack(expand=True, fill='both')

root.mainloop()