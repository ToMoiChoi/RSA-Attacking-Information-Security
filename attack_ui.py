# attack_ui.py
# Tkinter UI for RSA Attack Simulation

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import attack_src
import math # Import math if needed for checks like c < n
import os

# Constants
BRUTE_FORCE_LIMIT = 1000000 # Set default limit for brute-force M here

# Default file paths (same directory as script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PUBLIC_KEY_FILE = os.path.join(SCRIPT_DIR, "public_key.txt")
DEFAULT_CIPHERTEXT_FILE = os.path.join(SCRIPT_DIR, "ciphertext.txt")

def load_from_files():
    """Reads public_key.txt and ciphertext.txt, fills e, n, c entries."""
    # --- Read public_key.txt ---
    pub_path = DEFAULT_PUBLIC_KEY_FILE
    if not os.path.exists(pub_path):
        pub_path = filedialog.askopenfilename(
            title="Chọn file khóa công khai",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not pub_path:
            return

    e_val = None
    n_val = None
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

    # --- Read ciphertext.txt ---
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

    # --- Fill entries ---
    entry_e.delete(0, tk.END)
    entry_e.insert(0, e_val)

    entry_n.delete(0, tk.END)
    entry_n.insert(0, n_val)

    entry_c.delete(0, tk.END)
    entry_c.insert(0, c_val)

    messagebox.showinfo("Thành công",
        f"Đã tải:\n  e = {e_val}\n  n = {n_val}\n  c = {c_val}")

def validate_input(value_str, name):
    """Tries to convert input to int, shows error if fails."""
    if not value_str:
        messagebox.showerror("Lỗi Nhập Liệu", f"Vui lòng nhập giá trị cho '{name}'.")
        return None
    try:
        # Allow potentially large numbers, remove arbitrary size limit if present before
        value_int = int(value_str)
        if value_int <= 0 and name != "c (Bản mã)": # Allow C=0
             if value_int == 0 and name == "c (Bản mã)":
                 return value_int # Allow C=0
             else:
                 raise ValueError("Giá trị phải là số nguyên dương (ngoại trừ C có thể là 0).")
        return value_int
    except ValueError as e:
        messagebox.showerror("Lỗi Nhập Liệu", f"Giá trị không hợp lệ cho '{name}':\n{value_str}\n{e}")
        return None

def run_factorization_attack():
    """Gets inputs and runs the factorization attack."""
    e_str = entry_e.get()
    n_str = entry_n.get()
    c_str = entry_c.get()

    e = validate_input(e_str, "e (Số mũ công khai)")
    n = validate_input(n_str, "n (Modulus)")
    c = validate_input(c_str, "c (Bản mã)")

    if None in [e, n, c]:
        return # Stop if validation failed

    if c >= n:
         messagebox.showerror("Lỗi Nhập Liệu", f"Bản mã (c={c}) phải nhỏ hơn modulus (n={n}).")
         return

    # Disable buttons, show progress
    disable_buttons()
    progress_bar.start(10)
    root.update()

    result = attack_src.factorize_attack(e, n, c)

    # Stop progress, re-enable buttons
    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()

    display_results(result)

def run_wiener_attack():
    """Gets inputs and runs Wiener's attack."""
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

    # Disable buttons, show progress
    disable_buttons()
    progress_bar.start(10)
    root.update()

    result = attack_src.wiener_attack(e, n, c)

    # Stop progress, re-enable buttons
    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()

    display_results(result)

def run_brute_force_attack():
    """Gets inputs and runs the Brute-Force (Message) attack."""
    e_str = entry_e.get()
    n_str = entry_n.get()
    c_str = entry_c.get()

    e = validate_input(e_str, "e (Số mũ công khai)")
    n = validate_input(n_str, "n (Modulus)")
    c = validate_input(c_str, "c (Bản mã)") # Allows c=0

    if None in [e, n, c]:
        return

    if c >= n:
         messagebox.showerror("Lỗi Nhập Liệu", f"Bản mã (c={c}) phải nhỏ hơn modulus (n={n}).")
         return

    # Ask user about the limit? Or use a fixed one? Using fixed for now.
    limit = BRUTE_FORCE_LIMIT
    confirm = messagebox.askokcancel("Xác nhận Brute-Force",
                                     f"Tấn công Brute-Force sẽ thử tìm bản rõ M bằng cách kiểm tra các giá trị từ 0 đến {limit}.\n"
                                     f"Việc này có thể mất thời gian nếu giới hạn lớn.\n\n"
                                     f"Bạn có muốn tiếp tục?",
                                     icon='warning')
    if not confirm:
        return

    # Disable buttons, show progress
    disable_buttons()
    progress_bar.start(10)
    root.update()

    # Pass the limit to the attack function
    result = attack_src.brute_force_message_attack(e, n, c, limit=limit)

    # Stop progress, re-enable buttons
    progress_bar.stop()
    progress_bar['value'] = 0
    enable_buttons()
    root.update()

    display_results(result)


def display_results(result_dict):
    """Displays attack results in the text area."""
    text_results.config(state='normal')
    text_results.delete('1.0', tk.END) # Clear previous results

    text_results.insert(tk.END, f"--- Kết quả [{result_dict['attack_type']}] ---\n")
    text_results.insert(tk.END, f"Thời gian: {result_dict['time_taken']:.4f} giây\n")
    text_results.insert(tk.END, f"Trạng thái: {'THÀNH CÔNG' if result_dict['success'] else 'THẤT BẠI'}\n")
    text_results.insert(tk.END, f"Thông báo: {result_dict['message']}\n")

    # Display specific info based on attack type and success
    if result_dict['success']:
        text_results.insert(tk.END, "\n--- Chi tiết phục hồi ---\n")
        if result_dict['attack_type'] == "Factorization (Trial Division)" or \
           result_dict['attack_type'] == "Wiener's Attack (Small d)":
            if result_dict.get('p') is not None:
                text_results.insert(tk.END, f"p = {result_dict['p']}\n")
            if result_dict.get('q') is not None:
                text_results.insert(tk.END, f"q = {result_dict['q']}\n")
            if result_dict.get('phi') is not None:
                text_results.insert(tk.END, f"phi(n) = {result_dict['phi']}\n")
            if result_dict.get('phi_candidate') is not None: # For Wiener's
                text_results.insert(tk.END, f"phi(n) (candidate) = {result_dict['phi_candidate']}\n")
            if result_dict.get('k') is not None: # For Wiener's
                text_results.insert(tk.END, f"k (convergent num) = {result_dict['k']}\n")
            if result_dict.get('d') is not None:
                text_results.insert(tk.END, f"d (khóa bí mật) = {result_dict['d']}\n")

        # Always show decrypted message if successful
        if result_dict.get('decrypted_message') is not None:
            text_results.insert(tk.END, f"\nBản rõ giải mã được (M) = {result_dict['decrypted_message']}\n")

    # Add limit info for Brute-Force regardless of success/fail
    if result_dict['attack_type'] == "Brute-Force (Message)":
         if result_dict.get('limit_tested') is not None:
              text_results.insert(tk.END, f"Giới hạn thử M: {result_dict['limit_tested']}\n")

    text_results.insert(tk.END, "------------------------------------\n")
    text_results.config(state='disabled')

# --- Helper functions for button state ---
def disable_buttons():
    btn_factor.config(state='disabled', text="Đang chạy...")
    btn_wiener.config(state='disabled', text="Đang chạy...")
    btn_brute_force.config(state='disabled', text="Đang chạy...") # Disable new button

def enable_buttons():
    btn_factor.config(state='normal', text="Tấn công Phân tích Thừa số")
    btn_wiener.config(state='normal', text="Tấn công Wiener (d nhỏ)")
    btn_brute_force.config(state='normal', text="Tấn công Brute-Force (Bản rõ)") # Enable new button


# --- Main Window Setup ---
root = tk.Tk()
root.title("Mô Phỏng Tấn Công RSA")
root.geometry("650x700") # Increased size slightly for new button

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(expand=True, fill='both')

# --- Input Frame ---
input_frame = ttk.LabelFrame(main_frame, text="Nhập Tham Số RSA Công Khai và Bản Mã", padding="10")
input_frame.pack(fill='x', pady=5)
input_frame.columnconfigure(1, weight=1) # Allow entry to expand

ttk.Label(input_frame, text="e (Số mũ công khai):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
entry_e = ttk.Entry(input_frame, width=60) # Slightly wider entry
entry_e.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

ttk.Label(input_frame, text="n (Modulus):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
entry_n = ttk.Entry(input_frame, width=60)
entry_n.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

ttk.Label(input_frame, text="c (Bản mã):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
entry_c = ttk.Entry(input_frame, width=60)
entry_c.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

# --- Load from file button ---
btn_load_files = ttk.Button(input_frame, text="📂 Tải từ file (public_key.txt & ciphertext.txt)", command=load_from_files)
btn_load_files.grid(row=3, column=0, columnspan=2, padx=5, pady=8, sticky='ew')

# --- Attack Buttons Frame ---
# Using a grid layout for buttons for better control
attack_frame = ttk.Frame(main_frame, padding="5")
attack_frame.pack(fill='x', pady=10)
attack_frame.columnconfigure(0, weight=1) # Make columns expandable
attack_frame.columnconfigure(1, weight=1)
attack_frame.columnconfigure(2, weight=1)


btn_factor = ttk.Button(attack_frame, text="Tấn công Phân tích Thừa số", command=run_factorization_attack)
# btn_factor.pack(side='left', padx=5, pady=5, expand=True, fill='x')
btn_factor.grid(row=0, column=0, padx=5, pady=5, sticky='ew')


btn_wiener = ttk.Button(attack_frame, text="Tấn công Wiener (d nhỏ)", command=run_wiener_attack)
# btn_wiener.pack(side='left', padx=5, pady=5, expand=True, fill='x')
btn_wiener.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# Add the new Brute-Force button
btn_brute_force = ttk.Button(attack_frame, text="Tấn công Brute-Force (Bản rõ)", command=run_brute_force_attack)
# btn_brute_force.pack(side='left', padx=5, pady=5, expand=True, fill='x')
btn_brute_force.grid(row=0, column=2, padx=5, pady=5, sticky='ew')


# --- Progress Bar ---
progress_bar = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
progress_bar.pack(pady=10)

# --- Results Frame ---
results_frame = ttk.LabelFrame(main_frame, text="Kết Quả Tấn Công", padding="10")
results_frame.pack(expand=True, fill='both', pady=5)

text_results = scrolledtext.ScrolledText(results_frame, wrap='word', height=18, state='disabled', font=('Courier New', 9))
text_results.pack(expand=True, fill='both')


root.mainloop()