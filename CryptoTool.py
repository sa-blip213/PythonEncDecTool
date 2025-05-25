import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import os
import logging
import base64

# Configure logging
logging.basicConfig(filename='crypto_tool.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class CryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption and Hashing Tool")
        self.root.geometry("600x420")

        # Initialize RSA key pair
        self.rsa_key = RSA.generate(2048)
        self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)

        # GUI Elements
        tk.Label(root, text="Select File:").pack(pady=5)
        self.file_path_var = tk.StringVar()
        tk.Entry(root, textvariable=self.file_path_var, width=50).pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)

        tk.Label(root, text="AES Key (16, 24, or 32 bytes):").pack(pady=5)
        self.aes_key_var = tk.StringVar()
        tk.Entry(root, textvariable=self.aes_key_var, width=50).pack(pady=5)
        tk.Button(root, text="Generate AES Key", command=self.generate_aes_key).pack(pady=5)

        tk.Button(root, text="Encrypt File (AES)", command=self.encrypt_file_aes).pack(pady=5)
        tk.Button(root, text="Decrypt File (AES)", command=self.decrypt_file_aes).pack(pady=5)
        tk.Button(root, text="Encrypt File (RSA)", command=self.encrypt_file_rsa).pack(pady=5)
        tk.Button(root, text="Decrypt File (RSA)", command=self.decrypt_file_rsa).pack(pady=5)
        tk.Button(root, text="Generate File Hash (SHA-256)", command=self.generate_file_hash).pack(pady=5)

        self.result_var = tk.StringVar()
        tk.Label(root, textvariable=self.result_var).pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)
            logging.info(f"Selected file: {file_path}")

    def generate_aes_key(self):
        key = get_random_bytes(32)  # AES-256
        self.aes_key_var.set(base64.b64encode(key).decode('utf-8'))
        logging.info("Generated AES key")

    def validate_file_path(self, file_path):
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File does not exist")
            logging.error(f"Invalid file path: {file_path}")
            return False
        return True

    def encrypt_file_aes(self):
        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        key = self.aes_key_var.get()
        try:
            key = base64.b64decode(key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Invalid AES key length")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid AES key: {e}")
            logging.error(f"AES key error: {e}")
            return

        try:
            cipher = AES.new(key, AES.MODE_EAX)
            with open(file_path, 'rb') as f:
                data = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output_file = file_path + '.aes_enc'
            with open(output_file, 'wb') as f:
                [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
            self.result_var.set(f"File encrypted to {output_file}")
            logging.info(f"File encrypted (AES): {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            logging.error(f"AES encryption error: {e}")

    def decrypt_file_aes(self):
        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        key = self.aes_key_var.get()
        try:
            key = base64.b64decode(key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Invalid AES key length")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid AES key: {e}")
            logging.error(f"AES key error: {e}")
            return

        try:
            with open(file_path, 'rb') as f:
                nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            output_file = file_path + '.dec'
            with open(output_file, 'wb') as f:
                f.write(data)
            self.result_var.set(f"File decrypted to {output_file}")
            logging.info(f"File decrypted (AES): {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            logging.error(f"AES decryption error: {e}")

    def encrypt_file_rsa(self):
        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if len(data) > 245:  # RSA block size limit
                messagebox.showerror("Error", "File too large for RSA encryption")
                logging.error("RSA encryption failed: File too large")
                return
            ciphertext = self.rsa_cipher.encrypt(data)
            output_file = file_path + '.rsa_enc'
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
            self.result_var.set(f"File encrypted to {output_file}")
            logging.info(f"File encrypted (RSA): {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"RSA encryption failed: {e}")
            logging.error(f"RSA encryption error: {e}")

    def decrypt_file_rsa(self):
        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        try:
            with open(file_path, 'rb') as f:
                ciphertext = f.read()
            data = self.rsa_cipher.decrypt(ciphertext)
            output_file = file_path + '.dec'
            with open(output_file, 'wb') as f:
                f.write(data)
            self.result_var.set(f"File decrypted to {output_file}")
            logging.info(f"File decrypted (RSA): {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"RSA decryption failed: {e}")
            logging.error(f"RSA decryption error: {e}")

    def generate_file_hash(self):
        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            hash_value = sha256_hash.hexdigest()
            self.result_var.set(f"SHA-256 Hash: {hash_value}")
            logging.info(f"Generated SHA-256 hash for {file_path}: {hash_value}")
        except Exception as e:
            messagebox.showerror("Error", f"Hash generation failed: {e}")
            logging.error(f"Hash generation error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoTool(root)
    root.mainloop()
