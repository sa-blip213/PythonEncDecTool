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
        self.root.geometry("800x500")

        # Initialize RSA key pair and AES key as None
        self.rsa_key = None
        self.rsa_cipher = None
        self.aes_key_generated = False
        self.rsa_public_key_fingerprint = None  # Store public key fingerprint

        # Create frames for AES (left) and RSA (right)
        self.aes_frame = tk.Frame(root)
        self.aes_frame.pack(side=tk.LEFT, padx=20, pady=10, fill=tk.Y)
        self.rsa_frame = tk.Frame(root)
        self.rsa_frame.pack(side=tk.RIGHT, padx=20, pady=10, fill=tk.Y)

        # File selection (center, above frames)
        tk.Label(root, text="Select File:", font=("Arial", 12)).pack(pady=5)
        self.file_path_var = tk.StringVar()
        tk.Entry(root, textvariable=self.file_path_var, width=60).pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)

        # AES Section (Left)
        tk.Label(self.aes_frame, text="AES Key (16, 24, or 32 bytes):", font=("Arial", 10)).pack(pady=5)
        self.aes_key_var = tk.StringVar()
        tk.Entry(self.aes_frame, textvariable=self.aes_key_var, width=40).pack(pady=5)

        self.generate_aes_button = tk.Button(self.aes_frame, text="Generate AES Key", command=self.generate_aes_key)
        self.generate_aes_button.pack(pady=5)
        self.aes_tick_label = tk.Label(self.aes_frame, text="", font=("Arial", 12))
        self.aes_tick_label.pack(side=tk.TOP, pady=2)

        self.save_aes_button = tk.Button(self.aes_frame, text="Save AES Key", command=self.save_aes_key,
                                         state=tk.DISABLED)
        self.save_aes_button.pack(pady=5)
        tk.Button(self.aes_frame, text="Load AES Key", command=self.load_aes_key).pack(pady=5)
        tk.Button(self.aes_frame, text="Encrypt File (AES)", command=self.encrypt_file_aes).pack(pady=5)
        tk.Button(self.aes_frame, text="Decrypt File (AES)", command=self.decrypt_file_aes).pack(pady=5)

        # RSA Section (Right)
        tk.Label(self.rsa_frame, text="RSA Key Management:", font=("Arial", 10)).pack(pady=5)

        self.generate_rsa_button = tk.Button(self.rsa_frame, text="Generate RSA Key Pair",
                                             command=self.generate_rsa_key)
        self.generate_rsa_button.pack(pady=5)
        self.rsa_tick_label = tk.Label(self.rsa_frame, text="", font=("Arial", 12))
        self.rsa_tick_label.pack(side=tk.TOP, pady=2)

        self.save_rsa_button = tk.Button(self.rsa_frame, text="Save RSA Private Key", command=self.save_rsa_key,
                                         state=tk.DISABLED)
        self.save_rsa_button.pack(pady=5)
        tk.Button(self.rsa_frame, text="Load RSA Private Key", command=self.load_rsa_key).pack(pady=5)
        tk.Button(self.rsa_frame, text="Encrypt File (RSA)", command=self.encrypt_file_rsa).pack(pady=5)
        tk.Button(self.rsa_frame, text="Decrypt File (RSA)", command=self.decrypt_file_rsa).pack(pady=5)

        # Hashing (Center, below file selection)
        tk.Button(root, text="Generate File Hash (SHA-256)", command=self.generate_file_hash).pack(pady=10)

        self.result_var = tk.StringVar()
        tk.Label(root, textvariable=self.result_var, font=("Arial", 10)).pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)
            logging.info(f"Selected file: {file_path}")

    def generate_aes_key(self):
        try:
            key = get_random_bytes(32)  # AES-256
            self.aes_key_var.set(base64.b64encode(key).decode('utf-8'))
            self.aes_key_generated = True
            self.save_aes_button.config(state=tk.NORMAL)
            self.aes_tick_label.config(text="✔", fg="green")
            logging.info("Generated AES key")
        except Exception as e:
            messagebox.showerror("Error", f"AES key generation failed: {e}")
            logging.error(f"AES key generation error: {e}")

    def save_aes_key(self):
        key = self.aes_key_var.get()
        if not key:
            messagebox.showerror("Error", "No AES key to save")
            logging.error("Attempted to save empty AES key")
            return
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(key)
                messagebox.showinfo("Success", f"AES key saved to {file_path}")
                logging.info(f"Saved AES key to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save AES key: {e}")
            logging.error(f"AES key save error: {e}")

    def load_aes_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    key = f.read().strip()
                base64.b64decode(key)  # Validate key format
                self.aes_key_var.set(key)
                self.aes_key_generated = True
                self.save_aes_button.config(state=tk.NORMAL)
                self.aes_tick_label.config(text="✔", fg="green")
                messagebox.showinfo("Success", f"AES key loaded from {file_path}")
                logging.info(f"Loaded AES key from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load AES key: {e}")
                logging.error(f"AES key load error: {e}")

    def generate_rsa_key(self):
        try:
            self.rsa_key = RSA.generate(2048)
            self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
            self.save_rsa_button.config(state=tk.NORMAL)
            self.rsa_tick_label.config(text="✔", fg="green")
            # Store public key fingerprint
            self.rsa_public_key_fingerprint = hashlib.sha256(self.rsa_key.publickey().exportKey('DER')).hexdigest()
            messagebox.showinfo("Success", "RSA key pair generated")
            logging.info(f"Generated RSA key pair with public key fingerprint: {self.rsa_public_key_fingerprint}")
        except Exception as e:
            messagebox.showerror("Error", f"RSA key generation failed: {e}")
            logging.error(f"RSA key generation error: {e}")

    def save_rsa_key(self):
        if not self.rsa_key:
            messagebox.showerror("Error", "No RSA key pair to save")
            logging.error("Attempted to save empty RSA key")
            return
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(self.rsa_key.exportKey('PEM'))
                messagebox.showinfo("Success", f"RSA private key saved to {file_path}")
                logging.info(f"Saved RSA private key to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save RSA private key: {e}")
            logging.error(f"RSA key save error: {e}")

    def load_rsa_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                self.rsa_key = RSA.import_key(key_data)
                self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
                self.save_rsa_button.config(state=tk.NORMAL)
                self.rsa_tick_label.config(text="✔", fg="green")
                # Update public key fingerprint
                self.rsa_public_key_fingerprint = hashlib.sha256(self.rsa_key.publickey().exportKey('DER')).hexdigest()
                messagebox.showinfo("Success", f"RSA private key loaded from {file_path}")
                logging.info(
                    f"Loaded RSA private key from {file_path} with public key fingerprint: {self.rsa_public_key_fingerprint}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load RSA private key: {e}")
                logging.error(f"RSA key load error: {e}")

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
        if not self.rsa_key or not self.rsa_cipher:
            messagebox.showerror("Error", "RSA key pair not generated or loaded")
            logging.error("RSA encryption attempted without key")
            return

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
            logging.info(
                f"File encrypted (RSA): {output_file} with public key fingerprint: {self.rsa_public_key_fingerprint}")
        except Exception as e:
            messagebox.showerror("Error", f"RSA encryption failed: {e}")
            logging.error(f"RSA encryption error: {e}")

    def decrypt_file_rsa(self):
        if not self.rsa_key or not self.rsa_cipher:
            messagebox.showerror("Error", "RSA key pair not generated or loaded")
            logging.error("RSA decryption attempted without key")
            return

        file_path = self.file_path_var.get()
        if not self.validate_file_path(file_path):
            return

        try:
            with open(file_path, 'rb') as f:
                ciphertext = f.read()
            # Validate ciphertext length (256 bytes for 2048-bit RSA with PKCS1_OAEP)
            if len(ciphertext) != 256:
                messagebox.showerror("Error",
                                     f"Invalid ciphertext length: {len(ciphertext)} bytes. Expected 256 bytes for 2048-bit RSA.")
                logging.error(f"RSA decryption failed: Invalid ciphertext length ({len(ciphertext)} bytes)")
                return
            data = self.rsa_cipher.decrypt(ciphertext)
            output_file = file_path + '.dec'
            with open(output_file, 'wb') as f:
                f.write(data)
            self.result_var.set(f"File decrypted to {output_file}")
            logging.info(
                f"File decrypted (RSA): {output_file} with public key fingerprint: {self.rsa_public_key_fingerprint}")
        except Exception as e:
            messagebox.showerror("Error",
                                 f"RSA decryption failed: {str(e)}. Ensure the correct private key is loaded and the file is not corrupted.")
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
