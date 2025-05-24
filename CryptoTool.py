from Crypto.PublicKey import RSA

class CryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption and Hashing Tool")
        self.root.geometry("600x400")
        # Initialize RSA key pair
        self.rsa_key = RSA.generate(2048)
        self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
        # GUI Elements
        tk.Label(root, text="Select File:").pack(pady=5)
        self.file_path_var = tk.StringVar()
        tk.Entry(root, textvariable=self.file_path_var, width=50).pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)
        tk.Button(root, text="Encrypt File (RSA)", command=self.encrypt_file_rsa).pack(pady=5)
        tk.Button(root, text="Decrypt File (RSA)", command=self.decrypt_file_rsa).pack(pady=5)
        self.result_var = tk.StringVar()
        tk.Label(root, textvariable=self.result_var).pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)
            logging.info(f"Selected file: {file_path}")
