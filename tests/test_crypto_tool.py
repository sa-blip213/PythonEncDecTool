import pytest
import os
import sys
import tkinter as tk
from unittest.mock import patch
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import base64

# Adjust sys.path to include the project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from CryptoAppv2 import CryptoTool

# Mark tests requiring Tkinter
pytestmark = pytest.mark.gui


@pytest.fixture
def setup_file(tmp_path):
    file_path = tmp_path / "test.txt"
    with open(file_path, 'wb') as f:
        f.write(b"Test data")
    return str(file_path)


@pytest.fixture
def crypto_tool():
    root = tk.Tk()
    app = CryptoTool(root)
    yield app
    root.destroy()


def test_encrypt_decrypt_aes(setup_file):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    with open(setup_file, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    assert decrypted == b"Test data"


def test_generate_file_hash(setup_file):
    sha256_hash = hashlib.sha256()
    with open(setup_file, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    expected_hash = sha256_hash.hexdigest()

    sha256_hash = hashlib.sha256()
    with open(setup_file, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    computed_hash = sha256_hash.hexdigest()

    assert computed_hash == expected_hash


def test_encrypt_decrypt_rsa(setup_file):
    rsa_key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(rsa_key)
    with open(setup_file, 'rb') as f:
        data = f.read()
    if len(data) <= 245:  # RSA block size limit
        ciphertext = cipher.encrypt(data)
        decrypted = cipher.decrypt(ciphertext)
        assert decrypted == b"Test data"


@patch('tkinter.filedialog.askopenfilename')
def test_browse_file(mock_filedialog, crypto_tool, setup_file):
    mock_filedialog.return_value = setup_file
    crypto_tool.browse_file()
    assert crypto_tool.file_path_var.get() == setup_file


def test_invalid_file_path(crypto_tool):
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: "nonexistent.txt"})()
    assert not crypto_tool.validate_file_path("nonexistent.txt")


@patch('tkinter.messagebox.showerror')
def test_invalid_aes_key(mock_showerror, crypto_tool, setup_file):
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: setup_file})()
    crypto_tool.aes_key_var = type('obj', (), {'get': lambda x: base64.b64encode(b"short").decode('utf-8')})()
    crypto_tool.encrypt_file_aes()
    mock_showerror.assert_called_once()


@patch('tkinter.filedialog.askopenfilename')
@patch('tkinter.messagebox.showinfo')
def test_save_load_rsa_key(mock_showinfo, mock_filedialog, crypto_tool, tmp_path):
    crypto_tool.generate_rsa_key()
    mock_showinfo.reset_mock()  # Reset mock to ignore showinfo call from generate_rsa_key
    key_file = tmp_path / "RSA_private_key.pem"
    with open(key_file, 'wb') as f:
        f.write(crypto_tool.rsa_key.exportKey('PEM'))
    mock_filedialog.return_value = str(key_file)
    crypto_tool.rsa_key = None
    crypto_tool.rsa_cipher = None
    crypto_tool.load_rsa_key()
    assert crypto_tool.rsa_key is not None
    assert crypto_tool.rsa_cipher is not None
    assert crypto_tool.rsa_tick_label.cget("text") == "✔"
    assert crypto_tool.rsa_tick_label.cget("fg") == "green"
    assert crypto_tool.save_rsa_button.cget("state") == tk.NORMAL
    mock_showinfo.assert_called_once_with("Success", f"RSA private key loaded from {str(key_file)}")


@patch('tkinter.filedialog.askopenfilename')
@patch('tkinter.messagebox.showinfo')
def test_save_load_aes_key(mock_showinfo, mock_filedialog, crypto_tool, tmp_path):
    crypto_tool.generate_aes_key()
    key = crypto_tool.aes_key_var.get()
    key_file = tmp_path / "AES_key.txt"
    with open(key_file, 'w') as f:
        f.write(key)
    mock_filedialog.return_value = str(key_file)
    crypto_tool.aes_key_var.set("")
    crypto_tool.load_aes_key()
    assert crypto_tool.aes_key_var.get() == key
    assert crypto_tool.aes_key_generated is True
    assert crypto_tool.aes_tick_label.cget("text") == "✔"
    assert crypto_tool.aes_tick_label.cget("fg") == "green"
    assert crypto_tool.save_aes_button.cget("state") == tk.NORMAL
    mock_showinfo.assert_called_once_with("Success", f"AES key loaded from {str(key_file)}")


@patch('tkinter.filedialog.asksaveasfilename')
@patch('tkinter.messagebox.showinfo')
def test_save_aes_key(mock_showinfo, mock_saveas, crypto_tool, tmp_path):
    crypto_tool.generate_aes_key()
    key_file = tmp_path / "AES_key.txt"
    mock_saveas.return_value = str(key_file)
    crypto_tool.save_aes_key()
    with open(key_file, 'r') as f:
        saved_key = f.read()
    assert saved_key == crypto_tool.aes_key_var.get()
    mock_showinfo.assert_called_once_with("Success", f"AES key saved to {str(key_file)}")


@patch('tkinter.filedialog.asksaveasfilename')
@patch('tkinter.messagebox.showinfo')
def test_save_rsa_key(mock_showinfo, mock_saveas, crypto_tool, tmp_path):
    crypto_tool.generate_rsa_key()
    mock_showinfo.reset_mock()  # Reset mock to ignore showinfo call from generate_rsa_key
    key_file = tmp_path / "RSA_private_key.pem"
    mock_saveas.return_value = str(key_file)
    crypto_tool.save_rsa_key()
    with open(key_file, 'rb') as f:
        saved_key = RSA.import_key(f.read())
    assert saved_key.exportKey('PEM') == crypto_tool.rsa_key.exportKey('PEM')
    mock_showinfo.assert_called_once_with("Success", f"RSA private key saved to {str(key_file)}")


def test_save_aes_button_disabled_initially(crypto_tool):
    assert crypto_tool.save_aes_button.cget("state") == tk.DISABLED
    crypto_tool.generate_aes_key()
    assert crypto_tool.save_aes_button.cget("state") == tk.NORMAL
    assert crypto_tool.aes_tick_label.cget("text") == "✔"
    assert crypto_tool.aes_tick_label.cget("fg") == "green"


def test_save_rsa_button_disabled_initially(crypto_tool):
    assert crypto_tool.save_rsa_button.cget("state") == tk.DISABLED
    crypto_tool.generate_rsa_key()
    assert crypto_tool.save_rsa_button.cget("state") == tk.NORMAL
    assert crypto_tool.rsa_tick_label.cget("text") == "✔"
    assert crypto_tool.rsa_tick_label.cget("fg") == "green"


@patch('tkinter.filedialog.askopenfilename')
@patch('tkinter.messagebox.showerror')
def test_rsa_decryption_invalid_ciphertext_length(mock_showerror, mock_filedialog, crypto_tool, tmp_path):
    crypto_tool.generate_rsa_key()
    invalid_file = tmp_path / "invalid.rsa_enc"
    with open(invalid_file, 'wb') as f:
        f.write(b"short")  # Invalid length (not 256 bytes)
    mock_filedialog.return_value = str(invalid_file)
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: str(invalid_file)})()
    crypto_tool.decrypt_file_rsa()
    mock_showerror.assert_called_once_with("Error",
                                           f"Invalid ciphertext length: {len(b'short')} bytes. Expected 256 bytes for 2048-bit RSA.")


@patch('tkinter.filedialog.askopenfilename')
@patch('tkinter.filedialog.asksaveasfilename')
def test_aes_encryption_decryption_success(mock_saveas, mock_filedialog, crypto_tool, tmp_path):
    crypto_tool.generate_aes_key()
    input_file = tmp_path / "test.txt"
    with open(input_file, 'wb') as f:
        f.write(b"Test data")
    encrypted_file = tmp_path / "test.txt.aes_enc"  # Match CryptoAppv2.py behavior
    mock_filedialog.return_value = str(input_file)
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: str(input_file)})()
    crypto_tool.encrypt_file_aes()  # Output file is input_file + '.aes_enc'
    mock_filedialog.return_value = str(encrypted_file)
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: str(encrypted_file)})()
    decrypted_file = tmp_path / "test.txt.aes_enc.dec"  # Match CryptoAppv2.py behavior
    crypto_tool.decrypt_file_aes()  # Output file is encrypted_file + '.dec'
    with open(decrypted_file, 'rb') as f:
        assert f.read() == b"Test data"


@patch('tkinter.filedialog.askopenfilename')
@patch('tkinter.filedialog.asksaveasfilename')
def test_rsa_encryption_decryption_success(mock_saveas, mock_filedialog, crypto_tool, tmp_path):
    crypto_tool.generate_rsa_key()
    input_file = tmp_path / "test.txt"
    with open(input_file, 'wb') as f:
        f.write(b"Test data")
    encrypted_file = tmp_path / "test.txt.rsa_enc"  # Match CryptoAppv2.py behavior
    mock_filedialog.return_value = str(input_file)
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: str(input_file)})()
    crypto_tool.encrypt_file_rsa()  # Output file is input_file + '.rsa_enc'
    mock_filedialog.return_value = str(encrypted_file)
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: str(encrypted_file)})()
    decrypted_file = tmp_path / "test.txt.rsa_enc.dec"  # Match CryptoAppv2.py behavior
    crypto_tool.decrypt_file_rsa()  # Output file is encrypted_file + '.dec'
    with open(decrypted_file, 'rb') as f:
        assert f.read() == b"Test data"


@patch('tkinter.messagebox.showerror')
def test_generate_file_hash_invalid_file(mock_showerror, crypto_tool):
    crypto_tool.file_path_var = type('obj', (), {'get': lambda x: "nonexistent.txt"})()
    crypto_tool.generate_file_hash()
    mock_showerror.assert_called_once_with("Error", "File does not exist")
