import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox, QInputDialog


# Generate a key from the password
def key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt the file
def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = key_from_password(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

# Decrypt the file
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()
    
    key = key_from_password(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    with open(file_path, 'wb') as f:
        f.write(plaintext)

import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox

# [Previous code functions: key_from_password, encrypt_file, decrypt_file]

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'File Encryption'
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.file_path_label = QLabel("Enter File Path:")
        self.file_path_input = QLineEdit(self)

        self.encrypt_button = QPushButton('Encrypt', self)
        self.encrypt_button.clicked.connect(self.encrypt_clicked)

        self.decrypt_button = QPushButton('Decrypt', self)
        self.decrypt_button.clicked.connect(self.decrypt_clicked)

        layout.addWidget(self.file_path_label)
        layout.addWidget(self.file_path_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)
        self.setWindowTitle(self.title)
        self.show()

    def encrypt_clicked(self):
        file_path = self.file_path_input.text()
        if not file_path:
            self.show_message("Error", "Please enter a file path.")
            return
        password = self.get_password()
        if not password:
            return
        try:
            encrypt_file(file_path, password)
            self.show_message("Success", f"File {file_path} has been encrypted.")
        except Exception as e:
            self.show_message("Error", str(e))

    def decrypt_clicked(self):
        file_path = self.file_path_input.text()
        if not file_path:
            self.show_message("Error", "Please enter a file path.")
            return
        password = self.get_password()
        if not password:
            return
        try:
            decrypt_file(file_path, password)
            self.show_message("Success", f"File {file_path} has been decrypted.")
        except Exception as e:
            self.show_message("Error", str(e))

    def get_password(self):
        password_input = QInputDialog(self)
        password_input.setInputMode(QInputDialog.InputMode.TextInput)
        password_input.setTextEchoMode(QLineEdit.EchoMode.Password)  # Set echo mode to Password
        password_input.setWindowTitle("Password")
        password_input.setLabelText("Enter the password:")
        ok = password_input.exec()
        if ok:
            return password_input.textValue()
        return None


    def show_message(self, title, message):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec())

