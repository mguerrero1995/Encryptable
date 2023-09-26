import os
import random
import re
import sqlite3
import struct
import sys
import time

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtWidgets import (QApplication, QDialog, QFileDialog, QFrame,
                             QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                             QMenu, QMenuBar, QMessageBox, QPushButton,
                             QVBoxLayout, QWidget)

# Configurations for app
SIGNATURE = b'FAP_ENC'  # Your unique file signature, converted to bytes
HEADER_ADDITIONAL_LENGTH = 5  # The length of the additional header information, in bytes

# File path configurations for the app
SHOW_PW_ICON = "./icons/show_password_icon.png"
HIDE_PW_ICON = "./icons/hide_password_icon.png"



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
    
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
     # Adding a known signature at the start of the file
    signature = SIGNATURE
    version = 1
    timestamp = int(time.time())
    header = signature + struct.pack('B', version) + struct.pack('I', timestamp)
    plaintext = header + plaintext
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    encrypted_file_path = file_path + ".cyph"
    with open(encrypted_file_path, "wb") as f:
        f.write(salt + iv + ciphertext)

    # Optionally delete the original file after encryption
    os.remove(file_path)

# Decrypt the file
def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()
        
        key = key_from_password(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        signature = SIGNATURE

         # Step 2: Separating the header from the content
        signature_in_file = plaintext[:len(signature)]

        # Potential future header data for more advanced features
        # version_in_file = struct.unpack('B', plaintext[len(signature):len(signature) + 1])
        # timestamp_in_file = struct.unpack('I', plaintext[len(signature) + 1:len(signature) + HEADER_ADDITIONAL_LENGTH])

        # Step 3: Verifying the header
        if signature_in_file != signature:
            raise ValueError("Incorrect password or not a file encrypted by this application.")

        plaintext = plaintext[len(signature) + HEADER_ADDITIONAL_LENGTH:]

        # Remove custom extension to restore original file extension
        decrypted_file_path = file_path.rstrip(".cyph")

        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)
        
        # Optionally delete the encrypted file after decryption
        os.remove(file_path)

    except: 
        raise ValueError(f"Decryption failed for {file_path} due to an incorrect password.")

def hash_login_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed

def verify_login_password(stored_password_hash: bytes, provided_password: str) -> bool:
    return bcrypt.checkpw(provided_password.encode("utf-8"), stored_password_hash)

def show_message(title, message):
    msg = QMessageBox()
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec()

class PasswordDialog(QDialog):
    def __init__(self, mode, parent=None):
        super(PasswordDialog, self).__init__(parent)
        
        self.mode = mode  # Store the operation mode (Encrypt or Decrypt)

        self.setWindowTitle("Enter Password")
        
        self.layout = QVBoxLayout()  # Main layout
        
        # Password input field and Eyeball icon layout
        self.input_layout = QHBoxLayout()
        
        # Password input field
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Set default to hidden password
        self.input_layout.addWidget(self.password_input)
        
        # Eyeball button for toggling password visibility
        self.show_pw_icon = QIcon(QPixmap(SHOW_PW_ICON))
        self.hide_pw_icon = QIcon(QPixmap(HIDE_PW_ICON))
        self.toggle_password_btn = QPushButton(self)
        self.toggle_password_btn.setIcon(self.show_pw_icon)  
        self.toggle_password_btn.setFixedSize(30, 30)  # Fixed size for the icon button
        self.toggle_password_btn.setCheckable(True)
        self.toggle_password_btn.clicked.connect(self.toggle_password_visibility)
        self.input_layout.addWidget(self.toggle_password_btn)

        self.layout.addLayout(self.input_layout)

        # Encrypt/Decrypt action button
        self.action_btn = QPushButton(self.mode, self)
        self.action_btn.clicked.connect(self.accept)
        self.layout.addWidget(self.action_btn)
        self.layout.setAlignment(self.action_btn, Qt.AlignmentFlag.AlignCenter)  # Center-align the button
        
        self.setLayout(self.layout)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_password_btn.setIcon(self.hide_pw_icon)  # set to hide icon when password is visible
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_password_btn.setIcon(self.show_pw_icon)  # set back to show icon when password is hidden
    
    def get_dialog_password(self):
        return self.password_input.text()
    

class CreateAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Create New Account")

        self.layout = QVBoxLayout()

        self.email_label = QLabel("Email:")
        self.email_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input

        self.confirm_password_label = QLabel("Confirm Password:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input

        self.create_account_button = QPushButton("Create Account")
        self.create_account_button.clicked.connect(self.create_account_clicked)

        self.layout.addWidget(self.email_label)
        self.layout.addWidget(self.email_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.confirm_password_label)
        self.layout.addWidget(self.confirm_password_input)
        self.layout.addWidget(self.create_account_button)

        self.setLayout(self.layout)

    def create_account_clicked(self):
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if password != confirm_password:
            show_message("Error", "Passwords do not match.")
            self.email_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()
            return

        password_hash = hash_login_password(password)

        try:
            # Connect to database
            conn = sqlite3.connect("accounts_database.db")
            cur = conn.cursor()

            # Insert a new record into the users table with the email and password
            cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?);", 
                        (email, password_hash))
            conn.commit()
            conn.close()

            self.email_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()

            show_message("Success!", "New account successfully created.")
        except Exception as e:
            show_message("Error", str(e))
        
    
class ManageAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Manage Account")

        self.layout = QVBoxLayout()

        self.change_email_label = QLabel("Change Email (Placeholder)")

        self.change_password_label = QLabel("Change Password (Placeholder)")

        self.layout.addWidget(self.change_email_label)
        self.layout.addWidget(self.change_password_label)

        self.setLayout(self.layout)


class SignInDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle("Sign In")

        self.layout = QVBoxLayout()

        self.email_label = QLabel("Email:")
        self.email_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login_clicked)

        self.layout.addWidget(self.email_label)
        self.layout.addWidget(self.email_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)

        self.setLayout(self.layout)

    def login_clicked(self):
        # Handle login
        email = self.email_input.text()
        password = self.password_input.text()

        try:
            # Connect to database
            conn = sqlite3.connect("accounts_database.db")
            cur = conn.cursor()

            # Get password hash and salt for the provided email 
            password_hash = cur.execute("SELECT password_hash FROM users WHERE email = ?", (email,)).fetchone()

            if not password_hash: # Verify that a matching email was found
                self.password_input.clear()
                conn.close()
                show_message("Error", "Email not found.")
                return

            password_hash = password_hash[0] # Convert password_hash to a binary string instead of a tuple
            
            if verify_login_password(password_hash, password):
                show_message("Success", "Successful sign in attempt.")
                self.email_input.clear()
                self.password_input.clear()
                conn.close()
            else:
                show_message("Error", "Incorrect password.")
                self.password_input.clear()
                conn.close()
                
            return
        except Exception as e:
            show_message("Error", str(e)) 


class DropZone(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        self.setStyleSheet("background-color: #E0E0E0;")
        self.setFixedHeight(50)
        self.setText("Drop File(s) Here")

    def dragEnterEvent(self, event):
        mime_data = event.mimeData()
        if mime_data.hasUrls():  # Allow multiple files
            event.acceptProposedAction()

    def dropEvent(self, event):
        mime_data = event.mimeData()
        file_paths = [url.toLocalFile() for url in mime_data.urls()]  # Get all file paths
        formatted_paths = ",".join(f'"{path}"' for path in file_paths)  # Format paths
        self.parent().file_path_input.setText(formatted_paths)  # Update the QLineEdit with the formatted file paths



class EncyrptionUI(QWidget):
    def __init__(self):
        super().__init__()
        
        self.layout = QVBoxLayout()

        # Create a main layout
        main_layout = QVBoxLayout()

        # Label
        self.file_path_label = QLabel("Enter File Path(s) or Drag & Drop File(s):")
        main_layout.addWidget(self.file_path_label)
        main_layout.setAlignment(self.file_path_label, Qt.AlignmentFlag.AlignCenter)


        # File Path input field and Browse button layout
        path_layout = QHBoxLayout()

        path_layout.addStretch()

        # Input field for the file path
        self.file_path_input = QLineEdit(self)
        self.file_path_input.setFixedWidth(400)
        path_layout.addWidget(self.file_path_input)
        path_layout.setAlignment(self.file_path_input, Qt.AlignmentFlag.AlignCenter)

        # Browse button
        self.browse_button = QPushButton("Browse", self)
        self.browse_button.clicked.connect(self.browse_file)
        self.browse_button.setFixedWidth(60)
        path_layout.addWidget(self.browse_button)
        path_layout.setAlignment(self.browse_button, Qt.AlignmentFlag.AlignCenter)

        # Add a horizontal stretch after the Browse button
        path_layout.addStretch()

        main_layout.addLayout(path_layout)

        # Drag and Drop area
        drop_zone_layout = QHBoxLayout()
        drop_zone_layout.addStretch() # Add a stretch before the drop zone so that it stays centered when the window expands
        self.drop_zone = DropZone(self)
        self.drop_zone.setFixedWidth(650)  # Set the maximum width
        drop_zone_layout.addWidget(self.drop_zone)
        drop_zone_layout.addStretch() # Add a stretch after the drop zone so that it stays centered when the window expands

        main_layout.addLayout(drop_zone_layout)
        
        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.setFixedWidth(55)
        self.encrypt_button.clicked.connect(self.encrypt_clicked)
        main_layout.addWidget(self.encrypt_button)
        main_layout.setAlignment(self.encrypt_button, Qt.AlignmentFlag.AlignCenter)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.setFixedWidth(55)
        self.decrypt_button.clicked.connect(self.decrypt_clicked)
        main_layout.addWidget(self.decrypt_button)
        main_layout.setAlignment(self.decrypt_button, Qt.AlignmentFlag.AlignCenter)


        # Set fixed spacing between widgets
        main_layout.setSpacing(20)

        # Spacer to occupy any additional vertical space
        main_layout.addStretch(1)

        self.setLayout(main_layout)


    @staticmethod
    # This function allows for parsing of multiple file paths during encryption/decryption
    def extract_file_paths(formatted_paths): # File paths should be inputted as `"FileName1.ext","FileName2.ext",...`
        return re.findall(r'"(.*?)"', formatted_paths) # Returns a list of individual file names

    def browse_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Browse", "", "All Files (*);") # Default file type directory to all files
        if files:
            formatted_paths = ",".join(f'"{path}"' for path in files) # Return files as a list in `"FileName1.ext","FileName2.ext",...` format
            self.file_path_input.setText(formatted_paths)


    def encrypt_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path) # Use extract_file_paths method in case there are multiple files selected
        if not fls:
            show_message("Error", "Please enter a file path.")
            return
        else:
            for fl in fls:
                if os.path.splitext(fl)[1] == ".cyph": # Check if the file is already encrypted (i.e has custom ".cyph" extension)
                    show_message("Error", f"{fl} is already encrypted. Please ensure that all selected files are unencrypted.")
                    return
        
        password_dialog = PasswordDialog("Encrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()
        
        if not password:
            return
        
        try:
            for fl in fls:
                encrypt_file(fl, password)
            show_message("Success", "All files have been successfully encrypted.")
            self.file_path_input.clear()
        except Exception as e:
            show_message("Error", str(e))

    def decrypt_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path) 
        if not fls:
            show_message("Error", "Please enter a file path.")
            return
        else:
            for fl in fls: 
                if os.path.splitext(fl)[1] != ".cyph":
                    show_message("Error", f"{fl} is not encrypted or was not encrypted by this application.\n" 
                                    "\nPlease provide files with a `.cyph` extension.")
                    return
        
        password_dialog = PasswordDialog("Decrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()

        if not password:
            return
        
        try:
            for fl in fls:
                decrypt_file(fl, password)
            show_message("Success", "All files have been successfully decrypted.")
            self.file_path_input.clear()
        except Exception as e:
            show_message("Error", str(e))

    # Do I want to replace this logic in the encrypt/decrypt_clicked function with this method?
    # def get_password(self, mode):  # Added "mode" parameter
    #     password_dialog = PasswordDialog(mode, self)  # Pass the mode to the dialog
    #     result = password_dialog.exec()
    #     if result == QDialog.DialogCode.Accepted:
    #         self.file_path_input.clear()
    #         return password_dialog.get_password()
    #     return None


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = "File Access Pro (Alpha)"
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(100, 100, 600, 750)

        # Create a menu bar
        menu_bar = self.menuBar()

        # Create an 'Account' menu
        account_menu = QMenu("Account", self)

        # Create actions to add to the 'Account' menu
        create_account_action = QAction("Create Account", self)
        manage_account_action = QAction("Manage Accounts", self)
        sign_in_action = QAction("Sign In", self)
        
        # Connect actions to the methods
        create_account_action.triggered.connect(self.create_account)
        manage_account_action.triggered.connect(self.manage_account)
        sign_in_action.triggered.connect(self.sign_in)

        # Add actions to the 'Account' menu
        account_menu.addAction(create_account_action)
        account_menu.addAction(manage_account_action)
        account_menu.addAction(sign_in_action)

        # Add 'Account' menu to the menu bar
        menu_bar.addMenu(account_menu)

        # self.setWindowTitle(self.title)
        self.resize(600, 750)

        central_widget = EncyrptionUI()

        # Set the central widget to the QMainWindow
        self.setCentralWidget(central_widget)

        self.show()
    

    # Define the methods to handle the create account and sign-in actions
    def create_account(self):
        new_account = CreateAccountDialog(self)
        new_account.show()

    def manage_account(self):
        manage_account = ManageAccountDialog(self)
        manage_account.show()

    def sign_in(self):
        sign_in = SignInDialog(self)
        sign_in.show()



if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec())

