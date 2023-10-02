import datetime
import json
import os
import random
import re
import sqlite3
import struct
import sys
import time

import bcrypt
import gspread
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from google.oauth2.credentials import Credentials
from oauth2client.client import GoogleCredentials
from googleapiclient import discovery
from googleapiclient import errors
from oauth2client.service_account import ServiceAccountCredentials
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileDialog,
                             QFormLayout, QFrame, QHBoxLayout, QLabel,
                             QLineEdit, QMainWindow, QMenu, QMessageBox,
                             QPushButton, QVBoxLayout, QWidget)


def load_config(config_path, encryption_key):
    try:
        with open(config_path, 'rb') as f:
            encrypted_data = f.read()

        cipher_suite = Fernet(encryption_key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        decrypted_str = decrypted_data.decode('utf-8')

        return json.loads(decrypted_str)
    except:
        raise ValueError("Config file failed to load.")

# Configurations for app
config_file = "./resources/config.json"
ek = b'5sE83ehZ3E6GgIYx1DkzKbZWiOWhAv3R0YumjC1iHkM='

# Load and decrypt the config
config_data = load_config(config_file, ek)

# Pull out individual configs
APP_NAME = config_data["application"]["name"]
APP_LOGO = config_data["resources"]["app_logo"]
APP_VERSION = config_data["application"]["version"] # Version from config file in '#.#.#' format
APP_VERSION_MAJOR = int(APP_VERSION[0]) # First number (int)
APP_VERSION_MINOR = int(APP_VERSION[2]) # Second number (int)
APP_VERSION_PATCH = int(APP_VERSION[-1]) # Third (last) number (int)

GC_CLIENT_ID = config_data["google_cloud_api"]["client_id"]

SIGNATURE = b'ENCRYPTABLE_APP'  # Your unique file signature, converted to bytes
HEADER_ADDITIONAL_LENGTH = 5 # The length of the additional header information, in bytes

# File path configurations for the app
SHOW_PW_ICON = config_data["resources"]["show_password_icon"]
HIDE_PW_ICON = config_data["resources"]["hide_password_icon"]

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
'''
# Encrypt the file
def encrypt_file(file_path, password, user_id):
    try:
        salt = os.urandom(16)
        key = key_from_password(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, "rb") as f:
            plaintext = f.read()
        
        # Adding a known signature at the start of the file
        signature = SIGNATURE
        timestamp = int(time.time())
        header = signature + struct.pack('BBB', APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH) + struct.pack('I', timestamp)
        plaintext = header + plaintext
        # print(f"Signature Length: {len(signature)}") # debug
        # print(f"Version Length: {len(struct.pack('BBB', APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_PATCH))}") # debug
        # print(f"Timestamp Length: {len(struct.pack('I', timestamp))}") # debug
        # print(f"Total Header Length: {len(header)}") # debug

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        encrypted_file_path = file_path + ".cyph"
        with open(encrypted_file_path, "wb") as f:
            f.write(salt + iv + ciphertext)
        
        # Write the encryption metadata to the database if a user is logged in
        if user_id:
            try:
                with sqlite3.connect("./resources/accounts_database.db") as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO encrypted_files (user_id, file_name, encryption_signature, encrypted_date) "
                                "VALUES (?, ?, ?, ?)", 
                                (user_id, os.path.basename(encrypted_file_path), header, datetime.datetime.now()))
            except Exception as e:
                show_message("Error", str(e))
    except Exception as e:
        show_message("Error", str(e))

# Decrypt the file
def decrypt_file(file_path, password, user_id):
    # try:
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
    header_len = len(signature) + HEADER_ADDITIONAL_LENGTH # 3 bytes for the version and 4 bytes for the timestamp

    # print(f"Expected Header Length from File: {len(plaintext[:header_len])}") # debug

    signature_in_file, major, minor, patch, timestamp = struct.unpack(f'15sBBBI', plaintext[:header_len])

    # Step 3: Verifying the header
    if signature_in_file != signature:
        raise ValueError("Incorrect password or file not encrypted by this application.")

    # print(f"Header Content: {plaintext[:header_len]}") # debug
    plaintext = plaintext[header_len:]

    # Remove custom extension to restore original file extension
    decrypted_file_path = file_path.rstrip(".cyph")

    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    # Delete the encryption metadata from the database if a user is logged in
    if user_id:
        try:
            with sqlite3.connect("./resources/accounts_database.db") as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM encrypted_files WHERE user_id = ? AND file_name = ?", 
                            (user_id, os.path.basename(file_path)))
        except Exception as e:
            show_message("Error", str(e))
    # except:
    #     signature_in_file, major, minor, patch, timestamp = struct.unpack(f'15sBBBI', plaintext[:header_len])
    #     print(signature_in_file)
    #     raise ValueError(f"Decryption failed for {file_path} due to an incorrect password.")
 '''

# Encrypt the file
def encrypt_file(file_path, password, user_id):
    try:
        salt = os.urandom(16)
        key = key_from_password(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, "rb") as f:
            plaintext = f.read()
        
        # Adding a known signature at the start of the file
        signature = SIGNATURE
        version = 0
        timestamp = int(time.time())
        header = signature + struct.pack('B', version) + struct.pack('I', timestamp)
        plaintext = header + plaintext
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        encrypted_file_path = file_path + ".cyph"
        with open(encrypted_file_path, "wb") as f:
            f.write(salt + iv + ciphertext)
        
        # Write the encryption metadata to the database if a user is logged in
        if user_id:
            try:
                with sqlite3.connect("accounts_database.db") as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO encrypted_files (user_id, file_name, encryption_signature, encrypted_date) "
                                "VALUES (?, ?, ?, ?)", 
                                (user_id, os.path.basename(encrypted_file_path), header, datetime.datetime.now()))
            except Exception as e:
                show_message("Error", str(e))
    except Exception as e:
        show_message("Error", str(e))

# Decrypt the file
def decrypt_file(file_path, password, user_id):
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
            raise ValueError("Incorrect password or file not encrypted by this application.")

        plaintext = plaintext[len(signature) + HEADER_ADDITIONAL_LENGTH:]

        # Remove custom extension to restore original file extension
        decrypted_file_path = file_path.rstrip(".cyph")

        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        # Delete the encryption metadata from the database if a user is logged in
        if user_id:
            try:
                with sqlite3.connect("accounts_database.db") as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM encrypted_files WHERE user_id = ? AND file_name = ?", 
                                (user_id, os.path.basename(file_path)))
            except Exception as e:
                show_message("Error", str(e))
    except: 
        raise ValueError(f"Decryption failed for {file_path} due to an incorrect password.") 
    
def hash_login_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed

def verify_login_password(stored_password_hash: bytes, provided_password: str) -> bool:
    return bcrypt.checkpw(provided_password.encode("utf-8"), stored_password_hash)

def is_valid_email(email):
    """
    Check if the provided string is a valid email format.
    
    :param email: The email address string to check.
    :return: True if valid, False otherwise.
    """
    # The regular expression pattern for a valid email
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    
    return bool(re.match(pattern, email))

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
        
        self.password_dialog_layout = QVBoxLayout()  # Main layout
        
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

        self.password_dialog_layout.addLayout(self.input_layout)

        # Encrypt/Decrypt action button
        self.action_btn = QPushButton(self.mode, self)
        self.action_btn.clicked.connect(self.accept)
        self.password_dialog_layout.addWidget(self.action_btn)
        self.password_dialog_layout.setAlignment(self.action_btn, Qt.AlignmentFlag.AlignCenter)  # Center-align the button
        
        self.setLayout(self.password_dialog_layout)

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
        self.config_data = config_data
        self.email_spreadsheet_id = "1z5CeB_HSSh-zkib5yOUKrIEHcyocPqdr-s0W2ZWEV70"

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

    def get_google_credentials(self):
            # Using the decrypted config data to form the credentials
            creds = Credentials.from_authorized_user_info(self.config_data["google_cloud_api"])
            return creds
    
    def is_email_registered(self, email):
        """
        Check if the email is already registered in the Google Sheet.
        """
        creds = self.get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=creds)

        # Assuming you have only one sheet and you're checking the entire column A for emails
        result = service.spreadsheets().values().get(
            spreadsheetId=self.email_spreadsheet_id, range="A:B").execute()
        values = result.get("values", [])

        # Flatten the list and check if email exists
        flat_list = [item for sublist in values for item in sublist]
        return email in flat_list

    def register_email(self, email):
        """
        Register the email in the Google Sheet.
        """
        creds = self.get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=creds)

        # Assuming you're appending to column A
        values = [[email]]
        body = {"values": values}
        result = service.spreadsheets().values().append(
            spreadsheetId=self.email_spreadsheet_id, range="A:B",
            valueInputOption="RAW", body=body).execute()
        
        return result

    def create_account_clicked(self):
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if self.is_email_registered(email):
            show_message("Error", "This email is already in use.")
            return

        if not is_valid_email(email):
            show_message("Error", "Invalid email address. Please enter a valid email.")
            return

        if password != confirm_password:
            self.email_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()
            show_message("Error", "Passwords do not match.")
            return

        user_password_hash = hash_login_password(password)

        try:
            # Connect to database
            with sqlite3.connect("./resources/accounts_database.db") as conn:
                cur = conn.cursor()

                # Insert a new record into the users table with the email and password
                cur.execute("INSERT INTO users (email, user_password_hash) VALUES (?, ?);", 
                            (email, user_password_hash))

            # Register the email in the Google Sheet
            self.register_email(email)

            self.email_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()
            show_message("Success!", "New account successfully created.")
            self.close()
        except Exception as e:
            show_message("Error", str(e))
        


class ManageAccountDialog(QDialog):
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance

        self.setWindowTitle("Manage Account")

        self.manage_account_layout = QFormLayout()

        self.email_label = QLabel(f"Email:\n{self.app_instance.current_user_email}")
        self.edit_email_button = QPushButton("Edit")
        self.edit_email_button.setMaximumWidth(75)

        self.current_password_label = QLabel("Password:\n********")
        self.edit_password_button = QPushButton("Edit")
        self.edit_password_button.clicked.connect(self.edit_user_password_clicked)
        self.edit_password_button.setMaximumWidth(75)

        self.manage_account_layout.addRow(self.email_label, self.edit_email_button)
        self.manage_account_layout.addRow(self.current_password_label, self.edit_password_button)

        self.setLayout(self.manage_account_layout)
        
    def edit_user_password_clicked(self):
        edit_user_password = EditUserPassword(self, self.app_instance)
        edit_user_password.show()

class EditUserPassword(QDialog):
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance
        
        self.setWindowTitle("Change Password")

        self.edit_user_password_layout = QFormLayout()

        self.current_password_label = QLabel("Current Password:")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input
        self.current_password_input.setMinimumWidth(150)
        self.current_password_input.setMaximumWidth(300)

        self.new_password_label = QLabel("New Password:")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input
        self.new_password_input.setMinimumWidth(150)
        self.new_password_input.setMaximumWidth(300)

        self.confirm_new_password_label = QLabel("Confirm New Password:")
        self.confirm_new_password_input = QLineEdit()
        self.confirm_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input
        self.confirm_new_password_input.setMinimumWidth(150)
        self.confirm_new_password_input.setMaximumWidth(300)

        self.change_password_button = QPushButton("Change Password")
        self.change_password_button.setMaximumWidth(150)
        self.change_password_button.clicked.connect(self.change_password_clicked)

        self.edit_user_password_layout.addRow(self.current_password_label, self.current_password_input)
        self.edit_user_password_layout.addRow(self.new_password_label, self.new_password_input)
        self.edit_user_password_layout.addRow(self.confirm_new_password_label, self.confirm_new_password_input)
        self.edit_user_password_layout.addWidget(self.change_password_button)    

        self.setLayout(self.edit_user_password_layout)
        
    def change_password_clicked(self):
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_new_password_input.text()

        if not verify_login_password(self.app_instance.current_user_password_hash, current_password):
            self.current_password_input.clear()
            self.new_password_input.clear()
            self.confirm_new_password_input.clear()
            show_message("Error", "Current password is incorrect.")
            return

        if new_password != confirm_password:
            self.current_password_input.clear()
            self.new_password_input.clear()
            self.confirm_new_password_input.clear()
            show_message("Error", "New passwords do not match.")
            return
        
        new_user_password_hash = hash_login_password(new_password)

        try:
            # Connect to database
            with sqlite3.connect("./resources/accounts_database.db") as conn:
                cur = conn.cursor()

                # Get password hash and salt for the provided email 
                cur.execute("UPDATE users SET user_password_hash = ? WHERE user_id = ?", (new_user_password_hash, self.app_instance.current_user_id))
            
            self.current_password_input.clear()
            self.new_password_input.clear()
            self.confirm_new_password_input.clear()
            show_message("Success", "Password successfully changed.")
            self.close()
        except Exception as e:
            show_message("Error", str(e))

class SignInDialog(QDialog):
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance

        self.setWindowTitle("Sign In")

        self.sign_in_layout = QVBoxLayout()

        self.email_label = QLabel("Email:")
        self.email_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)  # Hide password input

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login_clicked)

        self.sign_in_layout.addWidget(self.email_label)
        self.sign_in_layout.addWidget(self.email_input)
        self.sign_in_layout.addWidget(self.password_label)
        self.sign_in_layout.addWidget(self.password_input)
        self.sign_in_layout.addWidget(self.login_button)

        self.setLayout(self.sign_in_layout)

    def login_clicked(self):
        # Handle login
        email = self.email_input.text()
        password = self.password_input.text()

        try:
            # Connect to database
            with sqlite3.connect("./resources/accounts_database.db") as conn:
                cur = conn.cursor()

                # Get password hash and salt for the provided email 
                login_details = cur.execute("SELECT user_id, user_password_hash FROM users WHERE email = ?", (email,)).fetchone()

            if not login_details: # Verify that a matching email was found
                self.password_input.clear()
                show_message("Error", "Invalid username or password.")
                return

            user_id, user_password_hash = login_details[0], login_details[1] # Convert user_password_hash to a binary string instead of a tuple
        
            if verify_login_password(user_password_hash, password):
                self.app_instance.current_user_id = user_id
                self.app_instance.current_user_email = email
                self.app_instance.current_user_password_hash = user_password_hash
                self.app_instance.title = f"{APP_NAME}   ({email})"
                self.app_instance.setWindowTitle(self.app_instance.title)
                self.app_instance.manage_account_action.setEnabled(True)
                self.email_input.clear()
                self.password_input.clear()
                self.close()
            else:
                show_message("Error", "Invalid username or password.")
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
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance
        
        self.layout = QVBoxLayout()

        # Create a main layout
        self.main_layout = QVBoxLayout()

        # Label
        self.file_path_label = QLabel("Enter File Path(s) or Drag & Drop File(s):")
        self.main_layout.addWidget(self.file_path_label)
        self.main_layout.setAlignment(self.file_path_label, Qt.AlignmentFlag.AlignCenter)


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

        self.main_layout.addLayout(path_layout)

        # Drag and Drop area
        self.drop_zone_layout = QHBoxLayout()
        self.drop_zone_layout.addStretch() # Add a stretch before the drop zone so that it stays centered when the window expands
        self.drop_zone = DropZone(self)
        self.drop_zone.setFixedWidth(650)  # Set the maximum width
        self.drop_zone_layout.addWidget(self.drop_zone)
        self.drop_zone_layout.addStretch() # Add a stretch after the drop zone so that it stays centered when the window expands

        self.main_layout.addLayout(self.drop_zone_layout)

        self.function_buttons_layout = QHBoxLayout()

        # Add a stretch before the buttons to push them towards the center
        self.function_buttons_layout.addStretch()

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt", self)
        self.encrypt_button.setFixedWidth(55)
        self.encrypt_button.clicked.connect(self.encrypt_clicked)
        self.function_buttons_layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.setFixedWidth(55)
        self.decrypt_button.clicked.connect(self.decrypt_clicked)
        self.function_buttons_layout.addWidget(self.decrypt_button)

        # Add another stretch after the buttons to keep them centered
        self.function_buttons_layout.addStretch()

        # A fixed space between the Encrypt and Decrypt buttons
        self.function_buttons_layout.addSpacing(20)

        self.main_layout.addLayout(self.function_buttons_layout)

        # Create a layout to organize the configurations/settings
        self.configurations_layout = QHBoxLayout()
        self.configurations_layout.setContentsMargins(5, 5, 5, 5)

        self.configurations_label = QLabel("Configurations:")
        self.configurations_layout.addWidget(self.configurations_label)
        
        self.retain_original_file = QCheckBox("Retain Original File(s)")
        self.retain_original_file.setChecked(False)
        self.configurations_layout.addWidget(self.retain_original_file)

        self.configurations_layout.addStretch()

        # Create a container to encapsulate the configurations layout
        self.configurations_container = QWidget()
        self.configurations_container.setObjectName("configurationsContainer")
        self.configurations_container.setStyleSheet("#configurationsContainer { border: 1px solid black; padding: 10px; }")
        self.configurations_container.setFixedWidth(650)

        self.configurations_container.setLayout(self.configurations_layout)
        
        self.main_layout.addWidget(self.configurations_container)
        self.main_layout.setAlignment(self.configurations_container, Qt.AlignmentFlag.AlignCenter)

        # Set fixed spacing between widgets
        self.main_layout.setSpacing(20)

        # Spacer to occupy any additional vertical space
        self.main_layout.addStretch(1)

        self.setLayout(self.main_layout)


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
        retain_original = self.retain_original_file.isChecked()

        if not fls:
            show_message("Error", "Please enter a file path.")
            return
        else:
            for fl in fls:
                if os.path.splitext(fl)[1] == ".cyph": # Check if the file is already encrypted (i.e has custom ".cyph" extension)
                    show_message("Error", f"{fl} is already encrypted. Please ensure that all selected files are unencrypted.")
                    return
        
        password = None  # Initialize the password variable

        password_dialog = PasswordDialog("Encrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()
        
        if not password:
            return
        
        try:
            for fl in fls:
                encrypt_file(fl, password, self.app_instance.current_user_id)
                if not retain_original: # Optionally delete the encrypted file after decryption
                    os.remove(fl)
            show_message("Success", "All files have been successfully encrypted.")
            self.file_path_input.clear()
        except Exception as e:
            show_message("Error", str(e))

    def decrypt_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path) 
        retain_original = self.retain_original_file.isChecked()

        if not fls:
            show_message("Error", "Please enter a file path.")
            return
        else:
            for fl in fls: 
                if os.path.splitext(fl)[1] != ".cyph":
                    show_message("Error", f"{fl} is not encrypted or was not encrypted by this application.\n" 
                                    "\nPlease provide files with a `.cyph` extension.")
                    return
                
        password = None  # Initialize the password variable

        password_dialog = PasswordDialog("Decrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()

        if not password:
            return
        
        try:
            for fl in fls:
                decrypt_file(fl, password, self.app_instance.current_user_id)
                if not retain_original: # Optionally delete the encrypted file after decryption
                    os.remove(fl)
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
        self.title = APP_NAME
        self.app_logo = QIcon(APP_LOGO)
        self.current_user_id = None
        self.current_user_email = None
        self.current_user_password_hash = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setWindowIcon(self.app_logo)
        self.setGeometry(100, 100, 600, 750)

        # Create a menu bar
        self.menu_bar = self.menuBar()

        # Create an 'Account' menu
        self.account_menu = QMenu("Account", self)

        # Create actions to add to the 'Account' menu
        self.create_account_action = QAction("Create Account", self)
        self.manage_account_action = QAction("Manage Accounts", self)
        self.manage_account_action.setEnabled(False) # Disabled by default unless there is a user logged in
        self.sign_in_action = QAction("Sign In", self)
        # self.print_user_action = QAction("Print User", self)

        # Connect actions to the methods
        self.create_account_action.triggered.connect(self.create_account)
        self.manage_account_action.triggered.connect(self.manage_account)
        self.sign_in_action.triggered.connect(self.sign_in)
        # self.print_user_action.triggered.connect(self.print_user)

        # Add actions to the 'Account' menu
        self.account_menu.addAction(self.create_account_action)
        self.account_menu.addAction(self.manage_account_action)
        self.account_menu.addAction(self.sign_in_action)
        # self.account_menu.addAction(self.print_user_action)

        # Add 'Account' menu to the menu bar
        self.menu_bar.addMenu(self.account_menu)

        # self.setWindowTitle(self.title)
        self.resize(600, 750)

        self.central_widget = EncyrptionUI(self, self)

        # Set the central widget to the QMainWindow
        self.setCentralWidget(self.central_widget)

        self.show()
    

    # Define the methods to handle the create account and sign-in actions
    def create_account(self):
        new_account = CreateAccountDialog(self)
        new_account.show()

    def manage_account(self):
        manage_account = ManageAccountDialog(self, self)
        manage_account.show()

    def sign_in(self):
        sign_in = SignInDialog(self, self)
        sign_in.show()

    # def print_user(self):
    #     show_message("Current User", f"Current user is {self.current_user_id}.")
    #     print(self.title, self.current_user_email, self.current_user_password_hash)
    #     return


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # app.setStyle("Windows")
    ex = App()
    sys.exit(app.exec())
