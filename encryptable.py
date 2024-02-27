import base64
import datetime
import json
import os
import re
import sqlite3
import struct
import sys
import time
import random
import string
from pathlib import Path

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QIcon, QPixmap
from PyQt6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileDialog,
                             QFormLayout, QFrame, QHBoxLayout, QLabel,
                             QLineEdit, QMainWindow, QMenu, QMessageBox,
                             QTabBar, QTabWidget, QPushButton, QVBoxLayout, QWidget)

def load_config(config_path, encryption_key):
    try:
        with open(config_path, "rb") as f:
            encrypted_data = f.read()

        cipher_suite = Fernet(encryption_key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        decrypted_str = decrypted_data.decode("utf-8")

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

IS_PRO_USER = True

LOCAL_DB_CONN = config_data["resources"]["database_name"]

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

def encrypt_file(file_path, password, email):
    if os.path.splitext(file_path)[1] == ".cyph": # Check if the file is already encrypted (i.e has custom ".cyph" extension)
        raise ValueError(f"Error: {os.path.normpath(file_path)} is already encrypted. Please ensure that all selected files are unencrypted.")
    
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
        if email:
            try:
                with sqlite3.connect(LOCAL_DB_CONN) as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO encrypted_files (email, file_name, encryption_signature, encrypted_date) "
                                "VALUES (?, ?, ?, ?)", 
                                (email, os.path.basename(encrypted_file_path), header, datetime.datetime.now()))
            except Exception as e:
                show_message("Error", str(e))
    except:
        raise ValueError(f"Encryption failed for {file_path}")

# Decrypt the file
def decrypt_file(file_path, password, email):
    if os.path.splitext(file_path)[1] != ".cyph":
        raise ValueError(f"Error: {os.path.normpath(file_path)} is not encrypted or was not encrypted by this application.\n" 
                        "\nPlease provide files with a `.cyph` extension.")
                
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
        if email:
            try:
                with sqlite3.connect(LOCAL_DB_CONN) as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM encrypted_files WHERE email = ? AND file_name = ?", 
                                (email, os.path.basename(file_path)))
            except Exception as e:
                show_message("Error", str(e))
    except: 
        raise ValueError(f"Decryption failed for {file_path} due to an incorrect password.") 

def shred_file(file_path, passes=3):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Encrypt the file multiple times
        for pass_count in range(passes):
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            data = encryptor.update(data) + encryptor.finalize() # Encrypt the data

        with open(file_path, "wb") as f:
            f.write(data)
        
        # Randomly rename the file and remove the extension
        dir_name = os.path.dirname(file_path)
        new_name = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        new_file_path = os.path.join(dir_name, new_name)
        os.rename(file_path, new_file_path)
        
        # Normal file deletion process
        os.remove(new_file_path)

    except Exception as e:
        raise ValueError(f"Shredding failed for {file_path}. Error: {e}")

def get_all_files_recursive(directory, encrypted, get_subdirs, return_count=False):
    """
    Recursively get all files in a directory and, optionally, its subdirectories.
    
    Parameters:
    - directory (str): The directory to start the search from.
    - encrypted (bool): If True, only return files with the ".cyph" extension (encrypted files).
                       If False, return all files except those with the ".cyph" extension.
    
    Returns:
    - List of file paths by default. Count of files if return_count=True.
    """
    
    if get_subdirs:
        file_list = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                if encrypted and filepath.endswith(".cyph"):
                    file_list.append(filepath)
                elif not encrypted and not filepath.endswith(".cyph"):
                    file_list.append(filepath)
        if return_count:
            return len(file_list)
        return file_list
    
    if encrypted:
        file_list = [os.path.join(directory, fl) for fl in os.listdir(directory) if os.path.isfile(os.path.join(directory, fl)) and fl.endswith(".cyph")]
    else:
        file_list = [os.path.join(directory, fl) for fl in os.listdir(directory) if os.path.isfile(os.path.join(directory, fl)) and not fl.endswith(".cyph")]

    if return_count:
        return len(file_list)
    return file_list

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

def get_google_credentials():
    # Using the decrypted config data to form the credentials
    credentials = Credentials.from_authorized_user_info(config_data["google_cloud_api"])
    return credentials

def perform_server_side_license_check(email):
    try:
        if email is None:
            return False
        # Get the Google API credentials and build the service
        credentials = get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=credentials)

        # The ID of your spreadsheet and the range of cells we want to retrieve
        spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"] 
        range_name = "A:F"  # Assuming emails are in column "A" and is_pro_user flags are in column "F"

        # Request the values from the sheet
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        values = result.get("values", [])

        # Check if we got any data back
        if not values:
            print("No data found.")
            return False

        # Look for the user's email in the data
        for row in values:
            # Assuming the email is the first element and the is_pro_user flag is the sixth element in the row
            if row[0] == email:
                is_pro_user = row[5]  # Column "F" (0-indexed)
                return bool(is_pro_user)  # Convert 1/0 from spreadsheet to True/False

        # If we reach this point, the user"s email was not found
        print("User not found.")
        return False
    except HttpError as e:
            print(f"An error occurred: {e}")
            return False
    

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
        self.action_btn.setDefault(True)  # Make this button the default button
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
        self.email_spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"]

        self.setWindowTitle("Create New Account")

        self.layout = QVBoxLayout()
        
        self.internet_required_label = QLabel("Note: Internet access required\n")
        
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

        self.layout.addWidget(self.internet_required_label)
        self.layout.addWidget(self.email_label)
        self.layout.addWidget(self.email_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.confirm_password_label)
        self.layout.addWidget(self.confirm_password_input)
        self.layout.addWidget(self.create_account_button)

        self.setLayout(self.layout)  

    def is_email_registered_cloud(self, email):
        """
        Check if the email is already registered in the Google Sheet.
        """
        credentials = get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=credentials)

        # Assuming you have only one sheet and you're checking the entire column A for emails
        result = service.spreadsheets().values().get(
            spreadsheetId=self.email_spreadsheet_id, range="A:A").execute()
        values = result.get("values", [])

        # Flatten the list and check if email exists
        flat_list = [item for sublist in values for item in sublist]
        return email in flat_list
    
    def register_email(self, service, email, hashed_password, registered_datetime):
        """
        Register the email, hashed password, and is_active in the Google Sheet.
        """
        # Including email, hashed_password, and registered_datetime, last_login_datetime, pro_license, and is_pro_user (0 default) for the new row
        values = [[email, hashed_password, str(registered_datetime), None, None, 0]]
        body = {"values": values}
        result = service.spreadsheets().values().append(
            spreadsheetId=self.email_spreadsheet_id, range="A:F",
            valueInputOption="RAW", body=body).execute()
    
        return result
            
    def create_account_clicked(self):
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        credentials = get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=credentials)

        if self.is_email_registered_cloud(email):
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
        uph_as_base64_str = base64.b64encode(user_password_hash).decode("utf-8") # Hashed password must be converted to string before being written to Google Sheets

        try:
            # Register the email in the Google Sheet
            self.register_email(service, email, uph_as_base64_str, datetime.datetime.now())


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
    
    def update_password_in_sheet(self, email, new_user_password_hash, spreadsheet_id):
        try:
            credentials = get_google_credentials()
            service = discovery.build("sheets", "v4", credentials=credentials)
            
            email_spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"]

            result = service.spreadsheets().values().get(
                        spreadsheetId=email_spreadsheet_id, range="A:A").execute()
            values = result.get("values", [])

            # Find the user row
            user_row = None
            for i, row in enumerate(values):
                if row[0] == email:
                    user_row = i + 1  # Adding 1 as the Sheets API is 1-indexed
                    break

            if user_row is None:
                show_message("Error", "User not found")
                return

            # Now, prepare the new password value
            password_range = f"registered_emails!B{user_row}:B{user_row}"  
            value_range_body = {
                "values": [
                    [new_user_password_hash]
                ]
            }

            # Call the Sheets API to update the cell
            result = service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id, range=password_range,
                valueInputOption="RAW", body=value_range_body).execute()
        except Exception as e:
            raise ValueError(e)
        
    def change_password_clicked(self):
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_new_password_input.text()

        # Decode the stored password hash from base64 before verification
        try:
            stored_password_hash = self.app_instance.current_user_password_hash
        except Exception as e:
            show_message("Error", f"An error occurred during decoding: {str(e)}")
            return

        if not verify_login_password(stored_password_hash, current_password):
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
        new_uph_as_base64_str = base64.b64encode(new_user_password_hash).decode("utf-8")

        try:
            if new_user_password_hash:
                email_spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"]
                self.update_password_in_sheet(self.app_instance.current_user_email, new_uph_as_base64_str, email_spreadsheet_id)

                # Assuming you want to update the local instance with the new hash as well
                self.app_instance.current_user_password_hash = new_uph_as_base64_str

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
        self.email_spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"]  # Ensure this is set correctly

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

    def get_user_details(self, email, service):
        # Retrieve data from the spreadsheet
        result = service.spreadsheets().values().get(spreadsheetId=self.email_spreadsheet_id, range="A:B").execute()
        values = result.get("values", [])

        for row in values:
            if row[0] == email:
                return row[1]  # Return the password hash for the matched email

        return None  # Return None if no match was found

    def update_last_login(self, service, email, date_time):
        try:
            email_spreadsheet_id = config_data["resources"]["registered_emails_sheet_id"]

            result = service.spreadsheets().values().get(
                        spreadsheetId=email_spreadsheet_id, range="A:A").execute()
            values = result.get("values", [])

            # Find the user row
            user_row = None
            for i, row in enumerate(values):
                if row[0] == email:
                    user_row = i + 1  # Adding 1 as the Sheets API is 1-indexed
                    break

            if user_row is None:
                show_message("Error", "User not found")
                return

            # Now, prepare the new password value
            password_range = f"registered_emails!D{user_row}:D{user_row}"  
            value_range_body = {
                "values": [
                    [date_time]
                ]
            }

            # Call the Sheets API to update the cell
            result = service.spreadsheets().values().update(
                spreadsheetId=email_spreadsheet_id, range=password_range,
                valueInputOption="RAW", body=value_range_body).execute()
        except Exception as e:
            raise ValueError(e)
        
    def login_clicked(self):
        email = self.email_input.text()
        password = self.password_input.text()

        credentials = get_google_credentials()
        service = discovery.build("sheets", "v4", credentials=credentials)

        try:
            user_password_hash_base64 = self.get_user_details(email, service)

            if user_password_hash_base64 is None:
                self.password_input.clear()
                show_message("Error", "Invalid username or password.")
                return

            # Decode the base64 password hash before verifying
            user_password_hash = base64.b64decode(user_password_hash_base64)
        
            if verify_login_password(user_password_hash, password):
                self.update_last_login(service, email, str(datetime.datetime.now()))
                self.app_instance.current_user_email = email
                self.app_instance.current_user_password_hash = user_password_hash
                self.app_instance.title = f"{APP_NAME}   ({email})"
                self.app_instance.setWindowTitle(self.app_instance.title)
                self.app_instance.is_current_user_pro = perform_server_side_license_check(email)
                self.app_instance.manage_account_action.setEnabled(True)
                self.app_instance.sign_out_action.setEnabled(True)
                self.app_instance.sign_in_action.setEnabled(False)
                self.email_input.clear()
                self.password_input.clear()
                self.close()
            else:
                self.password_input.clear()
                show_message("Error", "Invalid username or password.")
                return
        except Exception as e:
            show_message("Error", str(e)) 


class EncyrptionUI(QWidget):
    # Define a size limit, e.g., 100MB
    JOB_SIZE_LIMIT = 100 * 1024 * 1024  # 100MB in bytes
    ENCRYPTION_COUNT = 2

    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance
        self.advanced_config_states = {"ignore_file_types": None, "encrypt_file_types": None}
        
        # self.layout = QVBoxLayout()

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
        self.drop_zone.setFixedSize(650, 100)
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
        
        self.retain_target_file = QCheckBox("Retain Target File(s)")
        self.retain_target_file.setChecked(False)
        self.configurations_layout.addWidget(self.retain_target_file)

        self.recursive_folder_search = QCheckBox("Search Subfolders")
        self.recursive_folder_search.setChecked(False)
        self.configurations_layout.addWidget(self.recursive_folder_search)
        
        self.configurations_layout.addStretch()

        # Create a container to encapsulate the configurations layout
        self.configurations_container = QWidget()
        self.configurations_container.setObjectName("configurationsContainer")
        self.configurations_container.setStyleSheet("#configurationsContainer { border: 1px solid black; padding: 10px; }")
        self.configurations_container.setFixedWidth(650)

        self.configurations_container.setLayout(self.configurations_layout)
        
        self.main_layout.addWidget(self.configurations_container)

        # Container for the Advanced Configuration button
        self.advanced_config_container = QHBoxLayout()

        # Advanced Configuration button
        self.advanced_config_button = QPushButton("Advanced Configurations", self)
        self.advanced_config_button.setFixedWidth(150)
        self.advanced_config_button.clicked.connect(self.open_advanced_configurations)

        self.advanced_config_container.addStretch()
        self.advanced_config_container.addWidget(self.advanced_config_button)
        self.advanced_config_container.addStretch()
        
        self.main_layout.addLayout(self.advanced_config_container)

        # Center the entire main layout
        self.main_layout.setAlignment(self.configurations_container, Qt.AlignmentFlag.AlignCenter)

        # Set fixed spacing between widgets
        self.main_layout.setSpacing(20)

        # Spacer to occupy any additional vertical space
        self.main_layout.addStretch(1)

        # Set the layout for the entire window
        self.setLayout(self.main_layout)


    @staticmethod
    # This function allows for parsing of multiple file paths during encryption/decryption
    def extract_file_paths(formatted_paths): # File paths should be inputted as `"FileName1.ext","FileName2.ext",...`
        unique_paths = re.findall(r'"(.*?)"', formatted_paths) # Returns a list of individual file names
        return [str(Path(p).absolute()) for p in unique_paths]

    def browse_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Browse", "", "All Files (*);") # Default file type directory to all files
        if files:
            formatted_paths = ",".join(f'"{path}"' for path in files) # Return files as a list in `"FileName1.ext","FileName2.ext",...` format
            self.file_path_input.setText(formatted_paths)

    def prompt_directory_encryption(self, directory_path):
        if self.recursive_folder_search.isChecked():
            response = QMessageBox.warning(self, 
                                        "Directory Encryption Confirmation", 
                                        f"You are about to encrypt the file contents of the directory `{os.path.normpath(directory_path)}` and any subdirectories within. Continue?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        else:    
            response = QMessageBox.warning(self, 
                                            "Directory Encryption Confirmation", 
                                            f"You are about to encrypt the file contents of the directory `{os.path.normpath(directory_path)}`. Continue?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        return response

    def get_job_size(self, file_list, encrypted=False):
        """
        Calculate the total size of all files in the provided list.
        
        Parameters:
        - file_list (list): List of file paths
        
        Returns:
        - int: Total size of all files in bytes
        """
        total_size = 0
        for file_path in file_list:
            if os.path.isdir(file_path):
                # If it's a directory, walk through it and its subdirectories
                for root, _, files in os.walk(file_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        if not encrypted and not full_path.endswith(".cyph"):
                            total_size += os.path.getsize(full_path)
                        elif encrypted and full_path.endswith(".cyph"):
                            total_size += os.path.getsize(full_path)
            else:
                if not encrypted and not file_path.endswith(".cyph"):  
                    total_size += os.path.getsize(file_path)
                elif encrypted and file_path.endswith(".cyph"):
                    total_size += os.path.getsize(file_path)
        return total_size
    
    def encrypt_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path)
        if not fls:
            show_message("Error", "Please enter a valid file path.")
            return
        
        # If a non-Pro user attempts to encrypt/decrypt multiple files or a folder, notify them that this feature is for Pro users only.
        if not self.app_instance.is_current_user_pro and (len(fls) > 1 or any(os.path.isdir(path) for path in fls)):
            QMessageBox.warning(self, "Pro Feature", "Batch/folder processing is only available for Pro users. If you'd like to encrypt multiple files at once, " 
                                                    "please purchase a Pro license on our website (https://encryptable.app).")
            return
        
        # Check the size of the encryption job. If it is more than 100MB, prompt the user to continue.
        total_size = self.get_job_size(fls, encrypted=False)
        
        if total_size > self.JOB_SIZE_LIMIT:
            # Warn the user
            encrypt_response = QMessageBox.warning(self, 
                                        "Large Job Warning", 
                                        f"The file(s) you're about to process are quite large ({int(total_size / (1024 * 1024))}MB) and could result in temporary loss of performance. Do you wish to continue?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if encrypt_response != QMessageBox.StandardButton.Yes:
                return  # Abort the operation

        password = None # Initialize the password variable

        password_dialog = PasswordDialog("Encrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()
        
        if not password:
            return

        files_encrypted = False      
        
        try:
            for path in fls:
                if os.path.isdir(path):
                    directory_response = self.prompt_directory_encryption(path)
                    if directory_response == QMessageBox.StandardButton.No:
                        show_message("Directory Skipped", f"Skipped encryption for `{path}`.")
                        continue

                    # Use the recursive function to get all files in the directory and its subdirectories, if option is selected
                    files_in_directory = get_all_files_recursive(path, encrypted=False, get_subdirs=self.recursive_folder_search.isChecked(), return_count=False)
                    # Remove any files not included in the "Only Encrypt File Types" advanced config list
                    if self.advanced_config_states["encrypt_file_types"]:
                        files_in_directory = [f for f in files_in_directory if os.path.splitext(f)[1] in self.advanced_config_states["encrypt_file_types"]]
                    # Remove any files that are included in the "Ignore File Types" advanced config list (if specific file types specified for encryption, no need to check for ignored types)
                    if not self.advanced_config_states["encrypt_file_types"] and self.advanced_config_states["ignore_file_types"]:
                        files_in_directory = [f for f in files_in_directory if os.path.splitext(f)[1] not in self.advanced_config_states["ignore_file_types"]] 
                    if len(files_in_directory) == 0:
                        show_message("No Files Found", "No files matching specified file types were encrypted. Please check configurations.")
                        continue
                    for file in files_in_directory:
                        encrypt_file(file, password, self.app_instance.current_user_id)
                        if not self.retain_target_file.isChecked():
                            os.remove(file)
                        files_encrypted = True
                else:
                    if self.advanced_config_states["encrypt_file_types"] and os.path.splitext(path)[1] not in self.advanced_config_states["encrypt_file_types"]:
                        show_message("Missing Target File Type", f"{path} is not one of the specified target file types. Please check configurations.")
                        continue
                    if self.advanced_config_states["ignore_file_types"] and os.path.splitext(path)[1] in self.advanced_config_states["ignore_file_types"]:
                        show_message("File Ignored", f"{path} is an ignored file type. Please check configurations.")
                        continue
                    encrypt_file(path, password, self.app_instance.current_user_id)
                    if not self.retain_target_file.isChecked():
                        os.remove(path)
                    files_encrypted = True

            if files_encrypted:
                show_message("Success", "All files have been successfully encrypted.")
                # Reset the UI
                self.file_path_input.clear()
                self.retain_target_file.setChecked(False)
                self.recursive_folder_search.setChecked(False)
                self.advanced_config_states["ignore_file_types"] = None
                self.advanced_config_states["encrypt_file_types"] = None       
        except Exception as e:
            show_message("Error", str(e))

    def decrypt_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path)

        if not fls:
            show_message("Error", "Please enter a file path.")
            return
        
        # If a non-Pro user attempts to encrypt/decrypt multiple files or a folder, notify them that this feature is for Pro users only.
        if not self.app_instance.is_current_user_pro and (len(fls) > 1 or any(os.path.isdir(path) for path in fls)):
            QMessageBox.warning(self, "Pro Feature", "Batch/folder processing is only available for Pro users. If you'd like to decrypt multiple files at once, " 
                                                    "please purchase a Pro license on our website (https://encryptable.app).")
            return

        # Check the size of the encryption job. If it is more than 100MB, prompt the user to continue.
        total_size = self.get_job_size(fls, encrypted=False)
        
        if total_size > self.JOB_SIZE_LIMIT:
            response = QMessageBox.warning(self, 
                                        "Large Job Warning", 
                                        "The file(s) you're about to process are quite large and could result in temporary loss of performance. Do you wish to continue?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if response != QMessageBox.StandardButton.Yes:
                return  # Abort the operation
             
        password = None  # Initialize the password variable

        password_dialog = PasswordDialog("Decrypt", self)
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            password = password_dialog.get_dialog_password()
        
        if not password:
            return
        
        files_decrypted = False     

        try:
            for path in fls:
                if os.path.isdir(path):
                    # Use the recursive function to get all encrypted files in the directory and its subdirectories, if option is selected
                    files_in_directory = get_all_files_recursive(path, encrypted=True, get_subdirs=self.recursive_folder_search.isChecked(), return_count=False)

                    for file in files_in_directory:
                        decrypt_file(file, password, self.app_instance.current_user_id)
                        if not self.retain_target_file.isChecked():
                            os.remove(file)
                        files_decrypted = True
                else:
                    decrypt_file(path, password, self.app_instance.current_user_id)
                    if not self.retain_target_file.isChecked():
                        os.remove(path)
                    files_decrypted = True

            if files_decrypted:
                show_message("Success", "All files have been successfully decrypted.")
                # Reset the UI
                self.file_path_input.clear()
                self.retain_target_file.setChecked(False)
                self.recursive_folder_search.setChecked(False)
                self.advanced_config_states["ignore_file_types"] = None
                self.advanced_config_states["encrypt_file_types"] = None
        except Exception as e:
            show_message("Error", str(e))

    def open_advanced_configurations(self):
        if not self.app_instance.is_current_user_pro:
            show_message("Pro Feature Only", "Advanced configurations are only available to Pro users. "
                                            "Please purchase a Pro license on our website to access advanced configurations (https://encryptable.app).")
            return
        self.advanced_config_dialog = AdvancedEncryptionConfigurations(self, self)
        self.advanced_config_dialog.setWindowTitle("Advanced Configurations")

        # Initialize configurations or set to current settings
        if self.advanced_config_states["ignore_file_types"]:
            self.advanced_config_dialog.ignore_files.setText(",".join(self.advanced_config_states["ignore_file_types"]))
    
        if self.advanced_config_states["encrypt_file_types"]:
            self.advanced_config_dialog.include_files.setText(",".join(self.advanced_config_states["encrypt_file_types"]))

        self.advanced_config_dialog.exec()


class DropZone(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        self.setStyleSheet("background-color: #E0E0E0;")
        # self.setFixedHeight(50)
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
        

class AdvancedEncryptionConfigurations(QDialog):
    def __init__(self, parent, encryption_ui):
        super().__init__(parent)
        self.encryption_ui = encryption_ui

        self.main_layout = QFormLayout()

        self.ignore_files_label = QLabel("Ignore File Types:")
        self.ignore_files = QLineEdit()
        self.ignore_files.setMaximumWidth(200)
        self.ignore_files.setToolTip("Comma-separated file types if more than one (ex: `.txt, .csv, .jpg`)")

        self.include_files_label = QLabel("Target File Types:")
        self.include_files = QLineEdit()
        self.include_files.setMaximumWidth(200)
        self.include_files.setToolTip("Comma-separated file types if more than one (ex: `.txt, .csv, .jpg`)")

        self.main_layout.addRow(self.ignore_files_label, self.ignore_files)
        self.main_layout.addRow(self.include_files_label, self.include_files)

        # OK and Cancel buttons or similar actions
        self.return_buttons_layout = QHBoxLayout()
        self.apply_button = QPushButton("Apply", self)
        self.apply_button.setMaximumWidth(50)
        self.apply_button.clicked.connect(self.apply_advanced_configs)
        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.setMaximumWidth(50)
        self.cancel_button.clicked.connect(self.reject)
        self.return_buttons_layout.addWidget(self.apply_button)
        self.return_buttons_layout.addWidget(self.cancel_button)
        self.main_layout.addRow(None, self.return_buttons_layout)

        self.setLayout(self.main_layout)

    def validate_file_extensions(self, extension_string):
        if not extension_string:
            return True
        # Split the string by comma and strip whitespace
        extensions = [ext.strip() for ext in extension_string.split(",")]
        
        # This pattern means: start with a period, followed by one or more word characters (alphanumeric or underscore)
        pattern = re.compile(r'^\.\w+$')
        
        for ext in extensions:
            # Check if the extension matches the pattern
            if not pattern.match(ext):
                return False
        
        # If all extensions are valid
        return True
    
    def apply_advanced_configs(self):
        ignore_files_text = self.ignore_files.text().strip()
        include_files_text = self.include_files.text().strip()

        ignore_files_list = [ext.strip() for ext in ignore_files_text.split(",")] if ignore_files_text else None
        include_files_list = [ext.strip() for ext in include_files_text.split(",")] if include_files_text else None


        if not self.validate_file_extensions(self.ignore_files.text()):
            show_message("Error", "Invalid file extension entered in ignore file types list.")
            return
        if not self.validate_file_extensions(self.include_files.text()):
            show_message("Error", "Invalid file extension entered in encrypt file types list.")
            return
        if ignore_files_list and include_files_list and set(ignore_files_list).intersection(include_files_list): # Check for extensions entered in both fields
            show_message("Error", f"{set(ignore_files_list).intersection(include_files_list)} entered in both the ignore and include file type lists.")
            return
        
        self.encryption_ui.advanced_config_states["ignore_file_types"] = ignore_files_list
        self.encryption_ui.advanced_config_states["encrypt_file_types"] = include_files_list

        self.close()


class ShredderUI(QWidget):
    # Define a size limit, e.g., 100MB
    JOB_SIZE_LIMIT = 100 * 1024 * 1024  # 100MB in bytes

    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app_instance = app_instance

        # self.layout = QVBoxLayout()

        self.main_layout = QVBoxLayout()

        # File Path input field and Browse button layout

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

        self.shredder_drop_zone_layout = QHBoxLayout()
        self.shredder_drop_zone_layout.addStretch() # Add a stretch before the drop zone so that it stays centered when the window expands
        self.shredder_drop_zone = DropZone(self)
        self.shredder_drop_zone.setFixedSize(650, 100)
        self.shredder_drop_zone_layout.addWidget(self.shredder_drop_zone)
        self.shredder_drop_zone_layout.addStretch() # Add a stretch after the drop zone so that it stays centered when the window expands

        self.main_layout.addLayout(self.shredder_drop_zone_layout)
        
        # Shred button
        self.shred_button_layout = QHBoxLayout()
        self.shred_button_layout.addStretch()

        self.shred_button = QPushButton("Shred", self)
        self.shred_button.setFixedWidth(55)
        self.shred_button.clicked.connect(self.shred_clicked)

        self.shred_button_layout.addWidget(self.shred_button)
        self.shred_button_layout.addStretch()

        self.main_layout.addLayout(self.shred_button_layout)

        # Set fixed spacing between widgets
        self.main_layout.setSpacing(20)

        # Spacer to occupy any additional vertical space
        self.main_layout.addStretch(1)

        # Set the layout for the entire window
        self.setLayout(self.main_layout)


    @staticmethod
    # This function allows for parsing of multiple file paths during shredding
    def extract_file_paths(formatted_paths): # File paths should be inputted as `"FileName1.ext","FileName2.ext",...`
        unique_paths = re.findall(r'"(.*?)"', formatted_paths) # Returns a list of individual file names
        return [str(Path(p).absolute()) for p in unique_paths]
        # Drag and Drop area
    
    def browse_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Browse", "", "All Files (*);") # Default file type directory to all files
        if files:
            formatted_paths = ",".join(f'"{path}"' for path in files) # Return files as a list in `"FileName1.ext","FileName2.ext",...` format
            self.file_path_input.setText(formatted_paths)

    def get_job_size(self, file_list):
        """
        Calculate the total size of all files in the provided list.
        
        Parameters:
        - file_list (list): List of file paths
        
        Returns:
        - int: Total size of all files in bytes
        """
        total_size = 0
        for file_path in file_list:
            if os.path.isdir(file_path):
                # If it's a directory, walk through it and its subdirectories
                for root, _, files in os.walk(file_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        total_size += os.path.getsize(full_path)
            else:
                total_size += os.path.getsize(file_path)
        return total_size
    
    def shred_clicked(self):
        file_path = self.file_path_input.text()
        fls = self.extract_file_paths(file_path)
        if not fls:
            show_message("Error", "Please enter a valid file path.")
            return
        
        # If a non-Pro user attempts to shred multiple files or a folder, notify them that this feature is for Pro users only.
        if not self.app_instance.is_current_user_pro and (len(fls) > 1 or any(os.path.isdir(path) for path in fls)):
            QMessageBox.warning(self, "Pro Feature", "Batch/folder shredding is only available for Pro users. If you'd like to shred multiple files at once, " 
                                                    "please purchase a Pro license on our website (https://encryptable.app).")
            return
        
        shred_response = QMessageBox.warning(self, 
                                "Warning", 
                                f"You are about to perform a file shredding operation. Shredded files CANNOT be recovered and will result in PERMANENT loss of data. Do you wish to continue?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if shred_response != QMessageBox.StandardButton.Yes:
            return
        
        # Check the size of the shredding job. If it is more than 100MB, prompt the user to continue.
        total_size = self.get_job_size(fls)
        
        if total_size > self.JOB_SIZE_LIMIT:
            # Warn the user
            job_size_response = QMessageBox.warning(self, 
                                        "Large Job Warning", 
                                        f"The file(s) you're about to shred are quite large ({int(total_size / (1024 * 1024))}MB) and could result in temporary loss of performance. Do you wish to continue?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if job_size_response != QMessageBox.StandardButton.Yes:
                return  # Abort the operation
            
        files_shredded = False      
        
        try:
            for path in fls:
                if os.path.isdir(path):
                    show_message("Dangerous Activity", "Cannot entire shred directory. Please select individual files or a list of files.")
                    return
                else:
                    shred_file(path, passes=3)
                    files_shredded = True

            if files_shredded:
                show_message("Success", "All files have been successfully shredded.")
                # Reset the UI
                self.file_path_input.clear()  
            else:
                show_message("Cannot Access File", f"`{path}` does not exist or could not be opened. Make sure that the file exists and is not already open.")
                return
        except Exception as e:
            show_message("Error", str(e))

class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = APP_NAME #APP_NAME
        self.app_logo = QIcon(APP_LOGO)
        self.current_user_id = None
        self.current_user_email = None
        self.current_user_password_hash = None
        self.is_current_user_pro = IS_PRO_USER
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
        self.sign_in_action = QAction("Sign In", self)
        self.create_account_action = QAction("Create Account", self)
        self.manage_account_action = QAction("Manage Account", self)
        self.manage_account_action.setEnabled(False) # Disabled by default unless there is a user logged in
        self.sign_out_action = QAction("Sign Out", self)
        self.sign_out_action.setEnabled(False) # Disabled by default unless there is a user logged in
        self.print_user_action = QAction("Print User", self)
        self.set_pro_action = QAction("Set Pro", self)
        self.set_free_action = QAction("Set Free", self)

        # Connect actions to the methods
        self.sign_in_action.triggered.connect(self.sign_in)
        self.create_account_action.triggered.connect(self.create_account)
        self.manage_account_action.triggered.connect(self.manage_account)
        self.sign_out_action.triggered.connect(self.sign_out)
        self.print_user_action.triggered.connect(self.print_user)
        self.set_pro_action.triggered.connect(self.set_pro)
        self.set_free_action.triggered.connect(self.set_free)

        # Add actions to the 'Account' menu
        self.account_menu.addAction(self.sign_in_action)
        self.account_menu.addAction(self.create_account_action)
        self.account_menu.addAction(self.manage_account_action)
        self.account_menu.addSeparator()
        self.account_menu.addAction(self.sign_out_action)
        self.account_menu.addAction(self.print_user_action)
        self.account_menu.addAction(self.set_pro_action)
        self.account_menu.addAction(self.set_free_action)

        # Add 'Account' menu to the menu bar
        self.menu_bar.addMenu(self.account_menu)

        self.encryption_ui = EncyrptionUI(self, self)
        self.file_shredder = ShredderUI(self, self)

        self.tab_bar = QTabWidget()
        self.tab_bar.addTab(self.encryption_ui, "Encrypt/Decrypt")
        self.tab_bar.addTab(self.file_shredder, "File Shredder")

        self.setCentralWidget(self.tab_bar)

        self.resize(600, 750)
        
        self.show()

        # self.setup_periodic_license_check() # Initiate a check every 15 minutes to see if a signed in user has a valid license

    def setup_periodic_license_check(self):
        # Create a timer
        self.license_check_timer = QTimer(self)
        # Set the interval to 15 minutes (in milliseconds)
        self.license_check_timer.setInterval(15 * 60 * 1000)  # 15 minutes
        # Connect the timer to the function to check the license
        self.license_check_timer.timeout.connect(self.check_user_license)
        # Start the timer
        self.license_check_timer.start()

    def check_user_license(self):
        # Only perform the check if the user is currently marked as premium
        if self.is_current_user_pro:
            # Execute the function to check the license status from the server
            is_valid = perform_server_side_license_check(self.current_user_email)
            if is_valid:
                self.is_current_user_pro = True

            if not is_valid:
                # Handle what happens if the user no longer has a valid premium license
                # May want additional updates, such as UI or other settings
                self.is_current_user_pro = False

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

    def sign_out(self):
        # Update variables
        self.title = APP_NAME
        self.current_user_email = None
        self.current_user_password_hash = None
        self.is_current_user_pro = False

        # Update window title
        self.setWindowTitle(self.title)

        # Update button statuses
        self.manage_account_action.setEnabled(False) # Disabled by default unless there is a user logged in
        self.sign_out_action.setEnabled(False) # Disabled by default unless there is a user logged in
        self.sign_in_action.setEnabled(True)
        show_message("Signed Out", "You have successfully signed out.")
        return

    def set_pro(self):
        self.is_current_user_pro = True
        print(f"Pro Status = {self.is_current_user_pro}")

    def set_free(self):
        self.is_current_user_pro = False
        print(f"Pro Status = {self.is_current_user_pro}")

    def print_user(self):
        # show_message("Current User", f"Current user is {self.current_user_id}.")
        # show_message("DB Name", config_data["google_cloud_api"])
        print(f"Pro user status: {self.is_current_user_pro}", config_data["google_cloud_api"]["refresh_token"])
        # print(self.title, self.current_user_email, self.current_user_password_hash)
        return
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # app.setStyle("Windows")
    ex = App()
    sys.exit(app.exec())
