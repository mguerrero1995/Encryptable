import sys
import os
from PyQt6.QtCore import Qt, QMimeData
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox, QInputDialog, QDialog, QHBoxLayout, QPushButton, QFileDialog, QFrame
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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
        self.show_icon = QIcon(QPixmap("C:/Users/mguerrero/source/repos/FileAccessPro/icons/show_password_icon.png"))
        self.hide_icon = QIcon(QPixmap("C:/Users/mguerrero/source/repos/FileAccessPro/icons/hide_password_icon.png"))
        self.toggle_password_btn = QPushButton(self)
        self.toggle_password_btn.setIcon(self.show_icon)  
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
            self.toggle_password_btn.setIcon(self.hide_icon)  # set to hide icon when password is visible
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_password_btn.setIcon(self.show_icon)  # set back to show icon when password is hidden
    
    def get_password(self):
        return self.password_input.text()



class DropZone(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Sunken)
        self.setStyleSheet("background-color: #E0E0E0;")
        self.setFixedHeight(50)
        self.setText("Drop File Here")

    def dragEnterEvent(self, event):
        mime_data = event.mimeData()
        if mime_data.hasUrls() and len(mime_data.urls()) == 1:  # Only accept one file
            event.acceptProposedAction()

    def dropEvent(self, event):
        file_path = event.mimeData().urls()[0].toLocalFile()  # Get the file path
        self.parent().file_path_input.setText(file_path)  # Update the QLineEdit with the file path


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'File Encryption'
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()


        # Label
        self.file_path_label = QLabel("Enter File Path or Drag & Drop File:")
        main_layout.addWidget(self.file_path_label)
        main_layout.setAlignment(self.file_path_label, Qt.AlignmentFlag.AlignLeft)

        # File Path input field and Browse button layout
        path_layout = QHBoxLayout()

        # Input field for the file path
        self.file_path_input = QLineEdit(self)
        self.file_path_input.setFixedWidth(400)
        path_layout.addWidget(self.file_path_input)
        path_layout.setAlignment(self.file_path_input, Qt.AlignmentFlag.AlignLeft)

        # Browse button
        self.browse_button = QPushButton('Browse', self)
        self.browse_button.clicked.connect(self.browse_file)
        self.browse_button.setFixedWidth(60)
        path_layout.addWidget(self.browse_button)
        path_layout.setAlignment(self.browse_button, Qt.AlignmentFlag.AlignLeft)

        # Add a horizontal stretch after the Browse button
        path_layout.addStretch(1)

        main_layout.addLayout(path_layout)

        # Drag and Drop area
        self.drop_zone = DropZone(self)
        main_layout.addWidget(self.drop_zone)
    
        # Encrypt button
        self.encrypt_button = QPushButton('Encrypt', self)
        self.encrypt_button.setFixedWidth(55)
        self.encrypt_button.clicked.connect(self.encrypt_clicked)
        main_layout.addWidget(self.encrypt_button)
        main_layout.setAlignment(self.encrypt_button, Qt.AlignmentFlag.AlignLeft)

        # Decrypt button
        self.decrypt_button = QPushButton('Decrypt', self)
        self.decrypt_button.setFixedWidth(55)
        self.decrypt_button.clicked.connect(self.decrypt_clicked)
        main_layout.addWidget(self.decrypt_button)
        main_layout.setAlignment(self.decrypt_button, Qt.AlignmentFlag.AlignLeft)


        # Set fixed spacing between widgets
        main_layout.setSpacing(20)

        # Spacer to occupy any additional vertical space
        main_layout.addStretch(1)

        self.setLayout(main_layout)
        self.setWindowTitle(self.title)
        self.resize(600, 750)
        self.show()
    

    def browse_file(self):
        # Open a file dialog and set the selected file path to the input field
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path_input.setText(file_path)

    def encrypt_clicked(self):
        file_path = self.file_path_input.text()
        if not file_path:
            self.show_message("Error", "Please enter a file path.")
            return
        password = self.get_password("Encrypt")  # Pass the mode as an argument
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
        password = self.get_password("Decrypt")  # Pass the mode as an argument
        if not password:
            return
        try:
            decrypt_file(file_path, password)
            self.show_message("Success", f"File {file_path} has been decrypted.")
        except Exception as e:
            self.show_message("Error", str(e))

    def get_password(self, mode):  # Added 'mode' parameter
        password_dialog = PasswordDialog(mode, self)  # Pass the mode to the dialog
        result = password_dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return password_dialog.get_password()
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

