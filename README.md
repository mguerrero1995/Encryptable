![FullLogo_Transparent_NoBuffer](https://github.com/mguerrero1995/Encryptable/assets/51759047/4c4baaec-7d7d-402d-ac63-ad789f3a9409)
# Encryptable


**Owner/Developer:** Manny Guerrero  
**Website:** https://brand.page/Encryptable
**Email:** EncryptableService@gmail.com
**Owner's Professional LinkedIn:** https://www.linkedin.com/in/manny-g-933970263/
**Date:** September 28, 2023  
**Version:** 0.2.1
**Status:** Beta / Testing Stage

---

## ⚠️ Warning

This application is currently in its beta/testing stage. While we strive to develop a robust and secure file encryption tool, the application may contain bugs that could potentially lead to loss of data. 

**Users are solely responsible for any files that become irrecoverable due to use or misuse of Encryptable. It is highly recommended to exercise caution when using the application in its current state, including maintaining backups of all files to be encrypted or decrypted.**

We appreciate your understanding and welcome feedback and reports of any issues you encounter during use.

---

## What's New in Version 0.2.1

**New Features:**
- **User Account Support:** Added a backend SQLite database to support the use of user accounts. 
  - *Create Account:* Users now have the option to create an account by providing an email and password. Passwords are securely stored as hashes.
  - *Logged In State Tracking:* Application can now track if and which user is currently logged in.
  - *Change Password:* Users can now change their passwords at any time through the 'Manage Acount' toolbar item.
  - *File Metadata Storage:* When a logged in user encrypts a file, the encryption data for that file is stored securely as hashed data in the encrypted_files table. Similarly, when a file is decrypted by a logged in user, the entry for that file is deleted from the encrypted_files table.

**Bug Fixes:**
- A bug was fixed where the application crashed whenever the "Enter Password" dialog was closed using the close button.

---

## Overview

Encryptable is an open-source, free-to-use desktop application designed to offer robust file encryption and decryption solutions with password protection. Safeguard your files with heightened security right from your desktop.

## Features

- **File Encryption/Decryption:** Securely encrypt your files with a password of your choice. Decrypt them back whenever you need.
- **Batch Processing:** Encrypt or decrypt multiple files at once, a feature that offers convenience and saves time.
- **Drag and Drop:** Easily add files for encryption or decryption using a drag-and-drop interface.
- **Custom File Extensions:** Encrypted files are given a custom extension to prevent double encryption and facilitate easy identification.
- **Graphical User Interface (GUI):** A user-friendly GUI built with PyQt6 for seamless user experience.

## How to Use

1. **Download:** Download the `Encryptable_Download.zip` folder.
2. **Extract Files:** Extract the files to the location that you would like to run the program from (ex: C:\Users\UserName\Desktop).
3. **Open the Application:** Run `Encryptable.exe`. To ensure proper functioning of the program, please keep/run the executable in the same folder as the files that it was downloaded with.
4. **Adding Files:**
    - **Browse:** Use the 'Browse' button to select files from your file system.
    - **Drag and Drop:** Simply drag and drop the files into the designated area in the application.
5. **Encryption/Decryption:**
    - **Encrypt:** After adding the files, click on the 'Encrypt' button, enter a secure password, and the files will be encrypted.
    - **Decrypt:** To decrypt, add the encrypted files, click on the "Decrypt" button, and enter the correct password.
        - **Note**: When decrypting multiple files in a batch, ensure all files were encrypted with the same password.
6. **View Encrypted Files:** Encrypted files will have a custom extension. You can find them at the same location as the original files.

---

**Note on Windows Defender:** Due to the nature of this application involving encryption libraries, some users have reported that Windows flags Encryptable as a potential virus/malware. We assure you that Encryptable does not contain any malware. If you face this issue, you can exclude the directory you extract the files to from Windows Defender scans. Here's how:

1. Open the **Windows Security** app by clicking on the shield icon in the taskbar or searching for it in the start menu.
2. Go to **Virus & threat protection**.
3. Under "Virus & threat protection settings", click on **Manage settings**.
4. Scroll down and click on **Add or remove exclusions** under the "Exclusions" section.
5. Click on **Add an exclusion** and select **Folder**.
6. Browse to and select the directory where you extracted the Encryptable files.

By following these steps, Windows Defender will not scan the specified directory, and you can run Encryptable without any issues.

---
## Future Features

We aim to continually evolve Encryptable to meet user demands and enhance functionality. Here are some prospective features we are considering for future versions:

- **Multiple Account Support:** Introduce an account system to facilitate batch encryption/decryption processes through a single login password, negating the need to enter a password for each batch. Initially, this feature will be local only.
- **Directorly/Folder Level Batch Encryption:** Encrypt entire directories and/or subdirectories as a batch.
- **Advanced Configurations:** Allow users to set advanced configurations when encrypting/decrypting, such as only encrypting specific file types or skipping certain file types, multiple iteration encryption, etc..
- **Cloud Support:** Extend the functionality to support cloud services, enabling users to encrypt/decrypt files across different devices and integrate with popular cloud storage solutions like Dropbox and Google Drive.
- **Modernized GUI:** Update and modernize the appearance of the interface to improve the user experience.
- **Optional Write Destination:** Allow users to choose a specific destination where the encrypted/decrypted files will be saved.

## Contributing

As an open-source project, we welcome contributions from individuals and communities alike. Feel free to fork the repository and submit your contributions through pull requests.

## License

This project is open-source and free-to-use under the [MIT License](https://opensource.org/licenses/MIT).

---

We hope Encryptable serves you well in securing your files. For any queries or support, feel free to open an issue in the repository.
