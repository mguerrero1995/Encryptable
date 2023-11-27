![FullLogo_Transparent_NoBuffer](https://github.com/mguerrero1995/Encryptable/assets/51759047/4c4baaec-7d7d-402d-ac63-ad789f3a9409)
# Encryptable


**Owner/Developer:** Manny Guerrero  
**Website:** https://encryptable.app
**Email:** EncryptableApp@gmail.com
**Phone:** (530) 219-2898
**Owner's Professional LinkedIn:** https://www.linkedin.com/in/manny-g-933970263/
**Date:** November 27th, 2023  
**Version:** 2.0.0
**Status:** Beta / Testing Stage

---

## ⚠️ Warning

While we strive to develop a robust and secure file encryption tool, the application may contain bugs that could potentially lead to loss of data. 

**Users are solely responsible for any files that become irrecoverable due to use or misuse of Encryptable. It is highly recommended to exercise caution when using the application in its current state, including maintaining backups of all files to be encrypted or decrypted.**

We appreciate your understanding and welcome feedback and reports of any issues you encounter during use.

---

## What's New in Version 0.3.0

**New Features:**
- **File Shredding:** Digitally "shred" files using multi-pass random encryption followed by complete removal from the disk. Files are encrypted multiple times using random keys that are then disposed of before the file is ultimately wiped from the disk. This process makes data permanently irrecoverable in order to meet compliance and/or security demands.

---

## Overview

Encryptable is a free-to-use desktop application designed to offer robust file encryption and decryption solutions with password protection. Safeguard your files with heightened security right from your desktop.

## Features

- **File Encryption/Decryption:** Securely encrypt your files with a password of your choice. Decrypt them back whenever you need.
- **File Shredding:** "Shred" files, making them permanently irrecoverable through multi-pass encryption and deletion.
- **Batch Processing:** Encrypt, decrypt, or shred multiple files at once, a feature that offers convenience and saves time.
- **Drag and Drop:** Easily add files for encryption or decryption using a drag-and-drop interface.
- **Target/Exclude File Exclusions:** Choose file extensions to specifically target or ignore during processing. Prevents accidental encryption and allows for targeted batch processing. 
- **Custom Encrypted File Extension:** Encrypted files are given a custom extension to prevent double encryption and facilitate easy identification.
- **Retain Target File(s):** Option to retain an unaltered copy of the raw/encrypted files during encryption/decryption.
- **Traverse Subfolders:** Option to recursively traverse down the subfolders of a directory during encryption/decryption, allowing for single-shot processing of entire directories.
- **User Account Support:** Basic user account functionality. Create/login to an account using any email that has not previously been registered.
- **Graphical User Interface (GUI):** A user-friendly GUI built with PyQt6 for seamless user experience.

## How to Use

### Installation:
1. **Download:** Download the `Encryptable_Download.zip` folder.
2. **Extract Files:** Extract the files to the location that you would like to run the program from (ex: C:\Users\UserName\Desktop).
3. **Open the Application:** Run `Encryptable.exe`. To ensure proper functioning of the program, please keep/run the executable in the same folder as the files that it was downloaded with.

### Encryption App
1. **Adding Files:**
    - **Browse:** Use the 'Browse' button to select files from your file system.
    - **Drag and Drop:** Simply drag and drop the files into the designated area in the application.
2. **Encryption/Decryption:**
    - **Encrypt:** After adding the files, click on the 'Encrypt' button, enter a secure password, and the files will be encrypted.
    - **Decrypt:** To decrypt, add the encrypted files, click on the "Decrypt" button, and enter the correct password.
        - **Note:** When decrypting multiple files in a batch, ensure all files were encrypted with the same password.
3. **View Encrypted Files:** Encrypted files will have a custom extension. You can find them at the same location as the original files.

### File Shredding App
1. **Adding Files:**
    - **Browse:** Use the 'Browse' button to select files from your file system.
    - **Drag and Drop:** Simply drag and drop the files into the designated area in the application.
2. **Close Files:** Ensure that the files you are attempting to shred are not open or being accessed by any other users or applications.
3. **Shred:** Click 'Shred' and acknowledge the warning message(s).
4. **Verify:** You may now verify that your files no longer exist. They cannot be accessed directly via the file system (such as using Recycle Bin), and any advanced tools used to recover the files will only be able read the multiple-encrypted data.

---

## Windows Anti-Virus Issues

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
- **Additional Advanced Configurations:** Allow users to set additional advanced configurations when encrypting/decrypting or shredding, such as only encrypting/shredding specific file types or skipping certain file types, multiple iteration encryption, etc..
- **Cloud Support:** Extend the functionality to support cloud services, enabling users to encrypt/decrypt files across different devices and integrate with popular cloud storage solutions like Dropbox and Google Drive.
- **Modernized GUI:** Update and modernize the appearance of the interface to improve the user experience.
- **Optional Write Destination:** Allow users to choose a specific destination where the encrypted/decrypted files will be saved.

## License

This project is open-source and free-to-use under the [MIT License](https://opensource.org/licenses/MIT).

---

We hope Encryptable serves you well in securing your files. For any queries or support, feel free to open an issue in the repository.
