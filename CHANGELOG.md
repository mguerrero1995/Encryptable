## Version History

### Version 0.0.1 (Pre-Release) - September 12th, 2023
- **Note:** Initial pre-release of File Access Pro.

### Version 0.0.2 - September 17th, 2023
- **Bug Fixes:**
  - Resolved an issue where the application attempted to decrypt files even when incorrect passwords were inputted.
- **Minor Updates:**
  - The file path inputs are now cleared after a successful encryption or decryption operation.

### Version 0.1.0 (Alpha Release) - September 20th, 2023
- **Alpha Release Features:**
  - **Header Metadata**: Added header metadata to the encrypted files to store information such as signature and version. This aids in the validation of files during decryption, ensuring the correct application version is used and enhancing security.
  - **Custom File Extension**: Encrypted files are now saved with a custom `.cyph` extension to help users easily identify encrypted files and to facilitate the application in recognizing files encrypted by it.
  - **Drag and Drop Feature Enhancement**: Enhanced the drag and drop feature to support multiple files, simplifying the process of encrypting or decrypting multiple files at once.
  - **Password Visibility Toggle**: Introduced a feature allowing users to toggle the visibility of their password while typing it in, enhancing user experience.
  - **Improved UI**: Made several improvements to the UI, including better alignment of elements and fixed distances between them to ensure a cohesive and visually appealing layout.
  - **Bug Fixes and Performance Improvements**: Implemented several bug fixes and performance improvements to enhance the overall functionality and user experience of the application

### Version 0.1.1 (Alpha Release) - September 22nd, 2023
**Feature Updates:**
- Added a toolbar with an "Account" dropdown. Will be used to support multiple accounts and password management in the near future.

**Technical Notes:**
- Reorganized the code to accomodate the toolbar. The main app window is now a QMainWindow object rather than a QWidget, and the main encryption/decryption interface is now contained as a separate class (EncryptionUI). This keeps the code cleaner and more organized. The EncryptionUI is set as the central widget for the main App window.

### Version 0.2.0 (Beta Release) - September 26th, 2023
- **New Features:**
  - **User Account Support:** Added a backend SQLite database to support the use of user accounts. 
    - *Create Account:* Users now have the option to create an account by providing an email and password. Passwords are securely stored as hashes.
    - *Logged In State Tracking:* Application can now track if and which user is currently logged in.
    - *File Metadata Storage:* When a logged in user encrypts a file, the encryption data for that file is stored securely as hashed data in the encrypted_files table. Similarly, when a file is decrypted by a logged in user, the entry for that file is deleted from the encrypted_files table.
    - *Change User Password:* Allows users to change their sign in password.

### Version 0.2.1 (Beta Release) - October 1st, 2023
**Bug Fixes:**
- A bug was fixed where the application crashed whenever the "Enter Password" dialog was closed using the close button.

## What's New in Version 0.3.0

**New Features:**
- **Folder-Level Encryption/Decryption:** Encrypt or decrypt entire folders. App automatically detects which files are already encrypted or decrypted when performing the folder search in order to avoid double-encrypting or attempting to decrypt unencrypted files. Current version does not support recursive directory encryption/decryption, but we are planning to include this in a near future release.