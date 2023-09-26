DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_license;
DROP TABLE IF EXISTS license_detail;
DROP TABLE IF EXISTS encrypted_files;

CREATE TABLE IF NOT EXISTS users (
    user_id BLOB DEFAULT (randomblob(16)) PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    user_password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_license (
    license_id BLOB DEFAULT (randomblob(16)) PRIMARY KEY,
    user_id INTEGER BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS license_detail (
    license_id BLOB NULL,
    license_key TEXT NULL,
    license_type TEXT NULL,
    is_active INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_files (
    file_id DEFAULT (randomblob(16)) PRIMARY KEY,
    user_id BLOB NULL,
    file_name TEXT NOT NULL,
    encryption_signature TEXT NOT NULL,
    encrypted_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
