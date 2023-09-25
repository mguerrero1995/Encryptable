CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_license (
    license_id BLOB DEFAULT (randomblob(16)) PRIMARY KEY,
    user_id INTEGER
);

CREATE TABLE IF NOT EXISTS license_detail (
    license_id BLOB,
    license_key TEXT,
    license_type TEXT,
    is_active INTEGER
);