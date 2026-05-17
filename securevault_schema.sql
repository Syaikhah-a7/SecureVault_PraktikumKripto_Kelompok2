CREATE DATABASE IF NOT EXISTS db_password_manager;
USE db_password_manager;

CREATE TABLE IF NOT EXISTS user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    salt BLOB NOT NULL,
    master_hash BLOB NOT NULL,
    recovery_token_hash BLOB,
    recovery_expires_at DATETIME,
    failed_login_attempts INT DEFAULT 0,
    locked_until DATETIME
);

CREATE TABLE IF NOT EXISTS password_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    website VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_enc BLOB NOT NULL,
    iv BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL
);
