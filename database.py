import mysql.connector
from mysql.connector import Error
from datetime import datetime

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'db_password_manager'
}

def get_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def add_audit_log(user_id: int, action: str):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "INSERT INTO audit_log (user_id, action) VALUES (%s, %s)"
            cursor.execute(query, (user_id, action))
            conn.commit()
        except Error as e:
            print(f"Error add_audit_log: {e}")
        finally:
            cursor.close()
            conn.close()

def cek_user_ada() -> bool:
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM user")
            result = cursor.fetchone()
            return result[0] > 0
        except Error as e:
            print(f"Error cek_user_ada: {e}")
        finally:
            cursor.close()
            conn.close()
    return False

def get_user_by_username(username: str):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
            return cursor.fetchone()
        except Error as e:
            print(f"Error get_user_by_username: {e}")
        finally:
            cursor.close()
            conn.close()
    return None

def create_user(username: str, salt: bytes, master_hash: bytes) -> bool:
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "INSERT INTO user (username, salt, master_hash) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, salt, master_hash))
            conn.commit()
            
            user_id = cursor.lastrowid
            add_audit_log(user_id, "User registered")
            return True
        except Error as e:
            print(f"Error create_user: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    return False

def update_login_attempts(user_id: int, attempts: int, locked_until=None):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            if locked_until:
                query = "UPDATE user SET failed_login_attempts = %s, locked_until = %s WHERE id = %s"
                cursor.execute(query, (attempts, locked_until, user_id))
            else:
                query = "UPDATE user SET failed_login_attempts = %s WHERE id = %s"
                cursor.execute(query, (attempts, user_id))
            conn.commit()
        except Error as e:
            print(f"Error update_login_attempts: {e}")
        finally:
            cursor.close()
            conn.close()

def add_password_entry(user_id: int, website: str, username: str, password_enc: bytes, iv: bytes, auth_tag: bytes) -> bool:
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "INSERT INTO password_entries (user_id, website, username, password_enc, iv, auth_tag) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(query, (user_id, website, username, password_enc, iv, auth_tag))
            conn.commit()
            return True
        except Error as e:
            print(f"Error add_password_entry: {e}")
        finally:
            cursor.close()
            conn.close()
    return False

def get_passwords(user_id: int):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM password_entries WHERE user_id = %s", (user_id,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error get_passwords: {e}")
        finally:
            cursor.close()
            conn.close()
    return []

def delete_password(entry_id: int):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM password_entries WHERE id = %s", (entry_id,))
            conn.commit()
            return True
        except Error as e:
            print(f"Error delete_password: {e}")
        finally:
            cursor.close()
            conn.close()
    return False

def save_recovery_token(user_id: int, recovery_hash: bytes, expires_at: datetime):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "UPDATE user SET recovery_token_hash = %s, recovery_expires_at = %s WHERE id = %s"
            cursor.execute(query, (recovery_hash, expires_at, user_id))
            conn.commit()
            add_audit_log(user_id, "Generated recovery token")
        except Error as e:
            print(f"Error save_recovery_token: {e}")
        finally:
            cursor.close()
            conn.close()

def update_master_key(user_id: int, new_salt: bytes, new_hash: bytes):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "UPDATE user SET salt = %s, master_hash = %s, recovery_token_hash = NULL, recovery_expires_at = NULL WHERE id = %s"
            cursor.execute(query, (new_salt, new_hash, user_id))
            conn.commit()
            add_audit_log(user_id, "Reset Master Key")
            return True
        except Error as e:
            print(f"Error update_master_key: {e}")
        finally:
            cursor.close()
            conn.close()
    return False

def update_password_encryption(entry_id: int, password_enc: bytes, iv: bytes, auth_tag: bytes):
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = "UPDATE password_entries SET password_enc = %s, iv = %s, auth_tag = %s WHERE id = %s"
            cursor.execute(query, (password_enc, iv, auth_tag, entry_id))
            conn.commit()
        except Error as e:
            print(f"Error update_password_encryption: {e}")
        finally:
            cursor.close()
            conn.close()
