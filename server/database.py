import sqlite3
import threading
from contextlib import contextmanager
from encryption import hash_password, verify_password

DB_NAME = 'chat_server.db'

# Thread-safe database connection
_db_lock = threading.Lock()

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper cleanup."""
    conn = None
    try:
        with _db_lock:
            conn = sqlite3.connect(DB_NAME, timeout=30.0)
            conn.execute('PRAGMA foreign_keys = ON')  # Enable foreign key constraints
            yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def create_users_table():
    """Create the users table if it doesn't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Create index for faster username lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_username ON users(username)
        ''')
        
        conn.commit()

def register_user(username, password):
    """
    Register a new user.
    
    Args:
        username: The username (must be unique)
        password: The plain text password
        
    Returns:
        bool: True if registration successful, False if username exists
    """
    if not username or not password:
        return False
    
    username = username.lower().strip()  # Normalize username
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False
            
            # Hash password and insert user
            password_hash = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            return True
            
    except sqlite3.IntegrityError:
        # Username already exists (caught by UNIQUE constraint)
        return False
    except Exception as e:
        print(f"Error registering user {username}: {e}")
        return False

def login_user(username, password):
    """
    Authenticate a user login.
    
    Args:
        username: The username
        password: The plain text password
        
    Returns:
        bool: True if login successful, False otherwise
    """
    if not username or not password:
        return False
    
    username = username.lower().strip()  # Normalize username
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get stored password hash
            cursor.execute(
                "SELECT password_hash FROM users WHERE username = ?", 
                (username,)
            )
            row = cursor.fetchone()
            
            if row:
                stored_hash = row[0]
                # Verify password (fixed parameter order)
                if verify_password(password, stored_hash):
                    # Update last login time
                    cursor.execute(
                        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
                        (username,)
                    )
                    conn.commit()
                    return True
            
            return False
            
    except Exception as e:
        print(f"Error during login for user {username}: {e}")
        return False

def get_all_users():
    """
    Get list of all registered users.
    
    Returns:
        list: List of usernames
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users ORDER BY username")
            users = cursor.fetchall()
            return [user[0] for user in users]
            
    except Exception as e:
        print(f"Error getting users list: {e}")
        return []

def get_user_stats():
    """
    Get basic user statistics.
    
    Returns:
        dict: Dictionary with user statistics
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Total users
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            # Users who have logged in
            cursor.execute("SELECT COUNT(*) FROM users WHERE last_login IS NOT NULL")
            active_users = cursor.fetchone()[0]
            
            return {
                'total_users': total_users,
                'active_users': active_users
            }
            
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return {'total_users': 0, 'active_users': 0}

def user_exists(username):
    """
    Check if a username exists.
    
    Args:
        username: The username to check
        
    Returns:
        bool: True if user exists, False otherwise
    """
    if not username:
        return False
    
    username = username.lower().strip()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return cursor.fetchone() is not None
            
    except Exception as e:
        print(f"Error checking if user exists: {e}")
        return False

# Initialize database on import
try:
    create_users_table()
    print("Database initialized successfully")
except Exception as e:
    print(f"Error initializing database: {e}")