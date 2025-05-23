import sqlite3
from encryption import hash_password, verify_password

DB_NAME = 'chat_server.db'


# connectiog to database
def connect_db():
    conn = sqlite3.connect('chat_server.db')
    return conn


def create_users_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


def register_user(username, password):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        cursor.close()
        return False

    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    return True


def login_user(username, password):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if row:
        stored_password = row[0]
        if verify_password(password, stored_password):
            cursor.close()
            return True

    conn.close()
    return False


def get_all_users():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()

    conn.close()
    return [user[0] for user in users]



    