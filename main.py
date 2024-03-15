from hashlib import md5
import sqlite3
import os

connection = sqlite3.connect("app.db")

cursor = connection.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS plaintext_users (
        username TEXT,
        password TEXT
    );
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS hashed_users (
        username TEXT,
        hashed_password TEXT
    );
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS hashed_salted_users (
        username TEXT,
        hashed_salted_password TEXT,
        salt BLOB
    );
""")
connection.commit()
cursor.close()


def store_insecurely(username: str, password: str):
    cursor = connection.cursor()
    cursor.execute("""
        INSERT
          INTO plaintext_users
               (username, password)
        VALUES (?, ?)
    """, [username, password])
    connection.commit()
    cursor.close()


def check_insecurely(username: str, password_attempt: str):
    cursor = connection.cursor()
    cursor.execute("""
        SELECT password
          FROM plaintext_users
         WHERE username = ?
    """, [username])
    password = cursor.fetchone()[0]
    cursor.close()
    return password_attempt == password


def store_securely(username: str, password: str):
    cursor = connection.cursor()
    cursor.execute("""
        INSERT
          INTO hashed_users
               (username, hashed_password)
        VALUES (?, ?)
    """, [username, md5(password.encode()).hexdigest()])
    connection.commit()
    cursor.close()


def check_securely(username: str, password_attempt: str):
    cursor = connection.cursor()
    cursor.execute("""
        SELECT hashed_password
          FROM hashed_users
         WHERE username = ?
    """, [username])
    hashed_password = cursor.fetchone()[0]
    cursor.close()
    hashed_password_attempt = md5(password_attempt.encode()).hexdigest()
    print(f"Hashed password attempt: {hashed_password_attempt}")
    return hashed_password_attempt == hashed_password


def store_very_securely(username: str, password: str):
    salt = os.urandom(32)
    cursor = connection.cursor()
    cursor.execute("""
        INSERT
          INTO hashed_salted_users
               (username, hashed_salted_password, salt)
        VALUES (?, ?, ?)
    """, [username, md5(password.encode() + salt).hexdigest(), salt])
    connection.commit()
    cursor.close()


def check_very_securely(username: str, password_attempt: str):
    cursor = connection.cursor()
    cursor.execute("""
        SELECT hashed_salted_password, salt
          FROM hashed_salted_users
         WHERE username = ?
    """, [username])
    hashed_salted_password, salt = cursor.fetchone()
    cursor.close()
    hashed_salted_password_attempt = md5(password_attempt.encode() + salt).hexdigest()
    print(f"Hashed salted password attempt: {hashed_salted_password_attempt}")
    return hashed_salted_password_attempt == hashed_salted_password


print("SIGN UP")
username = input("Enter a new username: ")
password = input("Enter a new password: ")
store_insecurely(username, password)
store_securely(username, password)
store_very_securely(username, password)

print("LOG IN")
username = input("Enter username: ")
password = input("Enter password: ")
print(check_insecurely(username, password))
print(check_securely(username, password))
print(check_very_securely(username, password))
