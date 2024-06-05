import sqlite3

with sqlite3.connect("password_manager.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS adminCredentials(
            id INTEGER PRIMARY KEY,
            password TEXT NOT NULL,
            recoveryKey TEXT NOT NULL)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwordsTable(
            id INTEGER PRIMARY KEY,
            App TEXT NOT NULL,
            Username TEXT NOT NULL,
            Password TEXT NOT NULL)
""")