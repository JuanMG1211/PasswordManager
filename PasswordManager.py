import hashlib
import Database
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid, pyperclip, base64, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

import customtkinter as ctk


window = ctk.CTk()
window.title("Password Manager")

window.resizable(width=False, height=False)

cursor = Database.cursor

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

def hashPassword(input):
    hash = hashlib.sha256(input)
    return hash.hexdigest()

def popUpWindow(text):
    answer = ctk.CTkInputDialog(text=text, title="Input", button_fg_color="#992fbf", button_hover_color="#651e7e")
    answer = answer.get_input()
    return answer

def registerAdmin():
    window.geometry("400x300")

    CreatePasswordLabel = ctk.CTkLabel(window, text="Create your password", width=200, height=50)
    CreatePasswordLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    TextBox = ctk.CTkEntry(window, width=200, show="*")
    TextBox.place(relx=0.5, rely=0.35, anchor=CENTER)
    TextBox.focus()

    ConfirmPasswordLabel = ctk.CTkLabel(window, text="Confirm your password")
    ConfirmPasswordLabel.place(relx=0.5, rely=0.45, anchor=CENTER)

    ConfirmTextBox = ctk.CTkEntry(window, width=200, show="*")
    ConfirmTextBox.place(relx=0.5, rely=0.55, anchor=CENTER)
    ConfirmTextBox.focus()

    NoMatchLabel = ctk.CTkLabel(window)

    def checkCreation():
        if TextBox.get() == ConfirmTextBox.get():

            DeleteQuery = "DELETE FROM adminCredentials WHERE id = 1"

            cursor.execute(DeleteQuery)


            password = TextBox.get()
            hashedPassword = hashPassword(password.encode("utf-8"))

            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode("utf-8"))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(password.encode()))

            InsertQuery = """INSERT INTO adminCredentials(password, recoveryKey) VALUES(?, ?)"""
            cursor.execute(InsertQuery, [(hashedPassword), (recoveryKey)])
            Database.db.commit()
            for widget in window.winfo_children():
                widget.destroy()
            recoveryScreen(key)
        else:
            NoMatchLabel.configure(text="Passwords do not match")
            NoMatchLabel.place(relx=0.5, rely=0.77, anchor=CENTER)
            TextBox.delete(0, END)
            ConfirmTextBox.delete(0, END)


    btn = ctk.CTkButton(window, text="Create user", command=checkCreation)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.68, anchor=CENTER)

def resetPasswordScreen():
    window.geometry("400x300")

    KeyAskLabel = ctk.CTkLabel(window, text="Enter your recovery key")
    KeyAskLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    KeyTextBox = ctk.CTkEntry(window, width=200)
    KeyTextBox.place(relx=0.5, rely=0.35, anchor=CENTER)
    KeyTextBox.focus()

    BadLabel = ctk.CTkLabel(window)

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(KeyTextBox.get().encode("utf-8"))
        cursor.execute("SELECT * FROM adminCredentials WHERE recoveryKey = ?", [(recoveryKeyCheck)])
        return cursor.fetchall()
    
    def checkRecoveryKey():
        match = getRecoveryKey()

        if match:
            for widget in window.winfo_children():
                widget.destroy()
            registerAdmin()
        else:
            BadLabel.configure(text="Recovery key not recognized")
            BadLabel.place(relx=0.5, rely=0.65, anchor=CENTER)
            KeyTextBox.delete(0, END)


    btn = ctk.CTkButton(window, text="Submit", command=checkRecoveryKey)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.45, anchor=CENTER)

    def goToManager():
        for widget in window.winfo_children():
            widget.destroy()
        passwordManager()

    btn = ctk.CTkButton(window, text="Continue", command=goToManager)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.55, anchor=CENTER)

def recoveryScreen(key):
    window.geometry("400x300")

    SaveKeyLabel = ctk.CTkLabel(window, text="Save this key to recover your data", font=('Helvetica', 12, 'bold'))
    SaveKeyLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    KeyLabel = ctk.CTkLabel(window, text=key)
    KeyLabel.place(relx=0.5, rely=0.45, anchor=CENTER)

    def copyKey():
        pyperclip.copy(KeyLabel.cget("text"))

    btn = ctk.CTkButton(window, text="Copy to clipboard", command=copyKey)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.65, anchor=CENTER)

    def goToManager():
        for widget in window.winfo_children():
            widget.destroy()
        passwordManager()

    btn = ctk.CTkButton(window, text="Continue", command=goToManager)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.75, anchor=CENTER)

def loginScreen():
    window.geometry("400x300")

    LoginLabel = ctk.CTkLabel(window, text="Enter your password")
    LoginLabel.place(relx=0.5, rely=0.35, anchor=CENTER)

    LoginTextBox = ctk.CTkEntry(window, width=200, show="*")
    LoginTextBox.place(relx=0.5, rely=0.45, anchor=CENTER)
    LoginTextBox.focus()

    WrongLabel = ctk.CTkLabel(window)

    def getAdminPassword():
        checkHashedPassword = hashPassword(LoginTextBox.get().encode("utf-8"))


        cursor.execute("SELECT * FROM adminCredentials WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getAdminPassword()

        global encryptionKey

        if match:
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(LoginTextBox.get().encode()))
            for widget in window.winfo_children():
                widget.destroy()
            passwordManager()
        else:
            WrongLabel.configure(text="Incorrent password")
            WrongLabel.place(relx=0.5, rely=0.75, anchor=CENTER)
            LoginTextBox.delete(0, END)


    btn = ctk.CTkButton(window, text="Log in", command=checkPassword)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.55, anchor=CENTER)

    def resetPassword():
        for widget in window.winfo_children():
            widget.destroy()
        resetPasswordScreen()

    btn = ctk.CTkButton(window, text="Reset password", command=resetPassword)
    btn.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e")
    btn.place(relx=0.5, rely=0.65, anchor=CENTER)

def passwordManager():
    for widget in window.winfo_children():
        widget.destroy()


    def addEntry():
        appTag= "App"
        usernameTag = "Username"
        passwordTag = "Password"

        app = encrypt(popUpWindow(appTag).encode(), encryptionKey)
        username = encrypt(popUpWindow(usernameTag).encode(), encryptionKey)
        password = encrypt(popUpWindow(passwordTag).encode(), encryptionKey)

        InsertQuery = """INSERT INTO passwordsTable(App, Username, Password) VALUES(?, ?, ?)"""
        cursor.execute(InsertQuery, [(app), (username), (password)])
        Database.db.commit()

        passwordManager()

    def removeEntry(id):
        cursor.execute("DELETE FROM passwordsTable WHERE id = ?", [(id)])
        Database.db.commit()
        passwordManager()

    def copyPassword(label):
                pyperclip.copy(label.cget("text"))

    window.geometry("800x600")

    PageLabel = ctk.CTkLabel(window, text="Password Manager")
    PageLabel.configure(font=("Helvetica", 24, 'bold'))
    PageLabel.place(relx=0.5, rely=0.1, anchor=CENTER)

    AddButton = ctk.CTkButton(window, text="+", command=addEntry)
    AddButton.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e", width=25)
    AddButton.place(relx=0.935, rely=0.2, anchor=CENTER)

    AppLabel = ctk.CTkLabel(window, text="App", font=("Helvetica", 16, 'bold'))
    AppLabel.place(relx=0.13, rely=0.2, anchor=CENTER)

    UsernameLabel = ctk.CTkLabel(window, text="Username", font=("Helvetica", 16, 'bold'))
    UsernameLabel.place(relx=0.4, rely=0.2, anchor=CENTER)

    PasswordLabel = ctk.CTkLabel(window, text="Password", font=("Helvetica", 16, 'bold'))
    PasswordLabel.place(relx=0.68, rely=0.2, anchor=CENTER)

    frame = ctk.CTkScrollableFrame(window, width=750, height=425)
    frame.grid_columnconfigure((0, 1, 2), weight=6)
    frame.grid_columnconfigure((3,4,5), weight=1)
    frame.grid_rowconfigure(0, weight=1)
    frame.place(relx=0.5, rely=0.6, anchor=CENTER)


    cursor.execute("SELECT * FROM passwordsTable")

    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM passwordsTable")
            data = cursor.fetchall()

            if i >= len(data):
                break

            CurrentApp = decrypt(data[i][1], encryptionKey).decode("utf-8")
            CurrentUsername = decrypt(data[i][2], encryptionKey).decode("utf-8")
            CurrentPassword = decrypt(data[i][3], encryptionKey).decode("utf-8")

            CurrentAppLabel = ctk.CTkLabel(frame, text=CurrentApp)
            CurrentAppLabel.grid(row=i, column=0, pady=10)

            CurrentUsernameLabel = ctk.CTkLabel(frame, text=CurrentUsername)
            CurrentUsernameLabel.grid(row=i, column=1, pady=10)

            CurrentPasswordLabel = ctk.CTkLabel(frame, text=CurrentPassword)
            CurrentPasswordLabel.grid(row=i, column=2, pady=10)

            CopyButton = ctk.CTkButton(frame, text="Copy", command=partial(copyPassword, CurrentPasswordLabel))
            CopyButton.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e", width=50)
            CopyButton.grid(row=i, column=3, pady=10, columnspan=2)

            RemoveButton = ctk.CTkButton(frame, text="x", command=partial(removeEntry, data[i][0]))
            RemoveButton.configure(corner_radius=5, fg_color = "#992fbf", hover_color = "#651e7e", width=25)
            RemoveButton.grid(row=i, column=5, pady=10)

            i += 1

            cursor.execute("SELECT * FROM passwordsTable")
            if(i >= len(cursor.fetchall())):
                break

cursor.execute("SELECT * FROM adminCredentials")
if cursor.fetchall():
    loginScreen()
else:
    registerAdmin()

window.mainloop()