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


window = Tk()
window.title("Password Manager")

frame = Frame(window)
frame.grid(row=0, column=0, sticky="NSEW")

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
    answer = simpledialog.askstring("Input", text)
    return answer

def registerAdmin():
    window.geometry("400x300")


    CreatePasswordLabel = Label(window, text="Create your password")
    CreatePasswordLabel.config(font=("Courier", 12))
    CreatePasswordLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    TextBox = Entry(window, width=40, show="*")
    TextBox.place(relx=0.5, rely=0.35, anchor=CENTER)
    TextBox.focus()

    ConfirmPasswordLabel = Label(window, text="Confirm your password")
    ConfirmPasswordLabel.config(font=("Courier", 12))
    ConfirmPasswordLabel.place(relx=0.5, rely=0.45, anchor=CENTER)

    ConfirmTextBox = Entry(window, width=40, show="*")
    ConfirmTextBox.place(relx=0.5, rely=0.55, anchor=CENTER)
    ConfirmTextBox.focus()

    NoMatchLabel = Label(window)
    NoMatchLabel.config(font=("Courier", 12))
    NoMatchLabel.place(relx=0.5, rely=0.65, anchor=CENTER)

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
            NoMatchLabel.config(text="Passwords do not match")
            NoMatchLabel.place(relx=0.5, rely=0.75, anchor=CENTER)
            TextBox.delete(0, END)
            ConfirmTextBox.delete(0, END)


    btn = Button(window, text="Create user", command=checkCreation)
    btn.place(relx=0.5, rely=0.65, anchor=CENTER)

def resetPasswordScreen():
    window.geometry("400x300")

    KeyAskLabel = Label(window, text="Enter your recovery key")
    KeyAskLabel.config(font=("Courier", 12))
    KeyAskLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    KeyTextBox = Entry(window, width=40)
    KeyTextBox.place(relx=0.5, rely=0.35, anchor=CENTER)
    KeyTextBox.focus()

    BadLabel = Label(window)
    BadLabel.config(font=("Courier", 12))
    BadLabel.place(relx=0.5, rely=0.45, anchor=CENTER)

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
            BadLabel.config(text="Recovery key not recognized")
            BadLabel.place(relx=0.5, rely=0.55, anchor=CENTER)
            KeyTextBox.delete(0, END)


    btn = Button(window, text="Submit", command=checkRecoveryKey)
    btn.place(relx=0.5, rely=0.65, anchor=CENTER)

    def goToManager():
        for widget in window.winfo_children():
            widget.destroy()
        passwordManager()

    btn = Button(window, text="Continue", command=goToManager)
    btn.place(relx=0.5, rely=0.75, anchor=CENTER)

def recoveryScreen(key):
    window.geometry("400x300")

    SaveKeyLabel = Label(window, text="Save this key to recover your password")
    SaveKeyLabel.config(font=("Courier", 12))
    SaveKeyLabel.place(relx=0.5, rely=0.25, anchor=CENTER)

    KeyLabel = Label(window, text=key)
    KeyLabel.config(font=("Courier", 12))
    KeyLabel.place(relx=0.5, rely=0.45, anchor=CENTER)

    def copyKey():
        pyperclip.copy(KeyLabel.cget("text"))

    btn = Button(window, text="Copy to clipboard", command=copyKey)
    btn.place(relx=0.5, rely=0.65, anchor=CENTER)

    def goToManager():
        for widget in window.winfo_children():
            widget.destroy()
        passwordManager()

    btn = Button(window, text="Continue", command=goToManager)
    btn.place(relx=0.5, rely=0.75, anchor=CENTER)

def loginScreen():
    window.geometry("400x300")

    LoginLabel = Label(window, text="Enter your password")
    LoginLabel.config(font=("Courier", 12))
    LoginLabel.place(relx=0.5, rely=0.35, anchor=CENTER)

    LoginTextBox = Entry(window, width=40, show="*")
    LoginTextBox.place(relx=0.5, rely=0.45, anchor=CENTER)
    LoginTextBox.focus()

    WrongLabel = Label(window)
    WrongLabel.config(font=("Courier", 12))

    def getAdminPassword():
        checkHashedPassword = hashPassword(LoginTextBox.get().encode("utf-8"))

        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(LoginTextBox.get().encode()))

        cursor.execute("SELECT * FROM adminCredentials WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getAdminPassword()

        if match:
            for widget in window.winfo_children():
                widget.destroy()
            passwordManager()
        else:
            WrongLabel.config(text="Incorrent password")
            WrongLabel.place(relx=0.5, rely=0.65, anchor=CENTER)
            LoginTextBox.delete(0, END)


    btn = Button(window, text="Log in", command=checkPassword)
    btn.place(relx=0.5, rely=0.55, anchor=CENTER)

    def resetPassword():
        for widget in window.winfo_children():
            widget.destroy()
        resetPasswordScreen()

    btn = Button(window, text="Reset password", command=resetPassword)
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

    PageLabel = Label(window, text="Password Manager")
    PageLabel.config(font=("Courier", 14, 'bold'))
    PageLabel.place(relx=0.5, rely=0.1, anchor=CENTER)

    AddButton = Button(window, text="+", command=addEntry)
    AddButton.place(relx=0.8, rely=0.1, anchor=CENTER)

    AppLabel = Label(window, text="App", font=("Courier", 12, 'bold'))
    AppLabel.place(relx=0.2, rely=0.2, anchor=CENTER)

    UsernameLabel = Label(window, text="Username", font=("Courier", 12, 'bold'))
    UsernameLabel.place(relx=0.5, rely=0.2, anchor=CENTER)

    PasswordLabel = Label(window, text="Password", font=("Courier", 12, 'bold'))
    PasswordLabel.place(relx=0.8, rely=0.2, anchor=CENTER)

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

            CurrentAppLabel = Label(window, text=CurrentApp)
            CurrentAppLabel.place(relx=0.2, rely=0.3 + i*0.1, anchor=CENTER)

            CurrentUsernameLabel = Label(window, text=CurrentUsername)
            CurrentUsernameLabel.place(relx=0.5, rely=0.3 + i*0.1, anchor=CENTER)

            CurrentPasswordLabel = Label(window, text=CurrentPassword)
            CurrentPasswordLabel.place(relx=0.8, rely=0.3 + i*0.1, anchor=CENTER)

            CopyButton = Button(window, text="Copy", command=partial(copyPassword, CurrentPasswordLabel))
            CopyButton.place(relx=0.92, rely=0.3 + i*0.1, anchor=CENTER)

            RemoveButton = Button(window, text="x", command=partial(removeEntry, data[i][0]))
            RemoveButton.place(relx=0.97, rely=0.3 + i*0.1, anchor=CENTER)

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