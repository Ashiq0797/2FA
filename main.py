import pyotp
import qrcode
import webbrowser as w
import tkinter as tk
from tkinter import messagebox, PhotoImage
import hashlib
import os

userNames = []
passWords = []

def register(userName, passWord):
    if not userName.strip() or not passWord.strip():
        messagebox.showerror('Registration', 'PLEASE ENTER A USERNAME AND PASSWORD TO REGISTER')
    else:
        check1 = validate_username(userName)
        check2 = validate_password(passWord)
        if check1 and check2:
            if userName in userNames:
                messagebox.showerror('Registration', 'USERNAME ALREADY TAKEN')
            else:
                hashed_password = hashlib.sha256(passWord.encode('utf-8')).hexdigest()
                userNames.append(userName)
                passWords.append(hashed_password)

                instructions = (
                    'SETTING UP TWO-FACTOR AUTHENTICATION:\n'
                    '1. Download and open any authenticator app on your mobile device (recommended: Google Authenticator).\n'
                    '2. Click the "Scan a QR code" option.\n'
                    '3. A QR code has been generated for your account, scan it to add it to the app.\n'
                    '4. Use the OTP code in the app to log in to your account here.\n\n'
                    'You only need to add the QR code once during registration.\n'
                    'Do not click "Register" again after adding the QR code in the app. Just use "Login" thereafter.\n'
                    'Click "OK" to get the QR code on the screen.'
                )

                messagebox.showinfo('Registration', instructions)

                key = pyotp.random_base32(length=32)
                with open(f'{userName}_key.txt', 'w') as file:
                    file.write(key)

                totp_auth = pyotp.totp.TOTP(key).provisioning_uri(name=userName, issuer_name='PROJECT BLACK')
                qrcode.make(totp_auth).save(f'{userName}_qr.png')

                with open('data.txt', 'w') as file:
                    for username, password in zip(userNames, passWords):
                        file.write(f'{username},{password}\n')

                w.open(f'{userName}_qr.png')

def login():
    username = username_entry.get()
    password = password_entry.get()
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    if not username.strip() or not password.strip():
        messagebox.showerror('Login', 'PLEASE ENTER A USERNAME AND PASSWORD TO LOGIN')
    else:
        if username in userNames:
            index = userNames.index(username)
            if hashed_password == passWords[index]:
                try:
                    with open(f'{username}_key.txt', 'r') as file:
                        key = file.read().strip()
                    otp = otp_entry.get()
                    totp = pyotp.TOTP(key)
                    if totp.verify(otp):
                        login_attempts.set(0)
                        messagebox.showinfo('Login', 'LOGIN SUCCESSFUL')
                        w.open('https://www.royalholloway.ac.uk/')
                    else:
                        raise ValueError('INVALID OTP')
                except (FileNotFoundError, ValueError):
                    increment_login_attempts()
                    messagebox.showerror('Login', 'INVALID OTP')
            else:
                increment_login_attempts()
                messagebox.showerror('Login', 'INVALID PASSWORD')
        else:
            increment_login_attempts()
            messagebox.showerror('Login', 'INVALID USERNAME')

def validate_username(username):
    if 5 <= len(username) <= 15 and username.isalnum():
        return True
    else:
        messagebox.showerror('Registration', 'USERNAME SHOULD BE 5 TO 15 CHARACTERS LONG AND ALPHANUMERIC')
        return False

def validate_password(password):
    if 8 <= len(password) <= 12:
        has_upper = any(char.isupper() for char in password)
        has_lower = any(char.islower() for char in password)
        has_digit = any(char.isdigit() for char in password)
        if has_upper and has_lower and has_digit:
            return True
    messagebox.showerror('Registration', 'PASSWORD SHOULD BE 8 TO 12 CHARACTERS LONG AND CONTAIN AT LEAST ONE UPPERCASE LETTER, ONE LOWERCASE LETTER, AND ONE DIGIT')
    return False

def increment_login_attempts():
    login_attempts.set(login_attempts.get() + 1)
    if login_attempts.get() == 3:
        login_button.config(state=tk.DISABLED)

def load_user_data():
    if os.path.exists('data.txt'):
        with open('data.txt', 'r') as file:
            for line in file:
                username, password = line.strip().split(',')
                userNames.append(username)
                passWords.append(password)

load_user_data()

window = tk.Tk()
window.title('Secure Login System')
window.config(bg='#FCEDDA')

rhul_logo = PhotoImage(file='rhul.png')
info = '''WELCOME TO SECURE LOGIN SYSTEM FOR THE ROYAL HOLLOWAY WEBSITE
ENTER USERNAME AND PASSWORD TO REGISTER FIRST AND THEN LOGIN
IF YOU HAVE ALREADY REGISTERED ONCE BEFORE THEN JUST LOGIN USING YOUR DETAILS AND OTP CODE
YOU WILL ONLY HAVE 3 ATTEMPTS TO LOGIN'''

welcome_label_one = tk.Label(window, image=rhul_logo)
welcome_label_one.pack()

welcome_label_two = tk.Label(window, text=info, font=("Franklin Gothic", 13), bg='#FCEDDA')
welcome_label_two.pack()

username_label = tk.Label(window, text="Username:", bg='#FCEDDA')
username_label.pack()
username_entry = tk.Entry(window, bd=5)
username_entry.pack()

password_label = tk.Label(window, text="Password:", bg='#FCEDDA')
password_label.pack()
password_entry = tk.Entry(window, bd=5, show='*')
password_entry.pack()

login_button = tk.Button(window, text="Login", bg='#EE4E34', fg='#FCEDDA', command=login)
login_button.pack()
login_attempts = tk.IntVar()
login_attempts.set(0)

otp_label = tk.Label(window, text="OTP code:", bg='#FCEDDA')
otp_label.pack()
otp_entry = tk.Entry(window, bd=5)
otp_entry.pack()

register_button = tk.Button(window, text="Register", bg='#EE4E34', fg='#FCEDDA', command=lambda: register(username_entry.get(), password_entry.get()))
register_button.pack()

window.mainloop()
