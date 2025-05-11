import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import customtkinter as ctk

SALT_FILE = "salt.bin"
PASSWORDS_FILE = "passwords.txt"
password_global = ""  # Store the user's master password

ctk.set_appearance_mode("dark")




def get_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# GUI Setup
app = ctk.CTk()
app.title("Secure-Ish v1.0.0")
app.geometry("400x350")

dapp = ctk.CTk()
dapp.title("View Passwords")
dapp.geometry("500x400")
dapp.withdraw()

def on_closing():
    app.quit()
app.protocol("WM_DELETE_WINDOW", on_closing)



# Widgets
entry1 = ctk.CTkEntry(app, placeholder_text="Master password")
entry1.pack(pady=10)

entry2 = ctk.CTkEntry(app, placeholder_text="Password to encrypt")
entry2.pack(pady=10)

entry_label = ctk.CTkEntry(app, placeholder_text="Label (e.g., Gmail)")
entry_label.pack(pady=10)


def encrypt():
    global password_global
    password = entry1.get()
    value_to_encrypt = entry2.get()
    label = entry_label.get()

    if not all([password, value_to_encrypt, label]):
        ctk.CTkLabel(app, text="Please fill all fields").pack()
        return

    password_global = password
    salt = get_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(value_to_encrypt.encode())
    encrypted_b64 = base64.urlsafe_b64encode(encrypted).decode()

    # Append to the passwords file
    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{label}|||{encrypted_b64}\n")

    ctk.CTkLabel(app, text="Password saved successfully").pack(pady=5)


def dapp_func():
    dapp.deiconify()
    for widget in dapp.winfo_children():
        widget.destroy()

    ctk.CTkLabel(dapp, text="Enter master password:", font=("Arial", 14)).pack(pady=5)
    password_entry = ctk.CTkEntry(dapp, placeholder_text="Master password", show="*")
    password_entry.pack(pady=5)

    def decrypt_from_window():
        for widget in dapp.winfo_children()[2:]:
            widget.destroy()

        password = password_entry.get()
        if not password:
            ctk.CTkLabel(dapp, text="Please enter a password").pack()
            return

        salt = get_salt()
        key = derive_key(password, salt)
        fernet = Fernet(key)

        ctk.CTkLabel(dapp, text="Decrypted Passwords:", font=("Arial", 14)).pack(pady=10)

        if not os.path.exists(PASSWORDS_FILE):
            ctk.CTkLabel(dapp, text="No saved passwords.").pack()
            return

        with open(PASSWORDS_FILE, "r") as f:
            for line in f:
                try:
                    label, encrypted_b64 = line.strip().split("|||")
                    encrypted = base64.urlsafe_b64decode(encrypted_b64)
                    decrypted = fernet.decrypt(encrypted).decode()
                    ctk.CTkLabel(dapp, text=f"{label}: {decrypted}").pack(anchor="w", padx=10)
                except Exception:
                    ctk.CTkLabel(dapp, text=f"{label}: [Decryption failed]").pack(anchor="w", padx=10)

    ctk.CTkButton(dapp, text="Decrypt", command=decrypt_from_window).pack(pady=10)


# Buttons
ctk.CTkButton(app, text="Encrypt & Save", command=encrypt).pack(pady=10)
ctk.CTkButton(app, text="Decrypt All", command=dapp_func).pack(pady=10)

app.mainloop()




