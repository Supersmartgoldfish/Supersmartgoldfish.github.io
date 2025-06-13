# CipherSight - A free and open source file encryption app using face recognition
# Copyright (C) 2025 [supersmartgoldfish]
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import os
from cryptography.fernet import Fernet
import customtkinter as ctk

import keyring
import time
import add_person
import decrypt
from decrypt import activate_decrypt


# Function to load or generate key

def add_person_func():
    add_person.activate_add_person()


def start_decrypt():
    decrypt.activate_decrypt()

def load_key():
    key_file = "key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    return key


# Load or generate encryption key using keyring
def load_key():
    key = keyring.get_password("FaceEncryptApp", "encryption_key")
    if key is None:
        raise ValueError("❌ No key found in system keyring. Please generate it first.")
    return key.encode()

def generate_and_store_key():
    key = Fernet.generate_key()
    keyring.set_password("FaceEncryptApp", "encryption_key", key.decode())
    return key

# Encrypt either a folder or a single file
def encrypt_folder_or_file():
    path = folder_entry.get().strip()
    print(f"Encrypting path: '{path}'")  # Debug output

    try:
        key = load_key()
    except ValueError:
        # Auto-generate key if missing (optional fallback)
        key = generate_and_store_key()
        status_label.configure(text="ℹ️ Key generated and saved securely.")
        time.sleep(1)

    cipher = Fernet(key)

    if os.path.isdir(path):
        count = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                if filepath.endswith(".encrypted"):
                    continue
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    encrypted_data = cipher.encrypt(data)
                    encrypted_path = filepath + ".encrypted"
                    with open(encrypted_path, "wb") as f:
                        f.write(encrypted_data)
                    os.remove(filepath)
                    count += 1
                except Exception as e:
                    status_label.configure(text=f"❌ Error encrypting {file}: {e}")
                    return
        status_label.configure(text=f"✅ Encrypted {count} files in folder.")

    elif os.path.isfile(path):
        if path.endswith(".encrypted"):
            status_label.configure(text="⚠️ File is already encrypted.")
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            encrypted_data = cipher.encrypt(data)
            with open(path + ".encrypted", "wb") as f:
                f.write(encrypted_data)
            os.remove(path)
            status_label.configure(text=f"✅ Encrypted file: {os.path.basename(path)}")
        except Exception as e:
            status_label.configure(text=f"❌ Error encrypting file: {e}")

    else:
        status_label.configure(text="❌ Path not found or invalid.")

# GUI Setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

win = ctk.CTk()
win.geometry("400x300")
win.title("CipherSight v1.0.0")

folder_entry = ctk.CTkEntry(win, placeholder_text="Enter folder path to encrypt")
folder_entry.pack(pady=20, padx=20, fill="x")

encrypt_button = ctk.CTkButton(win, text="Encrypt Folder", command=encrypt_folder_or_file)
encrypt_button.pack(pady=10)

decrypt_button = ctk.CTkButton(win, text="Decrypt", command=start_decrypt)
decrypt_button.pack()

status_label = ctk.CTkLabel(win, text="Waiting for input...")
status_label.pack(pady=10)

add_person_button = ctk.CTkButton(win, text="add", command=add_person_func)
add_person_button.pack()

win.mainloop()
