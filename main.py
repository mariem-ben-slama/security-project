import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import json, os, hashlib, base64
from cryptography.fernet import Fernet
from pathlib import Path

# Constants
USER_FILE = 'users.json'

# Ensure folders exist
Path("encrypted_files").mkdir(exist_ok=True)
Path("decrypted_files").mkdir(exist_ok=True)
Path("hashes").mkdir(exist_ok=True)

# User management
def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)

def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Derive Fernet key from user input string
def derive_key_from_string(key_str):
    return base64.urlsafe_b64encode(hashlib.sha256(key_str.encode()).digest())

# Main App
class FileSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File App")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")
        self.root.minsize(700, 500)
        self.logged_in_user = None
        self.build_login()

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_login(self):
        self.clear()
        frame = tk.Frame(self.root, bg="#2c2c2c", pady=20, padx=40)
        frame.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(frame, text="Login", fg="white", bg="#2c2c2c", font=("Segoe UI", 20)).pack(pady=10)
        self.username = tk.Entry(frame, font=("Segoe UI", 14))
        self.username.pack(pady=5)
        self.password = tk.Entry(frame, show="*", font=("Segoe UI", 14))
        self.password.pack(pady=5)

        tk.Button(frame, text="Login", command=self.login, bg="#8e7cc3", fg="white", font=("Segoe UI", 12)).pack(pady=10)
        tk.Button(frame, text="Sign Up", command=self.build_signup, bg="#666666", fg="white", font=("Segoe UI", 12)).pack()

    def build_signup(self):
        self.clear()
        frame = tk.Frame(self.root, bg="#2c2c2c", pady=20, padx=40)
        frame.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(frame, text="Sign Up", fg="white", bg="#2c2c2c", font=("Segoe UI", 20)).pack(pady=10)
        self.new_username = tk.Entry(frame, font=("Segoe UI", 14))
        self.new_username.pack(pady=5)
        self.new_password = tk.Entry(frame, show="*", font=("Segoe UI", 14))
        self.new_password.pack(pady=5)

        tk.Button(frame, text="Create Account", command=self.signup, bg="#8e7cc3", fg="white", font=("Segoe UI", 12)).pack(pady=10)
        tk.Button(frame, text="Back to Login", command=self.build_login, bg="#666666", fg="white", font=("Segoe UI", 12)).pack()

    def login(self):
        users = load_users()
        username = self.username.get()
        password = encrypt_password(self.password.get())
        if username in users and users[username] == password:
            self.logged_in_user = username
            self.build_main_menu()
        else:
            messagebox.showerror("Error", "Invalid credentials.")

    def signup(self):
        users = load_users()
        username = self.new_username.get()
        password = encrypt_password(self.new_password.get())
        if username in users:
            messagebox.showerror("Error", "User already exists.")
        else:
            users[username] = password
            save_users(users)
            messagebox.showinfo("Success", "User created!")
            self.build_login()

    def build_main_menu(self):
        self.clear()
        frame = tk.Frame(self.root, bg="#2c2c2c", pady=20, padx=40)
        frame.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(frame, text=f"Welcome, {self.logged_in_user}", fg="white", bg="#2c2c2c", font=("Segoe UI", 18)).pack(pady=10)

        tk.Button(frame, text="Encrypt File", command=self.encrypt_file, bg="#8e7cc3", fg="white", font=("Segoe UI", 12)).pack(pady=5)
        tk.Button(frame, text="Decrypt File", command=self.decrypt_file, bg="#8e7cc3", fg="white", font=("Segoe UI", 12)).pack(pady=5)
        tk.Button(frame, text="Hash File", command=self.hash_file, bg="#8e7cc3", fg="white", font=("Segoe UI", 12)).pack(pady=5)

        tk.Button(frame, text="Log Out", command=self.build_login, bg="#666666", fg="white", font=("Segoe UI", 12)).pack(pady=20)

    def ask_key_string(self, action="use"):
        key_input = simpledialog.askstring("Key Input", f"Enter a key string to {action} the file:", show="*")
        if not key_input:
            messagebox.showerror("Error", "A key is required to proceed.")
            return None
        return derive_key_from_string(key_input)

    def encrypt_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            key = self.ask_key_string("encrypt")
            if not key:
                return
            fernet = Fernet(key)
            with open(filepath, 'rb') as f:
                encrypted = fernet.encrypt(f.read())
            name = os.path.basename(filepath)
            with open(f'encrypted_files/{name}.enc', 'wb') as f:
                f.write(encrypted)
            messagebox.showinfo("Success", "File encrypted and saved.")

    def decrypt_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            key = self.ask_key_string("decrypt")
            if not key:
                return
            fernet = Fernet(key)
            try:
                with open(filepath, 'rb') as f:
                    decrypted = fernet.decrypt(f.read())
                name = os.path.basename(filepath).replace('.enc', '')
                with open(f'decrypted_files/{name}', 'wb') as f:
                    f.write(decrypted)
                messagebox.showinfo("Success", "File decrypted and saved.")
            except:
                messagebox.showerror("Error", "Decryption failed. Invalid key or file.")

    def hash_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            name = os.path.basename(filepath)
            with open(f'hashes/{name}.hash.txt', 'w') as f:
                f.write(file_hash)
            messagebox.showinfo("Success", "File hashed and saved.")

# Launch the app
if __name__ == "__main__":
    root = tk.Tk()
    app = FileSecurityApp(root)
    root.mainloop()
