#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Scrollbar
import pyautogui
import time
import json
import os
import threading
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CONFIG_FILE = "typepaste_config.json"

class ConfigManager:
    _current_key = None

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def load_config_raw():
        """Loads the raw JSON from disk if it exists."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    @staticmethod
    def load_config():
        """
        Attempt to load and decrypt config. 
        Returns (config_dict, status_code).
        status_code: 
          0 = Success
          1 = No config (fresh)
          2 = Legacy config (needs migration)
          3 = Encrypted (needs password)
        """
        data = ConfigManager.load_config_raw()
        if data is None:
            return ConfigManager.get_default_config(), 1
        
        # Check if legacy or encrypted
        if "salt" in data and "data" in data:
            return data, 3
        
        # Assume legacy
        return data, 2

    @staticmethod
    def decrypt_config(password):
        raw_data = ConfigManager.load_config_raw()
        if not raw_data or "salt" not in raw_data or "data" not in raw_data:
            raise ValueError("Invalid config format")
        
        salt = base64.b64decode(raw_data["salt"])
        token = base64.b64decode(raw_data["data"])
        
        key = ConfigManager.derive_key(password, salt)
        f = Fernet(key)
        
        try:
            decrypted_json = f.decrypt(token).decode()
            config = json.loads(decrypted_json)
            ConfigManager._current_key = key # Cache key for saving
            return config
        except InvalidToken:
            raise ValueError("Invalid password")

    @staticmethod
    def save_config(config, password=None):
        """
        Save config. If password is provided, re-encrypts with new salt/password.
        If password is None, uses ConfigManager._current_key to encrypt.
        """
        try:
            json_bytes = json.dumps(config).encode()
            
            key = None
            salt = None
            
            if password:
                salt = os.urandom(16)
                key = ConfigManager.derive_key(password, salt)
                ConfigManager._current_key = key
            elif ConfigManager._current_key:
                key = ConfigManager._current_key
                # We need to reuse salt if we want to keep same password, 
                # but simpler to just regenerate salt every save? 
                # Actually, effectively we can regenerate salt every time we verify the user knew the password.
                # But if we only have the key, we can't derive a NEW key from password (we don't have password).
                # So we must use the EXISTING key. To use existing key with Fernet, we just encrypt.
                # However, we need to store the salt if we derived it from a password so we can derive it again next time.
                # Wait, if we only store the key, we can't save proper "salt" to disk for NEXT load unless we read the old salt
                # or we just keep using the same key.
                # Standard practice: derive key from password. We need password to save if we want to change salt.
                # If we rely on cached key, we can encrypt, but we need to write the SAME salt back to disk 
                # so the password still works next time!
                # So we must 'remember' the salt too or just load it from disk?
                # Let's simple approach: When we decrypt, we store 'salt' and 'key' in memory? 
                # Or better: We require password to save? No, that's annoying.
                
                # Correction: We can't easily rotate salt without password.
                # So we must read existing salt from disk or memory.
                pass
            else:
                raise ValueError("No key or password provided to save_config")

            validate_salt_logic = False
            if salt is None:
                # We are using cached key. We need to preserve the CURRENT salt on disk 
                # so the user's password (which generated this key with THAT salt) still works.
                raw_old = ConfigManager.load_config_raw()
                if raw_old and "salt" in raw_old:
                    salt = base64.b64decode(raw_old["salt"])
                else:
                    # Should not happen if we successfully logged in, unless it was fresh/legacy migration
                    # In fresh/legacy migration, 'password' arg MUST be provided.
                    raise ValueError("Cannot look up salt for cached key")

            f = Fernet(key)
            token = f.encrypt(json_bytes)
            
            output = {
                "salt": base64.b64encode(salt).decode(),
                "data": base64.b64encode(token).decode()
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(output, f, indent=4)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")
            raise e

    @staticmethod
    def get_default_config():
        return {
            "buttons": [
                {"label": "Email Signature", "text": "Best regards,\\n[Your Name]", "is_hidden": False},
                {"label": "Standard Reply", "text": "Thank you for reaching out. I will get back to you shortly.", "is_hidden": False},
                {"label": "Address", "text": "123 Main St, City, Country", "is_hidden": False},
                {"label": "Lorem Ipsum", "text": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", "is_hidden": False},
                {"label": "Phone Number", "text": "+1 (555) 123-4567", "is_hidden": False}
            ],
            "settings": {
                "delay": 5,
                "countdown": 3
            }
        }

class ButtonEditor(simpledialog.Dialog):
    def __init__(self, parent, title="Edit Button", initial_data=None):
        self.initial_data = initial_data or {"label": "", "text": "", "is_hidden": False}
        self.result_data = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Label:").grid(row=0, column=0, sticky="w")
        self.label_entry = ttk.Entry(master)
        self.label_entry.grid(row=0, column=1, sticky="ew")
        self.label_entry.insert(0, self.initial_data["label"])

        ttk.Label(master, text="Text:").grid(row=1, column=0, sticky="nw", pady=5)
        self.text_entry = tk.Text(master, height=5, width=40)
        self.text_entry.grid(row=1, column=1, pady=5)
        self.text_entry.insert("1.0", self.initial_data["text"])

        self.is_hidden_var = tk.BooleanVar(value=self.initial_data.get("is_hidden", False))
        self.hidden_check = ttk.Checkbutton(master, text="Is Password? (Mask content)", variable=self.is_hidden_var)
        self.hidden_check.grid(row=2, column=1, sticky="w")

        return self.label_entry

    def apply(self):
        self.result_data = {
            "label": self.label_entry.get(),
            "text": self.text_entry.get("1.0", "end-1c"),
            "is_hidden": self.is_hidden_var.get()
        }

class LoginDialog(tk.Toplevel):
    def __init__(self, parent, title="Security Check", is_creation=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x180")
        self.resizable(False, False)
        self.password = None
        self.is_creation = is_creation
        
        lbl_text = "Create a Master Password to encrypt your data:" if is_creation else "Enter Master Password to unlock:"
        ttk.Label(self, text=lbl_text, font=("Segoe UI", 10, "bold")).pack(pady=(20, 10))
        
        self.pw_entry = ttk.Entry(self, show="*")
        self.pw_entry.pack(fill="x", padx=40)
        self.pw_entry.focus()
        self.pw_entry.bind("<Return>", self.on_ok)
        
        btn_text = "Encrypt & Start" if is_creation else "Unlock"
        ttk.Button(self, text=btn_text, command=self.on_ok).pack(pady=20)
        
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        if parent.winfo_viewable():
            self.transient(parent)
        self.grab_set()
        self.wait_window(self)

    def on_ok(self, event=None):
        val = self.pw_entry.get()
        if not val:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        self.password = val
        self.destroy()

    def on_cancel(self):
        self.destroy()

class TypePasteApp:
    def __init__(self, root):
        self.root = root
        self.root.withdraw() # Hide until authenticated
        
        # Load logic
        _, status = ConfigManager.load_config()
        self.config = None
        
        if status == 1: # Freshi'd like some changes in the  layout of the app that make sense
            self.do_first_run()
        elif status == 2: # Legacy
            self.do_migration()
        elif status == 3: # Encrypted
            self.do_login()
        else: # Should not happen
            messagebox.showerror("Error", "Unknown config state")
            self.root.destroy()
            return
            
        if not self.config:
            # User cancelled or failed
            self.root.destroy()
            return

        self.root.deiconify()
        self.root.title("Type-Paste Utility (Secure)")
        self.root.geometry("600x550")
        
        self.create_widgets()
        self.refresh_custom_buttons()

    def do_first_run(self):
        dlg = LoginDialog(self.root, "Welcome to TypePaste", is_creation=True)
        if dlg.password:
            self.config = ConfigManager.get_default_config()
            ConfigManager.save_config(self.config, dlg.password)
        
    def do_migration(self):
        messagebox.showinfo("Security Update", "Legacy configuration found.\nYou must protect it with a Master Password now.")
        dlg = LoginDialog(self.root, "Migrate to Secure Storage", is_creation=True)
        if dlg.password:
            # Load the legacy plain JSON
            legacy, _ = ConfigManager.load_config() # effectively load_config_raw logic inside
            # load_config returns (data, 2)
            self.config = legacy
            ConfigManager.save_config(self.config, dlg.password)

    def do_login(self):
        attempts = 0
        while attempts < 3:
            dlg = LoginDialog(self.root, "Unlock TypePaste")
            if not dlg.password:
                return # User cancelled
            
            try:
                self.config = ConfigManager.decrypt_config(dlg.password)
                return # Success
            except Exception:
                attempts += 1
                messagebox.showerror("Error", "Incorrect password.")
        
        messagebox.showerror("Locked", "Too many failed attempts.")

    def create_widgets(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        # Typing Area
        ttk.Label(main, text="Text to type:").pack(anchor="w")
        self.text_box = tk.Text(main, height=8)
        self.text_box.pack(fill="x", pady=5)

        # Controls
        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=5)
        
        self.delay_var = tk.IntVar(value=self.config["settings"].get("delay", 5))
        self.countdown_var = tk.IntVar(value=self.config["settings"].get("countdown", 3))

        ttk.Label(controls, text="Key delay (ms):").pack(side="left")
        ttk.Spinbox(controls, from_=0, to=1000, textvariable=self.delay_var, width=5).pack(side="left", padx=5)

        ttk.Label(controls, text="Start delay (s):").pack(side="left", padx=(10, 0))
        ttk.Spinbox(controls, from_=0, to=30, textvariable=self.countdown_var, width=5).pack(side="left", padx=5)

        # Standard Actions
        actions = ttk.Frame(main)
        actions.pack(fill="x", pady=10)
        ttk.Button(actions, text="Type Custom Text", command=self.type_custom_text).pack(side="left", padx=5)
        ttk.Button(actions, text="Paste Clipboard", command=self.paste_clipboard).pack(side="left", padx=5)
        ttk.Button(actions, text="Manage Buttons", command=self.manage_buttons).pack(side="right", padx=5)

        # Custom Buttons Area
        ttk.Label(main, text="Saved Buttons (Click to type):").pack(anchor="w", pady=(10, 0))
        
        # Scrollable area for buttons
        self.canvas = tk.Canvas(main)
        self.scrollbar = ttk.Scrollbar(main, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Status
        self.status_label = ttk.Label(self.root, text="Ready | Secured", relief="sunken", anchor="w")
        self.status_label.pack(side="bottom", fill="x")

    def refresh_custom_buttons(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        for idx, btn_data in enumerate(self.config["buttons"]):
            frame = ttk.Frame(self.scrollable_frame)
            frame.pack(fill="x", pady=2, padx=5)
            
            label = btn_data.get("label", "Unnamed")
            text = btn_data.get("text", "")
            is_hidden = btn_data.get("is_hidden", False)
            
            display_text = "******" if is_hidden else (text[:30] + "..." if len(text) > 30 else text)
            
            btn = ttk.Button(frame, text=label, command=lambda t=text: self.start_typing(t))
            btn.pack(side="left", fill="x", expand=True)
            
            info = ttk.Label(frame, text=display_text, foreground="gray")
            info.pack(side="left", padx=10)

    def manage_buttons(self):
        top = tk.Toplevel(self.root)
        top.title("Manage Buttons")
        top.geometry("400x320")

        list_frame = ttk.Frame(top)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        lb = tk.Listbox(list_frame)
        lb.pack(side="left", fill="both", expand=True)
        
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=lb.yview)
        scroll.pack(side="right", fill="y")
        lb.config(yscrollcommand=scroll.set)

        def refresh_list():
            lb.delete(0, tk.END)
            for b in self.config["buttons"]:
                lb.insert(tk.END, f"{b['label']} ({'Secret' if b.get('is_hidden') else 'Visible'})")

        refresh_list()

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill="x", pady=5)

        def add_btn():
            editor = ButtonEditor(top, title="Add Button")
            if editor.result_data:
                self.config["buttons"].append(editor.result_data)
                self.save_settings()
                refresh_list()
                self.refresh_custom_buttons()

        def edit_btn():
            sel = lb.curselection()
            if not sel: return
            idx = sel[0]
            data = self.config["buttons"][idx]
            editor = ButtonEditor(top, title="Edit Button", initial_data=data)
            if editor.result_data:
                self.config["buttons"][idx] = editor.result_data
                self.save_settings()
                refresh_list()
                self.refresh_custom_buttons()

        def del_btn():
            sel = lb.curselection()
            if not sel: return
            idx = sel[0]
            if messagebox.askyesno("Confirm", "Delete this button?"):
                del self.config["buttons"][idx]
                self.save_settings()
                refresh_list()
                self.refresh_custom_buttons()

        ttk.Button(btn_frame, text="Add", command=add_btn).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Edit", command=edit_btn).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Delete", command=del_btn).pack(side="left", padx=5)
        
        ttk.Label(top, text="Changes are encrypted automatically.", foreground="gray", font=("Arial", 8)).pack(pady=5)

    def save_settings(self):
        # Update settings from vars
        self.config["settings"]["delay"] = self.delay_var.get()
        self.config["settings"]["countdown"] = self.countdown_var.get()
        ConfigManager.save_config(self.config) # Uses cached key

    def type_custom_text(self):
        text = self.text_box.get("1.0", tk.END).rstrip("\n")
        if not text:
            messagebox.showwarning("Empty", "No text to type.")
            return
        self.start_typing(text)

    def paste_clipboard(self):
        try:
            text = self.root.clipboard_get()
            self.text_box.delete("1.0", tk.END)
            self.text_box.insert(tk.END, text)
            self.status_label.config(text="Clipboard content pasted into text box.")
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def start_typing(self, text):
        self.save_settings() # Save config on action
        delay_s = self.delay_var.get() / 1000.0
        countdown = self.countdown_var.get()
        
        def run():
            try:
                for i in range(countdown, 0, -1):
                    self.status_label.config(text=f"Focus target window... {i}s")
                    time.sleep(1)
                
                self.status_label.config(text="Typing...")
                pyautogui.write(text, interval=delay_s)
                self.status_label.config(text="Done.")
            except Exception as e:
                self.status_label.config(text=f"Error: {e}")

        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = TypePasteApp(root)
    root.mainloop()
