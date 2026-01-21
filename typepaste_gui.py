#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import time

def type_text():
    text = text_box.get("1.0", tk.END).rstrip("\n")
    if not text:
        messagebox.showwarning("Empty", "No text to type.")
        return

    delay = delay_var.get()
    countdown = countdown_var.get()

    try:
        countdown_label.config(text=f"Focus target window… {countdown}s")
        root.update()

        time.sleep(countdown)

        subprocess.run([
            "xdotool",
            "type",
            "--delay", str(delay),
            "--clearmodifiers",
            text
        ])
    except Exception as e:
        messagebox.showerror("Error", str(e))

    countdown_label.config(text="Done.")

def paste_clipboard():
    try:
        clip = subprocess.check_output(["xclip", "-o"], text=True)
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, clip)
    except Exception:
        messagebox.showerror("Clipboard Error", "Install xclip to use this feature.")

# ---- GUI ----
root = tk.Tk()
root.title("Type-Paste Utility")
root.geometry("500x350")

main = ttk.Frame(root, padding=10)
main.pack(fill="both", expand=True)

ttk.Label(main, text="Text to type:").pack(anchor="w")

text_box = tk.Text(main, height=10)
text_box.pack(fill="both", expand=True, pady=5)

controls = ttk.Frame(main)
controls.pack(fill="x", pady=5)

delay_var = tk.IntVar(value=5)
countdown_var = tk.IntVar(value=3)

ttk.Label(controls, text="Key delay (ms):").grid(row=0, column=0, sticky="w")
ttk.Spinbox(controls, from_=1, to=100, textvariable=delay_var, width=5).grid(row=0, column=1)

ttk.Label(controls, text="Start delay (s):").grid(row=0, column=2, sticky="w", padx=(10,0))
ttk.Spinbox(controls, from_=0, to=10, textvariable=countdown_var, width=5).grid(row=0, column=3)

buttons = ttk.Frame(main)
buttons.pack(pady=10)

ttk.Button(buttons, text="Type Text", command=type_text).grid(row=0, column=0, padx=5)
ttk.Button(buttons, text="Paste Clipboard", command=paste_clipboard).grid(row=0, column=1, padx=5)
ttk.Button(buttons, text="Quit", command=root.quit).grid(row=0, column=2, padx=5)

countdown_label = ttk.Label(main, text="")
countdown_label.pack()

root.mainloop()
