import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# PIL for loading & resizing PNG/JPG images
from PIL import Image, ImageTk  

# Use your final container with offset/length trailer
from vault.container import PartialReadVault  

class VaultGUI(tk.Tk):
    def __init__(self, bg_image_path=None):
        super().__init__()
        self.title("Secure Vault")
        self.geometry("600x400")
        self.resizable(False, False)

        # Apply style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.configure_styles()

        # Debug check if the file is found
        if bg_image_path:
            print("bg_image_path =", bg_image_path, "| Exists?", os.path.exists(bg_image_path))

        self.bg_image = None
        if bg_image_path and os.path.exists(bg_image_path):
            original = Image.open(bg_image_path)
            # Use LANCZOS or Resampling.LANCZOS in Pillow 10+
            resized = original.resize((600, 400), Image.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(resized)

        # Create the vault object
        self.vault = PartialReadVault()
        self.is_unlocked = False

        # Create frames
        self.login_frame = LoginFrame(self, bg_image=self.bg_image)
        self.vault_frame = VaultFrame(self, bg_image=self.bg_image)

        # Show the login screen initially
        self.show_frame("login")

    def configure_styles(self):
        dark_bg = "#2c2c2c"
        light_text = "#ebebeb"
        accent_color = "#6c63ff"

        self.configure(bg=dark_bg)
        self.style.configure("TFrame", background=dark_bg)
        self.style.configure("TLabel", background=dark_bg, foreground=light_text, font=("Helvetica", 12))
        self.style.configure("TEntry", fieldbackground="#3e3e3e", foreground=light_text)
        self.style.configure(
            "TButton",
            foreground=light_text,
            background=accent_color,
            font=("Helvetica", 11, "bold")
        )
        self.style.map(
            "TButton",
            background=[("active", "#5c54ee")]
        )

    def show_frame(self, frame_name):
        if frame_name == "login":
            self.vault_frame.pack_forget()
            self.login_frame.pack(fill="both", expand=True)
        elif frame_name == "vault":
            self.login_frame.pack_forget()
            self.vault_frame.pack(fill="both", expand=True)

    def lock_vault(self):
        # Lock / clear
        self.vault.lock_vault()
        self.is_unlocked = False
        self.show_frame("login")


class BackgroundFrame(ttk.Frame):
    """
    A base frame that can display a background image if provided.
    """
    def __init__(self, parent, bg_image=None):
        super().__init__(parent)
        self.bg_image = bg_image

        if self.bg_image:
            # Label that covers entire frame
            self.bg_label = tk.Label(self, image=self.bg_image)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

            # content_frame for widgets on top
            self.content_frame = ttk.Frame(self)
            self.content_frame.pack(fill="both", expand=True)
        else:
            self.content_frame = self


class LoginFrame(BackgroundFrame):
    def __init__(self, master, bg_image=None):
        super().__init__(master, bg_image=bg_image)
        container = self.content_frame

        title_label = ttk.Label(container, text="Secure Vault Login / Create", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=20)

        # Vault path
        ttk.Label(container, text="Vault Path:").pack()
        self.vault_path_var = tk.StringVar()
        self.vault_path_entry = ttk.Entry(container, textvariable=self.vault_path_var, width=40)
        self.vault_path_entry.pack(pady=5)

        # Password
        ttk.Label(container, text="Password:").pack()
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="*", width=40)
        self.password_entry.pack(pady=5)

        # Buttons
        button_frame = ttk.Frame(container)
        button_frame.pack(pady=15)

        create_btn = ttk.Button(button_frame, text="Create Vault", command=self.create_vault)
        create_btn.grid(row=0, column=0, padx=5)

        open_btn = ttk.Button(button_frame, text="Open Vault", command=self.open_vault)
        open_btn.grid(row=0, column=1, padx=5)

        # Status label
        self.status_label = ttk.Label(container, text="", foreground="red")
        self.status_label.pack(pady=10)

        # Add the Bitcoin-themed image below the buttons
        try:
            image = Image.open("securevault.jpeg")  # Ensure the image file is named correctly and in the same directory
            resized_image = image.resize((300, 150), Image.LANCZOS)
            self.image_tk = ImageTk.PhotoImage(resized_image)
            image_label = tk.Label(container, image=self.image_tk, bg="#2c2c2c")
            image_label.pack(pady=10)
        except Exception as e:
            print(f"Failed to load image: {e}")

    def create_vault(self):
        vault_path = self.vault_path_var.get().strip()
        password = self.password_var.get().strip()
        if not vault_path or not password:
            self.status_label.config(text="Vault path & password required.")
            return

        try:
            self.master.vault.create_vault(vault_path, password)
            self.status_label.config(text=f"Vault created: {vault_path}", foreground="green")
            self.master.is_unlocked = True
            self.master.show_frame("vault")
        except FileExistsError:
            self.status_label.config(text="File exists. Use 'Open Vault' or a different name.", foreground="red")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", foreground="red")

    def open_vault(self):
        vault_path = self.vault_path_var.get().strip()
        password = self.password_var.get().strip()
        if not vault_path or not password:
            self.status_label.config(text="Vault path & password required.")
            return

        try:
            self.master.vault.unlock_vault(vault_path, password)
            self.status_label.config(text="Vault opened successfully.", foreground="green")
            self.master.is_unlocked = True
            self.master.show_frame("vault")
        except FileNotFoundError:
            self.status_label.config(text="Vault file not found.", foreground="red")
        except ValueError as e:
            self.status_label.config(text=f"Unlock failed: {e}", foreground="red")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}", foreground="red")



class VaultFrame(BackgroundFrame):
    def __init__(self, master, bg_image=None):
        super().__init__(master, bg_image=bg_image)
        container = self.content_frame

        title_label = ttk.Label(container, text="Vault Unlocked", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=20)

        action_frame = ttk.Frame(container)
        action_frame.pack(pady=10)

        ttk.Button(action_frame, text="Add File", command=self.add_file).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(action_frame, text="List Files", command=self.list_files).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(action_frame, text="Extract File", command=self.extract_file).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(action_frame, text="Remove File", command=self.remove_file).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(action_frame, text="Lock Vault", command=self.master.lock_vault).grid(row=2, column=0, columnspan=2, pady=5)

        # Text area for file listing or status
        self.output_text = tk.Text(container, width=60, height=8, bg="#3e3e3e", fg="#ffffff")
        self.output_text.pack(pady=10)

    def add_file(self):
        if not self.master.is_unlocked:
            messagebox.showerror("Error", "Vault is locked.")
            return
        file_path = filedialog.askopenfilename(title="Select file to add")
        if file_path:
            try:
                self.master.vault.add_file(file_path)
                messagebox.showinfo("Success", f"Added {os.path.basename(file_path)} to vault.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add file: {e}")

    def list_files(self):
        if not self.master.is_unlocked:
            messagebox.showerror("Error", "Vault is locked.")
            return
        try:
            files_dict = self.master.vault.list_files()
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            if files_dict:
                self.output_text.insert(tk.END, "Files in vault:\n")
                for fname, meta in files_dict.items():
                    self.output_text.insert(tk.END, f" - {fname} (size: {meta['plaintext_size']} bytes)\n")
            else:
                self.output_text.insert(tk.END, "No files in the vault.\n")
            self.output_text.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Could not list files: {e}")

    def extract_file(self):
        if not self.master.is_unlocked:
            messagebox.showerror("Error", "Vault is locked.")
            return

        vault_files = self.master.vault.list_files()
        if not vault_files:
            messagebox.showinfo("Info", "No files in the vault to extract.")
            return

        filename_in_vault = simple_input_dialog(self, "Extract File", "Enter filename in vault:")
        if filename_in_vault and filename_in_vault in vault_files:
            output_path = filedialog.asksaveasfilename(title="Save extracted file as...")
            if output_path:
                try:
                    self.master.vault.extract_file(filename_in_vault, output_path)
                    messagebox.showinfo("Success", f"Extracted '{filename_in_vault}' to '{output_path}'.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to extract file: {e}")
        else:
            if filename_in_vault:
                messagebox.showerror("Error", f"'{filename_in_vault}' not found in vault.")

    def remove_file(self):
        if not self.master.is_unlocked:
            messagebox.showerror("Error", "Vault is locked.")
            return
        vault_files = self.master.vault.list_files()
        if not vault_files:
            messagebox.showinfo("Info", "No files in the vault to remove.")
            return

        filename_in_vault = simple_input_dialog(self, "Remove File", "Enter filename in vault:")
        if filename_in_vault and filename_in_vault in vault_files:
            try:
                self.master.vault.remove_file(filename_in_vault)
                messagebox.showinfo("Success", f"Removed '{filename_in_vault}' from vault.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove file: {e}")
        else:
            if filename_in_vault:
                messagebox.showerror("Error", f"'{filename_in_vault}' not found in vault.")


def simple_input_dialog(parent, title, prompt):
    """
    A small modal dialog to get user text input.
    """
    input_win = tk.Toplevel(parent)
    input_win.title(title)
    input_win.geometry("300x120")
    input_win.resizable(False, False)
    input_win.grab_set()

    input_win.configure(bg="#2c2c2c")

    label = ttk.Label(input_win, text=prompt)
    label.pack(pady=10)

    entry_var = tk.StringVar()
    entry = ttk.Entry(input_win, textvariable=entry_var, width=30)
    entry.pack()

    btn_frame = ttk.Frame(input_win)
    btn_frame.pack(pady=10)

    result = {"value": None}

    def on_ok():
        result["value"] = entry_var.get().strip()
        input_win.destroy()

    def on_cancel():
        result["value"] = None
        input_win.destroy()

    ttk.Button(btn_frame, text="OK", command=on_ok).grid(row=0, column=0, padx=5)
    ttk.Button(btn_frame, text="Cancel", command=on_cancel).grid(row=0, column=1, padx=5)

    entry.focus()
    input_win.wait_window()
    return result["value"]


def main():
    # Make sure "securevault.png" is in the SAME folder as this code
    app = VaultGUI(bg_image_path="securevault.jpeg")
    app.mainloop()


if __name__ == "__main__":
    main()