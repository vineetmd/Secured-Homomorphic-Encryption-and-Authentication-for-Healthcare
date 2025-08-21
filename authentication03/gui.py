import tkinter as tk
import customtkinter as ctk
import subprocess
import os
import time
import threading
import re  # Import regex module for password validation

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Login System")
        self.root.geometry("500x400")

        # Main screen
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        self.create_welcome_screen()

        # Log window status
        self.log_window_open = False

    def create_welcome_screen(self):
        # Clear the main frame for welcome screen components
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # Welcome screen components
        welcome_label = ctk.CTkLabel(self.main_frame, text="Welcome", font=("Arial", 24))
        welcome_label.pack(pady=20)

        register_btn = ctk.CTkButton(self.main_frame, text="Register", command=self.open_register_screen, width=200)
        register_btn.pack(pady=10)

        login_btn = ctk.CTkButton(self.main_frame, text="Login", command=self.open_login_screen, width=200)
        login_btn.pack(pady=10)

        log_btn = ctk.CTkButton(self.main_frame, text="Logs", command=self.open_log_screen, width=200)
        log_btn.pack(pady=10)

    def open_register_screen(self):
        # Update the main frame for the registration screen
        self.clear_main_frame()

        label = ctk.CTkLabel(self.main_frame, text="Register", font=("Arial", 24))
        label.pack(pady=20)

        username_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Username")
        username_entry.pack(pady=10)

        password_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Password", show="*")
        password_entry.pack(pady=10)

        submit_btn = ctk.CTkButton(self.main_frame, text="Register", command=lambda: self.register_user(username_entry.get(), password_entry.get()))
        submit_btn.pack(pady=10)

        back_btn = ctk.CTkButton(self.main_frame, text="Back", command=self.create_welcome_screen)
        back_btn.pack(pady=10)

    def open_login_screen(self):
        # Update the main frame for the login screen
        self.clear_main_frame()

        label = ctk.CTkLabel(self.main_frame, text="Login", font=("Arial", 24))
        label.pack(pady=20)

        username_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Username")
        username_entry.pack(pady=10)

        password_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Password", show="*")
        password_entry.pack(pady=10)

        login_btn = ctk.CTkButton(self.main_frame, text="Login", command=lambda: self.login_user(username_entry.get(), password_entry.get()))
        login_btn.pack(pady=10)

        back_btn = ctk.CTkButton(self.main_frame, text="Back", command=self.create_welcome_screen)
        back_btn.pack(pady=10)

    def open_log_screen(self):
        # Open logs in a new separate window
        if not self.log_window_open:
            self.log_window_open = True  # Set flag to indicate log window is open
            self.log_window = ctk.CTkToplevel(self.root)
            self.log_window.title("Logs")
            self.log_window.geometry("600x400")

            log_label = ctk.CTkLabel(self.log_window, text="Logs", font=("Arial", 24))
            log_label.pack(pady=20)

            # Text widget for logs without scrollbar or border
            self.log_textbox = tk.Text(self.log_window, wrap=tk.WORD, width=70, height=15, font=("Arial", 12), bg="#242424", fg="#ffffff", insertbackground='white', bd=0, highlightthickness=0)
            self.log_textbox.pack(pady=20, fill=tk.BOTH, expand=True)

            # Disable editing
            self.log_textbox.config(state=tk.DISABLED)

            # Start thread to update logs
            self.log_thread = threading.Thread(target=self.update_logs, daemon=True)
            self.log_thread.start()

            # Close button for log window
            close_btn = ctk.CTkButton(self.log_window, text="Close", command=self.close_log_window)
            close_btn.pack(pady=10)

            # Close event for log window
            self.log_window.protocol("WM_DELETE_WINDOW", self.close_log_window)

    def close_log_window(self):
        self.log_window_open = False  # Set flag to indicate log window is closed
        self.log_window.destroy()  # Close the log window

    def register_user(self, username, password):
        # Check if password meets the criteria
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            self.show_floating_message("Password must be alphanumeric and include at least one special character.")
            return

        if username and password:
            result = subprocess.run(["python", "main.py"], input=f"1\n{username}\n{password}\n3\n", text=True)
            if result.returncode == 0:
                self.show_floating_message("User registered successfully.")
                self.open_login_screen()  # Redirect to login screen after successful registration
            else:
                self.show_floating_message("Registration failed. Please try again.")
        else:
            self.show_floating_message("Please fill in both fields.")

    def login_user(self, username, password):
        if username and password:
            result = subprocess.run(
                ["python", "main.py"],
                input=f"2\n{username}\n{password}\n3\n",
                text=True,
                capture_output=True  # Capture output for validation
            )
            if result.returncode == 0 and "Login successful" in result.stdout:
                self.show_floating_message("User logged in successfully.")
                self.create_dashboard_screen()  # Switch to dashboard on successful login
            else:
                self.show_floating_message("Login failed. User not found or incorrect credentials.")
        else:
            self.show_floating_message("Please fill in both fields.")


    def show_floating_message(self, message):
        # Create a floating message window
        floating = ctk.CTkToplevel(self.root)
        floating.overrideredirect(True)  # Remove title bar and window decorations
    
        # Adjust window size for better visibility
        width, height = 600, 150
        x = self.root.winfo_x() + (self.root.winfo_width() // 2 - width // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2 - height // 2)
        floating.geometry(f"{width}x{height}+{x}+{y}")
    
        floating.attributes("-alpha", 0.9)  # Set transparency

        # Increase font size for better readability
        label = ctk.CTkLabel(floating, text=message, font=("Arial", 16))
        label.pack(pady=30, padx=20)

        # Auto-close floating message after 2 seconds
        floating.after(2000, floating.destroy)

    def create_dashboard_screen(self):
        # Clear the main frame for the dashboard
        self.clear_main_frame()

        # Dashboard layout
        dashboard_label = ctk.CTkLabel(self.main_frame, text="Dashboard", font=("Arial", 24))
        dashboard_label.pack(pady=20)

        stats_label = ctk.CTkLabel(self.main_frame, text="User Statistics", font=("Arial", 18))
        stats_label.pack(pady=10)

        # Sample buttons for dashboard actions
        profile_btn = ctk.CTkButton(self.main_frame, text="Profile", command=lambda: self.show_floating_message("Profile Page"))
        profile_btn.pack(pady=10)

        settings_btn = ctk.CTkButton(self.main_frame, text="Settings", command=lambda: self.show_floating_message("Settings Page"))
        settings_btn.pack(pady=10)

        logout_btn = ctk.CTkButton(self.main_frame, text="Logout", command=self.create_welcome_screen)
        logout_btn.pack(pady=20)

    def update_logs(self):
        log_file_path = "app.log"  # Path to your log file
        last_read = 0

        while self.log_window_open:  # Only update if the log window is open
            try:
                with open(log_file_path, "r") as log_file:
                    log_file.seek(last_read)  # Move to the last read position
                    new_logs = log_file.read()  # Read new logs
                    if new_logs:
                        self.log_textbox.config(state=tk.NORMAL)
                        self.log_textbox.insert(tk.END, new_logs)  # Insert new log data
                        self.log_textbox.see(tk.END)  # Scroll to the end
                        self.log_textbox.config(state=tk.DISABLED)
                        last_read = log_file.tell()  # Update the last read position
            except FileNotFoundError:
                self.show_floating_message("Log file not found.")
                break  # Stop updating if the log file is missing
            time.sleep(1)  # Refresh rate

    def clear_main_frame(self):
        # Remove all widgets from the main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    app = App(root)
    root.mainloop()
