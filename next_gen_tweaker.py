import os
import ctypes
import subprocess
import winreg
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def create_restore_point():
    """Create a system restore point."""
    try:
        subprocess.run([
            "powershell", 
            "-Command", 
            "Checkpoint-Computer -Description 'Next Gen Tweaker Backup' -RestorePointType MODIFY_SETTINGS"
        ], check=True)
        messagebox.showinfo("Success", "System restore point created successfully.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "Failed to create a system restore point.")

def toggle_uac(enable):
    """Enable or disable User Account Control (UAC)."""
    value = 1 if enable else 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, value)
        messagebox.showinfo("Success", f"UAC has been {'enabled' if enable else 'disabled'}.")
    except PermissionError:
        messagebox.showerror("Error", "Failed to modify UAC. Run the script as Administrator.")

def toggle_service(service_name, enable):
    """Enable or disable a Windows service."""
    action = "start" if enable else "stop"
    config = "auto" if enable else "disabled"
    try:
        subprocess.run(["sc", "config", service_name, f"start= {config}"], check=True)
        subprocess.run(["net", action, service_name], check=True)
        messagebox.showinfo("Success", f"Service {service_name} has been {'enabled' if enable else 'disabled'}.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", f"Failed to {'enable' if enable else 'disable'} {service_name}.")

def toggle_windows_firewall(enable):
    """Enable or disable Windows Firewall."""
    state = "on" if enable else "off"
    try:
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", state], check=True)
        messagebox.showinfo("Success", f"Windows Firewall has been {'enabled' if enable else 'disabled'}.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "Failed to modify Windows Firewall settings.")

def toggle_hibernation(enable):
    """Enable or disable Hibernation."""
    state = "on" if enable else "off"
    try:
        subprocess.run(["powercfg", f"-h {state}"], shell=True, check=True)
        messagebox.showinfo("Success", f"Hibernation has been {'enabled' if enable else 'disabled'}.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "Failed to modify hibernation settings.")

def add_microsoft_store_ltsc():
    """Add Microsoft Store to LTSC editions."""
    try:
        messagebox.showinfo("Info", "Downloading Microsoft Store packages...")
        subprocess.run([
            "curl", "-L", "-o", "MicrosoftStorePackages.zip",
            "https://github.com/kkkgo/LTSC-Add-MicrosoftStore/releases/download/v1.0/MicrosoftStorePackages.zip"
        ], check=True)
        messagebox.showinfo("Info", "Extracting Microsoft Store packages...")
        subprocess.run([
            "powershell", "-Command", "Expand-Archive -Path MicrosoftStorePackages.zip -DestinationPath .\\MicrosoftStorePackages -Force"
        ], check=True)
        os.chdir("MicrosoftStorePackages")
        packages = [
            "Microsoft.VCLibs.x64.14.00.appx",
            "Microsoft.UI.Xaml.2.3.appx",
            "Microsoft.StorePurchaseApp.appx",
            "MicrosoftWindowsStore.appx"
        ]
        for package in packages:
            subprocess.run(["powershell", "-Command", f"Add-AppxPackage -Path {package}"], check=True)
        os.chdir("..")
        os.remove("MicrosoftStorePackages.zip")
        os.rmdir("MicrosoftStorePackages")
        messagebox.showinfo("Success", "Microsoft Store added successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add Microsoft Store: {e}")

def main():
    """Main function to initialize the GUI."""
    if not is_admin():
        messagebox.showerror("Error", "Please run this script as Administrator!")
        return

    root = tk.Tk()
    root.title("Next Gen Tweaker 10/11")
    root.geometry("500x500")
    root.configure(bg="black")

    # Create Notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(pady=10, expand=True)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="black")
    style.configure("TLabel", background="black", foreground="green", font=("Arial", 10))
    style.configure("TButton", background="black", foreground="green", font=("Arial", 10, "bold"))
    style.configure("TNotebook", background="black", borderwidth=0)
    style.configure("TNotebook.Tab", background="black", foreground="green", padding=(5, 5))
    style.map("TNotebook.Tab", background=[("selected", "green")], foreground=[("selected", "black")])

    # Settings Tab
    settings_tab = ttk.Frame(notebook)
    notebook.add(settings_tab, text="Settings")

    ttk.Label(settings_tab, text="Settings", font=("Arial", 14, "bold")).pack(pady=10)
    ttk.Button(settings_tab, text="Create Restore Point", command=create_restore_point, width=25).pack(pady=5)

    # Main Tweaker Tab with scrolling
    tweaker_tab = ttk.Frame(notebook)
    notebook.add(tweaker_tab, text="Tweaker")

    tweaker_canvas = tk.Canvas(tweaker_tab, bg="black")
    tweaker_scrollbar = ttk.Scrollbar(tweaker_tab, orient="vertical", command=tweaker_canvas.yview)
    tweaker_scrollable_frame = ttk.Frame(tweaker_canvas)

    tweaker_scrollable_frame.bind(
        "<Configure>",
        lambda e: tweaker_canvas.configure(scrollregion=tweaker_canvas.bbox("all"))
    )

    tweaker_canvas.create_window((0, 0), window=tweaker_scrollable_frame, anchor="nw")
    tweaker_canvas.configure(yscrollcommand=tweaker_scrollbar.set)

    tweaker_canvas.pack(side="left", fill="both", expand=True)
    tweaker_scrollbar.pack(side="right", fill="y")

    ttk.Label(tweaker_scrollable_frame, text="Tweaker Options", font=("Arial", 14, "bold")).pack(pady=10)
    ttk.Button(tweaker_scrollable_frame, text="Enable UAC", command=lambda: toggle_uac(True), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Disable UAC", command=lambda: toggle_uac(False), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Enable Windows Updates", command=lambda: toggle_service("wuauserv", True), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Disable Windows Updates", command=lambda: toggle_service("wuauserv", False), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Enable Windows Firewall", command=lambda: toggle_windows_firewall(True), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Disable Windows Firewall", command=lambda: toggle_windows_firewall(False), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Enable Hibernation", command=lambda: toggle_hibernation(True), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Disable Hibernation", command=lambda: toggle_hibernation(False), width=25).pack(pady=5)
    ttk.Button(tweaker_scrollable_frame, text="Add Microsoft Store to LTSC", command=add_microsoft_store_ltsc, width=25).pack(pady=5)

    # About Tab
    about_tab = ttk.Frame(notebook)
    notebook.add(about_tab, text="About")

    ttk.Label(about_tab, text="About Next Gen Tweaker", font=("Arial", 14, "bold")).pack(pady=10)
    ttk.Label(
        about_tab,
        text=(
            "Next Gen Tweaker 10/11\n"
            "Version: 1.0.0\n"
            "Author: B1TNEYM\n"
            "Description: A tool for tweaking Windows 10/11 settings.\n"
            "Use responsibly and with administrator privileges."
        ),
        font=("Arial", 10),
        justify="center",
    ).pack(pady=10)

    # Exit Button
    ttk.Button(root, text="Exit", command=root.quit, width=25).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()