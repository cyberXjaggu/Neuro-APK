import tkinter as tk
from tkinter import filedialog, messagebox
from androguard.core.apk import APK
import os

# ----------------------------- Stage 2 Analysis Functions -----------------------------

def extract_permissions(a):
    return a.get_permissions()

def detect_dangerous_permissions(a):
    dangerous_list = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE"
    ]
    permissions = a.get_permissions()
    return [perm for perm in permissions if perm in dangerous_list]

def get_exported_components(a):
    exported = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": []
    }
    for activity in a.get_activities():
        if a.get_activity(activity).get("exported", "false") == "true":
            exported["activities"].append(activity)

    for service in a.get_services():
        if a.get_service(service).get("exported", "false") == "true":
            exported["services"].append(service)

    for receiver in a.get_receivers():
        if a.get_receiver(receiver).get("exported", "false") == "true":
            exported["receivers"].append(receiver)

    for provider in a.get_providers():
        if a.get_provider(provider).get("exported", "false") == "true":
            exported["providers"].append(provider)

    return exported

def is_debuggable(a):
    return a.is_debuggable()

# ----------------------------- GUI Interface (Stage 1 + Stage 2) -----------------------------

def analyze_apk():
    apk_path = path_entry.get()

    if not apk_path.endswith(".apk"):
        messagebox.showerror("Error", "Please select a valid APK file.")
        return

    try:
        a = APK(apk_path)

        app_name = a.get_app_name()
        pkg_name = a.get_package()
        version = a.get_version_name()

        permissions = extract_permissions(a)
        dangerous = detect_dangerous_permissions(a)
        exported = get_exported_components(a)
        debug_status = is_debuggable(a)

        output = f"📱 App Name: {app_name}\n"
        output += f"📦 Package: {pkg_name}\n"
        output += f"🕓 Version: {version}\n\n"
        output += f"🛡 Permissions:\n" + "\n".join(permissions) + "\n\n"
        output += f"⚠️ Dangerous Permissions:\n" + ("\n".join(dangerous) if dangerous else "None") + "\n\n"
        output += "🔓 Exported Components:\n"
        for key, val in exported.items():
            output += f"{key.capitalize()}: {', '.join(val) if val else 'None'}\n"
        output += f"\n🐞 Debuggable: {'Yes' if debug_status else 'No'}"

        messagebox.showinfo("APK Analysis Report", output)

    except Exception as e:
        messagebox.showerror("Analysis Error", f"Failed to analyze APK:\n{str(e)}")

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if file_path:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, file_path)

# ----------------------------- UI Setup -----------------------------

root = tk.Tk()
root.title("🔒 Nebula APK Analyzer 🔍")
root.geometry("500x300")
root.configure(bg="black")

title_label = tk.Label(root, text="🔐 Nebula APK Analyzer 🔍", fg="red", bg="black", font=("Courier", 18, "bold"))
title_label.pack(pady=15)

path_entry = tk.Entry(root, width=50, font=("Courier", 10))
path_entry.pack(pady=5)

browse_btn = tk.Button(root, text="Browse", command=browse_file, bg="green", fg="white", width=10)
browse_btn.pack(pady=5)

analyze_btn = tk.Button(root, text="Analyze APK", command=analyze_apk, bg="red", fg="white", width=15)
analyze_btn.pack(pady=10)

root.mainloop()
