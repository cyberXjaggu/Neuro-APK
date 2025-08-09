import tkinter as tk
from tkinter import filedialog, scrolledtext
from androguard.core.apk import APK

# List of dangerous permissions
dangerous_permissions = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECEIVE_SMS",
]

def analyze_apk():
    file_path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if file_path:
        try:
            a = APK(file_path)
        except Exception as e:
            result.delete('1.0', tk.END)
            result.insert(tk.END, f"[!] Failed to open APK: {e}\n", "danger")
            return

        result.delete('1.0', tk.END)
        result.insert(tk.END, f"[+] APK File: {file_path}\n\n", "normal")

        # Permissions
        result.insert(tk.END, "[*] Permissions:\n", "section")
        try:
            permissions = a.get_permissions()
            if permissions:
                for perm in permissions:
                    if perm in dangerous_permissions:
                        result.insert(tk.END, f"   ⚠️ {perm}\n", "danger")
                    else:
                        result.insert(tk.END, f"   ✅ {perm}\n", "normal")
            else:
                result.insert(tk.END, "   No permissions found.\n", "normal")
        except Exception as e:
            result.insert(tk.END, f"   [!] Error reading permissions: {e}\n", "danger")

        # Debuggable status
        result.insert(tk.END, "\n[*] Debuggable:\n", "section")
        debuggable_flag = False
        try:
            manifest_xml = a.get_android_manifest_xml()
            for app_tag in manifest_xml.iter("application"):
                if "debuggable" in app_tag.attrib:
                    if app_tag.attrib["debuggable"].lower() == "true":
                        debuggable_flag = True
                        break
        except Exception as e:
            result.insert(tk.END, f"   [!] Error reading debuggable flag: {e}\n", "danger")

        if debuggable_flag:
            result.insert(tk.END, "   ⚠️ Yes (App is debuggable)\n", "danger")
        else:
            result.insert(tk.END, "   ✅ No (App is not debuggable)\n", "normal")

        # Exported components
        result.insert(tk.END, "\n[*] Exported Components:\n", "section")

        def show_exported(title, items, manifest_xml):
            result.insert(tk.END, f"   {title}:\n", "subsection")
            found = False
            for name in items:
                for elem in manifest_xml.iter():
                    if elem.get("name") == name and elem.get("exported") == "true":
                        result.insert(tk.END, f"     📤 {name}\n", "exported")
                        found = True
            if not found:
                result.insert(tk.END, "     None exported.\n", "normal")

        try:
            manifest_xml = a.get_android_manifest_xml()
            show_exported("Activities", a.get_activities(), manifest_xml)
            show_exported("Services", a.get_services(), manifest_xml)
            show_exported("Receivers", a.get_receivers(), manifest_xml)
            show_exported("Providers", a.get_providers(), manifest_xml)
        except Exception as e:
            result.insert(tk.END, f"   [!] Error reading exported components: {e}\n", "danger")

# ---------------- GUI Setup (Matching Stage 1 Style) ----------------
root = tk.Tk()
root.title("🛡️ Nebula APK Analyzer - Stage 2")
root.geometry("900x700")
root.configure(bg="black")

# Header label
header = tk.Label(root, text="NEBULA APK ANALYZER - STAGE 2",
                  font=("Consolas", 20, "bold"), fg="#39ff14", bg="black")
header.pack(pady=15)

# Button
btn = tk.Button(
    root, text="Select APK & Analyze", command=analyze_apk,
    bg="#39ff14", fg="black", font=("Consolas", 14, "bold"),
    activebackground="black", activeforeground="#39ff14",
    relief=tk.FLAT, padx=15, pady=5
)
btn.pack(pady=15)

# Result Area
result = scrolledtext.ScrolledText(
    root, wrap=tk.WORD, font=("Courier", 11),
    bg="black", fg="#39ff14", insertbackground="#39ff14",
    borderwidth=0
)
result.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

# Text tags for styling
result.tag_config("danger", foreground="red", font=("Courier", 11, "bold"))
result.tag_config("exported", foreground="#ffcc00")
result.tag_config("section", foreground="#00ffff", font=("Courier", 12, "bold"))
result.tag_config("subsection", foreground="#00ff88", font=("Courier", 11, "bold"))
result.tag_config("normal", foreground="#39ff14")

root.mainloop()
