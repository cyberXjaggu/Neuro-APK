import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from androguard.misc import AnalyzeAPK

def browse_apk():
    file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
    if file_path:
        apk_path.set(file_path)

def analyze_apk():
    path = apk_path.get()
    if not path:
        messagebox.showerror("Error", "Please select an APK file.")
        return
    try:
        a, d, dx = AnalyzeAPK(path)
        result = (
            f"🟢 App Name: {a.get_app_name()}\n"
            f"🧪 Package Name: {a.get_package()}\n"
            f"🧾 Version Code: {a.get_androidversion_code()}\n"
            f"📦 Version Name: {a.get_androidversion_name()}\n"
            f"🎯 Main Activity: {a.get_main_activity()}\n"
            f"📱 Min SDK: {a.get_min_sdk_version()}\n"
            f"📶 Target SDK: {a.get_target_sdk_version()}"
        )
        result_box.config(state="normal")
        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, result)
        result_box.config(state="disabled")
    except Exception as e:
        messagebox.showerror("Error", str(e))
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK
from androguard.misc import AnalyzeAPK


# ----------------------------
# Stage 2 Functions
# ----------------------------

def extract_permissions(apk_path):
    a, d, dx = AnalyzeAPK(apk_path)
    permissions = a.get_permissions()
    return permissions

def get_dangerous_permissions(apk_path):
    dangerous = {
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS"
    }
    all_permissions = extract_permissions(apk_path)
    flagged = [p for p in all_permissions if p in dangerous]
    return flagged

def get_exported_components(apk_path):
    a = APK(apk_path)
    components = {
        "Activities": [],
        "Services": [],
        "Receivers": [],
        "Providers": []
    }

    for activity in a.get_activities():
        if a.get_element('activity', 'android:exported', name=activity) == "true":
            components["Activities"].append(activity)

    for service in a.get_services():
        if a.get_element('service', 'android:exported', name=service) == "true":
            components["Services"].append(service)

    for receiver in a.get_receivers():
        if a.get_element('receiver', 'android:exported', name=receiver) == "true":
            components["Receivers"].append(receiver)

    for provider in a.get_providers():
        if a.get_element('provider', 'android:exported', name=provider) == "true":
            components["Providers"].append(provider)

    return components

def is_app_debuggable(apk_path):
    a = APK(apk_path)
    return a.is_debuggable()


# GUI Setup
root = tk.Tk()
root.title("CyberX APK Analyzer")
root.geometry("800x600")
root.resizable(False, False)

apk_path = tk.StringVar()

# --- Load background image ---
bg_image = Image.open("assets/cyberpunk.jpg")
bg_photo = ImageTk.PhotoImage(bg_image)

canvas = tk.Canvas(root, width=800, height=600)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, image=bg_photo, anchor="nw")

# --- Create Widgets ---
title_label = tk.Label(
    root,
    text="🛡️ Nebula APK Analyzer",
    font=("Courier New", 20, "bold"),
    bg="#000",
    fg="#FF3030"  # 🔴 Neon red
)

apk_label = tk.Label(root, text="APK File Path:", font=("Courier New", 12), bg="#000", fg="#33FF33")
apk_entry = tk.Entry(root, textvariable=apk_path, width=60, font=("Courier New", 11), bg="#111", fg="#33FF33", insertbackground="#33FF33")
browse_btn = tk.Button(root, text="Browse", command=browse_apk, bg="#33FF33", fg="#000", font=("Courier New", 11))
analyze_btn = tk.Button(root, text="Analyze APK", command=analyze_apk, bg="#0f0", fg="#000", font=("Courier New", 12, "bold"))
result_box = tk.Text(root, height=12, width=80, font=("Courier New", 10), bg="#000", fg="#33FF33", state="disabled", borderwidth=0)

# --- Place Widgets on Canvas ---
canvas.create_window(400, 50, window=title_label)
canvas.create_window(400, 100, window=apk_label)
canvas.create_window(400, 130, window=apk_entry)
canvas.create_window(400, 170, window=browse_btn)
canvas.create_window(400, 220, window=analyze_btn)
canvas.create_window(400, 370, window=result_box)
# Footer
footer = tk.Label(
    root,
    text="⚙️ Made by Digital Abyss | Stage 1",
    font=("Courier New", 12, "bold"),  # ⬅️ Increased font size & bold
    bg="#000",                         # ⬅️ Matches canvas background
    fg="red"                           # ⬅️ Changed to red
)
canvas.create_window(400, 580, window=footer)


root.mainloop()
