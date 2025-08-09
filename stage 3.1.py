import tkinter as tk
from tkinter import filedialog, scrolledtext
import hashlib
import os
import re
from androguard.core.apk import APK

# -------- CONFIG --------
malicious_db_file = "malicious_hashes.txt"

# Regex for URLs and IPs
url_pattern = re.compile(r"(https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


# -------- FUNCTIONS --------
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def load_malicious_hashes():
    if os.path.exists(malicious_db_file):
        with open(malicious_db_file, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return None


def analyze_stage3():
    file_path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if not file_path:
        return

    result.delete('1.0', tk.END)
    result.insert(tk.END, f"[+] APK File: {file_path}\n\n", "normal")

    # SHA256 signature detection
    sha256 = calculate_sha256(file_path)
    result.insert(tk.END, f"[*] SHA256: {sha256}\n", "section")
    malicious_hashes = load_malicious_hashes()
    if malicious_hashes is None:
        result.insert(tk.END, "   ⚠ Warning: malicious_hashes.txt not found — skipping signature DB check.\n", "danger")
    elif sha256 in malicious_hashes:
        result.insert(tk.END, "   🚨 Malicious APK detected (hash match)!\n", "danger")
    else:
        result.insert(tk.END, "   ✅ No match in malicious DB.\n", "normal")

    # Androguard APK object
    a = APK(file_path)

    # Extract network endpoints & deep links
    urls_found = set()
    ips_found = set()
    deep_links = []

    for f in a.get_files():
        try:
            content = a.get_file(f).decode(errors="ignore")
            urls_found.update(url_pattern.findall(content))
            ips_found.update(ip_pattern.findall(content))

            if "android.intent.action.VIEW" in content and "BROWSABLE" in content:
                deep_links.append(f)
        except:
            pass

    # Filter public IPs
    public_ips = [
        ip for ip in ips_found
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127."))
    ]

    # Output URLs
    result.insert(tk.END, "\n[*] Network Endpoints (Filtered & Unique):\n", "section")
    if urls_found:
        for i, url in enumerate(sorted(urls_found), start=1):
            result.insert(tk.END, f"   {i}. {url}\n", "normal")
    else:
        result.insert(tk.END, "   ⚠ No valid URLs found.\n", "danger")

    # Output IPs
    if public_ips:
        result.insert(tk.END, "\n[*] Public IP Addresses Found:\n", "section")
        for i, ip in enumerate(sorted(public_ips), start=1):
            result.insert(tk.END, f"   {i}. {ip}\n", "normal")
    else:
        result.insert(tk.END, "\n   ⚠ No external IP addresses found.\n", "danger")

    # Output Deep Links
    result.insert(tk.END, "\n[*] Unprotected Deep-Link Analysis:\n", "section")
    if deep_links:
        for link in deep_links:
            result.insert(tk.END, f"   Possible exported deep link in: {link}\n", "exported")
    else:
        result.insert(tk.END, "   ⚠ No exported deep links found.\n", "danger")


# -------- UI SETUP --------
root = tk.Tk()
root.title("Nebula APK Analyzer - Stage 3")
root.geometry("900x700")
root.configure(bg="#0f0f0f")

btn = tk.Button(
    root, text="Select APK", command=analyze_stage3,
    bg="#39ff14", fg="black", font=("Consolas", 14, "bold"),
    activebackground="black", activeforeground="#39ff14"
)
btn.pack(pady=15)

result = scrolledtext.ScrolledText(
    root, wrap=tk.WORD, font=("Courier", 11),
    bg="#0f0f0f", fg="#39ff14", insertbackground="#39ff14"
)
result.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

# Text styling
result.tag_config("danger", foreground="red", font=("Courier", 11, "bold"))
result.tag_config("exported", foreground="#ffcc00")
result.tag_config("section", foreground="#00ffff", font=("Courier", 12, "bold"))
result.tag_config("normal", foreground="#39ff14")

root.mainloop()
