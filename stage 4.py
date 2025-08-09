#!/usr/bin/env python3
"""
Nebula APK Analyzer - Stage 4
 - YARA scan (offline) on extracted APK files
 - Heuristic static analysis (offline)
 - Optional VirusTotal lookup (online) using VT v3 API (user-provided API key)
 - Tkinter neon UI consistent with previous stages
"""

import os
import re
import sys
import json
import shutil
import tempfile
import hashlib
import zipfile
import threading
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import scrolledtext

# Try imports that are optional
try:
    from androguard.core.apk import APK
except Exception as e:
    print("Androguard is required. Install with: pip install androguard")
    raise

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

# ---------------- Config ----------------
DEFAULT_RULES_FOLDER = "rules"  # default place to store yara rules
VT_API_KEY = None  # set by user in UI
TEMP_DIR_PREFIX = "nebula_stage4_"

# Heuristic patterns
HEURISTIC_PATTERNS = {
    "suspicious_apis": [
        r"Runtime\.getRuntime\(\)\.exec",
        r"Runtime\.exec\(",
        r"java/lang/Runtime->exec",
        r"DexClassLoader",
        r"PathClassLoader",
        r"System\.loadLibrary",
        r"System\.load\(",
        r"getRuntime\(",
        r"loadLibrary\(",
    ],
    "root_strings": [r"\bsu\b", r"magisk", r"superuser", r"busybox", r"xposed"],
    "native_libs": [r"\.so\b"],
    "suspicious_filenames": [r"crypt", r"obf", r"packed", r"encrypt", r"payload", r"shell"],
    "base64_blob": [r"([A-Za-z0-9+/]{100,}={0,2})"],  # long base64-like blobs
    "ip_regex": [r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"],
}

# ---------------- Utilities ----------------
def compute_hashes(file_path):
    m_md5 = hashlib.md5()
    m_sha1 = hashlib.sha1()
    m_sha256 = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            m_md5.update(chunk)
            m_sha1.update(chunk)
            m_sha256.update(chunk)
    return {"md5": m_md5.hexdigest(), "sha1": m_sha1.hexdigest(), "sha256": m_sha256.hexdigest()}

def extract_apk_to_temp(apk_path):
    """
    Extracts APK into a temporary directory (zip extraction). Returns temp_dir path.
    Uses zipfile (APK is a zip).
    """
    temp_dir = tempfile.mkdtemp(prefix=TEMP_DIR_PREFIX)
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            z.extractall(temp_dir)
    except Exception as e:
        # fallback: use androguard APK to list files and write them
        a = APK(apk_path)
        for name in a.get_files():
            data = a.get_file(name)
            if data is None:
                continue
            out_path = os.path.join(temp_dir, name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as fh:
                fh.write(data)
    return temp_dir

def load_yara_rules_from_folder(folder_path):
    """
    Loads all .yar/.yara files in folder_path into a compiled YARA ruleset.
    Returns compiled rules object or raises.
    """
    if not YARA_AVAILABLE:
        raise RuntimeError("yara-python is not available on this system.")
    rules_files = {}
    for fname in os.listdir(folder_path):
        if fname.lower().endswith((".yar", ".yara")):
            full = os.path.join(folder_path, fname)
            # yara.compile(filepaths=...) expects a dict name->path
            rules_files[f"r_{len(rules_files)+1}"] = full
    if not rules_files:
        raise FileNotFoundError("No .yar/.yara files found in the selected folder.")
    # compile combined
    return yara.compile(filepaths=rules_files)

def run_yara_scan(rules, target_folder):
    """
    Run YARA rules over files in target_folder. Returns list of tuples (match_rule, filepath, meta(optional)).
    """
    matches = []
    for root, dirs, files in os.walk(target_folder):
        for f in files:
            path = os.path.join(root, f)
            try:
                # use rules.match to avoid loading file entirely into memory for large files
                rs = rules.match(path)
                if rs:
                    for r in rs:
                        matches.append((r.rule, path, getattr(r, "meta", None)))
            except Exception:
                # fallback: read bytes and scan
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                    rs = rules.match(data=data)
                    for r in rs:
                        matches.append((r.rule, path, getattr(r, "meta", None)))
                except Exception:
                    continue
    return matches

def run_heuristics_scan(extracted_dir):
    """
    Run heuristic scans over extracted directory. Return dict with lists of findings.
    """
    findings = {
        "suspicious_apis": [],
        "root_keywords": [],
        "native_libs": [],
        "suspicious_files": [],
        "base64_blobs": [],
        "hardcoded_ips": [],
    }
    # compile combined regexes
    api_regex = re.compile("|".join(HEURISTIC_PATTERNS["suspicious_apis"]), re.IGNORECASE)
    root_regex = re.compile("|".join(HEURISTIC_PATTERNS["root_strings"]), re.IGNORECASE)
    so_regex = re.compile(r"\.so\b", re.IGNORECASE)
    base64_regex = re.compile(HEURISTIC_PATTERNS["base64_blob"][0])
    ip_regex = re.compile(HEURISTIC_PATTERNS["ip_regex"][0])

    for root, dirs, files in os.walk(extracted_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            lower = fname.lower()
            try:
                with open(fpath, "rb") as fh:
                    raw = fh.read()
                # attempt decode
                try:
                    text = raw.decode("utf-8", errors="ignore")
                except Exception:
                    text = raw.decode("latin-1", errors="ignore")
            except Exception:
                continue

            # check suspicious APIs
            if api_regex.search(text):
                findings["suspicious_apis"].append((fname, fpath))
            # check root keywords
            if root_regex.search(text):
                findings["root_keywords"].append((fname, fpath))
            # check native libs by filename
            if so_regex.search(lower):
                findings["native_libs"].append((fname, fpath))
            # suspicious filenames
            for s in HEURISTIC_PATTERNS["suspicious_filenames"]:
                if s in lower:
                    findings["suspicious_files"].append((fname, fpath))
                    break
            # base64 blobs
            if base64_regex.search(text):
                findings["base64_blobs"].append((fname, fpath))
            # ip addresses
            for ip in set(ip_regex.findall(text)):
                # filter private ranges: skip 10/172.16-31/192.168/127
                if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31):
                    continue
                findings["hardcoded_ips"].append((ip, fname, fpath))
    return findings

def vt_lookup_sha256(sha256, api_key):
    """
    Query VirusTotal v3 for file report by sha256.
    Returns dict or raises.
    """
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests is not installed.")
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code == 200:
        return r.json()
    else:
        # return dict with code and text for UI to show reason
        return {"error": True, "status_code": r.status_code, "text": r.text}

# ---------------- UI & Glue ----------------
class Stage4App:
    def __init__(self, root):
        self.root = root
        self.root.title("NEBULA APK ANALYZER - STAGE 4")
        self.root.geometry("980x760")
        self.root.configure(bg="black")
        self.yara_rules_path = None
        self.vt_api_key = None

        header = tk.Label(root, text="NEBULA APK ANALYZER - STAGE 4",
                          font=("Consolas", 18, "bold"), fg="#39ff14", bg="black")
        header.pack(pady=(10,4))
        sub = tk.Label(root, text="YARA rules • Heuristic checks • Optional VirusTotal lookup",
                       font=("Consolas", 10), fg="#00ffff", bg="black")
        sub.pack(pady=(0,8))

        # button row
        row = tk.Frame(root, bg="black")
        row.pack(pady=8)
        self.btn_select = tk.Button(row, text="Select APK", command=self.select_and_start, bg="#39ff14", fg="black", font=("Consolas", 12, "bold"), relief=tk.FLAT)
        self.btn_select.pack(side=tk.LEFT, padx=6)
        self.btn_select_rules = tk.Button(row, text="Select YARA Rules Folder", command=self.select_rules_folder, bg="#222222", fg="#39ff14", font=("Consolas", 11), relief=tk.FLAT)
        self.btn_select_rules.pack(side=tk.LEFT, padx=6)
        self.btn_set_vt = tk.Button(row, text="Set VirusTotal API Key", command=self.set_vt_key, bg="#222222", fg="#39ff14", font=("Consolas", 11), relief=tk.FLAT)
        self.btn_set_vt.pack(side=tk.LEFT, padx=6)
        self.btn_run = tk.Button(row, text="Run Advanced Scan", command=self.run_advanced_scan_threaded, bg="#00aa00", fg="black", font=("Consolas", 12, "bold"), relief=tk.FLAT)
        self.btn_run.pack(side=tk.LEFT, padx=6)

        # results area
        self.result = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 11), bg="black", fg="#39ff14", insertbackground="#39ff14")
        self.result.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        self._tag_setup()

    def _tag_setup(self):
        self.result.tag_config("danger", foreground="red", font=("Courier", 11, "bold"))
        self.result.tag_config("section", foreground="#00ffff", font=("Courier", 12, "bold"))
        self.result.tag_config("sub", foreground="#ffcc00", font=("Courier", 11, "bold"))
        self.result.tag_config("normal", foreground="#39ff14")

    def select_rules_folder(self):
        path = filedialog.askdirectory(initialdir=".", title="Select folder with .yara/.yar files")
        if path:
            self.yara_rules_path = path
            self.result.insert(tk.END, f"[+] YARA rules folder set: {path}\n", "normal")

    def set_vt_key(self):
        def save_key():
            key = entry.get().strip()
            self.vt_api_key = key if key else None
            top.destroy()
            self.result.insert(tk.END, "[+] VirusTotal API key saved.\n" if key else "[+] VirusTotal API key cleared.\n", "normal")

        top = tk.Toplevel(self.root)
        top.title("Set VirusTotal API Key")
        label = tk.Label(top, text="Paste VirusTotal API Key (v3):")
        label.pack(padx=8, pady=6)
        entry = tk.Entry(top, width=80, show="*")
        entry.pack(padx=8, pady=6)
        btn = tk.Button(top, text="Save", command=save_key)
        btn.pack(pady=6)

    def select_and_start(self):
        path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if not path:
            return
        self.apk_path = path
        self.result.delete("1.0", tk.END)
        self.result.insert(tk.END, f"[+] APK File: {path}\n\n", "normal")
        # compute hashes
        try:
            hashes = compute_hashes(path)
            self.result.insert(tk.END, f"[*] MD5:    {hashes['md5']}\n", "normal")
            self.result.insert(tk.END, f"[*] SHA1:   {hashes['sha1']}\n", "normal")
            self.result.insert(tk.END, f"[*] SHA256: {hashes['sha256']}\n\n", "normal")
        except Exception as e:
            self.result.insert(tk.END, f"[!] Error computing hashes: {e}\n", "danger")

    def run_advanced_scan_threaded(self):
        # run in a separate thread to avoid freezing UI
        t = threading.Thread(target=self.run_advanced_scan)
        t.daemon = True
        t.start()

    def run_advanced_scan(self):
        if not hasattr(self, "apk_path") or not self.apk_path:
            messagebox.showwarning("No APK", "Please select an APK first.")
            return

        apk_path = self.apk_path
        # extract
        self.result.insert(tk.END, "[*] Extracting APK...\n", "section")
        extracted = None
        try:
            extracted = extract_apk_to_temp(apk_path)
            self.result.insert(tk.END, f"   Extracted to: {extracted}\n", "normal")
        except Exception as e:
            self.result.insert(tk.END, f"   [!] Extraction failed: {e}\n", "danger")
            return

        # 1) YARA scan (if available and rules provided)
        yara_matches = []
        if YARA_AVAILABLE and (self.yara_rules_path or os.path.exists(DEFAULT_RULES_FOLDER)):
            rules_folder = self.yara_rules_path or DEFAULT_RULES_FOLDER
            try:
                self.result.insert(tk.END, "\n[*] YARA Scan:\n", "section")
                rules = load_yara_rules_from_folder(rules_folder)
                self.result.insert(tk.END, f"   Using rules from: {rules_folder}\n", "normal")
                yara_matches = run_yara_scan(rules, extracted)
                if not yara_matches:
                    self.result.insert(tk.END, "   ✅ No YARA matches.\n", "normal")
                else:
                    for rname, path, meta in yara_matches:
                        self.result.insert(tk.END, f"   ⚠ Rule: {rname} matched in {path}\n", "danger")
            except Exception as e:
                self.result.insert(tk.END, f"   [!] YARA error: {e}\n", "danger")
        else:
            if not YARA_AVAILABLE:
                self.result.insert(tk.END, "\n[*] YARA not available: install 'yara-python' to enable YARA scans.\n", "danger")
            else:
                self.result.insert(tk.END, "\n[*] No YARA rules folder found; skipping YARA scan.\n", "normal")

        # 2) Heuristic analysis
        self.result.insert(tk.END, "\n[*] Heuristic Analysis:\n", "section")
        try:
            heur = run_heuristics_scan(extracted)
            # print summary counts and details
            def print_list(name, items, warn_if_empty=True):
                if items:
                    self.result.insert(tk.END, f"   {name}: {len(items)}\n", "sub")
                    for it in items[:200]:
                        # print different shapes depending on tuple lengths
                        if isinstance(it, tuple) and len(it) == 3:
                            self.result.insert(tk.END, f"     - {it[0]} (in {it[2]})\n", "normal")
                        elif isinstance(it, tuple) and len(it) == 2:
                            self.result.insert(tk.END, f"     - {it[0]} (file: {it[1]})\n", "normal")
                        else:
                            self.result.insert(tk.END, f"     - {it}\n", "normal")
                else:
                    if warn_if_empty:
                        self.result.insert(tk.END, f"   {name}: 0\n", "normal")

            print_list("Suspicious API occurrences", heur.get("suspicious_apis", []))
            print_list("Root-related strings", heur.get("root_keywords", []))
            print_list("Native libs (.so)", heur.get("native_libs", []))
            print_list("Suspicious filenames", heur.get("suspicious_files", []))
            print_list("Base64-like blobs", heur.get("base64_blobs", []))
            print_list("Hardcoded external IPs", heur.get("hardcoded_ips", []))
        except Exception as e:
            self.result.insert(tk.END, f"   [!] Heuristic scan error: {e}\n", "danger")

        # 3) VirusTotal lookup (optional)
        if self.vt_api_key:
            self.result.insert(tk.END, "\n[*] VirusTotal Lookup:\n", "section")
            try:
                hashes = compute_hashes(apk_path)
                vt = vt_lookup_sha256(hashes["sha256"], self.vt_api_key)
                if isinstance(vt, dict) and vt.get("error"):
                    self.result.insert(tk.END, f"   [!] VT API error: {vt.get('status_code')} - {vt.get('text')}\n", "danger")
                else:
                    # parse typical fields (guarded)
                    stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    first_seen = vt.get("data", {}).get("attributes", {}).get("first_submission_date")
                    if stats:
                        positives = sum([v for v in stats.values()])  # not exact but gives context
                        total_engines = sum([v for v in stats.values()]) if stats else 0
                        self.result.insert(tk.END, f"   Detection stats: {json.dumps(stats)}\n", "normal")
                    else:
                        self.result.insert(tk.END, "   No detection stats returned by VT.\n", "normal")
                    if first_seen:
                        import datetime
                        try:
                            dt = datetime.datetime.utcfromtimestamp(first_seen)
                            self.result.insert(tk.END, f"   First seen (UTC): {dt.isoformat()}Z\n", "normal")
                        except Exception:
                            self.result.insert(tk.END, f"   First seen (raw): {first_seen}\n", "normal")
            except Exception as e:
                self.result.insert(tk.END, f"   [!] VirusTotal lookup error: {e}\n", "danger")
        else:
            self.result.insert(tk.END, "\n[*] VirusTotal: API key not set — skipping online lookup.\n", "normal")

        # cleanup extracted files
        try:
            shutil.rmtree(extracted)
            self.result.insert(tk.END, f"\n[+] Temporary extraction cleaned up.\n", "normal")
        except Exception:
            pass

# ---------------- Run App ----------------
def main():
    root = tk.Tk()
    app = Stage4App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
