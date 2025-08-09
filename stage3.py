#!/usr/bin/env python3
"""
Nebula APK Analyzer - Stage 3 (Improved)
- Malware signature detection using malicious_hashes.txt
- Network endpoint detection (filtered & deduped)
- Intent-filter analysis: exported + unprotected VIEW+BROWSABLE deep links
- Androguard 4.x compatible
- Neon hacker-style Tkinter UI (matches Stage 1/2)
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext
from androguard.core.apk import APK
import hashlib
import os
import re
from urllib.parse import urlparse

# Constants
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
HASH_DB_PATH = "malicious_hashes.txt"  # one hash per line; can be md5/sha1/sha256
URL_REGEX = re.compile(r'\b(?:https?://|ftp://|www\.)[^\s"\'<>]{6,256}', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')

# ----------------- Utilities -----------------
def compute_hashes(file_path, block_size=65536):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for b in iter(lambda: fh.read(block_size), b""):
            md5.update(b)
            sha1.update(b)
            sha256.update(b)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def load_malicious_hashes(path=HASH_DB_PATH):
    db = {"md5": set(), "sha1": set(), "sha256": set()}
    if not os.path.exists(path):
        return db, False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip().split("#", 1)[0].strip()  # ignore comments
            if not line:
                continue
            h = line.lower()
            if len(h) == 32:
                db["md5"].add(h)
            elif len(h) == 40:
                db["sha1"].add(h)
            elif len(h) == 64:
                db["sha256"].add(h)
            else:
                # try to be tolerant: classify by hex length if possible
                if all(c in "0123456789abcdef" for c in h):
                    if len(h) <= 32: db["md5"].add(h)
                    elif len(h) <= 40: db["sha1"].add(h)
                    else: db["sha256"].add(h)
    return db, True

def clean_url(raw):
    # remove surrounding characters, duplicates like http://*http:// etc.
    u = raw.strip().strip('.,;\'"()[]{}<>')
    # if starts with 'www.' add scheme
    if u.lower().startswith("www."):
        u = "http://" + u
    # ignore urls that are android schemas or internal
    parsed = urlparse(u)
    host = parsed.netloc.lower()
    if "schemas.android.com" in host:
        return None
    if host.startswith("android") or host.startswith("res."):
        return None
    if parsed.scheme.lower() in ("android-resource", "content", "file", "android"):
        return None
    # reject if only single char host
    if len(host) < 2:
        return None
    return u

def extract_endpoints_from_apk(apk_obj):
    urls = set()
    ips = set()
    for fname in apk_obj.get_files():
        try:
            raw = apk_obj.get_file(fname)
            if not raw:
                continue
            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                text = raw.decode("latin-1", errors="ignore")
            for m in URL_REGEX.findall(text):
                cu = clean_url(m)
                if cu:
                    urls.add(cu)
            for ip in IP_REGEX.findall(text):
                # basic filter: ignore local patterns that are obviously not external like 0.0.0.0
                if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                    # keep optional local entries? we skip by default to focus on external
                    continue
                ips.add(ip)
        except Exception:
            continue
    return sorted(urls), sorted(ips)

# Intent filter analysis: find exported + unprotected VIEW+BROWSABLE components
def analyze_intent_filters_for_unprotected(apk_obj):
    results = []
    try:
        manifest_xml = apk_obj.get_android_manifest_xml()
    except Exception:
        return results
    # helper to check exported boolean (explicit attribute)
    def is_exported(elem, has_intent_filter=False):
        exported_attr = elem.get(ANDROID_NS + "exported")
        if exported_attr is not None:
            return exported_attr.lower() == "true"
        # conservative: if no explicit exported but there is an intent-filter, treat as exported
        return has_intent_filter

    for comp in manifest_xml.iter():
        tag = comp.tag.lower()
        if tag.endswith("activity") or tag.endswith("service") or tag.endswith("receiver"):
            comp_name = comp.get(ANDROID_NS + "name") or comp.get("name") or "UNKNOWN"
            # find intent-filter children (note: sometimes namespace prefixes vary)
            has_view_browsable = False
            data_attrs = []
            for intent in comp.findall("intent-filter"):
                has_view = False
                has_browsable = False
                # iterate children
                for child in intent:
                    ctag = child.tag.lower()
                    if ctag.endswith("action"):
                        name = child.get(ANDROID_NS + "name") or child.get("name") or ""
                        if name.upper().endswith("VIEW"):
                            has_view = True
                    if ctag.endswith("category"):
                        name = child.get(ANDROID_NS + "name") or child.get("name") or ""
                        if name.upper().endswith("BROWSABLE"):
                            has_browsable = True
                    if ctag.endswith("data"):
                        data_attrs.append({
                            "scheme": child.get(ANDROID_NS + "scheme"),
                            "host": child.get(ANDROID_NS + "host"),
                            "path": child.get(ANDROID_NS + "path") or child.get(ANDROID_NS + "pathPrefix") or child.get(ANDROID_NS + "pathPattern")
                        })
                if has_view and has_browsable:
                    has_view_browsable = True
            if has_view_browsable:
                exported_flag = is_exported(comp, has_intent_filter=True)
                permission = comp.get(ANDROID_NS + "permission")
                # unprotected = exported True and no permission required
                if exported_flag and not permission:
                    results.append({
                        "component": comp_name,
                        "tag": comp.tag,
                        "exported": exported_flag,
                        "requires_permission": bool(permission),
                        "data": data_attrs
                    })
    return results

# ---------------- GUI & Main -----------------
def analyze_apk_gui():
    file_path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if not file_path:
        return

    result.delete("1.0", tk.END)
    result.insert(tk.END, f"[+] APK File: {file_path}\n\n", "normal")

    # Hash check
    result.insert(tk.END, "[*] Hashes & Signature Check:\n", "section")
    try:
        hashes = compute_hashes(file_path)
        result.insert(tk.END, f"   MD5:    {hashes['md5']}\n", "normal")
        result.insert(tk.END, f"   SHA1:   {hashes['sha1']}\n", "normal")
        result.insert(tk.END, f"   SHA256: {hashes['sha256']}\n", "normal")

        db, loaded = load_malicious_hashes(HASH_DB_PATH)
        if not loaded:
            result.insert(tk.END, "   ⚠ Warning: malicious_hashes.txt not found — skipping signature DB check.\n", "danger")
        else:
            matched = False
            if hashes["md5"] in db["md5"] or hashes["sha1"] in db["sha1"] or hashes["sha256"] in db["sha256"]:
                result.insert(tk.END, "   ⚠️ MATCH FOUND: APK hash matches known malicious signature!\n", "danger")
                matched = True
            if not matched:
                result.insert(tk.END, "   ✅ No signature match found.\n", "normal")
    except Exception as e:
        result.insert(tk.END, f"   [!] Hashing error: {e}\n", "danger")

    # Network endpoints
    result.insert(tk.END, "\n[*] Network Endpoints (filtered & unique):\n", "section")
    try:
        a = APK(file_path)
        urls, ips = extract_endpoints_from_apk(a)
        if urls:
            result.insert(tk.END, f"   URLs found: {len(urls)}\n", "subsection")
            for u in urls[:200]:  # guard: show up to 200 results
                result.insert(tk.END, f"     {u}\n", "normal")
        else:
            result.insert(tk.END, "   No external URLs found.\n", "normal")
        if ips:
            result.insert(tk.END, f"\n   IPs found: {len(ips)}\n", "subsection")
            for ip in ips[:200]:
                result.insert(tk.END, f"     {ip}\n", "normal")
        else:
            result.insert(tk.END, "\n   No external IP addresses found.\n", "normal")
    except Exception as e:
        result.insert(tk.END, f"   [!] Endpoint extraction error: {e}\n", "danger")

    # Intent-filter deep-link analysis
    result.insert(tk.END, "\n[*] Unprotected Deep-Link Analysis (exported VIEW+BROWSABLE):\n", "section")
    try:
        unprotected = analyze_intent_filters_for_unprotected(a)
        if not unprotected:
            result.insert(tk.END, "   None found — no exported unprotected VIEW+BROWSABLE components detected.\n", "normal")
        else:
            for it in unprotected:
                result.insert(tk.END, f"   Component: {it['component']}\n", "subsection")
                result.insert(tk.END, f"     Exported: {it['exported']}\n", "normal")
                result.insert(tk.END, f"     Requires Permission: {it['requires_permission']}\n", "danger")
                if it["data"]:
                    for d in it["data"]:
                        result.insert(tk.END, f"     Data: scheme={d.get('scheme')} host={d.get('host')} path={d.get('path')}\n", "normal")
                result.insert(tk.END, "\n", "normal")
    except Exception as e:
        result.insert(tk.END, f"   [!] Intent analysis error: {e}\n", "danger")

# ---------------- UI -----------------
root = tk.Tk()
root.title("NEBULA APK ANALYZER - STAGE 3 (Improved)")
root.geometry("940x740")
root.configure(bg="black")

header = tk.Label(root, text="NEBULA APK ANALYZER - STAGE 3", font=("Consolas", 20, "bold"), fg="#39ff14", bg="black")
header.pack(pady=(12,6))
sub = tk.Label(root, text="Malware signatures • Filtered network endpoints • Unprotected deep links", font=("Consolas", 10), fg="#00ffff", bg="black")
sub.pack(pady=(0,8))

frame = tk.Frame(root, bg="black")
frame.pack(pady=6)

analyze_btn = tk.Button(frame, text="Select APK & Analyze", command=analyze_apk_gui,
                        bg="#39ff14", fg="black", font=("Consolas", 13, "bold"),
                        activebackground="black", activeforeground="#39ff14", relief=tk.FLAT)
analyze_btn.pack(side=tk.LEFT, padx=8)

reload_btn = tk.Button(frame, text="Reload Hash DB", command=lambda: result.insert(tk.END, "[+] Reloaded malicious_hashes.txt\n", "normal"),
                       bg="#222222", fg="#39ff14", font=("Consolas", 11), relief=tk.FLAT)
reload_btn.pack(side=tk.LEFT, padx=6)

result = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 11), bg="black", fg="#39ff14", insertbackground="#39ff14")
result.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

result.tag_config("danger", foreground="red", font=("Courier", 11, "bold"))
result.tag_config("section", foreground="#00ffff", font=("Courier", 12, "bold"))
result.tag_config("subsection", foreground="#ffcc00", font=("Courier", 11, "bold"))
result.tag_config("normal", foreground="#39ff14")

root.mainloop()
