#!/usr/bin/env python3
"""
Nebula APK Analyzer - STAGE 5 (Dynamic Analysis)
- Installs APK to connected Android device/emulator (adb required)
- Starts logcat capture, optional tcpdump capture (device must have tcpdump & be rooted)
- Launches the app and injects Frida instrumentation to log suspicious runtime behavior
- Optionally stimulates UI with adb monkey
- Produces a JSON report and a simple HTML report
- WARNING: Run in an isolated test device/emulator only
"""

import os
import sys
import time
import json
import threading
import subprocess
import tempfile
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Frida library (python binding)
try:
    import frida
except Exception:
    frida = None

# ---------- Configuration ----------
ADB = "adb"  # path to adb binary
FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"  # where you placed frida-server on device
REPORTS_DIR = "stage5_reports"
LOGCAT_FILENAME = "logcat.txt"
FRIDA_LOG_FILENAME = "frida_msgs.txt"
TCPDUMP_FILENAME = "tcpdump.pcap"
DEFAULT_MONKEY_EVENTS = 100  # small default stimulation

# ---------- Helper functions ----------
def run_cmd(cmd, timeout=None, capture_output=True):
    """Run shell command, return (code, stdout, stderr)."""
    try:
        res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE if capture_output else None,
                             stderr=subprocess.PIPE if capture_output else None, timeout=timeout, check=False)
        out = res.stdout.decode("utf-8", errors="ignore") if res.stdout else ""
        err = res.stderr.decode("utf-8", errors="ignore") if res.stderr else ""
        return res.returncode, out, err
    except Exception as e:
        return -1, "", str(e)

def adb(cmd):
    return run_cmd([ADB] + cmd)

def check_adb_device():
    code, out, err = adb(["devices"])
    if code != 0:
        return False, err
    # parse out connected device lines (skip header)
    lines = out.strip().splitlines()
    devices = [l for l in lines[1:] if l.strip() and "device" in l]
    return len(devices) > 0, out if len(devices) > 0 else "No devices found"

# ---------- Frida JS payload ----------
# This script is loaded into the app process and logs suspicious calls and stack traces.
FRIDA_JS = r"""
// Nebula stage5 instrumentation
Java.perform(function () {
    var sendMessage = function (type, info) {
        send({type: type, info: info, ts: Date.now()});
    };

    // Hook Runtime.exec
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.getRuntime.overload().implementation = function() {
            sendMessage('runtime_getRuntime', this.toString());
            return this.getRuntime();
        };
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            sendMessage('runtime_exec', {cmd: cmd + ''});
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
            sendMessage('runtime_exec_array', {cmds: JSON.stringify(cmds)});
            return this.exec(cmds);
        };
    } catch (e) {}

    // Hook System.loadLibrary / load
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.overload('java.lang.String').implementation = function(lib) {
            sendMessage('load_library', {lib: lib + ''});
            return this.loadLibrary(lib);
        };
        System.load.overload('java.lang.String').implementation = function(path) {
            sendMessage('system_load', {path: path + ''});
            return this.load(path);
        };
    } catch (e) {}

    // Hook ClassLoader.loadClass
    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
            sendMessage('load_class', {class: name + ''});
            return this.loadClass(name);
        };
    } catch (e) {}

    // Hook common webview / network entrypoints
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            sendMessage('webview_loadurl', {url: url + ''});
            return this.loadUrl(url);
        };
    } catch (e) {}

    try {
        var HttpUrlConn = Java.use('java.net.HttpURLConnection');
        HttpUrlConn.getInputStream.implementation = function() {
            try {
                var url = this.getURL().toString();
                sendMessage('http_connect', {url: url});
            } catch (e) {}
            return this.getInputStream();
        };
    } catch (e) {}

    // okhttp3 hook common classes
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        // request hook via interceptors is complex; hook RealCall.execute
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            try {
                var req = this.request();
                if (req) {
                    var url = req.url().toString();
                    sendMessage('okhttp_request', {url: url});
                }
            } catch (e) {}
            return this.execute();
        };
    } catch (e) {}

    // Hook native methods via java.lang.Runtime native (best-effort)
    // Generic catch-all: intercept calls to native library load via System.mapLibraryName
    try {
        var SystemClass = Java.use('java.lang.System');
        // already hooked loadLibrary above
    } catch (e) {}

    // report environment info
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var pkg = ActivityThread.currentPackageName ? ActivityThread.currentPackageName.value : "unknown";
        sendMessage('env', {package: pkg});
    } catch (e) {}
});
"""

# ---------- Core dynamic analysis logic ----------
class DynamicAnalyzer:
    def __init__(self, gui):
        self.gui = gui
        self.proc_logcat = None
        self.proc_tcpdump = None
        self.frida_session = None
        self.frida_script = None
        self.stop_requested = False
        self.tempdir = Path(tempfile.mkdtemp(prefix="nebula_stage5_"))
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def install_apk(self, apk_path):
        self.gui.log(f"[+] Installing APK: {apk_path}")
        # adb install -r
        code, out, err = adb(["install", "-r", apk_path])
        if code != 0:
            self.gui.log(f"[!] adb install failed: {err}\n{out}")
            return False, err
        self.gui.log("[+] Installed.")
        return True, out

    def uninstall_package(self, pkg):
        self.gui.log(f"[*] Uninstalling package {pkg} (if exists)")
        adb(["uninstall", pkg])

    def start_logcat(self, out_path):
        self.gui.log("[*] Starting logcat capture...")
        # use adb logcat -v time
        f = open(out_path, "w", encoding="utf-8", errors="ignore")
        self.proc_logcat = subprocess.Popen([ADB, "logcat", "-v", "time"], stdout=f, stderr=subprocess.PIPE)
        self.gui.log(f"[+] Logcat -> {out_path}")

    def stop_logcat(self):
        if self.proc_logcat and self.proc_logcat.poll() is None:
            self.proc_logcat.terminate()
            try:
                self.proc_logcat.wait(timeout=3)
            except Exception:
                self.proc_logcat.kill()
        self.proc_logcat = None

    def start_tcpdump_on_device(self, out_remote="/sdcard/nebula_tcpdump.pcap"):
        # This requires tcpdump on device and/or root. We'll run it in background and pull file later.
        self.gui.log("[*] Attempting to start tcpdump on device (requires tcpdump & root).")
        # try to start tcpdump with adb shell su -c
        cmd = [ADB, "shell", "su", "-c", f"tcpdump -p -s 0 -w {out_remote} >/dev/null 2>&1 &"]
        code, out, err = run_cmd(cmd)
        if code == 0:
            self.gui.log(f"[+] Started tcpdump on device, saving to {out_remote}")
            return True, out_remote
        else:
            # try without su
            cmd = [ADB, "shell", f"tcpdump -p -s 0 -w {out_remote} >/dev/null 2>&1 &"]
            code, out, err = run_cmd(cmd)
            if code == 0:
                self.gui.log(f"[+] tcpdump started (no su). output: {out_remote}")
                return True, out_remote
            else:
                self.gui.log("[!] Failed to start tcpdump on device. Device may not have tcpdump or require root.")
                return False, None

    def pull_tcpdump(self, remote_path, local_path):
        code, out, err = adb(["pull", remote_path, local_path])
        if code != 0:
            self.gui.log(f"[!] Failed to pull tcpdump: {err}")
            return False
        self.gui.log(f"[+] Pulled tcpdump to {local_path}")
        return True

    def stop_tcpdump_on_device(self):
        # attempt to kill tcpdump
        adb(["shell", "pkill", "tcpdump"])
        self.gui.log("[*] Stopped tcpdump on device (pkill tcpdump).")

    def launch_app(self, pkg_name, activity=None):
        self.gui.log(f"[*] Launching app {pkg_name}/{activity or ''}")
        comp = f"{pkg_name}/{activity}" if activity else pkg_name
        adb(["shell", "am", "start", "-n", comp])
        time.sleep(1)

    def run_monkey(self, pkg_name, events=DEFAULT_MONKEY_EVENTS):
        self.gui.log(f"[*] Running adb monkey for {events} events")
        adb(["shell", "monkey", "-p", pkg_name, "-s", "0", str(events)])

    def attach_frida_and_inject(self, pkg_name, on_message):
        if frida is None:
            self.gui.log("[!] frida python not installed; cannot attach.")
            return False
        # wait for process to appear
        self.gui.log("[*] Waiting for app process to appear (frida attach)...")
        device = frida.get_usb_device(timeout=5)
        # try spawn or attach
        try:
            pid = None
            processes = device.enumerate_processes()
            for p in processes:
                if p.name == pkg_name:
                    pid = p.pid
                    break
            if pid is None:
                # try to spawn & resume
                self.gui.log("[*] App process not found: attempting to spawn")
                pid = device.spawn([pkg_name])
                self.gui.log(f"[*] Spawned pid {pid}, resuming...")
                device.resume(pid)
                time.sleep(1)
            session = device.attach(pid)
            self.frida_session = session
            self.gui.log("[+] Attached to process. Creating script...")
            script = session.create_script(FRIDA_JS)
            script.on("message", on_message)
            script.load()
            self.frida_script = script
            self.gui.log("[+] Frida script loaded.")
            return True
        except Exception as e:
            self.gui.log(f"[!] Frida attach failed: {e}")
            return False

    def stop_frida(self):
        try:
            if self.frida_script:
                self.frida_script.unload()
            if self.frida_session:
                self.frida_session.detach()
        except Exception:
            pass
        self.frida_script = None
        self.frida_session = None

    def generate_report(self, apk_path, pkg_name, results):
        now = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        base = Path(REPORTS_DIR) / f"report_{pkg_name}_{now}"
        base.mkdir(parents=True, exist_ok=True)
        # save JSON
        report_json = base / "report.json"
        with open(report_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        # make simple html
        report_html = base / "report.html"
        with open(report_html, "w", encoding="utf-8") as fh:
            fh.write("<html><head><meta charset='utf-8'><title>Nebula Stage5 Report</title></head><body style='background:#000;color:#cfc;font-family:monospace'>")
            fh.write(f"<h2>Nebula Stage5 Report - {pkg_name} - {now}</h2>")
            fh.write("<pre style='color:#9f9'>")
            fh.write(json.dumps(results, indent=2))
            fh.write("</pre></body></html>")
        self.gui.log(f"[+] Report written: {report_json} and {report_html}")
        return str(report_json), str(report_html)

# ---------- GUI ----------
class Stage5GUI:
    def __init__(self, master):
        self.master = master
        master.title("NEBULA APK ANALYZER - STAGE 5 (Dynamic)")
        master.geometry("980x760")
        master.configure(bg="black")

        self.analyzer = DynamicAnalyzer(self)
        self.apk_path = None
        self.pkg_name = None
        self.activity = None
        self.tcpdump_remote = None

        self.header = tk.Label(master, text="NEBULA APK ANALYZER - STAGE 5", font=("Consolas", 18, "bold"), fg="#39ff14", bg="black")
        self.header.pack(pady=(8,4))
        self.sub = tk.Label(master, text="Dynamic analysis using Frida • logcat • tcpdump (optional) • Safe lab only", font=("Consolas", 10), fg="#00ffff", bg="black")
        self.sub.pack(pady=(0,8))

        row = tk.Frame(master, bg="black")
        row.pack(pady=6)
        self.btn_select = tk.Button(row, text="Select APK", command=self.select_apk, bg="#39ff14", fg="black", font=("Consolas", 12, "bold"), relief=tk.FLAT)
        self.btn_select.pack(side=tk.LEFT, padx=6)
        self.btn_check_device = tk.Button(row, text="Check Device", command=self.check_device, bg="#222222", fg="#39ff14", font=("Consolas", 11), relief=tk.FLAT)
        self.btn_check_device.pack(side=tk.LEFT, padx=6)
        self.btn_install = tk.Button(row, text="Install APK", command=self.install_selected, bg="#222222", fg="#39ff14", font=("Consolas", 11), relief=tk.FLAT)
        self.btn_install.pack(side=tk.LEFT, padx=6)
        self.btn_start = tk.Button(row, text="Start Analysis", command=self.start_analysis_thread, bg="#00aa00", fg="black", font=("Consolas", 12, "bold"), relief=tk.FLAT)
        self.btn_start.pack(side=tk.LEFT, padx=6)
        self.btn_stop = tk.Button(row, text="Stop & Generate Report", command=self.stop_and_generate, bg="#ff3333", fg="black", font=("Consolas", 12, "bold"), relief=tk.FLAT)
        self.btn_stop.pack(side=tk.LEFT, padx=6)

        # options
        optrow = tk.Frame(master, bg="black")
        optrow.pack(pady=4)
        tk.Label(optrow, text="Monkey events:", font=("Consolas", 10), fg="#39ff14", bg="black").pack(side=tk.LEFT, padx=(6,0))
        self.monkey_entry = tk.Entry(optrow, width=6)
        self.monkey_entry.insert(0, "100")
        self.monkey_entry.pack(side=tk.LEFT, padx=(2,10))
        self.tcpdump_var = tk.IntVar(value=0)
        self.cb_tcpdump = tk.Checkbutton(optrow, text="Enable tcpdump (requires tcpdump+root on device)", variable=self.tcpdump_var, fg="#39ff14", bg="black", selectcolor="#0f0f0f")
        self.cb_tcpdump.pack(side=tk.LEFT, padx=6)

        # result area
        self.result = scrolledtext.ScrolledText(master, wrap=tk.WORD, font=("Courier", 11), bg="black", fg="#39ff14", insertbackground="#39ff14")
        self.result.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        self._tag_setup()

        # frida message buffer
        self.frida_messages = []

    def _tag_setup(self):
        self.result.tag_config("danger", foreground="red", font=("Courier", 11, "bold"))
        self.result.tag_config("section", foreground="#00ffff", font=("Courier", 12, "bold"))
        self.result.tag_config("sub", foreground="#ffcc00", font=("Courier", 11, "bold"))
        self.result.tag_config("normal", foreground="#39ff14")

    def log(self, message, tag="normal"):
        ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
        self.result.insert(tk.END, f"[{ts}] {message}\n", tag)
        self.result.see(tk.END)

    def select_apk(self):
        p = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if not p:
            return
        self.apk_path = p
        # try to get package name via aapt (androguard fallback)
        try:
            from androguard.core.apk import APK as AGAPK
            a = AGAPK(p)
            self.pkg_name = a.get_package()
            self.activity = a.get_main_activity()
            self.log(f"[+] Selected APK: {p}", "section")
            self.log(f"    Package: {self.pkg_name}", "normal")
            self.log(f"    Main activity: {self.activity}", "normal")
        except Exception as e:
            self.log(f"[!] Failed to parse APK manifest: {e}", "danger")

    def check_device(self):
        ok, info = check_adb_device()
        if ok:
            self.log("[+] ADB device found.", "section")
            self.log(info, "normal")
        else:
            self.log("[!] No ADB device found: " + str(info), "danger")

    def install_selected(self):
        if not self.apk_path:
            messagebox.showwarning("No APK", "Select an APK first.")
            return
        ok, msg = self.analyzer.install_apk(self.apk_path)
        if ok:
            self.log("[+] APK installed.", "normal")
        else:
            self.log("[!] Install failed: " + str(msg), "danger")

    def start_analysis_thread(self):
        t = threading.Thread(target=self.start_analysis)
        t.daemon = True
        t.start()

    def start_analysis(self):
        if not self.apk_path or not self.pkg_name:
            self.log("[!] Select APK and ensure package parsed before starting", "danger")
            return
        # check device
        ok, info = check_adb_device()
        if not ok:
            self.log("[!] No device/emulator connected. Connect one and enable USB debugging.", "danger")
            return
        # prepare capture files
        report_id = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_dir = self.analyzer.tempdir / f"run_{report_id}"
        os.makedirs(out_dir, exist_ok=True)
        logcat_path = str(out_dir / LOGCAT_FILENAME)
        frida_path = str(out_dir / FRIDA_LOG_FILENAME)
        tcpdump_local = str(out_dir / TCPDUMP_FILENAME)

        # start logcat
        self.analyzer.start_logcat(logcat_path)

        # optionally start tcpdump on device
        tcpdump_enabled = bool(self.tcpdump_var.get())
        tcp_remote_path = None
        if tcpdump_enabled:
            ok_tcp, remote = self.analyzer.start_tcpdump_on_device()
            if ok_tcp:
                tcp_remote_path = remote
                self.tcpdump_remote = remote
            else:
                self.log("[!] tcpdump not started. Continuing without network capture.", "danger")
                tcpdump_enabled = False

        # launch app
        self.analyzer.launch_app(self.pkg_name, self.activity)

        # attach frida and inject
        def on_frida_message(msg, data):
            try:
                if msg.get("type") == "send":
                    payload = msg.get("payload", {})
                    ts = datetime.datetime.utcnow().isoformat()
                    entry = {"ts": ts, "payload": payload}
                    self.frida_messages.append(entry)
                    self.log(f"FRIDA: {payload}", "sub")
                else:
                    self.log(f"FRIDA message: {msg}", "sub")
            except Exception as e:
                self.log(f"[!] frida msg handling error: {e}", "danger")

        attached = self.analyzer.attach_frida_and_inject(self.pkg_name, on_frida_message)
        if not attached:
            self.log("[!] Frida attach failed. Ensure frida-server is running on device and versions match.", "danger")

        # run UI stimulation (monkey)
        try:
            events = int(self.monkey_entry.get())
        except Exception:
            events = DEFAULT_MONKEY_EVENTS
        self.log(f"[*] Stimulating UI with monkey ({events} events)...", "section")
        self.analyzer.run_monkey(self.pkg_name, events=events)

        # run for some seconds to collect data (user may press Stop)
        self.log("[*] Collecting runtime data. Press 'Stop & Generate Report' when done.", "normal")

    def stop_and_generate(self):
        # stop capture processes and pull tcpdump if any
        self.log("[*] Stopping captures and collecting evidence...", "section")
        self.analyzer.stop_frida()
        self.analyzer.stop_logcat()
        if self.tcpdump_remote:
            local_pcap = str(self.analyzer.tempdir / "pulled_tcpdump.pcap")
            ok = self.analyzer.pull_tcpdump(self.tcpdump_remote, local_pcap)
            if ok:
                self.log(f"[+] Network pcap saved at {local_pcap}", "normal")
            self.analyzer.stop_tcpdump_on_device()

        # prepare results aggregation
        # read logcat
        results = {
            "apk_path": self.apk_path,
            "package": self.pkg_name,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "frida_messages": self.frida_messages,
            "logcat_tail": None,
            "tcpdump_pulled": None
        }
        # read last portion of logcat
        try:
            lg = (self.analyzer.tempdir / "run_" + datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") / LOGCAT_FILENAME)
            # logcat file may be in many run_ dirs; take the newest
            run_dirs = sorted([d for d in (self.analyzer.tempdir).glob("run_*")], key=os.path.getmtime)
            if run_dirs:
                latest = run_dirs[-1]
                lf = latest / LOGCAT_FILENAME
                if lf.exists():
                    with open(lf, "r", encoding="utf-8", errors="ignore") as fh:
                        results["logcat_tail"] = "".join(fh.readlines()[-400:])
        except Exception as e:
            self.log(f"[!] Could not read logcat file: {e}", "danger")

        # tcpdump file saved earlier as pulled_tcpdump.pcap
        pcap_local = self.analyzer.tempdir / "pulled_tcpdump.pcap"
        if pcap_local.exists():
            results["tcpdump_pulled"] = str(pcap_local)

        # write report
        report_json, report_html = self.analyzer.generate_report(self.apk_path, self.pkg_name, results)
        self.log(f"[+] Report ready: {report_json}", "section")
        messagebox.showinfo("Report Ready", f"Report generated:\n{report_json}\n{report_html}")

# ---------- Run ----------
def main():
    root = tk.Tk()
    app = Stage5GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
