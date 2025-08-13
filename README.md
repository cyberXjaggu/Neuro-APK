# 🌌 Nebula APK Analyzer

Nebula APK Analyzer is a Python-based GUI tool for **static analysis of Android APK files**.  
It is designed for **security researchers, developers, and students** to quickly inspect APKs for permissions, exported components, network endpoints, malware signatures, and deep link vulnerabilities — all with a **hacker-style neon UI**.

---

## ✨ Features

### ✅ Stage 1: Basic APK Information Extraction
- APK file name & size
- Package name, version code, and version name
- Minimum & target SDK versions

### ⚠ Stage 2: Security & Component Analysis
- Lists **all permissions**, highlighting **dangerous permissions** in red
- Checks if the app is **debuggable**
- Lists **exported components**:
  - Activities
  - Services
  - Broadcast receivers
  - Content providers

### 🛡 Stage 3: Advanced Threat Analysis
- **Malware signature detection** via SHA256 hash comparison
- **Network endpoint extraction** (URLs & IP addresses)
- **Deep link analysis** to detect unprotected `VIEW+BROWSABLE` intent filters

---

## 📦 Requirements

- **Python** 3.9+
- **Tkinter** (comes with Python on most OS)
- [Androguard](https://github.com/androguard/androguard) `pip install androguard`
- **Other dependencies** (install from `requirements.txt`)

**`requirements.txt`** example:
```
androguard
requests
colorama
```

---

## 🚀 Installation & Usage

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Nebula-APK-Analyzer.git
   cd Nebula-APK-Analyzer
   ```

2. **Create & activate a virtual environment** (optional but recommended)
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux/Mac
   .venv\Scripts\activate      # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the analyzer**
   - **Stage 1**
     ```bash
     python stage1.py
     ```
   - **Stage 2**
     ```bash
     python stage2.py
     ```
   - **Stage 3**
     ```bash
     python stage3.py
     ```

5. **Select an APK file** from the file picker — results will be displayed in the GUI.

---

## 📷 Screenshots

| Stage 1 | Stage 2 | Stage 3 |
|---------|---------|---------|
| ![Stage 1](assets/stage1.png) | ![Stage 2](assets/stage2.png) | ![Stage 3](assets/stage3.png) |

*(Replace with actual screenshots)*

---

## 🔮 Future Plans
- Integrate **VirusTotal API** for real-time malware scanning
- Add **certificate & signing info analysis**
- Generate **PDF reports** of analysis
- Improve **malware signature database**

---

## ⚖ License
This project is licensed under the **MIT License** — feel free to use and modify it.

---

💻 **Author:** [Jagarnath Mali & Thinles Wangchok]  
🔗 **GitHub:** [github.com/cyberXjaggu]  
📅 **Version:** 1.0
