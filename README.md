

# 🚀 **MaskURL – Modern URL Masking & Security Scanner Tool**

MaskURL is a modern Python-based cybersecurity utility developed by **Wilecurity**.
It allows you to **mask URLs** with custom domains + keywords and **verify URL reputation** using the **VirusTotal API**, all through a clean and interactive **GUI application** with togglable **Dark Mode**.

This tool is built for cybersecurity professionals, students, analysts, and hobbyists who need quick URL masking and threat verification in one place.

---

# 🌟 **Features**

### 🔒 **URL Masking**

* Shortens URLs using **is.gd**
* Auto-formats into a masked pattern:
  `domain-keywords@shorturl`
* Creates phishing-style educational examples for security training

### 🛡️ **VirusTotal URL Reputation Scanner**

* Submit URLs directly to VirusTotal
* Checks:

  * ✔ malicious
  * ✔ suspicious
  * ✔ undetected
* Real-time API key validation

### 🎨 **Modern GUI (Tkinter)**

* Two tab layout:

  * **Mask URL**
  * **Verify URL with VirusTotal**
* **Dark Mode toggle**
* **Loading animations**
* Clean, bold typography & spacing
* Smooth modern feel


---

# 🧰 **Installation**

Clone the repository:

```bash
git clone https://github.com/wilecurity/Mask-url.git
cd Mask-url
```

Install Python project dependencies:

```bash
pip install -r requirements.txt
```

---

# 🧩 **Install Tkinter (Required for the GUI)**

## 🐧 **Ubuntu / Debian / Kali / Linux Mint**

```bash
sudo apt update
sudo apt install python3-tk
```

## 🟥 **Fedora / CentOS / RHEL**

```bash
sudo dnf install python3-tkinter
```

## 🍎 **macOS**

If using Python installed via `python.org`, Tkinter is already included.

If using Homebrew Python:

```bash
brew install python-tk
```

## 🪟 **Windows**

Tkinter is already included with Python from **python.org**.
If you get an error:

* Reinstall Python
* Ensure **"tcl/tk and IDLE"** is selected during installation

---

# ▶️ **Running the Application**

```bash
python3 maskurl.py
```

The modern GUI will load instantly.

---

# 🔑 **VirusTotal API Key Setup**

1. Create a VirusTotal account
2. Go to: **User → API Key**
3. Copy your key
4. Paste into the GUI when asked

---

# 📦 **Project Structure**

```
Mask-url/
│── maskurl.py
│── README.md
│── requirements.txt
│── screenshots/
│── LICENSE (optional)
```

---

# ⚙️ **Under the Hood (Technical Overview)**

* GUI built using **Tkinter** + **ttk themes**
* REST API requests via the **requests** module
* URL shortening using **is.gd**
* VirusTotal scanning uses:

  * `/api/v3/urls` (submit)
  * `/api/v3/analyses/{id}` (retrieve results)
* Modern interface elements:

  * Dark mode styles
  * Loading animations
  * Enhanced labels + typography
  * Tabbed notebook interface

---

# ⚖️ **Disclaimer**

This tool is created for **cybersecurity education and research**.
Wilecurity **does NOT endorse misuse** of URL masking for fraud, phishing, or crime.

You are responsible for complying with your country’s laws.

---

# 🤝 **Contributing**

Pull requests are welcome!

You can contribute by:

* Adding new URL masking services
* Improving the GUI
* Adding threat-intelligence APIs (IPinfo, AbuseIPDB, URLScan)
* Creating detailed phishing awareness demos

---

# ⭐ **Support the Project**

If you like the work:

* Star ⭐ the repository
* Share with cybersecurity learners
* Follow Wilecurity on GitHub

---
