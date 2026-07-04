#!/usr/bin/env python3

import requests
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkfont
import threading
import time
import urllib.parse


def ShortenURL(original_url, timeout=15):
    """
    Shorten the URL using is.gd, fallback to TinyURL, else return the original domain+path.
    Returns domain+path string (e.g., "is.gd/abc123" or "tinyurl.com/xyz").
    """
    
    try:
        encoded = urllib.parse.quote_plus(original_url)
        resp = requests.post(f"https://is.gd/create.php?format=json&url={encoded}", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if "shorturl" in data:
                short_url = data["shorturl"]
                parsed = urlparse(short_url)
                return parsed.netloc + parsed.path
           
    except Exception:
        pass

  
    try:
        encoded = urllib.parse.quote_plus(original_url)
        resp = requests.get(f"https://tinyurl.com/api-create.php?url={encoded}", timeout=timeout)
        if resp.status_code == 200:
            short_url = resp.text.strip()  
            if short_url:
                parsed = urlparse(short_url)
                return parsed.netloc + parsed.path
    except Exception:
        pass


    parsed = urlparse(original_url)
    return parsed.netloc + parsed.path

def ValidateVirusTotalAPIKey(api_key, timeout=10):
    """Validate VirusTotal API key by checking the current user endpoint."""
    try:
        headers = {"x-apikey": api_key}
        resp = requests.get("https://www.virustotal.com/api/v3/users/current", headers=headers, timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False

def CheckVirusTotal(api_key, url, timeout=15, poll_interval=1.2, max_wait=20):
    """
    Submit the URL to VirusTotal and poll for analysis.
    Returns a tuple: (success:boolean, message:str)
    """
    headers = {"x-apikey": api_key}
    try:
        
        resp = requests.post("https://www.virustotal.com/api/v3/urls",
                             headers=headers,
                             data={"url": url},
                             timeout=timeout)
        if resp.status_code not in (200, 201):
            return False, f"Failed to submit URL (status {resp.status_code})"

        data = resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return False, "No analysis id returned."

        
        waited = 0.0
        while waited < max_wait:
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                  headers=headers,
                                  timeout=timeout)
            if report.status_code == 200:
                rep_json = report.json()
                status = rep_json.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    stats = rep_json.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    if malicious > 0 or suspicious > 0:
                        return True, f"⚠️ Flagged: malicious={malicious}, suspicious={suspicious}"
                    else:
                        return True, "✔️ No engines flagged this URL."
    
            time.sleep(poll_interval)
            waited += poll_interval
        return False, "Timed out waiting for analysis results."
    except Exception as e:
        return False, f"Error contacting VirusTotal: {e}"


class MaskURLApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MaskURL Detect  —  Wilecurity")
        self.root.geometry("720x480")
        self.root.minsize(720, 480)
        self.root.configure(background="#ececec")
        self.dark_mode = False

        
        self.title_font = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self.label_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.entry_font = tkfont.Font(family="Segoe UI", size=10)
        self.status_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")

        
        self.style = ttk.Style()
        self._setup_styles()

        
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=14, pady=(12, 6))

        title_label = ttk.Label(top, text="MaskURL Detect", font=self.title_font)
        title_label.pack(side="left")

        self.theme_btn = ttk.Button(top, text="Switch to Dark Mode", width=20, command=self.toggle_theme)
        self.theme_btn.pack(side="right")

        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(6, 14))

        self._build_tab_mask()
        self._build_tab_vt()

        
        self.status_var = tk.StringVar(value="Ready")
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", side="bottom")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, font=self.status_font, anchor="w")
        self.status_label.pack(fill="x", padx=8, pady=6)

        
        self._loading = False
        self._loading_text = ""
        self._loading_job = None

    def _setup_styles(self):
        
        self.style.theme_use("clam")
        self.style.configure("TNotebook", background="#f5f5f5")
        self.style.configure("TNotebook.Tab", padding=[12, 8], font=("Segoe UI", 10, "bold"))
        self.style.configure("TFrame", background="#f5f5f5")
        self.style.configure("TLabel", background="#f5f5f5")
        self.style.configure("TButton", padding=6)
        self.style.configure("Accent.TButton", foreground="#ffffff", background="#1f6feb")
        # Map for hover/pressed looks if supported
        self.style.map("Accent.TButton",
                       foreground=[("active", "#ffffff")],
                       background=[("active", "#1558c9")])

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self._apply_dark_theme()
            self.theme_btn.config(text="Switch to Light Mode")
        else:
            self._apply_light_theme()
            self.theme_btn.config(text="Switch to Dark Mode")

    def _apply_dark_theme(self):
        bg = "#111217"
        panel = "#14161a"
        fg = "#e6eef8"
        accent = "#2ea6ff"
        self.root.configure(bg=bg)
        self.style.configure("TFrame", background=panel)
        self.style.configure("TLabel", background=panel, foreground=fg)
        self.style.configure("TNotebook", background=panel)
        self.style.configure("TEntry", fieldbackground="#1b1d22", foreground=fg)
        self.style.configure("TButton", background="#222428", foreground=fg)
        self.style.configure("Accent.TButton", background=accent, foreground="#0b1220")
        
        self.status_label.configure(background=panel, foreground=fg)

    def _apply_light_theme(self):
        bg = "#f5f5f5"
        panel = "#ffffff"
        fg = "#222222"
        accent = "#1f6feb"
        self.root.configure(bg=bg)
        self.style.configure("TFrame", background=panel)
        self.style.configure("TLabel", background=panel, foreground=fg)
        self.style.configure("TNotebook", background=panel)
        self.style.configure("TEntry", fieldbackground="#ffffff", foreground=fg)
        self.style.configure("TButton", background=panel, foreground=fg)
        self.style.configure("Accent.TButton", background=accent, foreground="#ffffff")
        self.status_label.configure(background=panel, foreground=fg)

    def _build_tab_mask(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Mask URL")

        padd = {"padx": 14, "pady": 8}

        
        ttk.Label(tab, text="Original URL:", font=self.label_font).grid(row=0, column=0, sticky="w", **padd)
        self.entry_original = ttk.Entry(tab, font=self.entry_font, width=72)
        self.entry_original.grid(row=1, column=0, columnspan=3, sticky="w", **padd)

        
        ttk.Label(tab, text="Masking Domain:", font=self.label_font).grid(row=2, column=0, sticky="w", **padd)
        self.entry_domain = ttk.Entry(tab, font=self.entry_font, width=40)
        self.entry_domain.grid(row=3, column=0, sticky="w", **padd)

        
        ttk.Label(tab, text="Keywords (use '-' for spaces):", font=self.label_font).grid(row=2, column=1, sticky="w", **padd)
        self.entry_keywords = ttk.Entry(tab, font=self.entry_font, width=28)
        self.entry_keywords.grid(row=3, column=1, sticky="w", **padd)

        
        btn_frame = ttk.Frame(tab)
        btn_frame.grid(row=4, column=0, columnspan=3, sticky="w", **padd)

        self.generate_btn = ttk.Button(btn_frame, text="Generate Masked URL", style="Accent.TButton", command=self._on_generate_mask)
        self.generate_btn.pack(side="left", padx=(0, 8))

        self.copy_mask_btn = ttk.Button(btn_frame, text="Copy Result", command=self._copy_masked_to_clipboard)
        self.copy_mask_btn.pack(side="left", padx=(0, 8))

        self.clear_mask_btn = ttk.Button(btn_frame, text="Clear", command=self._clear_mask_fields)
        self.clear_mask_btn.pack(side="left")

        
        ttk.Label(tab, text="Masked URL:", font=self.label_font).grid(row=5, column=0, sticky="w", **padd)
        self.result_mask_var = tk.StringVar()
        self.result_entry = ttk.Entry(tab, textvariable=self.result_mask_var, font=self.entry_font, width=72)
        self.result_entry.grid(row=6, column=0, columnspan=3, sticky="w", **padd)

    def _build_tab_vt(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Verify URL Using VirusTotal")

        padd = {"padx": 14, "pady": 8}
        ttk.Label(tab, text="URL to Scan:", font=self.label_font).grid(row=0, column=0, sticky="w", **padd)
        self.entry_scan_url = ttk.Entry(tab, width=72, font=self.entry_font)
        self.entry_scan_url.grid(row=1, column=0, columnspan=3, sticky="w", **padd)

        ttk.Label(tab, text="VirusTotal API Key:", font=self.label_font).grid(row=2, column=0, sticky="w", **padd)
        self.entry_api_key = ttk.Entry(tab, width=72, font=self.entry_font, show="*")
        self.entry_api_key.grid(row=3, column=0, columnspan=3, sticky="w", **padd)

        btn_frame = ttk.Frame(tab)
        btn_frame.grid(row=4, column=0, columnspan=3, sticky="w", **padd)

        self.check_btn = ttk.Button(btn_frame, text="Check URL Reputation", style="Accent.TButton", command=self._on_check_vt)
        self.check_btn.pack(side="left", padx=(0, 8))

        self.copy_vt_btn = ttk.Button(btn_frame, text="Copy Result", command=self._copy_vt_to_clipboard)
        self.copy_vt_btn.pack(side="left", padx=(0, 8))

        self.clear_vt_btn = ttk.Button(btn_frame, text="Clear", command=self._clear_vt_fields)
        self.clear_vt_btn.pack(side="left")

        ttk.Label(tab, text="Scan Result:", font=self.label_font).grid(row=5, column=0, sticky="w", **padd)
        self.vt_result_var = tk.StringVar()
        self.vt_result_label = ttk.Label(tab, textvariable=self.vt_result_var, font=self.entry_font, wraplength=650)
        self.vt_result_label.grid(row=6, column=0, columnspan=3, sticky="w", **padd)


    def _set_status(self, text):
        self.status_var.set(text)

    def _start_loading(self, base_text="Loading"):
        """Start a simple dot-loading animation in status bar."""
        self._loading = True
        self._loading_text = base_text
        if self._loading_job is None:
            self._animate_loading(0)

    def _stop_loading(self, final_text=None):
        self._loading = False
        if self._loading_job:
            self.root.after_cancel(self._loading_job)
            self._loading_job = None
        if final_text is not None:
            self._set_status(final_text)
        else:
            self._set_status("Ready")

    def _animate_loading(self, step):
        if not self._loading:
            return
        dots = "." * ((step % 3) + 1)
        self._set_status(f"{self._loading_text}{dots}")
        self._loading_job = self.root.after(480, lambda: self._animate_loading(step + 1))

    def _on_generate_mask(self):
        
        url = self.entry_original.get().strip()
        domain = self.entry_domain.get().strip()
        keywords = self.entry_keywords.get().strip()

        if not url or not domain or not keywords:
            messagebox.showerror("Error", "All fields are required!")
            return

        
        self.generate_btn.config(state="disabled")
        self.result_mask_var.set("")
        self._start_loading("Shortening URL")

        
        thread = threading.Thread(target=self._generate_mask_thread, args=(url, domain, keywords), daemon=True)
        thread.start()

    def _generate_mask_thread(self, url, domain, keywords):
        try:
            short = ShortenURL(url)
            time.sleep(0.3)  
            if short:
                masked = f"{domain}-{keywords}@{short}"
                
                self.root.after(0, lambda: self.result_mask_var.set(masked))
                self.root.after(0, lambda: self._set_status("Masked URL generated."))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to shorten URL."))
                self.root.after(0, lambda: self._set_status("Error shortening URL."))
        finally:
            
            self.root.after(0, lambda: self.generate_btn.config(state="normal"))
            self.root.after(0, lambda: self._stop_loading())

    def _copy_masked_to_clipboard(self):
        val = self.result_mask_var.get().strip()
        if not val:
            messagebox.showinfo("Info", "No masked URL to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self._set_status("Masked URL copied to clipboard.")

    def _clear_mask_fields(self):
        self.entry_original.delete(0, tk.END)
        self.entry_domain.delete(0, tk.END)
        self.entry_keywords.delete(0, tk.END)
        self.result_mask_var.set("")
        self._set_status("Cleared mask fields.")

    def _on_check_vt(self):
        url = self.entry_scan_url.get().strip()
        api_key = self.entry_api_key.get().strip()
        if not url or not api_key:
            messagebox.showerror("Error", "Both URL and API key are required.")
            return

        
        self.check_btn.config(state="disabled")
        self.vt_result_var.set("")
        self._start_loading("Contacting VirusTotal")

        t = threading.Thread(target=self._check_vt_thread, args=(api_key, url), daemon=True)
        t.start()

    def _check_vt_thread(self, api_key, url):
        try:
            
            self.root.after(0, lambda: self._set_status("Validating API key..."))
            if not ValidateVirusTotalAPIKey(api_key):
                self.root.after(0, lambda: messagebox.showerror("Invalid API Key", "Your VirusTotal API key is invalid."))
                self.root.after(0, lambda: self.vt_result_var.set("Invalid API key."))
                return

            self.root.after(0, lambda: self._set_status("Submitted. Waiting for analysis..."))
            ok, message = CheckVirusTotal(api_key, url)
            
            if ok:
                self.root.after(0, lambda: self.vt_result_var.set(message))
                self.root.after(0, lambda: self._set_status("Scan completed."))
            else:
                self.root.after(0, lambda: self.vt_result_var.set(message))
                self.root.after(0, lambda: self._set_status("Scan failed or timed out."))
        finally:
            self.root.after(0, lambda: self.check_btn.config(state="normal"))
            self.root.after(0, lambda: self._stop_loading())

    def _copy_vt_to_clipboard(self):
        val = self.vt_result_var.get().strip()
        if not val:
            messagebox.showinfo("Info", "No result to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self._set_status("Scan result copied to clipboard.")

    def _clear_vt_fields(self):
        self.entry_scan_url.delete(0, tk.END)
        self.entry_api_key.delete(0, tk.END)
        self.vt_result_var.set("")
        self._set_status("Cleared VirusTotal fields.")


def main():
    root = tk.Tk()
    app = MaskURLApp(root)
    
    app._apply_light_theme()
    root.mainloop()

if __name__ == "__main__":
    main()
