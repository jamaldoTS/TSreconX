import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import subprocess
import requests
import os
import datetime
import tempfile
import shutil
import time
import re
from pathlib import Path

class TSReconX:
    def __init__(self, root):
        self.root = root
        self.root.title("TSReconX")
        self.root.geometry("1200x800")
        self.recon_active = False
        self.finding_stats = {"high": 0, "medium": 0, "low": 0, "dorks": 0, "repos": 0, "cicd": 0}
        self.webhook_url = ""
        self.create_widgets()

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.root, text="Target Configuration")
        input_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(input_frame, text="GitHub Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="GitHub Token:").grid(row=0, column=2, padx=5, pady=5)
        self.token_entry = ttk.Entry(input_frame, width=30, show="*")
        self.token_entry.grid(row=0, column=3, padx=5, pady=5)

        self.recon_button = ttk.Button(input_frame, text="Start Recon", command=self.toggle_recon)
        self.recon_button.grid(row=0, column=4, padx=10, pady=5)

        ttk.Button(input_frame, text="Support", command=self.open_support_window).grid(row=0, column=5, padx=5)

        module_frame = ttk.LabelFrame(self.root, text="Modules")
        module_frame.pack(fill="x", padx=10, pady=5)

        self.module_vars = {
            "dork": tk.BooleanVar(value=True),
            "repos": tk.BooleanVar(value=True),
            "userscan": tk.BooleanVar(value=True)
        }

        for mod in self.module_vars:
            ttk.Checkbutton(module_frame, text=mod.capitalize() + " Scan", variable=self.module_vars[mod]).pack(side="left", padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tabs = {}
        for name in ["Dork Scanner", "Repo Scanner", "Git History", "CI/CD Scanner", "User Scanner", "Report"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
            text_area.pack(fill="both", expand=True)
            text_area.config(state='disabled')
            self.tabs[name] = text_area

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(bottom_frame, text="Export Report", command=self.export_report).pack(side="left")

        attribution = ttk.Label(self.root, text="Created by Jamal Mohamed — Turbine Shield Technologies", anchor="center")
        attribution.pack(side="bottom", pady=2)

    def log(self, tab, message):
        def _log():
            now = datetime.datetime.now().strftime("[%H:%M:%S] ")
            widget = self.tabs[tab]
            widget.config(state='normal')
            widget.insert(tk.END, now + message + "\n")
            widget.see(tk.END)
            widget.config(state='disabled')
            self.update_report_tab()
        self.root.after(0, _log)

    def update_report_tab(self):
        report = self.generate_report(final=False)
        widget = self.tabs["Report"]
        widget.config(state='normal')
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, report)
        widget.config(state='disabled')

    def export_report(self):
        content = self.generate_report(final=True)
        file_path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown files", "*.md")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Exported", f"Saved to {file_path}")

    def toggle_recon(self):
        if self.recon_active:
            return
        self.recon_active = True
        self.recon_button.config(text="Recon Running", state="disabled")
        self.target_entry.config(state="disabled")
        self.token_entry.config(state="disabled")

        for tab in self.tabs.values():
            tab.config(state='normal')
            tab.delete("1.0", tk.END)
            tab.config(state='disabled')

        self.finding_stats = {"high": 0, "medium": 0, "low": 0, "dorks": 0, "repos": 0, "cicd": 0}
        self.update_report_tab()

        target = self.target_entry.get().strip()
        token = self.token_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Target required")
            self.reset_recon_ui()
            return

        def task():
            if self.module_vars["dork"].get():
                self.run_dork_scan(target, token)
            if self.module_vars["repos"].get():
                self.run_repo_clone_and_regex(target, token)
            if self.module_vars["userscan"].get():
                self.run_user_scanner(target, token)
            self.reset_recon_ui()

        threading.Thread(target=task).start()

    def reset_recon_ui(self):
        self.recon_button.config(text="Start Recon", state="normal")
        self.target_entry.config(state="normal")
        self.token_entry.config(state="normal")
        self.recon_active = False

    def send_alert(self, message):
        if not self.webhook_url:
            return
        try:
            requests.post(self.webhook_url, json={"content": message})
        except:
            pass

    def run_user_scanner(self, target, token):
        self.log("User Scanner", f"[+] Gathering user profile for {target}")
        headers = {"Authorization": f"token {token}"} if token else {}
        try:
            res = requests.get(f"https://api.github.com/users/{target}", headers=headers)
            data = res.json()
            for field in ["name", "email", "bio", "location", "blog", "company", "created_at", "public_repos", "followers"]:
                self.log("User Scanner", f"{field.capitalize()}: {data.get(field, 'N/A')}")
        except Exception as e:
            self.log("User Scanner", f"[!] Error: {e}")

    def run_dork_scan(self, target, token):
        self.log("Dork Scanner", f"[+] Starting dork scan on {target}")
        dorks = [
            "api_key in:file user:{target}",
            "password in:file user:{target}",
            "client_secret in:file user:{target}",
            "access_token in:file user:{target}",
            "filename:.env user:{target}",
            "filename:.git-credentials user:{target}"
        ]
        dorks = [d.replace("{target}", target) for d in dorks]
        headers = {"Authorization": f"token {token}"} if token else {}
        for dork in dorks:
            self.log("Dork Scanner", f"[*] Searching: {dork}")
            try:
                res = requests.get("https://api.github.com/search/code", params={"q": dork}, headers=headers)
                items = res.json().get("items", [])
                self.finding_stats["dorks"] += 1
                for item in items:
                    msg = f"[!] Dork hit: {item.get('html_url')}"
                    self.log("Dork Scanner", msg)
                    self.finding_stats["medium"] += 1
                    self.send_alert(msg)
            except Exception as e:
                self.log("Dork Scanner", f"[!] Error: {e}")
            time.sleep(1)
        self.log("Dork Scanner", "[+] Dork scan complete.")

    def run_repo_clone_and_regex(self, target, token):
        self.log("Repo Scanner", f"[+] Cloning repos for {target}")
        headers = {"Authorization": f"token {token}"} if token else {}
        try:
            repos = requests.get(f"https://api.github.com/users/{target}/repos", headers=headers).json()
            for repo in repos:
                name = repo.get("name")
                clone_url = repo.get("clone_url")
                self.log("Repo Scanner", f"[*] Cloning: {name}")
                tempdir = tempfile.mkdtemp()
                subprocess.run(["git", "clone", "--depth", "1", clone_url, tempdir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.finding_stats["repos"] += 1
                self.scan_repo_files(tempdir)
                self.run_git_history_scan(tempdir)
                self.run_cicd_scan(tempdir)
                shutil.rmtree(tempdir)
        except Exception as e:
            self.log("Repo Scanner", f"[!] Error: {e}")

    def scan_repo_files(self, path):
        for file in Path(path).rglob("*"):
            if file.is_file():
                try:
                    content = file.read_text(errors="ignore")
                    for line in content.splitlines():
                        if re.search(r'(AKIA|secret|token|key|password)[\s:="\']{0,10}[A-Za-z0-9/+]{8,}', line, re.I):
                            msg = f"[!!] Secret in {file.name}: {line.strip()[:100]}"
                            self.log("Repo Scanner", msg)
                            self.finding_stats["high"] += 1
                            self.send_alert(msg)
                except:
                    pass

    def run_git_history_scan(self, path):
        self.log("Git History", f"[+] Scanning Git history")
        try:
            result = subprocess.run(["git", "log", "-p"], cwd=path, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if re.search(r'(AKIA|SECRET|PRIVATE|TOKEN|PASSWORD)[\s:="\']{0,10}[A-Za-z0-9/+]{8,}', line, re.I):
                    msg = f"[!] Leak in commit: {line.strip()[:100]}"
                    self.log("Git History", msg)
                    self.finding_stats["high"] += 1
                    self.send_alert(msg)
        except Exception as e:
            self.log("Git History", f"[!] Error: {e}")

    def run_cicd_scan(self, path):
        self.log("CI/CD Scanner", f"[+] Scanning CI/CD configs")
        ci_paths = [".github/workflows", ".travis.yml", ".circleci/config.yml", "azure-pipelines.yml", ".gitlab-ci.yml", "bitbucket-pipelines.yml"]
        found_files = 0
        secrets_found = 0
        for ci_path in ci_paths:
            for file in Path(path).rglob(ci_path):
                if file.is_file():
                    found_files += 1
                    self.log("CI/CD Scanner", f"[*] Found: {file}")
                    try:
                        content = file.read_text(errors="ignore")
                        for lineno, line in enumerate(content.splitlines(), 1):
                            if re.search(r'(env:|secrets\.|token|key|password|api[_-]?key)', line, re.I):
                                msg = f"[!] Secret pattern in {file.name} (line {lineno}): {line.strip()[:100]}"
                                self.log("CI/CD Scanner", msg)
                                self.finding_stats["cicd"] += 1
                                secrets_found += 1
                                self.send_alert(msg)
                    except Exception as e:
                        self.log("CI/CD Scanner", f"[!] Error reading {file}: {e}")
        if found_files == 0:
            self.log("CI/CD Scanner", "[*] No CI/CD config files found.")
        elif secrets_found == 0:
            self.log("CI/CD Scanner", "[*] No secrets found in CI/CD files.")
        self.log("CI/CD Scanner", "[+] CI/CD scan complete.")

    def generate_report(self, final=False):
        report = ""
        for name in self.tabs:
            if name != "Report":
                content = self.tabs[name].get("1.0", tk.END).strip()
                if content:
                    report += f"## {name} Results\n\n{content}\n\n"
        report += ("\n---\n**Summary**\n\n"
                   f"❌ High Severity: {self.finding_stats['high']}\n"
                   f"⚠️ Medium Severity: {self.finding_stats['medium']}\n"
                   f"📁 Repos Scanned: {self.finding_stats['repos']}\n"
                   f"🔍 Dork Queries Run: {self.finding_stats['dorks']}\n"
                   f"⚙️ CI/CD Alerts: {self.finding_stats['cicd']}\n")
        return report

    def open_support_window(self):
        win = tk.Toplevel(self.root)
        win.title("Support Contact")
        win.geometry("350x150")
        ttk.Label(win, text="For support, contact:", font=("Arial", 12)).pack(pady=15)
        ttk.Label(win, text="turbineshield@gmail.com", foreground="blue", font=("Arial", 12, "bold")).pack(pady=5)
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = TSReconX(root)
    root.mainloop()
