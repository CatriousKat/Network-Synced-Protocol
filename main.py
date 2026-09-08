import json
import subprocess
import os
import shutil
import tkinter as tk
from http.server import HTTPServer, BaseHTTPRequestHandler

def is_admin_command(command):
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return False
    base_cmd = os.path.basename(cmd_parts[0]).lower()
    priv_binaries = ["sudo", "su", "doas", "runas", "pkexec"]
    if base_cmd in priv_binaries:
        return True
    if os.name != 'nt':
        exe_path = shutil.which(cmd_parts[0])
        if exe_path and ('/sbin/' in exe_path or '/usr/sbin/' in exe_path):
            return True
    return False

def ask_user_permission(origin, command):
    result = {"allowed": False}
    root = tk.Tk()
    root.withdraw()
    
    top = tk.Toplevel(root)
    top.title("NSP Security Prompt")
    top.geometry("440x160")
    top.resizable(False, False)
    top.attributes("-topmost", True)
    
    msg = f"Website {origin} is requesting an action: {command}"
    tk.Label(top, text=msg, wraplength=410, justify="left", font=("Arial", 10)).pack(pady=20, padx=15)
    
    btn_frame = tk.Frame(top)
    btn_frame.pack(pady=5)
    
    def on_allow():
        result["allowed"] = True
        top.destroy()
        root.destroy()
        
    def on_deny():
        result["allowed"] = False
        top.destroy()
        root.destroy()

    tk.Button(btn_frame, text="Allow", width=12, command=on_allow, bg="#e0e0e0").pack(side=tk.LEFT, padx=15)
    tk.Button(btn_frame, text="Don't allow", width=12, command=on_deny, bg="#e0e0e0").pack(side=tk.RIGHT, padx=15)
    
    top.protocol("WM_DELETE_WINDOW", on_deny)
    root.mainloop()
    return result["allowed"]

class NSPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-NSP, X-NSP-cmd")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()

    def do_POST(self):
        if self.headers.get("X-NSP") != "true":
            self.send_response(400)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(b"Invalid Request")
            return

        command = self.headers.get("X-NSP-cmd", "").strip()
        if not command:
            self.send_response(400)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(b"Invalid Request: Missing X-NSP-cmd")
            return

        if is_admin_command(command):
            self.send_response(403)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("X-NSP", "true")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            error_response = {"status": "error", "message": "Admin/root related commands are not allowed."}
            self.wfile.write(json.dumps(error_response).encode('utf-8'))
            return

        origin = self.headers.get("Origin", "Unknown Website")

        if ask_user_permission(origin, command):
            try:
                proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                response_data = {
                    "status": "success",
                    "exit_code": proc.returncode,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr
                }
            except Exception as e:
                response_data = {"status": "error", "message": str(e)}
        else:
            response_data = {"status": "denied", "message": "User blocked the action"}

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("X-NSP", "true")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

server = HTTPServer(('localhost', 65535), NSPHandler)
server.serve_forever()
