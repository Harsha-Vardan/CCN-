import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import sys
import os
import socket

# Path to socks_local.py relative to this file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOCKS_SCRIPT = os.path.join(SCRIPT_DIR, "socks_local.py")

PROCESS = None  # global handle for the running socks proxy

def start_vpn(server_ip, server_port):
    global PROCESS

    if PROCESS is not None:
        messagebox.showwarning("Already Running", "VPN is already running!")
        return

    if not server_ip:
        messagebox.showerror("Error", "Server IP cannot be empty")
        return
    
    try:
        port = int(server_port)
    except:
        messagebox.showerror("Error", "Port must be a number")
        return

    # Launch socks_local.py as a background process
    PROCESS = subprocess.Popen(
    [sys.executable, SOCKS_SCRIPT, "--server", server_ip, "--port", str(port), "--listen-port", "1080"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,   # <-- merge stderr into stdout
    text=True
)


    log_text.insert(tk.END, f"[+] Starting VPN tunnel to {server_ip}:{port}\n")
    log_text.insert(tk.END, "[+] SOCKS5 proxy on 127.0.0.1:1080\n")

    monitor_logs()
    btn_connect.config(state=tk.DISABLED)
    btn_disconnect.config(state=tk.NORMAL)


def monitor_logs():
    if PROCESS is None:
        return

    def reader():
        while True:
            if PROCESS.poll() is not None:
                break
            line = PROCESS.stdout.readline()
            if line:
                log_text.insert(tk.END, line)
                log_text.see(tk.END)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()



def stop_vpn():
    global PROCESS
    if PROCESS is None:
        return

    PROCESS.terminate()
    PROCESS = None

    log_text.insert(tk.END, "[!] VPN disconnected\n")
    btn_connect.config(state=tk.NORMAL)
    btn_disconnect.config(state=tk.DISABLED)


# ------------------- GUI SETUP -------------------

root = tk.Tk()
root.title("Encrypted VPN Client")
root.geometry("500x450")
root.resizable(False, False)

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

# Server input frame
frame_server = ttk.LabelFrame(main_frame, text="VPN Server Settings", padding=10)
frame_server.pack(fill=tk.X, pady=10)

ttk.Label(frame_server, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
entry_ip = ttk.Entry(frame_server)
entry_ip.grid(row=0, column=1, padx=5, pady=5)
entry_ip.insert(0, "127.0.0.1")  # default local testing

ttk.Label(frame_server, text="Port:").grid(row=1, column=0, padx=5, pady=5)
entry_port = ttk.Entry(frame_server)
entry_port.grid(row=1, column=1, padx=5, pady=5)
entry_port.insert(0, "9000")

# Buttons
btn_connect = ttk.Button(main_frame, text="Connect", command=lambda: start_vpn(entry_ip.get(), entry_port.get()))
btn_connect.pack(pady=5)

btn_disconnect = ttk.Button(main_frame, text="Disconnect", state=tk.DISABLED, command=stop_vpn)
btn_disconnect.pack(pady=5)

# Log display
ttk.Label(main_frame, text="Logs:").pack(anchor=tk.W)
log_text = tk.Text(main_frame, height=15, width=60, state=tk.NORMAL)
log_text.pack()

root.mainloop()
