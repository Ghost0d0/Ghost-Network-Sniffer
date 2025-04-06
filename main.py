import customtkinter as ctk
import platform
import ctypes
import sys

# Explicit imports for PyInstaller - Scapy dependencies
import scapy.all
import scapy.arch
import scapy.arch.windows
import scapy.layers
import scapy.layers.inet
import scapy.layers.l2
import scapy.layers.http
import scapy.layers.dns
import scapy.sendrecv
import scapy.supersocket
import scapy.utils

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    # Check and request admin privileges
    if platform.system() == "Windows" and not is_admin():
        # Re-run with admin rights if not elevated
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable, 
            " ".join(sys.argv), 
            None, 
            1
        )
        sys.exit()
    
    # Main application
    from gui import GhostSnifferGUI
    
    # Initialize main window
    root = ctk.CTk()
    root.title("Ghost Network Sniffer")
    root.geometry("1000x700")
    
    # Configure theme
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    
    # Start application
    app = GhostSnifferGUI(root)
    root.mainloop()