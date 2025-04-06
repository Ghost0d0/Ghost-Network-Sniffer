import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import tkinter as tk
import queue
import threading
import os
from datetime import datetime
from sniffer import PacketSniffer

class GhostSnifferGUI:
    def __init__(self, master):
        self.master = master
        self.packet_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.sniffer = PacketSniffer(self.packet_queue, self.status_queue)
        self.packets = []
        self.setup_gui()
        self.check_queues()

    def setup_gui(self):
        # Configure main window grid
        self.master.grid_rowconfigure(1, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        # Custom color scheme
        bg_color = "#2b2b2b"
        frame_color = "#3c3f41"
        accent_color = "#4e9af1"
        text_color = "#ffffff"
        
        # Header Frame
        header_frame = ctk.CTkFrame(
            self.master,
            fg_color=frame_color,
            corner_radius=10,
            border_width=2,
            border_color=accent_color
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10, ipadx=5, ipady=5)
        
        # Ghost Sniffer Title
        ctk.CTkLabel(
            header_frame,
            text="GHOST NETWORK SNIFFER",
            font=("Courier New", 24, "bold"),
            text_color=accent_color
        ).pack(pady=10)
        
        # Control Panel Frame
        control_frame = ctk.CTkFrame(
            self.master,
            fg_color=frame_color,
            corner_radius=10,
            border_width=2,
            border_color=accent_color
        )
        control_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0,10))
        
        # Interface Selection
        ctk.CTkLabel(
            control_frame,
            text="Network Interface:",
            font=("Arial", 12, "bold"),
            text_color=text_color
        ).grid(row=0, column=0, padx=5, pady=5)
        
        interfaces = self.sniffer.get_interfaces()
        self.interface_var = ctk.StringVar(value=interfaces[0] if interfaces else "")
        self.interface_menu = ctk.CTkComboBox(
            control_frame,
            values=interfaces,
            variable=self.interface_var,
            width=300,
            dropdown_fg_color=frame_color,
            button_color=accent_color,
            border_color=accent_color
        )
        self.interface_menu.grid(row=0, column=1, padx=5, pady=5)
        
        # Protocol Filter
        ctk.CTkLabel(
            control_frame,
            text="Protocol Filter:",
            font=("Arial", 12, "bold"),
            text_color=text_color
        ).grid(row=0, column=2, padx=5, pady=5)
        
        self.protocol_var = ctk.StringVar(value="All")
        self.protocol_menu = ctk.CTkComboBox(
            control_frame,
            values=["All", "TCP", "UDP", "HTTP", "DNS", "ICMP"],
            variable=self.protocol_var,
            width=120,
            dropdown_fg_color=frame_color,
            button_color=accent_color,
            border_color=accent_color
        )
        self.protocol_menu.grid(row=0, column=3, padx=5, pady=5)
        
        # Buttons
        button_style = {
            "width": 120,
            "height": 32,
            "border_width": 2,
            "border_color": accent_color,
            "corner_radius": 8,
            "font": ("Arial", 12, "bold")
        }
        
        self.start_btn = ctk.CTkButton(
            control_frame,
            text="START",
            command=self.start_sniffing,
            fg_color="#2e7d32",
            hover_color="#1b5e20",
            text_color=text_color,
            **button_style
        )
        self.start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.stop_btn = ctk.CTkButton(
            control_frame,
            text="STOP",
            command=self.stop_sniffing,
            fg_color="#c62828",
            hover_color="#8e0000",
            text_color=text_color,
            state="disabled",
            **button_style
        )
        self.stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        self.save_btn = ctk.CTkButton(
            control_frame,
            text="SAVE PCAP",
            command=self.save_pcap,
            fg_color=accent_color,
            hover_color="#3a7cc7",
            text_color=text_color,
            **button_style
        )
        self.save_btn.grid(row=0, column=6, padx=5, pady=5)
        
        # Packet Display Frame
        display_frame = ctk.CTkFrame(
            self.master,
            fg_color=frame_color,
            corner_radius=10,
            border_width=2,
            border_color=accent_color
        )
        display_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0,10))
        display_frame.grid_rowconfigure(0, weight=1)
        display_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background=frame_color,
            foreground=text_color,
            fieldbackground=frame_color,
            borderwidth=0,
            font=("Consolas", 10)
        )
        style.configure("Treeview.Heading",
            background=accent_color,
            foreground=text_color,
            font=("Arial", 11, "bold"),
            relief="flat"
        )
        style.map("Treeview", background=[("selected", "#4e9af1")])
        
        self.tree = ttk.Treeview(
            display_frame,
            columns=("Time", "Source", "Destination", "Protocol", "Length"),
            show="headings",
            height=15,
            selectmode="browse"
        )
        
        # Configure columns
        col_widths = {"Time": 120, "Source": 200, "Destination": 200, "Protocol": 80, "Length": 80}
        for col, width in col_widths.items():
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            display_frame,
            orient="vertical",
            command=self.tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Packet Details Frame
        details_frame = ctk.CTkFrame(
            self.master,
            fg_color=frame_color,
            corner_radius=10,
            border_width=2,
            border_color=accent_color
        )
        details_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0,10))
        details_frame.grid_rowconfigure(0, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        
        # Details Text
        self.details_text = tk.Text(
            details_frame,
            bg=frame_color,
            fg=text_color,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
            insertbackground=text_color,
            selectbackground=accent_color,
            borderwidth=0,
            highlightthickness=0
        )
        self.details_text.grid(row=0, column=0, sticky="nsew")
        
        # Details scrollbar
        details_scroll = ttk.Scrollbar(
            details_frame,
            orient="vertical",
            command=self.details_text.yview
        )
        details_scroll.grid(row=0, column=1, sticky="ns")
        self.details_text.configure(yscrollcommand=details_scroll.set)
        
        # Configure text tags
        self.details_text.tag_configure("header", foreground=accent_color, font=("Consolas", 10, "bold"))
        self.details_text.tag_configure("key", foreground="#4fc3f7")
        self.details_text.tag_configure("value", foreground="#a5d6a7")
        
        # Bind treeview selection
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
        # Status Bar
        status_frame = ctk.CTkFrame(
            self.master,
            fg_color=frame_color,
            corner_radius=10,
            border_width=2,
            border_color=accent_color
        )
        status_frame.grid(row=4, column=0, sticky="ew", padx=10, pady=(0,10))
        
        self.status_var = ctk.StringVar(value="Ready - Select interface and click START")
        ctk.CTkLabel(
            status_frame,
            textvariable=self.status_var,
            anchor="w",
            font=("Arial", 11),
            text_color=text_color
        ).pack(side="left", padx=10, fill="x", expand=True)
        
        self.packet_count_var = ctk.StringVar(value="Packets: 0")
        ctk.CTkLabel(
            status_frame,
            textvariable=self.packet_count_var,
            anchor="e",
            font=("Arial", 11, "bold"),
            text_color=accent_color
        ).pack(side="right", padx=10)

    def start_sniffing(self):
        iface = self.interface_var.get()
        protocol = self.protocol_var.get()
        
        if not iface:
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.interface_menu.configure(state="disabled")
        self.protocol_menu.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.details_text.configure(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.configure(state="disabled")
        self.packets = []
        
        self.sniffer.start_sniffing(iface, protocol)

    def stop_sniffing(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.interface_menu.configure(state="normal")
        self.protocol_menu.configure(state="normal")
        self.save_btn.configure(state="normal")
        self.sniffer.stop_sniffing()

    def save_pcap(self):
        if not hasattr(self.sniffer, 'packets') or not self.sniffer.packets:
            messagebox.showerror("Error", "No packets captured to save")
            return
            
        os.makedirs("captures", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_file = f"captures/capture_{timestamp}.pcap"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            initialfile=os.path.basename(default_file),
            initialdir=os.path.dirname(default_file)
        )
        
        if filename:
            if self.sniffer.save_to_pcap(filename):
                self.status_var.set(f"Saved {len(self.sniffer.packets)} packets to {filename}")
            else:
                messagebox.showerror("Error", "Failed to save PCAP file")

    def show_packet_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = self.tree.item(selected[0])
        index = self.tree.index(selected[0])
        
        if 0 <= index < len(self.packets):
            self.display_details(self.packets[index]['details'])

    def display_details(self, details):
        self.details_text.configure(state="normal")
        self.details_text.delete(1.0, tk.END)
        
        if not details:
            self.details_text.insert(tk.END, "No details available\n", "header")
        else:
            for layer, data in details.items():
                self.details_text.insert(tk.END, f"\n{layer}\n", "header")
                for key, value in data.items():
                    self.details_text.insert(tk.END, f"  {key}: ", "key")
                    self.details_text.insert(tk.END, f"{value}\n", "value")
        
        self.details_text.see(tk.END)
        self.details_text.configure(state="disabled")

    def check_queues(self):
        # Process packet queue
        try:
            while True:
                packet = self.packet_queue.get_nowait()
                self.packets.append(packet)
                
                src = f"{packet['summary']['src_ip']}:{packet['summary']['src_port']}" if packet['summary']['src_port'] else packet['summary']['src_ip']
                dst = f"{packet['summary']['dst_ip']}:{packet['summary']['dst_port']}" if packet['summary']['dst_port'] else packet['summary']['dst_ip']
                
                self.tree.insert("", "end", values=(
                    packet['timestamp'],
                    src,
                    dst,
                    packet['summary']['protocol'],
                    packet['summary']['length']
                ))
                
                self.tree.yview_moveto(1)
                self.packet_count_var.set(f"Packets: {len(self.packets)}")
        except queue.Empty:
            pass
            
        # Process status queue
        try:
            while True:
                status = self.status_queue.get_nowait()
                self.status_var.set(status)
        except queue.Empty:
            pass
            
        self.master.after(100, self.check_queues)