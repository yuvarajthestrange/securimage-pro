import os
import zlib
import base64
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk, ImageDraw, ImageFont, ImageOps, ExifTags
import numpy as np
import json
from datetime import datetime, timedelta
import qrcode
import tempfile
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinterdnd2 import TkinterDnD, DND_FILES

class SteganographyApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecurImage Pro - Advanced Steganography")
        self.geometry("1100x850")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)
        
        # Custom fonts
        self.title_font = ("Arial", 18, "bold")
        self.subtitle_font = ("Arial", 12, "bold")
        self.body_font = ("Arial", 10)
        self.button_font = ("Arial", 10, "bold")
        
        # App state
        self.current_theme = "dark"
        self.extracted_file_data = None
        self.extracted_filename = None
        self.operation_in_progress = False
        self.steganalysis_results = {}
        self.batch_queue = []
        
        # Security settings
        self.encryption_algorithm = "AES-256-GCM"
        self.compression_level = 6  # Default zlib compression
        
        self.setup_ui()
        self.setup_menu()
        
    def setup_menu(self):
        menu_bar = tk.Menu(self, bg="#2a2a3e", fg="white")
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0, bg="#2a2a3e", fg="white")
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0, bg="#2a2a3e", fg="white")
        tools_menu.add_command(label="Password Generator", command=self.show_password_generator)
        tools_menu.add_command(label="File Shredder", command=self.show_file_shredder)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings", command=self.show_settings)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0, bg="#2a2a3e", fg="white")
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.config(menu=menu_bar)
    
    def setup_ui(self):
        # Header frame
        header_frame = tk.Frame(self, bg="#161625", height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        
        # App title
        title_label = tk.Label(header_frame, text="SECURIMAGE PRO", font=self.title_font, 
                             fg="#1abc9c", bg="#161625", padx=20)
        title_label.pack(side=tk.LEFT)
        
        # Tab navigation
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.embed_frame = ttk.Frame(self.notebook)
        self.extract_frame = ttk.Frame(self.notebook)
        self.multi_frame = ttk.Frame(self.notebook)
        self.batch_frame = ttk.Frame(self.notebook)
        self.analyze_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.embed_frame, text="Embed Data")
        self.notebook.add(self.extract_frame, text="Extract Data")
        self.notebook.add(self.multi_frame, text="Multi-Image")
        self.notebook.add(self.batch_frame, text="Batch Processing")
        self.notebook.add(self.analyze_frame, text="Steganalysis")
        
        # Setup each tab
        self.setup_embed_tab()
        self.setup_extract_tab()
        self.setup_multi_tab()
        self.setup_batch_tab()
        self.setup_analyze_tab()
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Frame(self, bg="#161625", height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        status_label = tk.Label(status_bar, textvariable=self.status_var, anchor=tk.W, 
                              bg="#161625", fg="#aaaaaa", padx=20, font=self.body_font)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_bar, variable=self.progress_var, 
                                          mode='determinate', length=200)
        
        # Configure progress bar styles
        style = ttk.Style()
        style.configure("green.Horizontal.TProgressbar", troughcolor="#1e1e2e", background="#1abc9c")
        style.configure("orange.Horizontal.TProgressbar", troughcolor="#1e1e2e", background="#f39c12")
        style.configure("red.Horizontal.TProgressbar", troughcolor="#1e1e2e", background="#e74c3c")
    
    def setup_embed_tab(self):
        # Two-column layout
        left_frame = tk.Frame(self.embed_frame, bg="#1e1e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        right_frame = tk.Frame(self.embed_frame, bg="#1e1e2e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Cover Image Section
        cover_frame = tk.LabelFrame(left_frame, text="COVER IMAGE", font=self.subtitle_font,
                                 bg="#2a2a3e", fg="white", padx=15, pady=15)
        cover_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.cover_path = tk.StringVar()
        
        # Image preview container
        preview_container = tk.Frame(cover_frame, bg="#1e1e2e", bd=1, relief=tk.SUNKEN, height=200)
        preview_container.pack(fill=tk.BOTH, expand=True, pady=10)
        preview_container.pack_propagate(False)
        
        self.image_preview = tk.Label(preview_container, bg="#1e1e2e")
        self.image_preview.pack(fill=tk.BOTH, expand=True)
        
        # Placeholder image
        self.show_placeholder_image()
        
        # Image info
        self.image_info = tk.Label(cover_frame, text="No image loaded", bg="#2a2a3e", 
                                 fg="#aaaaaa", font=self.body_font)
        self.image_info.pack(pady=5)
        
        # Browse button
        browse_btn = tk.Button(cover_frame, text="Select Cover Image", 
                             font=self.button_font, bg="#3498db", fg="white", 
                             activebackground="#2980b9", command=self.browse_cover)
        browse_btn.pack(fill=tk.X, pady=10)
        
        # Clear button
        clear_btn = tk.Button(cover_frame, text="Clear Image", 
                             font=self.button_font, bg="#e74c3c", fg="white", 
                             activebackground="#c0392b", command=self.clear_cover)
        clear_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Drag and drop hint
        drag_label = tk.Label(cover_frame, text="↥ Drag & Drop Image Here", 
                            bg="#2a2a3e", fg="#7f8c8d", font=("Arial", 9))
        drag_label.pack(pady=5)
        
        # Setup drag and drop
        self.setup_drag_drop()
        
        # Capacity meter
        capacity_frame = tk.LabelFrame(left_frame, text="CAPACITY", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        capacity_frame.pack(fill=tk.X, padx=5, pady=5)
        
        capacity_info = tk.Label(capacity_frame, text="Maximum data you can embed:", 
                              bg="#2a2a3e", fg="#aaaaaa", font=("Arial", 9))
        capacity_info.pack(anchor=tk.W)
        
        self.capacity_label = tk.Label(capacity_frame, text="0%", bg="#2a2a3e", fg="white", 
                                    font=("Arial", 14, "bold"))
        self.capacity_label.pack(pady=5)
        
        self.capacity_meter = ttk.Progressbar(capacity_frame, orient=tk.HORIZONTAL, 
                                            length=200, mode='determinate')
        self.capacity_meter.pack(fill=tk.X, pady=5)
        
        # Color indicators
        color_frame = tk.Frame(capacity_frame, bg="#2a2a3e")
        color_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(color_frame, text="Low", bg="#2a2a3e", fg="#2ecc71").pack(side=tk.LEFT)
        tk.Label(color_frame, text="Medium", bg="#2a2a3e", fg="#f39c12", padx=20).pack(side=tk.LEFT)
        tk.Label(color_frame, text="High", bg="#2a2a3e", fg="#e74c3c").pack(side=tk.RIGHT)
        
        # ================ RIGHT COLUMN ===================
        
        # Secret Data Section
        secret_frame = tk.LabelFrame(right_frame, text="SECRET DATA", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        secret_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Data type selector
        data_type_frame = tk.Frame(secret_frame, bg="#2a2a3e")
        data_type_frame.pack(fill=tk.X, pady=5)
        
        self.data_type = tk.StringVar(value="text")
        
        text_radio = tk.Radiobutton(data_type_frame, text="Text", variable=self.data_type, value="text",
                                  bg="#2a2a3e", fg="white", selectcolor="#1e1e2e", 
                                  activebackground="#2a2a3e", command=self.toggle_data_type)
        text_radio.pack(side=tk.LEFT, padx=(0, 15))
        
        file_radio = tk.Radiobutton(data_type_frame, text="File", variable=self.data_type, value="file",
                                  bg="#2a2a3e", fg="white", selectcolor="#1e1e2e", 
                                  activebackground="#2a2a3e", command=self.toggle_data_type)
        file_radio.pack(side=tk.LEFT)
        
        # Text input
        self.text_frame = tk.Frame(secret_frame, bg="#2a2a3e")
        self.text_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.text_data = scrolledtext.ScrolledText(self.text_frame, height=8, bg="#3a3a4e", 
                                                fg="white", insertbackground="white",
                                                font=self.body_font)
        self.text_data.pack(fill=tk.BOTH, expand=True)
        self.text_data.insert(tk.END, "Enter your secret message here...")
        self.text_data.bind("<FocusIn>", self.clear_default_text)
        
        # File input
        self.file_frame = tk.Frame(secret_frame, bg="#2a2a3e")
        
        file_input_frame = tk.Frame(self.file_frame, bg="#2a2a3e")
        file_input_frame.pack(fill=tk.X, pady=10)
        
        self.file_path = tk.StringVar()
        file_entry = tk.Entry(file_input_frame, textvariable=self.file_path, 
                            bg="#3a3a4e", fg="white", insertbackground="white",
                            font=self.body_font, state="readonly")
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_file_btn = tk.Button(file_input_frame, text="Browse", 
                                  font=self.button_font, bg="#3498db", fg="white", 
                                  activebackground="#2980b9", command=self.browse_secret_file)
        browse_file_btn.pack(side=tk.RIGHT)
        
        self.file_info = tk.Label(self.file_frame, text="No file selected", bg="#2a2a3e", 
                                fg="#aaaaaa", font=self.body_font)
        self.file_info.pack(anchor=tk.W, pady=(0, 10))
        
        # Initially show text input
        self.text_frame.pack(fill=tk.BOTH, expand=True)
        self.file_frame.pack_forget()
        
        # Security Section
        security_frame = tk.LabelFrame(right_frame, text="SECURITY", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Password fields
        pass_frame = tk.Frame(security_frame, bg="#2a2a3e")
        pass_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pass_frame, text="Password:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.password = tk.Entry(pass_frame, show="*", bg="#3a3a4e", fg="white", 
                              font=self.body_font, bd=1, relief=tk.SOLID)
        self.password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Password strength
        self.pass_strength = tk.Label(pass_frame, text="", bg="#2a2a3e", fg="#e74c3c", 
                                    font=("Arial", 9), width=10)
        self.pass_strength.pack(side=tk.RIGHT, padx=5)
        self.password.bind("<KeyRelease>", self.check_password_strength)
        
        # Confirm password
        confirm_frame = tk.Frame(security_frame, bg="#2a2a3e")
        confirm_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(confirm_frame, text="Confirm Password:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.confirm_password = tk.Entry(confirm_frame, show="*", bg="#3a3a4e", fg="white", 
                                      font=self.body_font, bd=1, relief=tk.SOLID)
        self.confirm_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Encryption info
        encrypt_info = tk.Label(security_frame, text="Data encrypted with AES-256-GCM", 
                              bg="#2a2a3e", fg="#aaaaaa", font=("Arial", 9))
        encrypt_info.pack(anchor=tk.W, pady=5)
        
        # Advanced Options
        advanced_frame = tk.LabelFrame(right_frame, text="ADVANCED OPTIONS", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        advanced_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # LSB pattern
        pattern_frame = tk.Frame(advanced_frame, bg="#2a2a3e")
        pattern_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pattern_frame, text="LSB Pattern:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.lsb_pattern = tk.StringVar(value="sequential")
        pattern_combo = ttk.Combobox(pattern_frame, textvariable=self.lsb_pattern, 
                                   state="readonly", width=15)
        pattern_combo['values'] = ('Sequential', 'Random', 'Interleaved')
        pattern_combo.pack(side=tk.LEFT)
        
        # Compression level
        compression_frame = tk.Frame(advanced_frame, bg="#2a2a3e")
        compression_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(compression_frame, text="Compression:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.compression_level_var = tk.StringVar(value="Medium")
        compression_combo = ttk.Combobox(compression_frame, textvariable=self.compression_level_var, 
                                       state="readonly", width=15)
        compression_combo['values'] = ('Low', 'Medium', 'High')
        compression_combo.pack(side=tk.LEFT)
        
        # Self-destruct option
        self.self_destruct_var = tk.BooleanVar(value=False)
        self.self_destruct_frame = tk.Frame(advanced_frame, bg="#2a2a3e")
        self.self_destruct_frame.pack(fill=tk.X, pady=5)
        
        tk.Checkbutton(self.self_destruct_frame, text="Enable Self-Destruct", 
                      variable=self.self_destruct_var, bg="#2a2a3e", fg="white",
                      selectcolor="#1e1e2e", command=self.toggle_self_destruct).pack(side=tk.LEFT)
        
        # Only show when checked
        self.sd_settings_frame = tk.Frame(advanced_frame, bg="#2a2a3e")
        
        tk.Label(self.sd_settings_frame, text="Max Views:", bg="#2a2a3e", fg="white",
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        self.max_views = tk.Spinbox(self.sd_settings_frame, from_=1, to=100, width=5)
        self.max_views.pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.sd_settings_frame, text="Days Valid:", bg="#2a2a3e", fg="white",
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        self.days_valid = tk.Spinbox(self.sd_settings_frame, from_=1, to=365, width=5)
        self.days_valid.pack(side=tk.LEFT, padx=5)
        
        # Plausible deniability
        self.dual_layer_var = tk.BooleanVar(value=False)
        tk.Checkbutton(advanced_frame, text="Enable Dual-Layer Steganography", 
                      variable=self.dual_layer_var, bg="#2a2a3e", fg="white",
                      selectcolor="#1e1e2e").pack(anchor=tk.W, pady=5)
        
        # Embed Button
        embed_btn_frame = tk.Frame(right_frame, bg="#1e1e2e")
        embed_btn_frame.pack(fill=tk.X, padx=5, pady=20)
        
        embed_btn = tk.Button(embed_btn_frame, text="EMBED DATA", font=("Arial", 12, "bold"), 
                           bg="#1abc9c", fg="white", bd=0, padx=30, pady=10,
                           command=self.start_embedding)
        embed_btn.pack(fill=tk.X)
    
    def setup_extract_tab(self):
        # Two-column layout
        left_frame = tk.Frame(self.extract_frame, bg="#1e1e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        right_frame = tk.Frame(self.extract_frame, bg="#1e1e2e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Stego Image Section
        stego_frame = tk.LabelFrame(left_frame, text="STEGO IMAGE", font=self.subtitle_font,
                                 bg="#2a2a3e", fg="white", padx=15, pady=15)
        stego_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stego_path = tk.StringVar()
        
        # Image preview container
        preview_container = tk.Frame(stego_frame, bg="#1e1e2e", bd=1, relief=tk.SUNKEN, height=200)
        preview_container.pack(fill=tk.BOTH, expand=True, pady=10)
        preview_container.pack_propagate(False)
        
        self.stego_preview = tk.Label(preview_container, bg="#1e1e2e")
        self.stego_preview.pack(fill=tk.BOTH, expand=True)
        
        # Placeholder image for extraction
        self.show_extract_placeholder()
        
        # Image info
        self.stego_info = tk.Label(stego_frame, text="No image loaded", bg="#2a2a3e", 
                                 fg="#aaaaaa", font=self.body_font)
        self.stego_info.pack(pady=5)
        
        # Browse button
        browse_btn = tk.Button(stego_frame, text="Select Stego Image", 
                             font=self.button_font, bg="#3498db", fg="white", 
                             activebackground="#2980b9", command=self.browse_stego)
        browse_btn.pack(fill=tk.X, pady=10)
        
        # Clear button
        clear_btn = tk.Button(stego_frame, text="Clear Image", 
                             font=self.button_font, bg="#e74c3c", fg="white", 
                             activebackground="#c0392b", command=self.clear_stego)
        clear_btn.pack(fill=tk.X, pady=(0, 10))
        
        # Drag and drop hint
        drag_label = tk.Label(stego_frame, text="↥ Drag & Drop Image Here", 
                            bg="#2a2a3e", fg="#7f8c8d", font=("Arial", 9))
        drag_label.pack(pady=5)
        
        # Setup drag and drop for extraction
        self.stego_preview.drop_target_register(DND_FILES)
        self.stego_preview.dnd_bind('<<Drop>>', self.handle_stego_drop)
        
        # Security Section
        security_frame = tk.LabelFrame(right_frame, text="SECURITY", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Password field
        pass_frame = tk.Frame(security_frame, bg="#2a2a3e")
        pass_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pass_frame, text="Password:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.extract_password = tk.Entry(pass_frame, show="*", bg="#3a3a4e", fg="white", 
                                      font=self.body_font, bd=1, relief=tk.SOLID)
        self.extract_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # QR code button
        self.qr_btn = tk.Button(pass_frame, text="Scan QR", font=self.button_font, 
                              bg="#9b59b6", fg="white", command=self.scan_qr)
        self.qr_btn.pack(side=tk.RIGHT, padx=5)
        
        # Self-destruct info
        self.sd_info = tk.Label(security_frame, text="", bg="#2a2a3e", fg="#e74c3c", 
                              font=("Arial", 9))
        self.sd_info.pack(anchor=tk.W, pady=5)
        
        # Output Section
        output_frame = tk.LabelFrame(right_frame, text="EXTRACTED DATA", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(output_frame, height=8, bg="#3a3a4e", 
                                                  fg="white", insertbackground="white",
                                                  font=self.body_font)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Save button
        self.save_btn_frame = tk.Frame(output_frame, bg="#2a2a3e")
        self.save_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.save_btn = tk.Button(self.save_btn_frame, text="Save File", 
                                font=self.button_font, bg="#1abc9c", fg="white",
                                state=tk.DISABLED, command=self.save_extracted)
        self.save_btn.pack(side=tk.RIGHT)
        
        # Extract Button
        extract_btn_frame = tk.Frame(right_frame, bg="#1e1e2e")
        extract_btn_frame.pack(fill=tk.X, padx=5, pady=20)
        
        extract_btn = tk.Button(extract_btn_frame, text="EXTRACT DATA", font=("Arial", 12, "bold"), 
                              bg="#1abc9c", fg="white", bd=0, padx=30, pady=10,
                              command=self.start_extraction)
        extract_btn.pack(fill=tk.X)
    
    def setup_multi_tab(self):
        # Multi-image steganography tab
        main_frame = tk.Frame(self.multi_frame, bg="#1e1e2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Cover images
        left_frame = tk.Frame(main_frame, bg="#1e1e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Cover images list
        cover_list_frame = tk.LabelFrame(left_frame, text="COVER IMAGES", font=self.subtitle_font,
                                      bg="#2a2a3e", fg="white", padx=15, pady=15)
        cover_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.cover_list = tk.Listbox(cover_list_frame, bg="#3a3a4e", fg="white", 
                                   selectbackground="#1abc9c", font=self.body_font)
        self.cover_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add/remove buttons
        btn_frame = tk.Frame(cover_list_frame, bg="#2a2a3e")
        btn_frame.pack(fill=tk.X, pady=5)
        
        add_btn = tk.Button(btn_frame, text="Add Images", font=self.button_font, 
                          bg="#3498db", fg="white", command=self.add_multi_images)
        add_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        remove_btn = tk.Button(btn_frame, text="Remove", font=self.button_font, 
                            bg="#e74c3c", fg="white", command=self.remove_multi_image)
        remove_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Right panel - Settings and controls
        right_frame = tk.Frame(main_frame, bg="#1e1e2e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Secret data section
        secret_frame = tk.LabelFrame(right_frame, text="SECRET DATA", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        secret_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # File input
        file_frame = tk.Frame(secret_frame, bg="#2a2a3e")
        file_frame.pack(fill=tk.X, pady=5)
        
        self.multi_file_path = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.multi_file_path, 
                            bg="#3a3a4e", fg="white", insertbackground="white",
                            font=self.body_font, state="readonly")
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_file_btn = tk.Button(file_frame, text="Browse", 
                                  font=self.button_font, bg="#3498db", fg="white", 
                                  activebackground="#2980b9", command=self.browse_multi_secret_file)
        browse_file_btn.pack(side=tk.RIGHT)
        
        self.multi_file_info = tk.Label(secret_frame, text="No file selected", bg="#2a2a3e", 
                                      fg="#aaaaaa", font=self.body_font)
        self.multi_file_info.pack(anchor=tk.W, pady=(0, 10))
        
        # Security Section
        security_frame = tk.LabelFrame(right_frame, text="SECURITY", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Password field
        pass_frame = tk.Frame(security_frame, bg="#2a2a3e")
        pass_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pass_frame, text="Password:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.multi_password = tk.Entry(pass_frame, show="*", bg="#3a3a4e", fg="white", 
                                    font=self.body_font, bd=1, relief=tk.SOLID)
        self.multi_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Output Section
        output_frame = tk.LabelFrame(right_frame, text="OUTPUT SETTINGS", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Output directory
        dir_frame = tk.Frame(output_frame, bg="#2a2a3e")
        dir_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(dir_frame, text="Output Directory:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.output_dir = tk.StringVar()
        dir_entry = tk.Entry(dir_frame, textvariable=self.output_dir, 
                           bg="#3a3a4e", fg="white", insertbackground="white",
                           font=self.body_font, state="readonly")
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_dir_btn = tk.Button(dir_frame, text="Browse", 
                                 font=self.button_font, bg="#3498db", fg="white", 
                                 activebackground="#2980b9", command=self.browse_output_dir)
        browse_dir_btn.pack(side=tk.RIGHT)
        
        # Embed Button
        embed_btn_frame = tk.Frame(right_frame, bg="#1e1e2e")
        embed_btn_frame.pack(fill=tk.X, padx=5, pady=20)
        
        embed_btn = tk.Button(embed_btn_frame, text="EMBED ACROSS IMAGES", font=("Arial", 12, "bold"), 
                           bg="#1abc9c", fg="white", bd=0, padx=30, pady=10,
                           command=self.start_multi_embedding)
        embed_btn.pack(fill=tk.X)
    
    def setup_batch_tab(self):
        # Batch processing tab
        main_frame = tk.Frame(self.batch_frame, bg="#1e1e2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Input files
        left_frame = tk.Frame(main_frame, bg="#1e1e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Input files list
        input_list_frame = tk.LabelFrame(left_frame, text="INPUT FILES", font=self.subtitle_font,
                                      bg="#2a2a3e", fg="white", padx=15, pady=15)
        input_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.input_list = tk.Listbox(input_list_frame, bg="#3a3a4e", fg="white", 
                                   selectbackground="#1abc9c", font=self.body_font)
        self.input_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add/remove buttons
        btn_frame = tk.Frame(input_list_frame, bg="#2a2a3e")
        btn_frame.pack(fill=tk.X, pady=5)
        
        add_btn = tk.Button(btn_frame, text="Add Files", font=self.button_font, 
                          bg="#3498db", fg="white", command=self.add_batch_files)
        add_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        remove_btn = tk.Button(btn_frame, text="Remove", font=self.button_font, 
                            bg="#e74c3c", fg="white", command=self.remove_batch_file)
        remove_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Right panel - Settings and controls
        right_frame = tk.Frame(main_frame, bg="#1e1e2e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Operation selection
        op_frame = tk.LabelFrame(right_frame, text="OPERATION", font=self.subtitle_font,
                              bg="#2a2a3e", fg="white", padx=15, pady=15)
        op_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.batch_op = tk.StringVar(value="embed")
        
        embed_radio = tk.Radiobutton(op_frame, text="Embed Data", variable=self.batch_op, value="embed",
                                   bg="#2a2a3e", fg="white", selectcolor="#1e1e2e", 
                                   activebackground="#2a2a3e")
        embed_radio.pack(anchor=tk.W, padx=5, pady=2)
        
        extract_radio = tk.Radiobutton(op_frame, text="Extract Data", variable=self.batch_op, value="extract",
                                     bg="#2a2a3e", fg="white", selectcolor="#1e1e2e", 
                                     activebackground="#2a2a3e")
        extract_radio.pack(anchor=tk.W, padx=5, pady=2)
        
        # Secret data section (for embedding)
        secret_frame = tk.LabelFrame(right_frame, text="SECRET DATA", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        secret_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # File input
        file_frame = tk.Frame(secret_frame, bg="#2a2a3e")
        file_frame.pack(fill=tk.X, pady=5)
        
        self.batch_file_path = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.batch_file_path, 
                            bg="#3a3a4e", fg="white", insertbackground="white",
                            font=self.body_font, state="readonly")
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_file_btn = tk.Button(file_frame, text="Browse", 
                                  font=self.button_font, bg="#3498db", fg="white", 
                                  activebackground="#2980b9", command=self.browse_batch_secret_file)
        browse_file_btn.pack(side=tk.RIGHT)
        
        self.batch_file_info = tk.Label(secret_frame, text="No file selected", bg="#2a2a3e", 
                                      fg="#aaaaaa", font=self.body_font)
        self.batch_file_info.pack(anchor=tk.W, pady=(0, 10))
        
        # Security Section
        security_frame = tk.LabelFrame(right_frame, text="SECURITY", font=self.subtitle_font,
                                    bg="#2a2a3e", fg="white", padx=15, pady=15)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Password field
        pass_frame = tk.Frame(security_frame, bg="#2a2a3e")
        pass_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pass_frame, text="Password:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.batch_password = tk.Entry(pass_frame, show="*", bg="#3a3a4e", fg="white", 
                                    font=self.body_font, bd=1, relief=tk.SOLID)
        self.batch_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Output Section
        output_frame = tk.LabelFrame(right_frame, text="OUTPUT SETTINGS", font=self.subtitle_font,
                                  bg="#2a2a3e", fg="white", padx=15, pady=15)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Output directory
        dir_frame = tk.Frame(output_frame, bg="#2a2a3e")
        dir_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(dir_frame, text="Output Directory:", bg="#2a2a3e", fg="white", 
               font=self.body_font, width=15, anchor=tk.W).pack(side=tk.LEFT)
        
        self.batch_output_dir = tk.StringVar()
        dir_entry = tk.Entry(dir_frame, textvariable=self.batch_output_dir, 
                           bg="#3a3a4e", fg="white", insertbackground="white",
                           font=self.body_font, state="readonly")
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_dir_btn = tk.Button(dir_frame, text="Browse", 
                                 font=self.button_font, bg="#3498db", fg="white", 
                                 activebackground="#2980b9", command=self.browse_batch_output_dir)
        browse_dir_btn.pack(side=tk.RIGHT)
        
        # Start Button
        start_btn_frame = tk.Frame(right_frame, bg="#1e1e2e")
        start_btn_frame.pack(fill=tk.X, padx=5, pady=20)
        
        start_btn = tk.Button(start_btn_frame, text="START BATCH PROCESSING", font=("Arial", 12, "bold"), 
                            bg="#1abc9c", fg="white", bd=0, padx=30, pady=10,
                            command=self.start_batch_processing)
        start_btn.pack(fill=tk.X)
    
    def setup_analyze_tab(self):
        # Steganalysis tab
        main_frame = tk.Frame(self.analyze_frame, bg="#1e1e2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Image selection
        left_frame = tk.Frame(main_frame, bg="#1e1e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Image selection
        image_frame = tk.LabelFrame(left_frame, text="IMAGE TO ANALYZE", font=self.subtitle_font,
                                 bg="#2a2a3e", fg="white", padx=15, pady=15)
        image_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.analyze_path = tk.StringVar()
        
        # Image preview container
        preview_container = tk.Frame(image_frame, bg="#1e1e2e", bd=1, relief=tk.SUNKEN, height=200)
        preview_container.pack(fill=tk.BOTH, expand=True, pady=10)
        preview_container.pack_propagate(False)
        
        self.analyze_preview = tk.Label(preview_container, bg="#1e1e2e")
        self.analyze_preview.pack(fill=tk.BOTH, expand=True)
        
        # Placeholder image
        self.show_analyze_placeholder()
        
        # Image info
        self.analyze_info = tk.Label(image_frame, text="No image loaded", bg="#2a2a3e", 
                                   fg="#aaaaaa", font=self.body_font)
        self.analyze_info.pack(pady=5)
        
        # Browse button
        browse_btn = tk.Button(image_frame, text="Select Image", 
                             font=self.button_font, bg="#3498db", fg="white", 
                             activebackground="#2980b9", command=self.browse_analyze_image)
        browse_btn.pack(fill=tk.X, pady=10)
        
        # Analyze Button
        analyze_btn = tk.Button(left_frame, text="ANALYZE IMAGE", font=("Arial", 12, "bold"), 
                              bg="#1abc9c", fg="white", bd=0, padx=30, pady=10,
                              command=self.start_analysis)
        analyze_btn.pack(fill=tk.X, pady=20)
        
        # Right panel - Results
        right_frame = tk.Frame(main_frame, bg="#1e1e2e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Results display
        results_frame = tk.LabelFrame(right_frame, text="ANALYSIS RESULTS", font=self.subtitle_font,
                                   bg="#2a2a3e", fg="white", padx=15, pady=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tabbed results
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Basic analysis tab
        basic_frame = ttk.Frame(results_notebook)
        results_notebook.add(basic_frame, text="Basic")
        
        self.basic_results = scrolledtext.ScrolledText(basic_frame, bg="#3a3a4e", 
                                                     fg="white", insertbackground="white",
                                                     font=self.body_font)
        self.basic_results.pack(fill=tk.BOTH, expand=True)
        self.basic_results.config(state=tk.DISABLED)
        
        # Advanced analysis tab
        advanced_frame = ttk.Frame(results_notebook)
        results_notebook.add(advanced_frame, text="Advanced")
        
        self.advanced_results = scrolledtext.ScrolledText(advanced_frame, bg="#3a3a4e", 
                                                        fg="white", insertbackground="white",
                                                        font=self.body_font)
        self.advanced_results.pack(fill=tk.BOTH, expand=True)
        self.advanced_results.config(state=tk.DISABLED)
        
        # Visualization tab
        vis_frame = ttk.Frame(results_notebook)
        results_notebook.add(vis_frame, text="Visualization")
        
        # Placeholder for visualizations
        vis_label = tk.Label(vis_frame, text="LSB Visualization will appear here", 
                          bg="#3a3a4e", fg="#aaaaaa", font=self.body_font)
        vis_label.pack(fill=tk.BOTH, expand=True)
    
    def toggle_self_destruct(self):
        if self.self_destruct_var.get():
            self.sd_settings_frame.pack(fill=tk.X, pady=5)
        else:
            self.sd_settings_frame.pack_forget()
    
    def check_password_strength(self, event=None):
        password = self.password.get()
        if not password:
            self.pass_strength.config(text="", fg="#e74c3c")
            return
            
        # Calculate password strength
        strength = 0
        if len(password) >= 8: strength += 1
        if len(password) >= 12: strength += 1
        if any(c.isdigit() for c in password): strength += 1
        if any(c.islower() for c in password): strength += 1
        if any(c.isupper() for c in password): strength += 1
        if any(not c.isalnum() for c in password): strength += 1
        
        # Update display
        if strength < 3:
            self.pass_strength.config(text="Weak", fg="#e74c3c")
        elif strength < 5:
            self.pass_strength.config(text="Medium", fg="#f39c12")
        else:
            self.pass_strength.config(text="Strong", fg="#2ecc71")
    
    # ================== IMAGE HANDLING ===================
    
    def show_placeholder_image(self):
        img = Image.new('RGB', (300, 200), color="#2a2a3e")
        draw = ImageDraw.Draw(img)
        camera_size = 50
        camera_x = (img.width - camera_size) // 2
        camera_y = (img.height - camera_size) // 2 - 10
        draw.rectangle([camera_x, camera_y, camera_x + camera_size, camera_y + camera_size//1.5], 
                     fill="#3a3a4e", outline="#1abc9c", width=2)
        draw.ellipse([camera_x + camera_size//4, camera_y + camera_size//6, 
                    camera_x + 3*camera_size//4, camera_y + 3*camera_size//6], 
                   fill="#1e1e2e", outline="#1abc9c", width=2)
        try:
            font = ImageFont.truetype("arial", 12)
        except:
            font = ImageFont.load_default()
        draw.text((img.width//2, camera_y + camera_size//1.5 + 20), "Select an image", 
                fill="#aaaaaa", font=font, anchor="mt")
        photo = ImageTk.PhotoImage(img)
        self.image_preview.configure(image=photo)
        self.image_preview.image = photo
    
    def show_extract_placeholder(self):
        img = Image.new('RGB', (300, 200), color="#2a2a3e")
        draw = ImageDraw.Draw(img)
        lock_size = 40
        lock_x = (img.width - lock_size) // 2
        lock_y = (img.height - lock_size) // 2 - 10
        draw.rectangle([lock_x, lock_y + lock_size//3, 
                      lock_x + lock_size, lock_y + lock_size], 
                     fill="#3a3a4e", outline="#1abc9c", width=2)
        draw.arc([lock_x - lock_size//4, lock_y, 
                lock_x + lock_size//4, lock_y + lock_size//2], 
               0, 180, fill="#1abc9c", width=2)
        try:
            font = ImageFont.truetype("arial", 12)
        except:
            font = ImageFont.load_default()
        draw.text((img.width//2, lock_y + lock_size + 20), "Select stego image", 
                fill="#aaaaaa", font=font, anchor="mt")
        photo = ImageTk.PhotoImage(img)
        self.stego_preview.configure(image=photo)
        self.stego_preview.image = photo
    
    def show_analyze_placeholder(self):
        img = Image.new('RGB', (300, 200), color="#2a2a3e")
        draw = ImageDraw.Draw(img)
        mag_size = 50
        mag_x = (img.width - mag_size) // 2
        mag_y = (img.height - mag_size) // 2 - 10
        draw.ellipse([mag_x, mag_y, mag_x + mag_size, mag_y + mag_size], 
                   outline="#1abc9c", width=2)
        draw.line([mag_x + mag_size//2, mag_y, mag_x + mag_size, mag_y - mag_size//3], 
                fill="#1abc9c", width=2)
        draw.line([mag_x + mag_size//2, mag_y + mag_size, mag_x + mag_size, mag_y + mag_size + mag_size//3], 
                fill="#1abc9c", width=2)
        try:
            font = ImageFont.truetype("arial", 12)
        except:
            font = ImageFont.load_default()
        draw.text((img.width//2, mag_y + mag_size + 20), "Select image to analyze", 
                fill="#aaaaaa", font=font, anchor="mt")
        photo = ImageTk.PhotoImage(img)
        self.analyze_preview.configure(image=photo)
        self.analyze_preview.image = photo
    
    def show_image_preview(self, path, preview_widget, info_widget):
        try:
            img = Image.open(path)
            width, height = img.size
            max_width = 300
            max_height = 200
            
            if width > max_width or height > max_height:
                ratio = min(max_width/width, max_height/height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), Image.LANCZOS)
            
            photo = ImageTk.PhotoImage(img)
            preview_widget.configure(image=photo)
            preview_widget.image = photo
            
            # Update image info
            size = os.path.getsize(path)
            info_text = f"{width}×{height} | {img.mode} | {size/1024:.1f} KB"
            info_widget.config(text=info_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
    
    # ================== FILE BROWSING ===================
    
    def browse_cover(self):
        filetypes = [("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.cover_path.set(path)
            self.show_image_preview(path, self.image_preview, self.image_info)
            self.update_capacity_meter()
    
    def browse_secret_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            try:
                file_size = os.path.getsize(path)
                self.file_info.config(text=f"{os.path.basename(path)} - {file_size/1024:.1f} KB")
                self.update_capacity_meter(file_size)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def browse_stego(self):
        filetypes = [("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.stego_path.set(path)
            self.show_image_preview(path, self.stego_preview, self.stego_info)
    
    def browse_analyze_image(self):
        filetypes = [("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            self.analyze_path.set(path)
            self.show_image_preview(path, self.analyze_preview, self.analyze_info)
    
    def add_multi_images(self):
        filetypes = [("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        paths = filedialog.askopenfilenames(filetypes=filetypes)
        if paths:
            for path in paths:
                self.cover_list.insert(tk.END, path)
    
    def browse_multi_secret_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.multi_file_path.set(path)
            try:
                file_size = os.path.getsize(path)
                self.multi_file_info.config(text=f"{os.path.basename(path)} - {file_size/1024:.1f} KB")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def browse_output_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.output_dir.set(path)
    
    def add_batch_files(self):
        filetypes = [("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        paths = filedialog.askopenfilenames(filetypes=filetypes)
        if paths:
            for path in paths:
                self.input_list.insert(tk.END, path)
    
    def browse_batch_secret_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.batch_file_path.set(path)
            try:
                file_size = os.path.getsize(path)
                self.batch_file_info.config(text=f"{os.path.basename(path)} - {file_size/1024:.1f} KB")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def browse_batch_output_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.batch_output_dir.set(path)
    
    # ================== OPERATIONS ===================
    
    def start_embedding(self):
        if self.operation_in_progress:
            return
            
        self.operation_in_progress = True
        self.progress_bar.pack(side=tk.RIGHT, padx=20)
        threading.Thread(target=self.embed_data, daemon=True).start()
    
    def start_extraction(self):
        if self.operation_in_progress:
            return
            
        self.operation_in_progress = True
        self.progress_bar.pack(side=tk.RIGHT, padx=20)
        threading.Thread(target=self.extract_data, daemon=True).start()
    
    def start_multi_embedding(self):
        if self.operation_in_progress:
            return
            
        if self.cover_list.size() < 2:
            messagebox.showerror("Error", "Please select at least 2 cover images")
            return
            
        if not self.multi_file_path.get():
            messagebox.showerror("Error", "Please select a file to hide")
            return
            
        if not self.output_dir.get():
            messagebox.showerror("Error", "Please select an output directory")
            return
            
        self.operation_in_progress = True
        self.progress_bar.pack(side=tk.RIGHT, padx=20)
        threading.Thread(target=self.embed_multi_data, daemon=True).start()
    
    def start_batch_processing(self):
        if self.operation_in_progress:
            return
            
        if self.input_list.size() == 0:
            messagebox.showerror("Error", "Please add files to process")
            return
            
        if self.batch_op.get() == "embed" and not self.batch_file_path.get():
            messagebox.showerror("Error", "Please select a file to hide")
            return
            
        if not self.batch_output_dir.get():
            messagebox.showerror("Error", "Please select an output directory")
            return
            
        self.operation_in_progress = True
        self.progress_bar.pack(side=tk.RIGHT, padx=20)
        threading.Thread(target=self.process_batch, daemon=True).start()
    
    def start_analysis(self):
        if self.operation_in_progress:
            return
            
        if not self.analyze_path.get():
            messagebox.showerror("Error", "Please select an image to analyze")
            return
            
        self.operation_in_progress = True
        self.progress_bar.pack(side=tk.RIGHT, padx=20)
        threading.Thread(target=self.analyze_image, daemon=True).start()
    
    # ================== CORE FUNCTIONALITY ===================
    
    def embed_data(self):
        try:
            # Validate inputs
            if not self.cover_path.get():
                messagebox.showerror("Error", "Please select a cover image")
                return
            
            if self.data_type.get() == "text" and not self.text_data.get("1.0", tk.END).strip():
                messagebox.showerror("Error", "Please enter text to hide")
                return
            
            if self.data_type.get() == "file" and not self.file_path.get():
                messagebox.showerror("Error", "Please select a file to hide")
                return
            
            password = self.password.get()
            confirm = self.confirm_password.get()
            if password and password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            # Prepare payload
            self.update_status("Preparing payload...")
            self.progress_var.set(10)
            
            if self.data_type.get() == "text":
                payload = self.text_data.get("1.0", tk.END).encode("utf-8")
                metadata = b"TEXT"  # Metadata identifier
            else:
                with open(self.file_path.get(), "rb") as f:
                    payload = f.read()
                filename = os.path.basename(self.file_path.get())
                metadata = f"FILE:{filename}".encode("utf-8")
            
            # Add self-destruct metadata if enabled
            if self.self_destruct_var.get():
                max_views = int(self.max_views.get())
                days_valid = int(self.days_valid.get())
                expiration = (datetime.now() + timedelta(days=days_valid)).isoformat()
                sd_metadata = {
                    'max_views': max_views,
                    'view_count': 0,
                    'expiration': expiration
                }
                metadata = b"SD:" + json.dumps(sd_metadata).encode() + b":::" + metadata
            
            # Encrypt if password provided
            if password:
                self.update_status("Encrypting data...")
                self.progress_var.set(20)
                payload = self.encrypt_data(payload, password)
                metadata = b"ENC:" + metadata
            
            # Compress payload
            self.update_status("Compressing data...")
            self.progress_var.set(30)
            
            # Set compression level based on UI selection
            comp_level = {
                "Low": 1,
                "Medium": 6,
                "High": 9
            }.get(self.compression_level_var.get(), 6)
            
            payload = zlib.compress(payload, comp_level)
            
            # Prepare full payload (metadata + payload)
            full_payload = metadata + b":::" + payload
            full_payload = base64.b64encode(full_payload)
            
            # Embed data
            output_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("BMP files", "*.bmp")]
            )
            
            if not output_path:
                return
                
            self.update_status("Embedding data...")
            self.progress_var.set(50)
            
            self.embed_lsb(self.cover_path.get(), output_path, full_payload)
            
            # Preserve EXIF metadata
            self.preserve_exif(self.cover_path.get(), output_path)
            
            self.progress_var.set(100)
            self.update_status("Data embedded successfully")
            messagebox.showinfo("Success", f"Data embedded successfully in {output_path}")
            
            # Generate recovery QR code if self-destruct is enabled
            if self.self_destruct_var.get() and password:
                self.generate_recovery_qr(password, sd_metadata)
            
        except Exception as e:
            messagebox.showerror("Error", f"Embedding failed: {str(e)}")
            self.update_status("Embedding failed")
        finally:
            self.operation_in_progress = False
            self.progress_var.set(0)
            self.progress_bar.pack_forget()
    
    def extract_data(self):
        try:
            if not self.stego_path.get():
                messagebox.showerror("Error", "Please select a stego image")
                return
            
            password = self.extract_password.get()
            
            self.update_status("Extracting data...")
            self.progress_var.set(30)
            
            payload = self.extract_lsb(self.stego_path.get())
            
            # Decode payload
            full_payload = base64.b64decode(payload)
            
            # Check self-destruct metadata
            if full_payload.startswith(b"SD:"):
                sd_end = full_payload.find(b":::", 3)
                if sd_end != -1:
                    sd_metadata = json.loads(full_payload[3:sd_end].decode())
                    full_payload = full_payload[sd_end+3:]
                    
                    # Check expiration
                    expiration = datetime.fromisoformat(sd_metadata['expiration'])
                    if datetime.now() > expiration:
                        messagebox.showerror("Error", "This image has expired and can no longer be accessed")
                        return
                    
                    # Check view count
                    if sd_metadata['view_count'] >= sd_metadata['max_views']:
                        messagebox.showerror("Error", "Maximum view count reached")
                        return
                    
                    # Update view count
                    sd_metadata['view_count'] += 1
                    self.update_view_count(self.stego_path.get(), sd_metadata)
                    self.sd_info.config(text=f"Views: {sd_metadata['view_count']}/{sd_metadata['max_views']} | Expires: {expiration.strftime('%Y-%m-%d')}")
            
            # Check if encrypted
            if full_payload.startswith(b"ENC:"):
                if not password:
                    messagebox.showerror("Error", "Password required for decryption")
                    return
                full_payload = full_payload[4:]
                encrypted = True
            else:
                encrypted = False
            
            # Split metadata and payload
            parts = full_payload.split(b":::", 1)
            if len(parts) < 2:
                raise ValueError("Invalid payload format")
                
            metadata, payload = parts
            
            # Decompress
            try:
                payload = zlib.decompress(payload)
                compressed = True
            except:
                compressed = False
            
            # Decrypt if needed
            if encrypted:
                self.update_status("Decrypting data...")
                self.progress_var.set(70)
                payload = self.decrypt_data(payload, password)
            
            self.progress_var.set(90)
            
            # Process based on metadata
            if metadata.startswith(b"TEXT"):
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, payload.decode("utf-8", errors="replace"))
                self.save_btn.config(state=tk.DISABLED)
                self.update_status("Text extracted successfully")
                
            elif metadata.startswith(b"FILE"):
                filename = metadata[5:].decode("utf-8")
                self.extracted_file_data = payload
                self.extracted_filename = filename
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, f"Extracted file: {filename}\nSize: {len(payload)} bytes")
                if compressed:
                    self.output_text.insert(tk.END, "\n(Compressed)")
                self.save_btn.config(state=tk.NORMAL)
                self.update_status("File extracted successfully")
                
            else:
                messagebox.showerror("Error", "Unknown data format")
                
        except Exception as e:
            messagebox.showerror("Error", f"Extraction failed: {str(e)}")
            self.update_status("Extraction failed")
        finally:
            self.progress_var.set(100)
            self.operation_in_progress = False
            self.progress_var.set(0)
            self.progress_bar.pack_forget()
    
    def embed_multi_data(self):
        try:
            # Get all cover image paths
            cover_paths = [self.cover_list.get(i) for i in range(self.cover_list.size())]
            
            # Read secret file
            with open(self.multi_file_path.get(), "rb") as f:
                secret_data = f.read()
            
            # Split data into chunks
            num_chunks = len(cover_paths)
            chunk_size = len(secret_data) // num_chunks
            chunks = [secret_data[i:i+chunk_size] for i in range(0, len(secret_data), chunk_size)]
            
            # Pad last chunk if needed
            if len(chunks) > num_chunks:
                chunks = chunks[:num_chunks]
            elif len(chunks) < num_chunks:
                chunks.extend([b""] * (num_chunks - len(chunks)))
            
            # Process each image
            output_dir = self.output_dir.get()
            os.makedirs(output_dir, exist_ok=True)
            
            total = len(cover_paths)
            for i, path in enumerate(cover_paths):
                self.update_status(f"Processing image {i+1}/{total}...")
                self.progress_var.set(i * 100 / total)
                
                # Prepare metadata
                filename = os.path.basename(path)
                metadata = f"MULTI:{i+1}/{total}:{filename}".encode("utf-8")
                
                # Encrypt if password provided
                password = self.multi_password.get()
                if password:
                    chunk = self.encrypt_data(chunks[i], password)
                    metadata = b"ENC:" + metadata
                else:
                    chunk = chunks[i]
                
                # Compress chunk
                chunk = zlib.compress(chunk)
                
                # Prepare full payload
                full_payload = metadata + b":::" + chunk
                full_payload = base64.b64encode(full_payload)
                
                # Embed in image
                output_path = os.path.join(output_dir, f"stego_{i+1}_{filename}")
                self.embed_lsb(path, output_path, full_payload)
                
                # Preserve EXIF metadata
                self.preserve_exif(path, output_path)
            
            self.progress_var.set(100)
            self.update_status("Data embedded across images successfully")
            messagebox.showinfo("Success", f"Secret data split across {total} images in {output_dir}")
            
            # Generate recovery QR code
            if password:
                recovery_info = {
                    "type": "multi",
                    "num_parts": total,
                    "password": password
                }
                self.generate_recovery_qr(json.dumps(recovery_info))
            
        except Exception as e:
            messagebox.showerror("Error", f"Multi-image embedding failed: {str(e)}")
            self.update_status("Multi-image embedding failed")
        finally:
            self.operation_in_progress = False
            self.progress_var.set(0)
            self.progress_bar.pack_forget()
    
    def process_batch(self):
        try:
            # Get all input paths
            input_paths = [self.input_list.get(i) for i in range(self.input_list.size())]
            output_dir = self.batch_output_dir.get()
            os.makedirs(output_dir, exist_ok=True)
            
            total = len(input_paths)
            for i, path in enumerate(input_paths):
                self.update_status(f"Processing file {i+1}/{total}...")
                self.progress_var.set(i * 100 / total)
                
                if self.batch_op.get() == "embed":
                    # Embedding operation
                    with open(self.batch_file_path.get(), "rb") as f:
                        secret_data = f.read()
                    
                    # Prepare metadata
                    filename = os.path.basename(path)
                    metadata = f"FILE:{os.path.basename(self.batch_file_path.get())}".encode("utf-8")
                    
                    # Encrypt if password provided
                    password = self.batch_password.get()
                    if password:
                        secret_data = self.encrypt_data(secret_data, password)
                        metadata = b"ENC:" + metadata
                    
                    # Compress data
                    secret_data = zlib.compress(secret_data)
                    
                    # Prepare full payload
                    full_payload = metadata + b":::" + secret_data
                    full_payload = base64.b64encode(full_payload)
                    
                    # Embed in image
                    output_path = os.path.join(output_dir, f"stego_{filename}")
                    self.embed_lsb(path, output_path, full_payload)
                    
                    # Preserve EXIF metadata
                    self.preserve_exif(path, output_path)
                    
                else:
                    # Extraction operation
                    payload = self.extract_lsb(path)
                    full_payload = base64.b64decode(payload)
                    
                    # Check if encrypted
                    if full_payload.startswith(b"ENC:"):
                        password = self.batch_password.get()
                        if not password:
                            continue
                        full_payload = full_payload[4:]
                    
                    # Split metadata and payload
                    parts = full_payload.split(b":::", 1)
                    if len(parts) < 2:
                        continue
                    
                    metadata, payload = parts
                    
                    # Decompress
                    try:
                        payload = zlib.decompress(payload)
                    except:
                        pass
                    
                    # Decrypt if needed
                    if full_payload.startswith(b"ENC:"):
                        payload = self.decrypt_data(payload, password)
                    
                    # Process metadata
                    if metadata.startswith(b"FILE:"):
                        filename = metadata[5:].decode("utf-8")
                        output_path = os.path.join(output_dir, filename)
                        with open(output_path, "wb") as f:
                            f.write(payload)
            
            self.progress_var.set(100)
            self.update_status("Batch processing completed")
            messagebox.showinfo("Success", f"Processed {total} files in {output_dir}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Batch processing failed: {str(e)}")
            self.update_status("Batch processing failed")
        finally:
            self.operation_in_progress = False
            self.progress_var.set(0)
            self.progress_bar.pack_forget()
    
    def analyze_image(self):
        try:
            path = self.analyze_path.get()
            self.update_status("Analyzing image...")
            self.progress_var.set(30)
            
            # Perform basic steganalysis
            results = self.basic_steganalysis(path)
            
            # Update UI with results
            self.basic_results.config(state=tk.NORMAL)
            self.basic_results.delete(1.0, tk.END)
            
            self.basic_results.insert(tk.END, f"Image Analysis: {os.path.basename(path)}\n")
            self.basic_results.insert(tk.END, f"Size: {results['width']}x{results['height']} | Format: {results['format']}\n")
            self.basic_results.insert(tk.END, f"Mode: {results['mode']} | Size on disk: {results['size_kb']:.1f} KB\n\n")
            
            self.basic_results.insert(tk.END, "Steganalysis Results:\n")
            self.basic_results.insert(tk.END, f"LSB Uniformity: {results['lsb_uniformity']:.2%}\n")
            self.basic_results.insert(tk.END, f"Chi-Square: {results['chi_square']:.4f}\n")
            self.basic_results.insert(tk.END, f"Likely Contains Hidden Data: {'YES' if results['likely_stego'] else 'NO'}\n")
            
            if results['exif']:
                self.basic_results.insert(tk.END, "\nEXIF Metadata:\n")
                for tag, value in results['exif'].items():
                    self.basic_results.insert(tk.END, f"{tag}: {value}\n")
            
            self.basic_results.config(state=tk.DISABLED)
            
            # Advanced analysis
            self.advanced_results.config(state=tk.NORMAL)
            self.advanced_results.delete(1.0, tk.END)
            
            self.advanced_results.insert(tk.END, "Advanced Analysis:\n")
            self.advanced_results.insert(tk.END, f"Entropy: {results['entropy']:.4f}\n")
            self.advanced_results.insert(tk.END, f"Pixel Value Distribution: {results['pixel_distribution']}\n")
            
            self.advanced_results.config(state=tk.DISABLED)
            
            self.progress_var.set(100)
            self.update_status("Analysis completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.update_status("Analysis failed")
        finally:
            self.operation_in_progress = False
            self.progress_var.set(0)
            self.progress_bar.pack_forget()
    
    # ================== STEGANOGRAPHY METHODS ===================
    
    def embed_lsb(self, image_path, output_path, data):
        img = Image.open(image_path)
        if img.mode not in ['RGB', 'RGBA']:
            img = img.convert('RGB')
            
        width, height = img.size
        max_bytes = (width * height * 3) // 8 - 100
        
        if len(data) > max_bytes:
            raise ValueError(f"Image too small to hold data (max: {max_bytes} bytes, needed: {len(data)} bytes)")
        
        # Convert data to binary
        binary_data = ''.join(format(byte, '08b') for byte in data)
        binary_data += '0' * 8  # Add null terminator
        
        data_index = 0
        pixels = list(img.getdata())
        new_pixels = []
        total_bits = len(binary_data)
        processed = 0
        
        for i, pixel in enumerate(pixels):
            if data_index < len(binary_data):
                new_pixel = []
                for color in pixel[:3]:
                    if data_index >= len(binary_data):
                        new_pixel.append(color)
                        continue
                        
                    color_bin = format(color, '08b')
                    new_color_bin = color_bin[:-1] + binary_data[data_index]
                    new_pixel.append(int(new_color_bin, 2))
                    data_index += 1
                    processed += 1
                    self.progress_var.set(50 + (processed / total_bits) * 40)
                
                # Handle alpha channel if exists
                if len(pixel) == 4:
                    new_pixel.append(pixel[3])
                
                new_pixels.append(tuple(new_pixel))
            else:
                new_pixels.append(pixel)
        
        # Create new image
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path)
        return output_path
    
    def extract_lsb(self, image_path):
        img = Image.open(image_path)
        if img.mode not in ['RGB', 'RGBA']:
            img = img.convert('RGB')
            
        pixels = list(img.getdata())
        binary_data = ''
        total_pixels = len(pixels)
        
        for i, pixel in enumerate(pixels):
            for color in pixel[:3]:
                color_bin = format(color, '08b')
                binary_data += color_bin[-1]
            # Update progress
            self.progress_var.set(30 + (i / total_pixels) * 40)
        
        # Find null terminator
        null_index = binary_data.find('0' * 8)
        if null_index != -1:
            binary_data = binary_data[:null_index]
        
        # Convert to bytes
        data_bytes = bytearray()
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                data_bytes.append(int(byte, 2))
        
        return bytes(data_bytes)
    
    def update_view_count(self, image_path, sd_metadata):
        # This is a simplified implementation
        # In a real application, we would need to update the embedded metadata
        # For demonstration, we'll just save the updated metadata to a file
        metadata_path = image_path + ".meta"
        with open(metadata_path, "w") as f:
            json.dump(sd_metadata, f)
    
    def preserve_exif(self, original_path, new_image_path):
        try:
            original = Image.open(original_path)
            if hasattr(original, '_getexif') and original._getexif() is not None:
                exif_data = original.info['exif']
                new_img = Image.open(new_image_path)
                new_img.save(new_image_path, exif=exif_data)
        except Exception as e:
            print(f"Failed to preserve EXIF: {str(e)}")
    
    def basic_steganalysis(self, image_path):
        img = Image.open(image_path)
        width, height = img.size
        size_kb = os.path.getsize(image_path) / 1024
        
        # Get EXIF data if available
        exif = {}
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                for tag, value in img._getexif().items():
                    if tag in ExifTags.TAGS:
                        exif[ExifTags.TAGS[tag]] = value
        except:
            pass
        
        # Convert to RGB for analysis
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = np.array(img)
        
        # Calculate LSB uniformity
        lsb_values = pixels[:, :, 0] & 1
        lsb_uniformity = np.mean(lsb_values)
        
        # Chi-square test
        observed = np.bincount(pixels.flatten(), minlength=256)
        expected = np.full(256, len(pixels.flatten()) / 256)
        chi_square = np.sum((observed - expected) ** 2 / expected)
        
        # Determine if likely contains stego
        likely_stego = lsb_uniformity > 0.55 or chi_square > 0.8
        
        # Calculate entropy
        hist = np.histogram(pixels, bins=256, range=(0, 255))[0]
        hist = hist / hist.sum()
        entropy = -np.sum(hist * np.log2(hist + 1e-10))
        
        # Pixel value distribution
        pixel_distribution = {
            "mean": np.mean(pixels),
            "std": np.std(pixels),
            "min": np.min(pixels),
            "max": np.max(pixels)
        }
        
        return {
            "width": width,
            "height": height,
            "format": img.format,
            "mode": img.mode,
            "size_kb": size_kb,
            "lsb_uniformity": lsb_uniformity,
            "chi_square": chi_square,
            "likely_stego": likely_stego,
            "entropy": entropy,
            "pixel_distribution": pixel_distribution,
            "exif": exif
        }
    
    # ================== SECURITY METHODS ===================
    
    def encrypt_data(self, data, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return salt + nonce + encryptor.tag + ciphertext
    
    def decrypt_data(self, data, password):
        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def generate_recovery_qr(self, data, sd_metadata=None):
        if sd_metadata:
            # For self-destruct images
            qr_data = {
                "type": "self_destruct",
                "password": data,
                "max_views": sd_metadata['max_views'],
                "expiration": sd_metadata['expiration']
            }
        else:
            # For multi-image or other cases
            qr_data = data
        
        if not isinstance(qr_data, str):
            qr_data = json.dumps(qr_data)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Show QR in a new window
        qr_window = tk.Toplevel(self)
        qr_window.title("Recovery QR Code")
        qr_window.geometry("400x450")
        
        # Convert to PhotoImage
        photo = ImageTk.PhotoImage(qr_img)
        
        qr_label = tk.Label(qr_window, image=photo)
        qr_label.image = photo
        qr_label.pack(padx=20, pady=20)
        
        tk.Label(qr_window, text="Scan this QR code for recovery information", 
               font=self.body_font).pack(pady=10)
    
    def scan_qr(self):
        # Placeholder for QR scanning functionality
        messagebox.showinfo("QR Scan", "QR scanning functionality would be implemented here")
    
    # ================== UTILITY METHODS ===================
    
    def toggle_data_type(self):
        if self.data_type.get() == "text":
            self.text_frame.pack(fill=tk.BOTH, expand=True)
            self.file_frame.pack_forget()
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack(fill=tk.BOTH, expand=True)
        
        # Update capacity meter
        self.update_capacity_meter()
    
    def clear_default_text(self, event):
        if self.text_data.get("1.0", "end-1c") == "Enter your secret message here...":
            self.text_data.delete("1.0", tk.END)
    
    def clear_cover(self):
        self.cover_path.set("")
        self.show_placeholder_image()
        self.image_info.config(text="No image loaded")
        self.capacity_meter["value"] = 0
        self.capacity_label.config(text="0%")
    
    def clear_stego(self):
        self.stego_path.set("")
        self.show_extract_placeholder()
        self.stego_info.config(text="No image loaded")
        self.output_text.delete(1.0, tk.END)
        self.save_btn.config(state=tk.DISABLED)
        self.sd_info.config(text="")
    
    def remove_multi_image(self):
        selected = self.cover_list.curselection()
        if selected:
            self.cover_list.delete(selected[0])
    
    def remove_batch_file(self):
        selected = self.input_list.curselection()
        if selected:
            self.input_list.delete(selected[0])
    
    def update_capacity_meter(self, data_size=None):
        if not self.cover_path.get():
            self.capacity_meter["value"] = 0
            self.capacity_label.config(text="0%")
            return
            
        try:
            img = Image.open(self.cover_path.get())
            if img.mode not in ['RGB', 'RGBA']:
                img = img.convert('RGB')
            
            width, height = img.size
            max_bytes = (width * height * 3) // 8
            
            if data_size is None:
                if self.data_type.get() == "text":
                    data = self.text_data.get("1.0", tk.END).encode("utf-8")
                    data_size = len(data)
                elif self.data_type.get() == "file" and self.file_path.get():
                    data_size = os.path.getsize(self.file_path.get())
                else:
                    self.capacity_meter["value"] = 0
                    self.capacity_label.config(text="0%")
                    return
            
            percentage = min(100, (data_size / max_bytes) * 100)
            self.capacity_meter["value"] = percentage
            self.capacity_label.config(text=f"{percentage:.1f}%")
            
            # Color coding
            if percentage > 90:
                self.capacity_meter.configure(style="red.Horizontal.TProgressbar")
            elif percentage > 70:
                self.capacity_meter.configure(style="orange.Horizontal.TProgressbar")
            else:
                self.capacity_meter.configure(style="green.Horizontal.TProgressbar")
                
        except Exception as e:
            print(f"Capacity error: {e}")
    
    def save_extracted(self):
        if not self.extracted_file_data:
            return
            
        path = filedialog.asksaveasfilename(
            initialfile=self.extracted_filename,
            filetypes=[("All files", "*.*")]
        )
        
        if path:
            with open(path, "wb") as f:
                f.write(self.extracted_file_data)
            messagebox.showinfo("Success", f"File saved successfully: {path}")
    
    def setup_drag_drop(self):
        # Enable drag and drop for image preview
        self.image_preview.drop_target_register(DND_FILES)
        self.image_preview.dnd_bind('<<Drop>>', self.handle_drop)
    
    def handle_drop(self, event):
        files = self.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            if file_path.lower().endswith(('.png', '.bmp', '.tiff', '.jpg', '.jpeg')):
                self.cover_path.set(file_path)
                self.show_image_preview(file_path, self.image_preview, self.image_info)
                self.update_capacity_meter()
    
    def handle_stego_drop(self, event):
        files = self.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            if file_path.lower().endswith(('.png', '.bmp', '.tiff', '.jpg', '.jpeg')):
                self.stego_path.set(file_path)
                self.show_image_preview(file_path, self.stego_preview, self.stego_info)
    
    def update_status(self, message):
        self.status_var.set(f"Status: {message}")
        self.update_idletasks()
    
    # ================== MENU FUNCTIONS ===================
    
    def new_session(self):
        self.clear_cover()
        self.clear_stego()
        self.cover_list.delete(0, tk.END)
        self.input_list.delete(0, tk.END)
        self.text_data.delete(1.0, tk.END)
        self.password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.extract_password.delete(0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.sd_info.config(text="")
        self.status_var.set("Ready")
        self.progress_var.set(0)
    
    def save_config(self):
        # Placeholder for configuration saving
        messagebox.showinfo("Save Configuration", "Configuration saving would be implemented here")
    
    def load_config(self):
        # Placeholder for configuration loading
        messagebox.showinfo("Load Configuration", "Configuration loading would be implemented here")
    
    def show_password_generator(self):
        # Placeholder for password generator
        messagebox.showinfo("Password Generator", "Password generator would be implemented here")
    
    def show_file_shredder(self):
        # Placeholder for file shredder
        messagebox.showinfo("File Shredder", "File shredder would be implemented here")
    
    def show_settings(self):
        # Placeholder for settings dialog
        messagebox.showinfo("Settings", "Application settings would be configured here")
    
    def show_user_guide(self):
        # Placeholder for user guide
        messagebox.showinfo("User Guide", "User guide documentation would be displayed here")
    
    def show_about(self):
        messagebox.showinfo("About SecurImage Pro", 
                          "SecurImage Pro - Advanced Steganography Tool\n\n"
                          "Version 2.0\n"
                          "© 2023 Security Solutions Inc.\n\n"
                          "A professional tool for securely hiding data within images.")

if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
