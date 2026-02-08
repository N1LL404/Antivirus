"""
Windows 10 Antivirus - Main Dashboard
Primary application window
"""
import customtkinter as ctk
import threading
from datetime import datetime
from typing import Optional

from config import UI_CONFIG, APP_NAME, APP_VERSION
from gui.components.cards import StatusCard, ProtectionToggle, ActionButton, ScanProgressBar
from core.scanner import scanner
from core.realtime import realtime_protection
from core.quarantine import quarantine_manager
from database import db
from loguru import logger


class Dashboard(ctk.CTk):
    """Main dashboard window"""
    
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1100x750")
        self.minsize(900, 600)
        
        # Theme
        ctk.set_appearance_mode(UI_CONFIG.get("theme", "dark"))
        ctk.set_default_color_theme("blue")
        
        self._scan_thread = None
        self._is_scanning = False
        
        self._create_ui()
        self._load_status()
    
    def _create_ui(self):
        """Create the main UI"""
        # Main container
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self._create_header()
        
        # Content area with sidebar
        content = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, pady=(20, 0))
        
        # Sidebar
        self._create_sidebar(content)
        
        # Main content
        self.content_area = ctk.CTkFrame(content, fg_color="transparent")
        self.content_area.pack(side="left", fill="both", expand=True, padx=(20, 0))
        
        # Show dashboard by default
        self._show_dashboard()
    
    def _create_header(self):
        """Create header section"""
        header = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        header.pack(fill="x")
        
        # Logo and title
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame, text="🛡️", 
            font=("Segoe UI Emoji", 36)
        ).pack(side="left")
        
        name_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        name_frame.pack(side="left", padx=15)
        
        ctk.CTkLabel(
            name_frame, text=APP_NAME,
            font=("Segoe UI", 24, "bold")
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            name_frame, text=f"Version {APP_VERSION}",
            font=("Segoe UI", 11),
            text_color="gray"
        ).pack(anchor="w")
        
        # Status indicator
        status_frame = ctk.CTkFrame(header, fg_color="transparent")
        status_frame.pack(side="right")
        
        self.protection_status = ctk.CTkLabel(
            status_frame, text="● PROTECTED",
            font=("Segoe UI", 16, "bold"),
            text_color=UI_CONFIG["success_color"]
        )
        self.protection_status.pack(side="right")
    
    def _create_sidebar(self, parent):
        """Create navigation sidebar"""
        sidebar = ctk.CTkFrame(parent, width=200, corner_radius=15)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        
        nav_items = [
            ("🏠", "Dashboard", self._show_dashboard),
            ("🔍", "Scan", self._show_scan),
            ("🛡️", "Protection", self._show_protection),
            ("📁", "Quarantine", self._show_quarantine),
            ("🔧", "Tools", self._show_tools),
            ("⚙️", "Settings", self._show_settings),
        ]
        
        for icon, text, command in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=f"{icon}  {text}",
                font=("Segoe UI", 14),
                height=45, anchor="w",
                fg_color="transparent",
                hover_color=("gray80", "gray30"),
                text_color=("gray20", "gray90"),
                command=command
            )
            btn.pack(fill="x", padx=10, pady=5)
    
    def _clear_content(self):
        """Clear content area"""
        for widget in self.content_area.winfo_children():
            widget.destroy()
    
    def _show_dashboard(self):
        """Show dashboard view"""
        self._clear_content()
        
        # Stats cards
        stats_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 20))
        
        # Get stats
        threats = db.get_threats()
        quarantined = quarantine_manager.list_quarantine()
        
        cards = [
            ("Threats Today", str(len([t for t in threats if t.get('detected_at', '').startswith(datetime.now().strftime('%Y-%m-%d'))])), "normal", "🦠"),
            ("Files Scanned", str(scanner.get_status().get('files_scanned', 0)), "normal", "📄"),
            ("Quarantined", str(len(quarantined)), "warning" if quarantined else "normal", "📦"),
            ("Protection", "Active" if realtime_protection.is_running() else "Inactive", "normal" if realtime_protection.is_running() else "danger", "🔒"),
        ]
        
        for i, (title, value, status, icon) in enumerate(cards):
            card = StatusCard(stats_frame, title, value, status, icon)
            card.pack(side="left", fill="both", expand=True, padx=(0 if i == 0 else 10, 0))
        
        # Quick actions
        actions_label = ctk.CTkLabel(
            self.content_area, text="Quick Actions",
            font=("Segoe UI", 18, "bold")
        )
        actions_label.pack(anchor="w", pady=(20, 10))
        
        actions_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
        actions_frame.pack(fill="x")
        
        ActionButton(actions_frame, "Quick Scan", "⚡", command=lambda: self._start_scan("quick")).pack(side="left", padx=(0, 10))
        ActionButton(actions_frame, "Full Scan", "🔍", command=lambda: self._start_scan("full")).pack(side="left", padx=(0, 10))
        ActionButton(actions_frame, "Update", "🔄", style="success").pack(side="left")
        
        # Progress bar
        self.progress_bar = ScanProgressBar(self.content_area)
        self.progress_bar.pack(fill="x", pady=(20, 0))
        
        # Recent activity
        activity_label = ctk.CTkLabel(
            self.content_area, text="Recent Activity",
            font=("Segoe UI", 18, "bold")
        )
        activity_label.pack(anchor="w", pady=(30, 10))
        
        activity_frame = ctk.CTkFrame(self.content_area, corner_radius=15)
        activity_frame.pack(fill="both", expand=True)
        
        logs = db.get_activity_logs(10)
        if logs:
            for log in logs[:5]:
                log_row = ctk.CTkFrame(activity_frame, fg_color="transparent")
                log_row.pack(fill="x", padx=15, pady=5)
                
                ctk.CTkLabel(log_row, text=log.get('timestamp', '')[:16], 
                           font=("Consolas", 10), text_color="gray").pack(side="left")
                ctk.CTkLabel(log_row, text=f"[{log.get('component', '')}]",
                           font=("Segoe UI", 11)).pack(side="left", padx=10)
                ctk.CTkLabel(log_row, text=log.get('message', ''),
                           font=("Segoe UI", 11)).pack(side="left")
        else:
            ctk.CTkLabel(activity_frame, text="No recent activity",
                        font=("Segoe UI", 12), text_color="gray").pack(pady=30)
    
    def _show_scan(self):
        """Show scan view"""
        self._clear_content()
        
        ctk.CTkLabel(self.content_area, text="Virus Scan",
                    font=("Segoe UI", 24, "bold")).pack(anchor="w")
        
        # Scan options
        options = ctk.CTkFrame(self.content_area, corner_radius=15)
        options.pack(fill="x", pady=20)
        
        scans = [
            ("Quick Scan", "Scans common threat locations", "quick"),
            ("Full Scan", "Complete system scan", "full"),
            ("Custom Scan", "Select files/folders to scan", "custom"),
        ]
        
        for title, desc, scan_type in scans:
            row = ctk.CTkFrame(options, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=10)
            
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left")
            
            ctk.CTkLabel(info, text=title, font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=desc, font=("Segoe UI", 11), text_color="gray").pack(anchor="w")
            
            ActionButton(row, "Start", command=lambda t=scan_type: self._start_scan(t)).pack(side="right")
        
        # Progress
        self.scan_progress = ScanProgressBar(self.content_area)
        self.scan_progress.pack(fill="x", pady=20)
    
    def _show_protection(self):
        """Show protection settings"""
        self._clear_content()
        
        ctk.CTkLabel(self.content_area, text="Protection Settings",
                    font=("Segoe UI", 24, "bold")).pack(anchor="w")
        
        protections = [
            ("Real-time Protection", "Monitor files in real-time", "🛡️", realtime_protection.is_running()),
            ("USB Protection", "Auto-scan USB drives", "💾", True),
            ("Web Protection", "Block malicious websites", "🌐", True),
            ("Firewall", "Monitor network connections", "🔥", True),
            ("Anti-Keylogger", "Detect keylogging attempts", "⌨️", True),
        ]
        
        for title, desc, icon, enabled in protections:
            toggle = ProtectionToggle(
                self.content_area, title, desc, icon,
                on_toggle=lambda state, t=title: self._toggle_protection(t, state)
            )
            toggle.pack(fill="x", pady=5)
            toggle.set_state(enabled)
    
    def _show_quarantine(self):
        """Show quarantine view"""
        self._clear_content()
        
        ctk.CTkLabel(self.content_area, text="Quarantine",
                    font=("Segoe UI", 24, "bold")).pack(anchor="w")
        
        items = quarantine_manager.list_quarantine()
        
        if items:
            for item in items[:10]:
                row = ctk.CTkFrame(self.content_area, corner_radius=10)
                row.pack(fill="x", pady=5)
                
                info = ctk.CTkFrame(row, fg_color="transparent")
                info.pack(side="left", fill="x", expand=True, padx=15, pady=10)
                
                ctk.CTkLabel(info, text=item.get('original_name', 'Unknown'),
                           font=("Segoe UI", 12, "bold")).pack(anchor="w")
                ctk.CTkLabel(info, text=item.get('threat_name', 'Malware'),
                           font=("Segoe UI", 10), text_color="orange").pack(anchor="w")
                
                ActionButton(row, "Restore", style="warning",
                           command=lambda i=item: quarantine_manager.restore_file(i['id'])).pack(side="right", padx=(0, 10), pady=10)
                ActionButton(row, "Delete", style="danger",
                           command=lambda i=item: quarantine_manager.delete_quarantine(i['id'])).pack(side="right", pady=10)
        else:
            ctk.CTkLabel(self.content_area, text="No quarantined items",
                        font=("Segoe UI", 14), text_color="gray").pack(pady=50)
    
    def _show_tools(self):
        """Show tools view"""
        self._clear_content()
        
        ctk.CTkLabel(self.content_area, text="System Tools",
                    font=("Segoe UI", 24, "bold")).pack(anchor="w")
        
        tools = [
            ("Registry Cleaner", "Clean invalid registry entries", "🔧"),
            ("Disk Defragmenter", "Optimize disk performance", "💿"),
            ("Secure Delete", "Permanently shred files", "🗑️"),
            ("Backup", "Backup important files", "💾"),
            ("Rescue Mode", "Emergency malware removal", "🚨"),
        ]
        
        for title, desc, icon in tools:
            row = ctk.CTkFrame(self.content_area, corner_radius=10)
            row.pack(fill="x", pady=5)
            
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", padx=15, pady=15)
            
            ctk.CTkLabel(info, text=f"{icon} {title}",
                        font=("Segoe UI", 14, "bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=desc,
                        font=("Segoe UI", 11), text_color="gray").pack(anchor="w")
            
            ActionButton(row, "Open", command=lambda t=title: logger.info(f"Opening {t}")).pack(side="right", padx=15, pady=15)
    
    def _show_settings(self):
        """Show settings view"""
        self._clear_content()
        
        ctk.CTkLabel(self.content_area, text="Settings",
                    font=("Segoe UI", 24, "bold")).pack(anchor="w")
        
        # Theme
        theme_frame = ctk.CTkFrame(self.content_area, corner_radius=10)
        theme_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(theme_frame, text="Theme",
                    font=("Segoe UI", 14, "bold")).pack(side="left", padx=15, pady=15)
        
        theme_var = ctk.StringVar(value="dark")
        ctk.CTkSegmentedButton(
            theme_frame, values=["Light", "Dark", "System"],
            variable=theme_var,
            command=lambda v: ctk.set_appearance_mode(v.lower())
        ).pack(side="right", padx=15, pady=15)
    
    def _start_scan(self, scan_type: str):
        """Start a scan"""
        if self._is_scanning:
            return
        
        self._is_scanning = True
        
        def run():
            try:
                def on_progress(scanned, total, file_path):
                    progress = int((scanned / total) * 100) if total > 0 else 0
                    self.after(0, lambda: self._update_progress(file_path, progress))
                
                if scan_type == "quick":
                    scanner.quick_scan(on_progress=on_progress)
                elif scan_type == "full":
                    scanner.full_scan(on_progress=on_progress)
                
                self.after(0, self._scan_complete)
            finally:
                self._is_scanning = False
        
        self._scan_thread = threading.Thread(target=run, daemon=True)
        self._scan_thread.start()
    
    def _update_progress(self, file: str, progress: int):
        """Update scan progress"""
        if hasattr(self, 'progress_bar'):
            self.progress_bar.update_progress(progress, f"Scanning... {progress}%", file)
        if hasattr(self, 'scan_progress'):
            self.scan_progress.update_progress(progress, f"Scanning... {progress}%", file)
    
    def _scan_complete(self):
        """Handle scan completion"""
        if hasattr(self, 'progress_bar'):
            self.progress_bar.update_progress(100, "Scan complete!", "")
        if hasattr(self, 'scan_progress'):
            self.scan_progress.update_progress(100, "Scan complete!", "")
        
        logger.info("Scan completed")
    
    def _toggle_protection(self, name: str, state: bool):
        """Toggle protection feature"""
        logger.info(f"Toggled {name}: {'ON' if state else 'OFF'}")
        
        if name == "Real-time Protection":
            if state:
                realtime_protection.start()
            else:
                realtime_protection.stop()
    
    def _load_status(self):
        """Load current protection status"""
        if realtime_protection.is_running():
            self.protection_status.configure(
                text="● PROTECTED",
                text_color=UI_CONFIG["success_color"]
            )
        else:
            self.protection_status.configure(
                text="● UNPROTECTED",
                text_color=UI_CONFIG["danger_color"]
            )


def run_dashboard():
    """Run the dashboard application"""
    app = Dashboard()
    app.mainloop()
