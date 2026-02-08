"""
Windows 10 Antivirus - UI Components
Reusable GUI components
"""
import customtkinter as ctk
from typing import Callable, Optional
from config import UI_CONFIG


class StatusCard(ctk.CTkFrame):
    """Status card component"""
    
    def __init__(self, parent, title: str, value: str = "0", 
                 status: str = "normal", icon: str = "🛡️", **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(corner_radius=15, fg_color=("gray90", "gray17"))
        
        # Icon and title
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(header, text=icon, font=("Segoe UI Emoji", 24)).pack(side="left")
        ctk.CTkLabel(header, text=title, font=("Segoe UI", 14, "bold")).pack(side="left", padx=10)
        
        # Value
        colors = {
            "normal": UI_CONFIG["success_color"],
            "warning": UI_CONFIG["warning_color"],
            "danger": UI_CONFIG["danger_color"]
        }
        
        self.value_label = ctk.CTkLabel(
            self, text=value, 
            font=("Segoe UI", 28, "bold"),
            text_color=colors.get(status, UI_CONFIG["accent_color"])
        )
        self.value_label.pack(padx=15, pady=(0, 15))
    
    def update_value(self, value: str, status: str = "normal"):
        """Update the displayed value"""
        colors = {
            "normal": UI_CONFIG["success_color"],
            "warning": UI_CONFIG["warning_color"],
            "danger": UI_CONFIG["danger_color"]
        }
        self.value_label.configure(text=value, text_color=colors.get(status))


class ProtectionToggle(ctk.CTkFrame):
    """Protection toggle component"""
    
    def __init__(self, parent, title: str, description: str = "",
                 icon: str = "🔒", on_toggle: Callable = None, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(corner_radius=10, fg_color=("gray90", "gray17"))
        self.on_toggle = on_toggle
        
        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=10)
        
        # Left side
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(left, text=f"{icon} {title}", 
                    font=("Segoe UI", 14, "bold")).pack(anchor="w")
        
        if description:
            ctk.CTkLabel(left, text=description,
                        font=("Segoe UI", 11),
                        text_color="gray").pack(anchor="w")
        
        # Toggle switch
        self.switch = ctk.CTkSwitch(
            content, text="", width=50,
            command=self._on_toggle_internal,
            progress_color=UI_CONFIG["accent_color"]
        )
        self.switch.pack(side="right")
    
    def _on_toggle_internal(self):
        if self.on_toggle:
            self.on_toggle(self.switch.get())
    
    def set_state(self, enabled: bool):
        if enabled:
            self.switch.select()
        else:
            self.switch.deselect()


class ActionButton(ctk.CTkButton):
    """Styled action button"""
    
    def __init__(self, parent, text: str, icon: str = "",
                 style: str = "primary", **kwargs):
        
        colors = {
            "primary": UI_CONFIG["accent_color"],
            "danger": UI_CONFIG["danger_color"],
            "warning": UI_CONFIG["warning_color"],
            "success": UI_CONFIG["success_color"]
        }
        
        display_text = f"{icon} {text}" if icon else text
        
        super().__init__(
            parent, text=display_text,
            corner_radius=10, height=40,
            fg_color=colors.get(style, UI_CONFIG["accent_color"]),
            hover_color=self._darken_color(colors.get(style)),
            font=("Segoe UI", 13, "bold"),
            **kwargs
        )
    
    def _darken_color(self, color: str) -> str:
        if not color:
            return "#333333"
        try:
            r = max(0, int(color[1:3], 16) - 30)
            g = max(0, int(color[3:5], 16) - 30)
            b = max(0, int(color[5:7], 16) - 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        except:
            return "#333333"


class ScanProgressBar(ctk.CTkFrame):
    """Scan progress component"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(corner_radius=10, fg_color=("gray90", "gray17"))
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self, text="Ready to scan",
            font=("Segoe UI", 12)
        )
        self.status_label.pack(padx=15, pady=(15, 5), anchor="w")
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(
            self, width=400, height=12,
            progress_color=UI_CONFIG["accent_color"]
        )
        self.progress.pack(padx=15, pady=5, fill="x")
        self.progress.set(0)
        
        # File label
        self.file_label = ctk.CTkLabel(
            self, text="",
            font=("Segoe UI", 10),
            text_color="gray"
        )
        self.file_label.pack(padx=15, pady=(0, 15), anchor="w")
    
    def update_progress(self, progress: float, status: str = "", file: str = ""):
        self.progress.set(progress / 100)
        if status:
            self.status_label.configure(text=status)
        if file:
            # Truncate long paths
            if len(file) > 60:
                file = "..." + file[-57:]
            self.file_label.configure(text=file)
    
    def reset(self):
        self.progress.set(0)
        self.status_label.configure(text="Ready to scan")
        self.file_label.configure(text="")
