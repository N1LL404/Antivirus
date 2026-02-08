"""
Windows 10 Antivirus - System Tray
System tray icon and menu
"""
import threading
from typing import Callable, Optional
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item

from config import UI_CONFIG
from loguru import logger


class SystemTray:
    """System tray icon management"""
    
    def __init__(self):
        self._icon = None
        self._is_running = False
        self._thread = None
        
        # Callbacks
        self._on_open_dashboard: Optional[Callable] = None
        self._on_quick_scan: Optional[Callable] = None
        self._on_exit: Optional[Callable] = None
        
        self._status = "protected"  # protected, warning, danger
    
    def _create_icon_image(self, status: str = "protected") -> Image:
        """Create tray icon image"""
        colors = {
            "protected": UI_CONFIG["success_color"],
            "warning": UI_CONFIG["warning_color"],
            "danger": UI_CONFIG["danger_color"]
        }
        
        color = colors.get(status, colors["protected"])
        
        # Create shield icon
        size = 64
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw shield shape
        points = [
            (size//2, 5),       # Top
            (size-5, 20),      # Top right
            (size-5, 40),      # Middle right
            (size//2, size-5), # Bottom
            (5, 40),           # Middle left
            (5, 20),           # Top left
        ]
        
        draw.polygon(points, fill=color, outline=color)
        
        # Draw checkmark if protected
        if status == "protected":
            draw.line([(20, 35), (28, 45), (44, 25)], fill="white", width=4)
        elif status == "warning":
            draw.text((size//2-5, 20), "!", fill="white")
        elif status == "danger":
            draw.text((size//2-6, 20), "X", fill="white")
        
        return img
    
    def _build_menu(self) -> pystray.Menu:
        """Build tray context menu"""
        return pystray.Menu(
            item("eScan Antivirus", self._on_open, default=True),
            item("─────────────", None, enabled=False),
            item("Quick Scan", lambda icon, item: self._on_scan(icon, item)),
            item("Full Scan", lambda icon, item: self._on_scan(icon, item, full=True)),
            item("─────────────", None, enabled=False),
            item("Status: Protected", None, enabled=False),
            item("─────────────", None, enabled=False),
            item("Exit", self._on_quit),
        )
    
    def _on_open(self, icon=None, item=None):
        """Open dashboard callback"""
        if self._on_open_dashboard:
            self._on_open_dashboard()
    
    def _on_scan(self, icon=None, item=None, full=False):
        """Quick scan callback"""
        if self._on_quick_scan:
            self._on_quick_scan(full)
    
    def _on_quit(self, icon=None, item=None):
        """Exit callback"""
        self.stop()
        if self._on_exit:
            self._on_exit()
    
    def _run_tray(self):
        """Run tray icon in background"""
        self._icon = pystray.Icon(
            "eScan",
            self._create_icon_image(self._status),
            "eScan Antivirus - Protected",
            self._build_menu()
        )
        self._icon.run()
    
    def start(self, on_open: Callable = None, on_scan: Callable = None,
              on_exit: Callable = None):
        """Start system tray"""
        if self._is_running:
            return
        
        self._on_open_dashboard = on_open
        self._on_quick_scan = on_scan
        self._on_exit = on_exit
        
        self._is_running = True
        self._thread = threading.Thread(target=self._run_tray, daemon=True)
        self._thread.start()
        
        logger.info("System tray started")
    
    def stop(self):
        """Stop system tray"""
        if self._icon:
            self._icon.stop()
        self._is_running = False
    
    def update_status(self, status: str, tooltip: str = None):
        """Update tray icon status"""
        self._status = status
        
        if self._icon:
            self._icon.icon = self._create_icon_image(status)
            if tooltip:
                self._icon.title = tooltip
    
    def show_notification(self, title: str, message: str):
        """Show system notification"""
        if self._icon:
            self._icon.notify(message, title)


# Global tray instance
system_tray = SystemTray()
