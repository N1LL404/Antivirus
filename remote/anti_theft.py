"""
Windows 10 Antivirus - Anti-Theft
Remote lock and wipe functionality
"""
import os
import json
import threading
import time
import shutil
from typing import Dict, Callable, Optional, List
from datetime import datetime
from pathlib import Path

from config import ANTITHEFT_CONFIG, DATA_DIR
from database import db
from loguru import logger


class AntiTheft:
    """Anti-theft protection with remote lock and wipe"""
    
    def __init__(self):
        self._is_enabled = False
        self._is_locked = False
        self._command_check_thread = None
        self._config_file = DATA_DIR / "antitheft_config.json"
        self._pending_commands: List[Dict] = []
        self._on_command: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Load saved config
        self._load_config()
    
    def _load_config(self):
        """Load anti-theft configuration"""
        if self._config_file.exists():
            try:
                with open(self._config_file, 'r') as f:
                    config = json.load(f)
                    self._is_enabled = config.get('enabled', False)
            except:
                pass
    
    def _save_config(self):
        """Save anti-theft configuration"""
        try:
            with open(self._config_file, 'w') as f:
                json.dump({
                    'enabled': self._is_enabled
                }, f)
        except:
            pass
    
    def enable(self, server_url: str = None):
        """Enable anti-theft protection"""
        self._is_enabled = True
        self._save_config()
        
        logger.info("🔐 Anti-theft protection ENABLED")
        db.log_activity("antitheft", "Enabled", severity="info")
    
    def disable(self):
        """Disable anti-theft protection"""
        self._is_enabled = False
        self._save_config()
        
        logger.info("Anti-theft protection DISABLED")
        db.log_activity("antitheft", "Disabled", severity="warning")
    
    def lock_device(self, message: str = "This device has been locked.") -> bool:
        """
        Lock the device
        
        Args:
            message: Message to display on lock screen
        
        Returns:
            True if lock was successful
        """
        try:
            import ctypes
            
            logger.warning("LOCKING DEVICE")
            db.log_activity("antitheft", "Device locked", severity="critical")
            
            self._is_locked = True
            
            # Lock the workstation
            ctypes.windll.user32.LockWorkStation()
            
            return True
            
        except Exception as e:
            logger.error(f"Lock error: {e}")
            return False
    
    def wipe_data(self, paths: List[str] = None, secure: bool = True) -> Dict:
        """
        Wipe sensitive data from the device
        
        Args:
            paths: Specific paths to wipe (uses defaults if None)
            secure: Use secure deletion (multiple passes)
        
        Returns:
            Wipe summary
        """
        try:
            from utilities.secure_delete import secure_delete
            
            logger.warning("⚠️ INITIATING DATA WIPE")
            db.log_activity("antitheft", "Data wipe initiated", severity="critical")
            
            # Default paths to wipe
            if paths is None:
                paths = [
                    os.path.expanduser("~\\Documents"),
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Pictures"),
                ]
            
            wiped = 0
            failed = 0
            
            for path in paths:
                if os.path.exists(path):
                    try:
                        if secure:
                            result = secure_delete.shred_folder(path, passes=3)
                            wiped += result.get('files_shredded', 0)
                            failed += result.get('files_failed', 0)
                        else:
                            shutil.rmtree(path, ignore_errors=True)
                            wiped += 1
                    except Exception as e:
                        logger.error(f"Wipe error for {path}: {e}")
                        failed += 1
            
            # Also clear browser data
            self._clear_browser_data()
            
            summary = {
                "files_wiped": wiped,
                "failed": failed,
                "paths_processed": len(paths),
                "wiped_at": datetime.now().isoformat()
            }
            
            logger.info(f"Data wipe complete: {wiped} files wiped")
            db.log_activity("antitheft", f"Wipe complete: {wiped} files", severity="critical")
            
            return summary
            
        except Exception as e:
            logger.error(f"Wipe error: {e}")
            return {"error": str(e)}
    
    def _clear_browser_data(self):
        """Clear browser history and data"""
        try:
            browser_paths = [
                # Chrome
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"),
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
                # Firefox
                os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
                # Edge
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"),
            ]
            
            for path in browser_paths:
                if os.path.exists(path):
                    try:
                        if os.path.isfile(path):
                            os.unlink(path)
                        else:
                            shutil.rmtree(path, ignore_errors=True)
                    except:
                        pass
            
            logger.info("Cleared browser data")
            
        except Exception as e:
            logger.error(f"Clear browser data error: {e}")
    
    def play_alarm(self, duration: int = 30) -> bool:
        """
        Play alarm sound on the device
        
        Args:
            duration: Duration in seconds
        """
        try:
            import winsound
            
            logger.warning("PLAYING ALARM")
            db.log_activity("antitheft", "Alarm triggered", severity="warning")
            
            # Play repeating beeps
            end_time = time.time() + duration
            while time.time() < end_time:
                winsound.Beep(1000, 500)  # 1000 Hz for 500 ms
                time.sleep(0.1)
            
            return True
            
        except Exception as e:
            logger.error(f"Alarm error: {e}")
            return False
    
    def take_screenshot(self) -> Optional[str]:
        """Take a screenshot (for tracking)"""
        try:
            from PIL import ImageGrab
            
            screenshot = ImageGrab.grab()
            
            screenshot_dir = DATA_DIR / "screenshots"
            screenshot_dir.mkdir(exist_ok=True)
            
            filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath = screenshot_dir / filename
            
            screenshot.save(filepath)
            
            logger.info(f"Screenshot saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Screenshot error: {e}")
            return None
    
    def get_device_info(self) -> Dict:
        """Get device information for tracking"""
        import platform
        import socket
        import uuid
        
        try:
            info = {
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "version": platform.version(),
                "machine": platform.machine(),
                "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                        for ele in range(0,8*6,8)][::-1]),
                "local_ip": socket.gethostbyname(socket.gethostname()),
                "timestamp": datetime.now().isoformat()
            }
            
            return info
            
        except Exception as e:
            return {"error": str(e)}
    
    def add_command(self, command: str, params: Dict = None):
        """
        Add a command to be executed
        (For testing - in production this would come from server)
        """
        with self._lock:
            self._pending_commands.append({
                "command": command,
                "params": params or {},
                "added_at": datetime.now().isoformat()
            })
    
    def process_commands(self):
        """Process pending commands"""
        with self._lock:
            commands = self._pending_commands.copy()
            self._pending_commands.clear()
        
        for cmd in commands:
            command = cmd['command']
            params = cmd['params']
            
            logger.info(f"Processing anti-theft command: {command}")
            
            if command == "lock":
                self.lock_device(params.get('message', ''))
            elif command == "wipe":
                self.wipe_data(params.get('paths'), params.get('secure', True))
            elif command == "alarm":
                self.play_alarm(params.get('duration', 30))
            elif command == "screenshot":
                self.take_screenshot()
            elif command == "locate":
                # Get device info for tracking
                info = self.get_device_info()
                if self._on_command:
                    self._on_command('locate', info)
    
    def get_status(self) -> Dict:
        """Get anti-theft status"""
        return {
            "enabled": self._is_enabled,
            "is_locked": self._is_locked,
            "pending_commands": len(self._pending_commands),
            "device_info": self.get_device_info()
        }


# Global anti-theft instance
anti_theft = AntiTheft()
