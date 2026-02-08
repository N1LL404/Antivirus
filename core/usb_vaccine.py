"""
Windows 10 Antivirus - USB Vaccine
Protects USB/Pen drives from autorun malware
"""
import os
import time
import threading
import string
import ctypes
from pathlib import Path
from typing import List, Callable, Optional
import win32api
import win32file
import win32con

from core.scanner import scanner
from database import db
from loguru import logger


class USBVaccine:
    """USB/Pen Drive protection and vaccination"""
    
    def __init__(self):
        self.is_monitoring = False
        self._monitor_thread = None
        self._known_drives = set()
        self._on_usb_inserted: Optional[Callable] = None
        self._on_threat_found: Optional[Callable] = None
        self._auto_scan = True
        self._auto_vaccinate = True
    
    def _get_removable_drives(self) -> List[str]:
        """Get list of removable drives"""
        removable = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            try:
                drive_type = win32file.GetDriveType(drive)
                if drive_type == win32con.DRIVE_REMOVABLE:
                    if os.path.exists(drive):
                        removable.append(drive)
            except:
                pass
        return removable
    
    def _get_drive_info(self, drive: str) -> dict:
        """Get information about a drive"""
        try:
            volume_name, serial, max_component, flags, fs_type = win32api.GetVolumeInformation(drive)
            total, used, free = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                drive, ctypes.byref(free), ctypes.byref(total), ctypes.byref(used)
            )
            
            return {
                "drive": drive,
                "volume_name": volume_name or "Unnamed",
                "serial": serial,
                "filesystem": fs_type,
                "total_size_gb": round(total.value / (1024**3), 2),
                "free_space_gb": round(free.value / (1024**3), 2)
            }
        except Exception as e:
            logger.debug(f"Could not get drive info for {drive}: {e}")
            return {"drive": drive, "volume_name": "Unknown"}
    
    def vaccinate_drive(self, drive: str) -> bool:
        """
        Vaccinate a USB drive against autorun malware
        
        Creates an undeletable AUTORUN.INF folder to prevent malware
        from creating an autorun.inf file
        """
        try:
            autorun_path = Path(drive) / "AUTORUN.INF"
            
            # If autorun.inf is a file, remove it (potential malware)
            if autorun_path.is_file():
                try:
                    # Remove attributes and delete
                    os.chmod(str(autorun_path), 0o777)
                    ctypes.windll.kernel32.SetFileAttributesW(str(autorun_path), 0)
                    autorun_path.unlink()
                    logger.warning(f"Removed suspicious autorun.inf from {drive}")
                    db.log_activity("usb", f"Removed autorun.inf from {drive}", severity="warning")
                except Exception as e:
                    logger.error(f"Could not remove autorun.inf: {e}")
                    return False
            
            # Create AUTORUN.INF folder with special file inside
            if not autorun_path.exists():
                autorun_path.mkdir(exist_ok=True)
                
                # Create a file with special characters that's hard to delete
                special_file = autorun_path / "eScan_Vaccine.lck"
                special_file.touch()
                
                # Set folder attributes: HIDDEN, SYSTEM, READONLY
                try:
                    attrs = win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM | win32con.FILE_ATTRIBUTE_READONLY
                    ctypes.windll.kernel32.SetFileAttributesW(str(special_file), attrs)
                    ctypes.windll.kernel32.SetFileAttributesW(str(autorun_path), attrs)
                except:
                    pass
                
                logger.info(f"✓ Vaccinated drive: {drive}")
                db.log_activity("usb", f"Vaccinated drive: {drive}", severity="info")
                return True
            
            elif autorun_path.is_dir():
                logger.info(f"Drive already vaccinated: {drive}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to vaccinate {drive}: {e}")
            return False
    
    def scan_drive(self, drive: str, on_progress: Callable = None, 
                   on_threat: Callable = None) -> dict:
        """Scan a USB drive for malware"""
        logger.info(f"Scanning USB drive: {drive}")
        db.log_activity("usb", f"Scanning drive: {drive}", severity="info")
        
        def threat_callback(result):
            if on_threat:
                on_threat(result)
            if self._on_threat_found:
                self._on_threat_found(result)
        
        return scanner.scan([drive], "usb_scan", on_progress, threat_callback)
    
    def _check_for_new_drives(self):
        """Check for newly inserted drives"""
        current_drives = set(self._get_removable_drives())
        
        # Find new drives
        new_drives = current_drives - self._known_drives
        
        for drive in new_drives:
            logger.info(f"USB drive inserted: {drive}")
            drive_info = self._get_drive_info(drive)
            
            db.log_activity("usb", f"USB inserted: {drive_info.get('volume_name', 'Unknown')}", 
                           severity="info")
            
            if self._on_usb_inserted:
                self._on_usb_inserted(drive, drive_info)
            
            # Auto-vaccinate
            if self._auto_vaccinate:
                self.vaccinate_drive(drive)
            
            # Auto-scan
            if self._auto_scan:
                threading.Thread(
                    target=self.scan_drive, 
                    args=(drive,),
                    kwargs={"on_threat": self._on_threat_found},
                    daemon=True
                ).start()
        
        # Find removed drives
        removed_drives = self._known_drives - current_drives
        for drive in removed_drives:
            logger.info(f"USB drive removed: {drive}")
            db.log_activity("usb", f"USB removed: {drive}", severity="info")
        
        self._known_drives = current_drives
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        self._known_drives = set(self._get_removable_drives())
        
        while self.is_monitoring:
            try:
                self._check_for_new_drives()
            except Exception as e:
                logger.error(f"USB monitoring error: {e}")
            
            time.sleep(2)  # Check every 2 seconds
    
    def start_monitoring(self, on_inserted: Callable = None, 
                         on_threat: Callable = None,
                         auto_scan: bool = True,
                         auto_vaccinate: bool = True):
        """
        Start USB drive monitoring
        
        Args:
            on_inserted: Callback(drive, drive_info) when USB is inserted
            on_threat: Callback(scan_result) when threat found
            auto_scan: Automatically scan new drives
            auto_vaccinate: Automatically vaccinate new drives
        """
        if self.is_monitoring:
            logger.warning("USB monitoring already running")
            return
        
        self._on_usb_inserted = on_inserted
        self._on_threat_found = on_threat
        self._auto_scan = auto_scan
        self._auto_vaccinate = auto_vaccinate
        
        self.is_monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        db.log_activity("usb", "USB monitoring started", severity="info")
        logger.info("🔌 USB monitoring ENABLED")
    
    def stop_monitoring(self):
        """Stop USB drive monitoring"""
        self.is_monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        
        db.log_activity("usb", "USB monitoring stopped", severity="info")
        logger.info("USB monitoring DISABLED")
    
    def vaccinate_all_drives(self) -> int:
        """Vaccinate all currently connected removable drives"""
        drives = self._get_removable_drives()
        vaccinated = 0
        
        for drive in drives:
            if self.vaccinate_drive(drive):
                vaccinated += 1
        
        logger.info(f"Vaccinated {vaccinated}/{len(drives)} drives")
        return vaccinated
    
    def get_connected_drives(self) -> List[dict]:
        """Get list of connected removable drives with info"""
        drives = self._get_removable_drives()
        return [self._get_drive_info(d) for d in drives]
    
    def get_status(self) -> dict:
        """Get USB vaccine status"""
        return {
            "monitoring": self.is_monitoring,
            "auto_scan": self._auto_scan,
            "auto_vaccinate": self._auto_vaccinate,
            "connected_drives": self.get_connected_drives()
        }


# Global USB vaccine instance
usb_vaccine = USBVaccine()
