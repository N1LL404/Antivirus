"""
Windows 10 Antivirus - Real-time Protection
Monitors file system for threats in real-time
"""
import os
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileMovedEvent

from config import REALTIME_CONFIG, QUARANTINE_DIR
from core.scanner import scanner, ScanResult
from core.quarantine import quarantine_manager
from database import db
from loguru import logger


class ThreatHandler:
    """Handles detected threats"""
    
    def __init__(self, auto_quarantine: bool = True, 
                 on_threat_callback: Callable = None):
        self.auto_quarantine = auto_quarantine
        self.on_threat_callback = on_threat_callback
    
    def handle_threat(self, result: ScanResult):
        """Process a detected threat"""
        logger.warning(f"🚨 THREAT DETECTED: {result.threat_name} in {result.file_path}")
        
        if self.auto_quarantine:
            quarantine_path = quarantine_manager.quarantine_file(
                result.file_path, 
                result.threat_name
            )
            if quarantine_path:
                logger.info(f"File quarantined successfully")
        
        if self.on_threat_callback:
            self.on_threat_callback(result)


class RealTimeEventHandler(FileSystemEventHandler):
    """Handles file system events for real-time protection"""
    
    def __init__(self, threat_handler: ThreatHandler):
        super().__init__()
        self.threat_handler = threat_handler
        self._scan_queue = set()
        self._queue_lock = threading.Lock()
        self._debounce_time = 0.5  # seconds
        self._last_scan_times = {}
    
    def _should_scan(self, file_path: str) -> bool:
        """Check if file should be scanned"""
        try:
            path = Path(file_path)
            
            # Skip if doesn't exist
            if not path.exists() or not path.is_file():
                return False
        except (PermissionError, OSError):
            return False
        
        # Skip quarantine directory
        if str(QUARANTINE_DIR) in file_path:
            return False
        
        # Skip temp/cache files
        skip_patterns = ['.tmp', '.temp', '~', '.log', '.cache']
        if any(pattern in path.name.lower() for pattern in skip_patterns):
            return False
        
        # Debounce - don't scan same file too frequently
        current_time = time.time()
        if file_path in self._last_scan_times:
            if current_time - self._last_scan_times[file_path] < self._debounce_time:
                return False
        
        self._last_scan_times[file_path] = current_time
        return True
    
    def _scan_file_async(self, file_path: str):
        """Scan file in a separate thread"""
        def do_scan():
            try:
                result = scanner.scan_file(file_path)
                if result.is_threat:
                    self.threat_handler.handle_threat(result)
            except Exception as e:
                logger.debug(f"Error in real-time scan: {e}")
        
        thread = threading.Thread(target=do_scan, daemon=True)
        thread.start()
    
    def on_created(self, event):
        """Handle file creation"""
        if isinstance(event, FileCreatedEvent) and REALTIME_CONFIG.get("scan_on_create", True):
            if self._should_scan(event.src_path):
                logger.debug(f"[RT] Scanning new file: {event.src_path}")
                self._scan_file_async(event.src_path)
    
    def on_modified(self, event):
        """Handle file modification"""
        if isinstance(event, FileModifiedEvent) and REALTIME_CONFIG.get("scan_on_modify", True):
            if self._should_scan(event.src_path):
                logger.debug(f"[RT] Scanning modified file: {event.src_path}")
                self._scan_file_async(event.src_path)
    
    def on_moved(self, event):
        """Handle file move"""
        if isinstance(event, FileMovedEvent) and REALTIME_CONFIG.get("scan_on_access", True):
            if self._should_scan(event.dest_path):
                logger.debug(f"[RT] Scanning moved file: {event.dest_path}")
                self._scan_file_async(event.dest_path)


class RealTimeProtection:
    """Real-time file system protection"""
    
    def __init__(self):
        self.is_enabled = False
        self.observer = None
        self.threat_handler = ThreatHandler(auto_quarantine=True)
        self.event_handler = RealTimeEventHandler(self.threat_handler)
        self._monitor_paths = []
        self._lock = threading.Lock()
    
    def start(self, paths: List[str] = None, on_threat: Callable = None):
        """
        Start real-time protection
        
        Args:
            paths: Paths to monitor (uses config if not specified)
            on_threat: Callback when threat is detected
        """
        if self.is_enabled:
            logger.warning("Real-time protection already running")
            return
        
        with self._lock:
            if on_threat:
                self.threat_handler.on_threat_callback = on_threat
            
            self._monitor_paths = paths or REALTIME_CONFIG.get("monitor_paths", [])
            
            self.observer = Observer()
            
            for path in self._monitor_paths:
                if os.path.exists(path):
                    try:
                        self.observer.schedule(
                            self.event_handler,
                            path,
                            recursive=True
                        )
                        logger.info(f"[RT] Monitoring: {path}")
                    except Exception as e:
                        logger.error(f"[RT] Failed to monitor {path}: {e}")
            
            self.observer.start()
            self.is_enabled = True
            
            db.log_activity("realtime", "Real-time protection started", severity="info")
            logger.info("🛡️ Real-time protection ENABLED")
    
    def stop(self):
        """Stop real-time protection"""
        if not self.is_enabled:
            return
        
        with self._lock:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5)
                self.observer = None
            
            self.is_enabled = False
            
            
            db.log_activity("realtime", "Real-time protection stopped", severity="warning")
            logger.info("Real-time protection DISABLED")
    
    def is_running(self) -> bool:
        """Check if real-time protection is running"""
        return self.is_enabled
    
    def restart(self):
        """Restart real-time protection"""
        self.stop()
        time.sleep(1)
        self.start()
    
    def add_path(self, path: str):
        """Add a path to monitor"""
        if not os.path.exists(path):
            logger.error(f"Path does not exist: {path}")
            return False
        
        if path in self._monitor_paths:
            return True
        
        self._monitor_paths.append(path)
        
        if self.is_enabled and self.observer:
            try:
                self.observer.schedule(
                    self.event_handler,
                    path,
                    recursive=True
                )
                logger.info(f"[RT] Added monitoring: {path}")
                return True
            except Exception as e:
                logger.error(f"[RT] Failed to add monitoring for {path}: {e}")
                return False
        
        return True
    
    def remove_path(self, path: str):
        """Remove a path from monitoring"""
        if path in self._monitor_paths:
            self._monitor_paths.remove(path)
            # Need to restart to apply changes
            if self.is_enabled:
                self.restart()
    
    def set_auto_quarantine(self, enabled: bool):
        """Enable or disable automatic quarantine"""
        self.threat_handler.auto_quarantine = enabled
        logger.info(f"Auto-quarantine: {'enabled' if enabled else 'disabled'}")
    
    def get_status(self) -> dict:
        """Get real-time protection status"""
        return {
            "enabled": self.is_enabled,
            "monitoring_paths": self._monitor_paths,
            "auto_quarantine": self.threat_handler.auto_quarantine
        }


# Global real-time protection instance
realtime_protection = RealTimeProtection()
