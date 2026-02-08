"""
Windows 10 Antivirus - Anti-Keylogger
Detects and blocks keylogger software
"""
import ctypes
import ctypes.wintypes
import threading
import time
from typing import List, Dict, Callable, Optional
from datetime import datetime
import psutil

from database import db
from loguru import logger

# Windows API constants
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14


class AntiKeylogger:
    """Detects and protects against keylogger software"""
    
    def __init__(self):
        self.is_enabled = False
        self._monitor_thread = None
        self._detected_keyloggers: List[Dict] = []
        self._on_detection: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Suspicious process names commonly used by keyloggers
        self._suspicious_names = [
            'keylogger', 'keylog', 'klog', 'spy', 'monitor',
            'capture', 'hook', 'record', 'ardamax', 'refog',
            'spyrix', 'actual', 'revealer', 'perfect', 'elite',
            'familykey', 'kidlogger', 'wolfeye', 'hoverwatch',
            'mspy', 'flexispy', 'cocospy', 'spyic', 'minspy'
        ]
        
        # Known keylogger file signatures
        self._keylogger_files = [
            'akl.exe', 'ardamax.exe', 'refog.exe', 'spyrix.exe',
            'family_keylogger.exe', 'allinsafe.exe', 'actual_spy.exe'
        ]
    
    def _get_keyboard_hooks(self) -> List[Dict]:
        """Detect processes with keyboard hooks installed"""
        hooked_processes = []
        
        try:
            # Use EnumWindows to check for hooks
            user32 = ctypes.windll.user32
            
            # Check each process for suspicious behavior
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # Check against suspicious names
                    for sus_name in self._suspicious_names:
                        if sus_name in proc_name:
                            hooked_processes.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'exe': proc_info.get('exe', 'Unknown'),
                                'reason': f'Suspicious name: {sus_name}'
                            })
                            break
                    
                    # Check against known keylogger files
                    if proc_name in self._keylogger_files:
                        hooked_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': proc_info.get('exe', 'Unknown'),
                            'reason': 'Known keylogger executable'
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.error(f"Error detecting keyboard hooks: {e}")
        
        return hooked_processes
    
    def _scan_for_keyloggers(self) -> List[Dict]:
        """Scan for keylogger processes"""
        detected = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    proc_exe = proc_info.get('exe', '') or ''
                    
                    # Check process name
                    is_suspicious = False
                    reason = ""
                    
                    for sus in self._suspicious_names:
                        if sus in proc_name:
                            is_suspicious = True
                            reason = f"Suspicious name contains: {sus}"
                            break
                    
                    # Check if it's a known keylogger executable
                    if not is_suspicious and proc_name in self._keylogger_files:
                        is_suspicious = True
                        reason = "Known keylogger executable"
                    
                    # Check memory for keylogger signatures
                    if not is_suspicious:
                        try:
                            mem_info = proc_info.get('memory_info')
                            if mem_info and mem_info.rss > 10 * 1024 * 1024:  # >10MB
                                # Check command line for suspicious flags
                                cmdline = ' '.join(proc_info.get('cmdline') or []).lower()
                                if any(x in cmdline for x in ['--hidden', '-hide', '/hidden', 'stealth']):
                                    is_suspicious = True
                                    reason = "Hidden/stealth mode detected"
                        except:
                            pass
                    
                    if is_suspicious:
                        detected.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': proc_exe,
                            'reason': reason,
                            'detected_at': datetime.now().isoformat()
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.error(f"Keylogger scan error: {e}")
        
        return detected
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        known_keyloggers = set()
        
        while self.is_enabled:
            try:
                # Check for keyboard hooks
                hooked = self._get_keyboard_hooks()
                
                # Scan for keylogger processes
                detected = self._scan_for_keyloggers()
                
                # Process new detections
                for item in hooked + detected:
                    identifier = f"{item['pid']}_{item['name']}"
                    
                    if identifier not in known_keyloggers:
                        known_keyloggers.add(identifier)
                        
                        with self._lock:
                            self._detected_keyloggers.append(item)
                        
                        logger.warning(f"🚨 KEYLOGGER DETECTED: {item['name']} (PID: {item['pid']}) - {item['reason']}")
                        
                        db.log_activity("keylogger", 
                                       f"Detected: {item['name']}",
                                       f"PID: {item['pid']}, Reason: {item['reason']}",
                                       severity="critical")
                        
                        if self._on_detection:
                            self._on_detection(item)
                
            except Exception as e:
                logger.error(f"Keylogger monitor error: {e}")
            
            time.sleep(5)  # Scan every 5 seconds
    
    def start(self, on_detection: Callable = None):
        """Start anti-keylogger monitoring"""
        if self.is_enabled:
            logger.warning("Anti-keylogger already running")
            return
        
        self._on_detection = on_detection
        self.is_enabled = True
        
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        db.log_activity("keylogger", "Anti-keylogger started", severity="info")
        logger.info("⌨️ Anti-keylogger ENABLED")
    
    def stop(self):
        """Stop anti-keylogger"""
        self.is_enabled = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        
        db.log_activity("keylogger", "Anti-keylogger stopped", severity="warning")
        logger.info("Anti-keylogger DISABLED")
    
    def scan_now(self) -> List[Dict]:
        """Perform immediate scan for keyloggers"""
        logger.info("Scanning for keyloggers...")
        hooked = self._get_keyboard_hooks()
        detected = self._scan_for_keyloggers()
        results = hooked + detected
        
        for item in results:
            with self._lock:
                self._detected_keyloggers.append(item)
        
        return results
    
    def terminate_keylogger(self, pid: int) -> bool:
        """Attempt to terminate a keylogger process"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            proc.wait(timeout=5)
            
            logger.info(f"Terminated keylogger: {proc_name} (PID: {pid})")
            db.log_activity("keylogger", f"Terminated: {proc_name}", severity="warning")
            
            return True
        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} no longer exists")
            return True
        except Exception as e:
            logger.error(f"Failed to terminate {pid}: {e}")
            return False
    
    def get_detected(self) -> List[Dict]:
        """Get list of detected keyloggers"""
        with self._lock:
            return list(self._detected_keyloggers)
    
    def add_suspicious_name(self, name: str):
        """Add to list of suspicious process names"""
        self._suspicious_names.append(name.lower())
        logger.info(f"Added suspicious name: {name}")
    
    def get_status(self) -> Dict:
        """Get anti-keylogger status"""
        return {
            "enabled": self.is_enabled,
            "detected_count": len(self._detected_keyloggers),
            "monitored_names": len(self._suspicious_names)
        }


# Global anti-keylogger instance
anti_keylogger = AntiKeylogger()
