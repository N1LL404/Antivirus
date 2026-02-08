"""
Windows 10 Antivirus - Folder Lock
Protects confidential folders from unauthorized access
"""
import os
import hashlib
import json
import shutil
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database import db
from loguru import logger


class FolderProtectionHandler(FileSystemEventHandler):
    """Handles file system events for protected folders"""
    
    def __init__(self, folder_lock, folder_path: str):
        super().__init__()
        self.folder_lock = folder_lock
        self.folder_path = folder_path
    
    def on_any_event(self, event):
        """Handle any file system event in protected folder"""
        if event.is_directory:
            return
        
        # Check if modification is allowed
        if not self.folder_lock._is_modification_allowed(self.folder_path):
            logger.warning(f"🔒 Blocked: {event.event_type} on {event.src_path}")
            
            db.log_activity("folder_lock",
                           f"Blocked modification: {event.event_type}",
                           f"Path: {event.src_path}",
                           severity="warning")
            
            # Notify callback
            if self.folder_lock._on_blocked:
                self.folder_lock._on_blocked(event)


class FolderLock:
    """Folder protection and access control"""
    
    def __init__(self):
        self._protected_folders: Dict[str, Dict] = {}
        self._observers: Dict[str, Observer] = {}
        self._allowed_modifications: Dict[str, bool] = {}
        self._on_blocked: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Load protected folders from database
        self._load_from_db()
    
    def _load_from_db(self):
        """Load protected folders from database"""
        try:
            folders = db.get_protected_folders()
            for folder in folders:
                self._protected_folders[folder['folder_path']] = {
                    'password_hash': folder.get('password_hash'),
                    'protection_level': folder.get('protection_level', 'read_only'),
                    'created_at': folder.get('created_at')
                }
        except Exception as e:
            logger.error(f"Error loading protected folders: {e}")
    
    def _hash_password(self, password: str) -> str:
        """Hash a password for storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _verify_password(self, folder_path: str, password: str) -> bool:
        """Verify password for a protected folder"""
        folder_info = self._protected_folders.get(folder_path)
        if not folder_info or not folder_info.get('password_hash'):
            return True  # No password set
        
        return self._hash_password(password) == folder_info['password_hash']
    
    def _is_modification_allowed(self, folder_path: str) -> bool:
        """Check if modifications are currently allowed"""
        return self._allowed_modifications.get(folder_path, False)
    
    def add_protected_folder(self, folder_path: str, password: str = None,
                            protection_level: str = "read_only") -> bool:
        """
        Add a folder to protection
        
        Args:
            folder_path: Path to folder to protect
            password: Optional password for unlocking
            protection_level: 'read_only', 'hidden', or 'locked'
        
        Returns:
            True if successful
        """
        try:
            path = Path(folder_path)
            
            if not path.exists():
                logger.error(f"Folder does not exist: {folder_path}")
                return False
            
            if not path.is_dir():
                logger.error(f"Not a directory: {folder_path}")
                return False
            
            folder_path = str(path.absolute())
            
            # Hash password if provided
            password_hash = self._hash_password(password) if password else None
            
            # Add to database
            db.add_protected_folder(folder_path, password_hash, protection_level)
            
            # Add to local cache
            with self._lock:
                self._protected_folders[folder_path] = {
                    'password_hash': password_hash,
                    'protection_level': protection_level,
                    'created_at': datetime.now().isoformat()
                }
            
            # Start monitoring
            self._start_monitoring(folder_path)
            
            # Apply protection
            if protection_level == 'hidden':
                self._hide_folder(folder_path)
            elif protection_level == 'locked':
                self._lock_folder(folder_path)
            
            logger.info(f"🔒 Protected folder: {folder_path} (level: {protection_level})")
            db.log_activity("folder_lock", f"Added protection: {folder_path}", severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Error protecting folder: {e}")
            return False
    
    def remove_protection(self, folder_path: str, password: str = None) -> bool:
        """Remove protection from a folder"""
        try:
            folder_path = str(Path(folder_path).absolute())
            
            # Verify password
            if not self._verify_password(folder_path, password or ""):
                logger.warning(f"Invalid password for: {folder_path}")
                return False
            
            # Stop monitoring
            self._stop_monitoring(folder_path)
            
            # Restore folder visibility/access
            folder_info = self._protected_folders.get(folder_path, {})
            if folder_info.get('protection_level') == 'hidden':
                self._unhide_folder(folder_path)
            elif folder_info.get('protection_level') == 'locked':
                self._unlock_folder(folder_path)
            
            # Remove from cache
            with self._lock:
                if folder_path in self._protected_folders:
                    del self._protected_folders[folder_path]
            
            logger.info(f"🔓 Removed protection: {folder_path}")
            db.log_activity("folder_lock", f"Removed protection: {folder_path}", severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Error removing protection: {e}")
            return False
    
    def unlock_folder(self, folder_path: str, password: str) -> bool:
        """Temporarily unlock a folder for modifications"""
        folder_path = str(Path(folder_path).absolute())
        
        if not self._verify_password(folder_path, password):
            logger.warning(f"Invalid password for: {folder_path}")
            db.log_activity("folder_lock", "Failed unlock attempt", 
                           folder_path, severity="warning")
            return False
        
        with self._lock:
            self._allowed_modifications[folder_path] = True
        
        logger.info(f"🔓 Temporarily unlocked: {folder_path}")
        return True
    
    def lock_folder_again(self, folder_path: str):
        """Re-lock a temporarily unlocked folder"""
        folder_path = str(Path(folder_path).absolute())
        
        with self._lock:
            if folder_path in self._allowed_modifications:
                del self._allowed_modifications[folder_path]
        
        logger.info(f"🔒 Re-locked: {folder_path}")
    
    def _start_monitoring(self, folder_path: str):
        """Start monitoring a protected folder"""
        if folder_path in self._observers:
            return
        
        try:
            handler = FolderProtectionHandler(self, folder_path)
            observer = Observer()
            observer.schedule(handler, folder_path, recursive=True)
            observer.start()
            
            self._observers[folder_path] = observer
            logger.debug(f"Started monitoring: {folder_path}")
        except Exception as e:
            logger.error(f"Error starting folder monitor: {e}")
    
    def _stop_monitoring(self, folder_path: str):
        """Stop monitoring a protected folder"""
        if folder_path in self._observers:
            try:
                self._observers[folder_path].stop()
                self._observers[folder_path].join(timeout=2)
                del self._observers[folder_path]
            except:
                pass
    
    def _hide_folder(self, folder_path: str):
        """Hide a folder using Windows attributes"""
        try:
            import ctypes
            # Set HIDDEN and SYSTEM attributes
            ctypes.windll.kernel32.SetFileAttributesW(
                folder_path, 
                0x02 | 0x04  # HIDDEN | SYSTEM
            )
            logger.debug(f"Hidden folder: {folder_path}")
        except Exception as e:
            logger.error(f"Error hiding folder: {e}")
    
    def _unhide_folder(self, folder_path: str):
        """Unhide a folder"""
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(folder_path, 0x80)  # NORMAL
            logger.debug(f"Unhidden folder: {folder_path}")
        except Exception as e:
            logger.error(f"Error unhiding folder: {e}")
    
    def _lock_folder(self, folder_path: str):
        """Lock folder by removing access permissions"""
        # Note: This requires admin privileges
        try:
            import subprocess
            # Remove all access except for current user
            subprocess.run(
                ['icacls', folder_path, '/deny', 'Everyone:(OI)(CI)F'],
                capture_output=True, check=True
            )
            logger.debug(f"Locked folder: {folder_path}")
        except Exception as e:
            logger.error(f"Error locking folder (may need admin): {e}")
    
    def _unlock_folder(self, folder_path: str):
        """Unlock folder by restoring permissions"""
        try:
            import subprocess
            subprocess.run(
                ['icacls', folder_path, '/remove:d', 'Everyone'],
                capture_output=True, check=True
            )
            logger.debug(f"Unlocked folder: {folder_path}")
        except Exception as e:
            logger.error(f"Error unlocking folder: {e}")
    
    def get_protected_folders(self) -> List[Dict]:
        """Get list of protected folders"""
        with self._lock:
            return [
                {
                    "folder_path": path,
                    "protection_level": info.get('protection_level', 'read_only'),
                    "has_password": info.get('password_hash') is not None,
                    "is_unlocked": self._allowed_modifications.get(path, False)
                }
                for path, info in self._protected_folders.items()
            ]
    
    def set_block_callback(self, callback: Callable):
        """Set callback for when modifications are blocked"""
        self._on_blocked = callback
    
    def start_all_monitoring(self):
        """Start monitoring all protected folders"""
        for folder_path in self._protected_folders:
            if os.path.exists(folder_path):
                self._start_monitoring(folder_path)
        
        logger.info(f"Monitoring {len(self._protected_folders)} protected folders")
    
    def stop_all_monitoring(self):
        """Stop all folder monitoring"""
        for folder_path in list(self._observers.keys()):
            self._stop_monitoring(folder_path)
    
    def get_status(self) -> Dict:
        """Get folder lock status"""
        return {
            "protected_folders": len(self._protected_folders),
            "actively_monitoring": len(self._observers),
            "temporarily_unlocked": sum(1 for v in self._allowed_modifications.values() if v)
        }


# Global folder lock instance
folder_lock = FolderLock()
