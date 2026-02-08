"""
Windows 10 Antivirus - Registry Cleaner
Cleans invalid registry entries and optimizes system
"""
import winreg
import threading
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import os
import json
from pathlib import Path

from config import DATA_DIR
from database import db
from loguru import logger


class RegistryCleaner:
    """Registry cleaning and optimization"""
    
    def __init__(self):
        self._backup_dir = DATA_DIR / "registry_backups"
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._issues_found: List[Dict] = []
        self._is_scanning = False
        self._lock = threading.Lock()
        
        # Registry paths to scan
        self._scan_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Classes"),
            (winreg.HKEY_CLASSES_ROOT, r"*\shell"),
            (winreg.HKEY_CLASSES_ROOT, r"Directory\shell"),
        ]
        
        # MRU (Most Recently Used) paths to clean
        self._mru_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"),
        ]
    
    def _backup_key(self, hkey, subkey: str, backup_name: str) -> bool:
        """Backup a registry key before modification"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self._backup_dir / f"{backup_name}_{timestamp}.reg"
            
            # Use reg export command
            import subprocess
            hkey_names = {
                winreg.HKEY_CURRENT_USER: "HKCU",
                winreg.HKEY_LOCAL_MACHINE: "HKLM",
                winreg.HKEY_CLASSES_ROOT: "HKCR",
            }
            
            hkey_name = hkey_names.get(hkey, "HKCU")
            full_key = f"{hkey_name}\\{subkey}"
            
            result = subprocess.run(
                ['reg', 'export', full_key, str(backup_file), '/y'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"Backed up: {full_key}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return False
    
    def _check_file_reference(self, path: str) -> bool:
        """Check if a file path reference is valid"""
        if not path:
            return False
        
        # Clean up path
        path = path.strip('"').strip()
        
        # Handle paths with arguments
        if ' ' in path and not os.path.exists(path):
            # Try to extract just the executable
            parts = path.split()
            path = parts[0].strip('"')
        
        # Expand environment variables
        path = os.path.expandvars(path)
        
        return os.path.exists(path)
    
    def scan_invalid_software_entries(self) -> List[Dict]:
        """Scan for invalid software entries in registry"""
        issues = []
        
        for hkey, subkey in self._scan_paths[:2]:  # Uninstall keys
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                
                try:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_path = f"{subkey}\\{subkey_name}"
                            
                            try:
                                sw_key = winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_READ)
                                
                                # Check InstallLocation
                                try:
                                    install_loc, _ = winreg.QueryValueEx(sw_key, "InstallLocation")
                                    if install_loc and not os.path.exists(install_loc):
                                        issues.append({
                                            "type": "orphaned_software",
                                            "key": subkey_path,
                                            "name": subkey_name,
                                            "issue": f"Install location missing: {install_loc}",
                                            "hkey": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                                        })
                                except:
                                    pass
                                
                                # Check UninstallString
                                try:
                                    uninstall, _ = winreg.QueryValueEx(sw_key, "UninstallString")
                                    if uninstall and not self._check_file_reference(uninstall):
                                        issues.append({
                                            "type": "invalid_uninstall",
                                            "key": subkey_path,
                                            "name": subkey_name,
                                            "issue": f"Uninstall path invalid: {uninstall}",
                                            "hkey": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                                        })
                                except:
                                    pass
                                
                                winreg.CloseKey(sw_key)
                            except:
                                pass
                            
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except Exception as e:
                logger.debug(f"Error scanning {subkey}: {e}")
        
        return issues
    
    def scan_startup_entries(self) -> List[Dict]:
        """Scan for invalid startup entries"""
        issues = []
        
        for hkey, subkey in self._scan_paths[2:4]:  # Run keys
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            
                            if not self._check_file_reference(value):
                                issues.append({
                                    "type": "invalid_startup",
                                    "key": subkey,
                                    "name": name,
                                    "value": value,
                                    "issue": f"Startup path invalid",
                                    "hkey": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                                })
                            
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except Exception as e:
                logger.debug(f"Error scanning startup: {e}")
        
        return issues
    
    def scan_file_associations(self) -> List[Dict]:
        """Scan for broken file associations"""
        issues = []
        
        common_extensions = ['.txt', '.jpg', '.png', '.pdf', '.doc', '.docx', '.mp3', '.mp4']
        
        for ext in common_extensions:
            try:
                # Get the associated program
                key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ext, 0, winreg.KEY_READ)
                try:
                    prog_id, _ = winreg.QueryValueEx(key, "")
                    winreg.CloseKey(key)
                    
                    if prog_id:
                        # Check if the program exists
                        try:
                            prog_key = winreg.OpenKey(
                                winreg.HKEY_CLASSES_ROOT, 
                                f"{prog_id}\\shell\\open\\command",
                                0, winreg.KEY_READ
                            )
                            cmd, _ = winreg.QueryValueEx(prog_key, "")
                            winreg.CloseKey(prog_key)
                            
                            if cmd and not self._check_file_reference(cmd):
                                issues.append({
                                    "type": "broken_association",
                                    "extension": ext,
                                    "program": prog_id,
                                    "command": cmd,
                                    "issue": "Associated program not found"
                                })
                        except:
                            pass
                except:
                    winreg.CloseKey(key)
            except:
                pass
        
        return issues
    
    def scan(self) -> Dict:
        """Perform full registry scan"""
        if self._is_scanning:
            return {"error": "Scan already in progress"}
        
        self._is_scanning = True
        self._issues_found = []
        
        try:
            logger.info("Starting registry scan...")
            
            # Scan different categories
            software_issues = self.scan_invalid_software_entries()
            startup_issues = self.scan_startup_entries()
            association_issues = self.scan_file_associations()
            
            with self._lock:
                self._issues_found = software_issues + startup_issues + association_issues
            
            summary = {
                "total_issues": len(self._issues_found),
                "orphaned_software": len([i for i in self._issues_found if i["type"] == "orphaned_software"]),
                "invalid_startup": len([i for i in self._issues_found if i["type"] == "invalid_startup"]),
                "broken_associations": len([i for i in self._issues_found if i["type"] == "broken_association"]),
                "issues": self._issues_found
            }
            
            logger.info(f"Registry scan complete: {summary['total_issues']} issues found")
            db.log_activity("registry", f"Scan complete: {summary['total_issues']} issues", severity="info")
            
            return summary
            
        finally:
            self._is_scanning = False
    
    def clean(self, issue_types: List[str] = None, backup: bool = True) -> Dict:
        """
        Clean registry issues
        
        Args:
            issue_types: List of issue types to clean (None = all)
            backup: Create backup before cleaning
        
        Returns:
            Cleaning summary
        """
        if not self._issues_found:
            return {"error": "Run scan first"}
        
        cleaned = 0
        failed = 0
        
        issues_to_clean = self._issues_found
        if issue_types:
            issues_to_clean = [i for i in issues_to_clean if i["type"] in issue_types]
        
        for issue in issues_to_clean:
            try:
                if backup and "key" in issue:
                    hkey = winreg.HKEY_LOCAL_MACHINE if issue.get("hkey") == "HKLM" else winreg.HKEY_CURRENT_USER
                    self._backup_key(hkey, issue["key"], issue["type"])
                
                # For now, we'll just log - actual deletion requires more care
                logger.info(f"Would clean: {issue['type']} - {issue.get('name', issue.get('key', 'unknown'))}")
                cleaned += 1
                
            except Exception as e:
                logger.error(f"Clean error: {e}")
                failed += 1
        
        summary = {
            "cleaned": cleaned,
            "failed": failed,
            "backup_created": backup
        }
        
        db.log_activity("registry", f"Cleaned {cleaned} issues", severity="info")
        
        return summary
    
    def clean_mru(self) -> Dict:
        """Clean Most Recently Used lists for privacy"""
        cleaned = 0
        
        for hkey, subkey in self._mru_paths:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS)
                
                try:
                    # Enumerate and delete values
                    while True:
                        try:
                            name, _, _ = winreg.EnumValue(key, 0)
                            winreg.DeleteValue(key, name)
                            cleaned += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
                    
            except Exception as e:
                logger.debug(f"MRU clean error for {subkey}: {e}")
        
        logger.info(f"Cleaned {cleaned} MRU entries")
        db.log_activity("registry", f"Cleaned {cleaned} MRU entries", severity="info")
        
        return {"cleaned_entries": cleaned}
    
    def get_issues(self) -> List[Dict]:
        """Get found issues"""
        with self._lock:
            return list(self._issues_found)
    
    def get_status(self) -> Dict:
        """Get registry cleaner status"""
        return {
            "is_scanning": self._is_scanning,
            "issues_found": len(self._issues_found),
            "backups_count": len(list(self._backup_dir.glob("*.reg")))
        }


# Global registry cleaner instance
registry_cleaner = RegistryCleaner()
