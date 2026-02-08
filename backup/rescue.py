"""
Windows 10 Antivirus - Rescue Mode
Emergency malware removal and system recovery
"""
import os
import subprocess
import shutil
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

from config import DATA_DIR
from database import db
from loguru import logger


class RescueMode:
    """Emergency recovery and malware removal"""
    
    def __init__(self):
        self._rescue_dir = DATA_DIR / "rescue"
        self._rescue_dir.mkdir(parents=True, exist_ok=True)
    
    def create_restore_point(self, description: str = "eScan Restore Point") -> Dict:
        """
        Create a Windows System Restore point
        
        Args:
            description: Description for the restore point
        
        Returns:
            Result dictionary
        """
        try:
            logger.info("Creating system restore point...")
            
            # PowerShell command to create restore point
            ps_command = f'''
            Checkpoint-Computer -Description "{description}" -RestorePointType "MODIFY_SETTINGS"
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info(f"✓ Restore point created: {description}")
                db.log_activity("rescue", f"Created restore point: {description}", severity="info")
                
                return {
                    "success": True,
                    "description": description,
                    "created_at": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or "Failed to create restore point"
                }
                
        except Exception as e:
            logger.error(f"Restore point error: {e}")
            return {"success": False, "error": str(e)}
    
    def list_restore_points(self) -> List[Dict]:
        """List available system restore points"""
        try:
            ps_command = '''
            Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, CreationTime | ConvertTo-Json
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                points = json.loads(result.stdout)
                if not isinstance(points, list):
                    points = [points]
                return points
            
            return []
            
        except Exception as e:
            logger.error(f"List restore points error: {e}")
            return []
    
    def emergency_scan(self) -> Dict:
        """
        Perform emergency malware scan
        Scans critical system areas
        """
        try:
            from core.scanner import scanner
            
            logger.info("Starting emergency scan...")
            db.log_activity("rescue", "Started emergency scan", severity="warning")
            
            # Critical paths to scan
            critical_paths = [
                os.environ.get("WINDIR", "C:\\Windows"),
                os.environ.get("SYSTEMROOT", "C:\\Windows") + "\\System32",
                os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                os.environ.get("APPDATA", ""),
                os.environ.get("LOCALAPPDATA", ""),
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
            ]
            
            critical_paths = [p for p in critical_paths if p and os.path.exists(p)]
            
            result = scanner.scan(critical_paths, "emergency")
            
            return result
            
        except Exception as e:
            logger.error(f"Emergency scan error: {e}")
            return {"error": str(e)}
    
    def remove_startup_items(self, suspicious_only: bool = True) -> Dict:
        """
        Review and optionally remove startup items
        
        Args:
            suspicious_only: Only show suspicious items
        
        Returns:
            List of startup items
        """
        import winreg
        
        startup_items = []
        
        # Registry startup locations
        startup_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        suspicious_keywords = ['temp', 'tmp', 'random', 'unknown', 'backdoor', 'shell']
        
        for hkey, subkey in startup_keys:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        is_suspicious = any(kw in name.lower() or kw in value.lower() 
                                           for kw in suspicious_keywords)
                        
                        if not suspicious_only or is_suspicious:
                            startup_items.append({
                                "name": name,
                                "command": value,
                                "location": subkey,
                                "hkey": "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                                "suspicious": is_suspicious
                            })
                        
                        i += 1
                    except OSError:
                        break
                
                winreg.CloseKey(key)
            except:
                pass
        
        return {
            "items": startup_items,
            "total": len(startup_items),
            "suspicious": len([i for i in startup_items if i["suspicious"]])
        }
    
    def safe_mode_reboot(self) -> bool:
        """Prepare and trigger safe mode reboot"""
        try:
            logger.warning("Preparing safe mode reboot...")
            
            # Set boot configuration for safe mode
            subprocess.run(
                ['bcdedit', '/set', '{current}', 'safeboot', 'network'],
                capture_output=True
            )
            
            db.log_activity("rescue", "Safe mode reboot prepared", severity="warning")
            
            return True
            
        except Exception as e:
            logger.error(f"Safe mode setup error: {e}")
            return False
    
    def disable_safe_mode(self) -> bool:
        """Disable safe mode for next boot"""
        try:
            subprocess.run(
                ['bcdedit', '/deletevalue', '{current}', 'safeboot'],
                capture_output=True
            )
            return True
        except:
            return False
    
    def kill_suspicious_processes(self) -> List[str]:
        """Kill known malicious processes"""
        import psutil
        
        killed = []
        
        suspicious_processes = [
            'backdoor', 'keylogger', 'miner', 'cryptominer',
            'ransomware', 'trojan', 'worm', 'rootkit'
        ]
        
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                proc_name = proc.info['name'].lower()
                
                for suspicious in suspicious_processes:
                    if suspicious in proc_name:
                        proc.kill()
                        killed.append(proc.info['name'])
                        logger.warning(f"Killed suspicious process: {proc.info['name']}")
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        if killed:
            db.log_activity("rescue", f"Killed {len(killed)} suspicious processes", severity="warning")
        
        return killed
    
    def reset_hosts_file(self) -> bool:
        """Reset hosts file to default"""
        try:
            hosts_path = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), 
                                      "System32", "drivers", "etc", "hosts")
            
            # Backup current hosts file
            backup_path = self._rescue_dir / f"hosts_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(hosts_path, backup_path)
            
            # Write default hosts file
            default_hosts = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

127.0.0.1       localhost
::1             localhost
"""
            
            with open(hosts_path, 'w') as f:
                f.write(default_hosts)
            
            logger.info("Reset hosts file to default")
            db.log_activity("rescue", "Reset hosts file", severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Reset hosts file error: {e}")
            return False
    
    def flush_dns(self) -> bool:
        """Flush DNS cache"""
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
            logger.info("Flushed DNS cache")
            return True
        except:
            return False
    
    def get_system_health(self) -> Dict:
        """Get system health overview"""
        import psutil
        
        return {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('C:\\').percent,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "process_count": len(list(psutil.process_iter()))
        }


# Global rescue mode instance
rescue_mode = RescueMode()
