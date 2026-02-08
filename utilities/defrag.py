"""
Windows 10 Antivirus - Disk Defragmenter
Optimizes disk performance
"""
import subprocess
import threading
from typing import Dict, Callable, Optional, List
from datetime import datetime
import ctypes

from database import db
from loguru import logger


class DiskDefragmenter:
    """Disk defragmentation and optimization"""
    
    def __init__(self):
        self._is_running = False
        self._current_drive = ""
        self._progress = 0
        self._on_progress: Optional[Callable] = None
    
    def _is_admin(self) -> bool:
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def analyze_drive(self, drive: str) -> Dict:
        """
        Analyze a drive for fragmentation
        
        Args:
            drive: Drive letter (e.g., "C:")
        
        Returns:
            Analysis results
        """
        try:
            logger.info(f"Analyzing drive: {drive}")
            
            result = subprocess.run(
                ['defrag', drive, '/A', '/U'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout + result.stderr
            
            # Parse the output
            analysis = {
                "drive": drive,
                "analyzed_at": datetime.now().isoformat(),
                "output": output,
                "needs_defrag": "defragmentation" in output.lower() and "not" not in output.lower()
            }
            
            # Try to extract fragmentation percentage
            for line in output.split('\n'):
                if 'fragmented' in line.lower():
                    try:
                        parts = line.split()
                        for part in parts:
                            if '%' in part:
                                analysis["fragmentation_percent"] = int(part.replace('%', ''))
                                break
                    except:
                        pass
            
            logger.info(f"Analysis complete for {drive}")
            return analysis
            
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timed out", "drive": drive}
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {"error": str(e), "drive": drive}
    
    def defragment(self, drive: str, on_progress: Callable = None, 
                   quick: bool = False) -> Dict:
        """
        Defragment a drive
        
        Args:
            drive: Drive letter (e.g., "C:")
            on_progress: Callback(progress_percent, status_message)
            quick: Use quick optimization instead of full defrag
        
        Returns:
            Defragmentation results
        """
        if self._is_running:
            return {"error": "Defragmentation already in progress"}
        
        if not self._is_admin():
            return {"error": "Administrator privileges required"}
        
        self._is_running = True
        self._current_drive = drive
        self._on_progress = on_progress
        
        try:
            logger.info(f"Starting defragmentation: {drive}")
            db.log_activity("defrag", f"Started defragmentation: {drive}", severity="info")
            
            if on_progress:
                on_progress(0, "Starting defragmentation...")
            
            # Build command
            cmd = ['defrag', drive]
            if quick:
                cmd.append('/O')  # Optimize
            else:
                cmd.append('/U')  # Full defrag with progress
                cmd.append('/V')  # Verbose
            
            # Run defragmentation
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output_lines = []
            
            # Read output in real-time
            for line in process.stdout:
                output_lines.append(line)
                
                # Try to parse progress
                if '%' in line:
                    try:
                        for part in line.split():
                            if '%' in part:
                                progress = int(part.replace('%', ''))
                                self._progress = progress
                                if on_progress:
                                    on_progress(progress, line.strip())
                                break
                    except:
                        pass
            
            process.wait()
            
            result = {
                "drive": drive,
                "success": process.returncode == 0,
                "output": '\n'.join(output_lines),
                "completed_at": datetime.now().isoformat()
            }
            
            if process.returncode == 0:
                logger.info(f"✓ Defragmentation complete: {drive}")
                db.log_activity("defrag", f"Completed: {drive}", severity="info")
            else:
                logger.warning(f"Defragmentation issues: {drive}")
            
            return result
            
        except Exception as e:
            logger.error(f"Defragmentation error: {e}")
            return {"error": str(e), "drive": drive}
            
        finally:
            self._is_running = False
            self._current_drive = ""
            self._progress = 0
    
    def optimize_ssd(self, drive: str) -> Dict:
        """
        Optimize an SSD (TRIM operation)
        
        Args:
            drive: Drive letter
        
        Returns:
            Optimization results
        """
        try:
            logger.info(f"Optimizing SSD: {drive}")
            
            result = subprocess.run(
                ['defrag', drive, '/L'],  # Retrim
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "drive": drive,
                "success": result.returncode == 0,
                "output": result.stdout + result.stderr,
                "operation": "SSD TRIM"
            }
            
        except Exception as e:
            logger.error(f"SSD optimization error: {e}")
            return {"error": str(e)}
    
    def get_drive_info(self, drive: str) -> Dict:
        """Get drive information"""
        try:
            import shutil
            
            total, used, free = shutil.disk_usage(drive)
            
            # Check if SSD using PowerShell
            is_ssd = False
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 
                     f'Get-PhysicalDisk | Where-Object {{$_.DeviceId -eq 0}} | Select-Object MediaType'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                is_ssd = 'SSD' in result.stdout or 'Solid' in result.stdout
            except:
                pass
            
            return {
                "drive": drive,
                "total_size_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "used_percent": round((used / total) * 100, 1),
                "is_ssd": is_ssd
            }
            
        except Exception as e:
            logger.error(f"Drive info error: {e}")
            return {"error": str(e)}
    
    def get_all_drives(self) -> List[Dict]:
        """Get info for all drives"""
        import string
        import os
        
        drives = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:"
            if os.path.exists(drive + "\\"):
                info = self.get_drive_info(drive)
                if "error" not in info:
                    drives.append(info)
        
        return drives
    
    def get_status(self) -> Dict:
        """Get defragmenter status"""
        return {
            "is_running": self._is_running,
            "current_drive": self._current_drive,
            "progress": self._progress
        }


# Global defragmenter instance
disk_defragmenter = DiskDefragmenter()
