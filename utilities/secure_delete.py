"""
Windows 10 Antivirus - Secure Delete
Permanently shreds files beyond recovery
"""
import os
import random
import threading
from pathlib import Path
from typing import List, Callable, Optional
from datetime import datetime

from database import db
from loguru import logger


class SecureDelete:
    """Secure file deletion (shredding)"""
    
    # Overwrite patterns
    PATTERNS = {
        "zeros": b'\x00',
        "ones": b'\xFF',
        "random": None,  # Generated at runtime
        "dod_5220": None,  # DoD 5220.22-M pattern
    }
    
    def __init__(self):
        self._is_deleting = False
        self._current_file = ""
        self._progress = 0
        self._on_progress: Optional[Callable] = None
        self._lock = threading.Lock()
    
    def _generate_random_bytes(self, size: int) -> bytes:
        """Generate random bytes"""
        return bytes(random.getrandbits(8) for _ in range(min(size, 4096)))
    
    def _overwrite_file(self, file_path: str, passes: int = 3) -> bool:
        """
        Overwrite file content with secure patterns
        
        Args:
            file_path: Path to file
            passes: Number of overwrite passes (default: 3 for DoD standard)
        
        Returns:
            True if successful
        """
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    
                    if pass_num == 0:
                        # Pass 1: Write zeros
                        pattern = b'\x00' * 4096
                    elif pass_num == 1:
                        # Pass 2: Write ones
                        pattern = b'\xFF' * 4096
                    else:
                        # Pass 3+: Write random data
                        pattern = None
                    
                    bytes_written = 0
                    while bytes_written < file_size:
                        chunk_size = min(4096, file_size - bytes_written)
                        
                        if pattern is None:
                            chunk = self._generate_random_bytes(chunk_size)
                        else:
                            chunk = pattern[:chunk_size]
                        
                        f.write(chunk)
                        bytes_written += chunk_size
                        
                        # Update progress
                        with self._lock:
                            self._progress = int((pass_num + bytes_written / file_size) / passes * 100)
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            return True
            
        except Exception as e:
            logger.error(f"Overwrite error for {file_path}: {e}")
            return False
    
    def _rename_before_delete(self, file_path: str) -> str:
        """Rename file to random name before deletion"""
        try:
            directory = os.path.dirname(file_path)
            # Generate random filename
            random_name = ''.join(random.choices('0123456789abcdef', k=16))
            new_path = os.path.join(directory, random_name)
            os.rename(file_path, new_path)
            return new_path
        except:
            return file_path
    
    def shred_file(self, file_path: str, passes: int = 3, 
                   on_progress: Callable = None) -> bool:
        """
        Securely delete a file
        
        Args:
            file_path: Path to file to shred
            passes: Number of overwrite passes (3 = DoD standard, 7 = maximum)
            on_progress: Callback(progress_percent)
        
        Returns:
            True if file was securely deleted
        """
        if self._is_deleting:
            logger.warning("Secure delete already in progress")
            return False
        
        path = Path(file_path)
        
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return False
        
        if path.is_dir():
            logger.error(f"Use shred_folder for directories: {file_path}")
            return False
        
        self._is_deleting = True
        self._current_file = file_path
        self._progress = 0
        self._on_progress = on_progress
        
        try:
            file_size = path.stat().st_size
            
            logger.info(f"Shredding file ({passes} passes): {file_path}")
            
            # Remove read-only attribute if set
            if not os.access(file_path, os.W_OK):
                os.chmod(file_path, 0o777)
            
            # Overwrite the file
            if not self._overwrite_file(file_path, passes):
                return False
            
            # Truncate to zero
            with open(file_path, 'w') as f:
                pass
            
            # Rename to random name
            renamed_path = self._rename_before_delete(file_path)
            
            # Delete the file
            os.unlink(renamed_path)
            
            logger.info(f"✓ Securely deleted: {file_path}")
            db.log_activity("secure_delete", f"Shredded: {path.name}", 
                           f"Size: {file_size} bytes, Passes: {passes}", 
                           severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Secure delete failed: {e}")
            return False
            
        finally:
            self._is_deleting = False
            self._current_file = ""
            self._progress = 0
    
    def shred_folder(self, folder_path: str, passes: int = 3,
                     on_progress: Callable = None) -> Dict:
        """
        Securely delete a folder and all contents
        
        Args:
            folder_path: Path to folder
            passes: Number of overwrite passes
            on_progress: Callback(current_file, progress_percent)
        
        Returns:
            Summary of deletion
        """
        path = Path(folder_path)
        
        if not path.exists():
            return {"error": "Folder not found"}
        
        if not path.is_dir():
            return {"error": "Not a directory"}
        
        logger.info(f"Shredding folder: {folder_path}")
        
        files_shredded = 0
        files_failed = 0
        total_size = 0
        
        # Collect all files first
        files = list(path.rglob('*'))
        files = [f for f in files if f.is_file()]
        total_files = len(files)
        
        for i, file_path in enumerate(files):
            try:
                file_size = file_path.stat().st_size
                
                if on_progress:
                    on_progress(str(file_path), int((i / total_files) * 100))
                
                if self.shred_file(str(file_path), passes):
                    files_shredded += 1
                    total_size += file_size
                else:
                    files_failed += 1
                    
            except Exception as e:
                logger.error(f"Error shredding {file_path}: {e}")
                files_failed += 1
        
        # Remove empty directories
        for dir_path in sorted(path.rglob('*'), reverse=True):
            if dir_path.is_dir():
                try:
                    dir_path.rmdir()
                except:
                    pass
        
        # Remove the root folder
        try:
            path.rmdir()
        except:
            pass
        
        summary = {
            "files_shredded": files_shredded,
            "files_failed": files_failed,
            "total_size": total_size,
            "passes": passes
        }
        
        logger.info(f"Folder shredding complete: {files_shredded} files deleted")
        db.log_activity("secure_delete", f"Shredded folder: {path.name}",
                       f"Files: {files_shredded}, Size: {total_size} bytes",
                       severity="info")
        
        return summary
    
    def wipe_free_space(self, drive: str, passes: int = 1) -> bool:
        """
        Wipe free space on a drive to prevent recovery of deleted files
        
        Args:
            drive: Drive letter (e.g., "C:")
            passes: Number of passes
        
        Returns:
            True if successful
        """
        try:
            import shutil
            
            logger.info(f"Wiping free space on {drive}")
            
            temp_file = os.path.join(drive, f"escan_wipe_{random.randint(1000, 9999)}.tmp")
            
            # Get available space
            total, used, free = shutil.disk_usage(drive)
            
            # Leave some space available
            wipe_size = int(free * 0.95)
            
            # Write zeros in chunks
            chunk_size = 100 * 1024 * 1024  # 100MB chunks
            written = 0
            
            try:
                with open(temp_file, 'wb') as f:
                    while written < wipe_size:
                        try:
                            chunk = b'\x00' * min(chunk_size, wipe_size - written)
                            f.write(chunk)
                            written += len(chunk)
                        except OSError:
                            # Disk full
                            break
            finally:
                # Delete the temp file
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            
            logger.info(f"✓ Wiped {written / (1024**3):.2f} GB of free space on {drive}")
            db.log_activity("secure_delete", f"Wiped free space: {drive}",
                           f"Size: {written / (1024**3):.2f} GB",
                           severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Free space wipe error: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get secure delete status"""
        return {
            "is_deleting": self._is_deleting,
            "current_file": self._current_file,
            "progress": self._progress
        }


# Global secure delete instance
secure_delete = SecureDelete()
