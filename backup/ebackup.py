"""
Windows 10 Antivirus - eBackup System
File and folder backup with scheduling
"""
import os
import shutil
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Callable, Optional
import py7zr
from cryptography.fernet import Fernet

from config import BACKUP_DIR, BACKUP_CONFIG
from database import db
from loguru import logger


class EBackup:
    """Backup system with compression and encryption"""
    
    def __init__(self):
        self._backup_dir = BACKUP_DIR
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._encryption_key = self._get_or_create_key()
        self._is_backing_up = False
        self._current_progress = 0
        self._on_progress: Optional[Callable] = None
        self._lock = threading.Lock()
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        key_file = self._backup_dir / ".backup_key"
        
        if key_file.exists():
            return key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            key_file.write_bytes(key)
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(key_file), 2)
            except:
                pass
            return key
    
    def _get_files_to_backup(self, source_paths: List[str]) -> List[str]:
        """Get list of files to backup"""
        files = []
        
        for path in source_paths:
            path = Path(path)
            if not path.exists():
                continue
            
            if path.is_file():
                files.append(str(path))
            else:
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        files.append(str(file_path))
        
        return files
    
    def create_backup(self, source_paths: List[str], backup_name: str = None,
                      compress: bool = True, encrypt: bool = False,
                      on_progress: Callable = None) -> Dict:
        """
        Create a backup of specified paths
        
        Args:
            source_paths: List of files/folders to backup
            backup_name: Custom name for backup (auto-generated if None)
            compress: Whether to compress the backup
            encrypt: Whether to encrypt the backup
            on_progress: Callback(current_file, progress_percent)
        
        Returns:
            Backup summary
        """
        if self._is_backing_up:
            return {"error": "Backup already in progress"}
        
        self._is_backing_up = True
        self._on_progress = on_progress
        
        try:
            # Generate backup name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if not backup_name:
                backup_name = f"backup_{timestamp}"
            
            # Determine backup extension
            if compress:
                backup_file = self._backup_dir / f"{backup_name}.7z"
            else:
                backup_file = self._backup_dir / f"{backup_name}"
                backup_file.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Creating backup: {backup_name}")
            db.log_activity("backup", f"Started backup: {backup_name}", severity="info")
            
            # Get files to backup
            files = self._get_files_to_backup(source_paths)
            total_files = len(files)
            total_size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
            
            if on_progress:
                on_progress("Preparing...", 0)
            
            if compress:
                # Create compressed archive
                with py7zr.SevenZipFile(backup_file, 'w') as archive:
                    for i, file_path in enumerate(files):
                        try:
                            # Calculate relative path
                            rel_path = os.path.basename(file_path)
                            archive.write(file_path, rel_path)
                            
                            progress = int((i + 1) / total_files * 100)
                            self._current_progress = progress
                            
                            if on_progress:
                                on_progress(file_path, progress)
                        except Exception as e:
                            logger.warning(f"Could not backup {file_path}: {e}")
            else:
                # Simple copy
                for i, file_path in enumerate(files):
                    try:
                        dest = backup_file / os.path.basename(file_path)
                        shutil.copy2(file_path, dest)
                        
                        progress = int((i + 1) / total_files * 100)
                        self._current_progress = progress
                        
                        if on_progress:
                            on_progress(file_path, progress)
                    except Exception as e:
                        logger.warning(f"Could not backup {file_path}: {e}")
            
            # Encrypt if requested
            if encrypt and compress:
                encrypted_file = str(backup_file) + ".enc"
                self._encrypt_file(str(backup_file), encrypted_file)
                os.unlink(backup_file)
                backup_file = Path(encrypted_file)
            
            # Get final backup size
            if backup_file.is_file():
                backup_size = backup_file.stat().st_size
            else:
                backup_size = sum(f.stat().st_size for f in backup_file.rglob('*') if f.is_file())
            
            # Save to database
            db.log_activity("backup", f"Completed: {backup_name}",
                           f"Files: {total_files}, Size: {backup_size / (1024*1024):.2f} MB",
                           severity="info")
            
            summary = {
                "backup_name": backup_name,
                "backup_path": str(backup_file),
                "source_paths": source_paths,
                "file_count": total_files,
                "original_size": total_size,
                "backup_size": backup_size,
                "compressed": compress,
                "encrypted": encrypt,
                "created_at": datetime.now().isoformat()
            }
            
            logger.info(f"✓ Backup complete: {backup_name} ({total_files} files)")
            
            return summary
            
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return {"error": str(e)}
            
        finally:
            self._is_backing_up = False
            self._current_progress = 0
    
    def restore_backup(self, backup_path: str, restore_to: str = None,
                       on_progress: Callable = None) -> Dict:
        """
        Restore a backup
        
        Args:
            backup_path: Path to backup file/folder
            restore_to: Destination path (defaults to original locations)
            on_progress: Callback(current_file, progress_percent)
        
        Returns:
            Restore summary
        """
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            return {"error": "Backup not found"}
        
        try:
            logger.info(f"Restoring backup: {backup_path}")
            
            # Handle encrypted backups
            if str(backup_path).endswith('.enc'):
                decrypted_path = str(backup_path).replace('.enc', '')
                self._decrypt_file(str(backup_path), decrypted_path)
                backup_path = Path(decrypted_path)
            
            # Determine restore destination
            if not restore_to:
                restore_to = os.path.expanduser("~\\Restored")
            
            restore_dir = Path(restore_to)
            restore_dir.mkdir(parents=True, exist_ok=True)
            
            restored_files = 0
            
            if backup_path.suffix == '.7z':
                # Extract compressed backup
                with py7zr.SevenZipFile(backup_path, 'r') as archive:
                    archive.extractall(restore_dir)
                    restored_files = len(archive.getnames())
            elif backup_path.is_dir():
                # Copy files
                for file_path in backup_path.rglob('*'):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(backup_path)
                        dest = restore_dir / rel_path
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(file_path, dest)
                        restored_files += 1
            
            logger.info(f"✓ Restored {restored_files} files to {restore_dir}")
            db.log_activity("backup", f"Restored: {backup_path.name}",
                           f"Files: {restored_files}, To: {restore_dir}",
                           severity="info")
            
            return {
                "restored_files": restored_files,
                "restore_path": str(restore_dir),
                "restored_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Restore error: {e}")
            return {"error": str(e)}
    
    def _encrypt_file(self, source: str, dest: str):
        """Encrypt a file"""
        fernet = Fernet(self._encryption_key)
        
        with open(source, 'rb') as f:
            data = f.read()
        
        encrypted = fernet.encrypt(data)
        
        with open(dest, 'wb') as f:
            f.write(encrypted)
    
    def _decrypt_file(self, source: str, dest: str):
        """Decrypt a file"""
        fernet = Fernet(self._encryption_key)
        
        with open(source, 'rb') as f:
            encrypted = f.read()
        
        decrypted = fernet.decrypt(encrypted)
        
        with open(dest, 'wb') as f:
            f.write(decrypted)
    
    def list_backups(self) -> List[Dict]:
        """List all backups"""
        backups = []
        
        for item in self._backup_dir.iterdir():
            if item.name.startswith('.'):
                continue
            
            is_encrypted = item.suffix == '.enc'
            is_compressed = item.suffix in ['.7z', '.enc']
            
            backup_info = {
                "name": item.name,
                "path": str(item),
                "size": item.stat().st_size if item.is_file() else sum(f.stat().st_size for f in item.rglob('*') if f.is_file()),
                "created": datetime.fromtimestamp(item.stat().st_ctime).isoformat(),
                "is_compressed": is_compressed,
                "is_encrypted": is_encrypted
            }
            backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup"""
        try:
            backup_path = self._backup_dir / backup_name
            
            if backup_path.is_file():
                backup_path.unlink()
            elif backup_path.is_dir():
                shutil.rmtree(backup_path)
            else:
                return False
            
            logger.info(f"Deleted backup: {backup_name}")
            return True
        except Exception as e:
            logger.error(f"Delete backup error: {e}")
            return False
    
    def cleanup_old_backups(self, keep_count: int = None) -> int:
        """Remove old backups, keeping only the most recent ones"""
        if keep_count is None:
            keep_count = BACKUP_CONFIG.get("max_backups", 10)
        
        backups = self.list_backups()
        
        if len(backups) <= keep_count:
            return 0
        
        to_delete = backups[keep_count:]
        deleted = 0
        
        for backup in to_delete:
            if self.delete_backup(backup['name']):
                deleted += 1
        
        if deleted:
            logger.info(f"Cleaned up {deleted} old backups")
        
        return deleted
    
    def get_status(self) -> Dict:
        """Get backup status"""
        backups = self.list_backups()
        total_size = sum(b['size'] for b in backups)
        
        return {
            "is_backing_up": self._is_backing_up,
            "progress": self._current_progress,
            "backup_count": len(backups),
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }


# Global backup instance
ebackup = EBackup()
