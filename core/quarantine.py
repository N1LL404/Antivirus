"""
Windows 10 Antivirus - Quarantine Manager
Safely isolates detected threats
"""
import os
import shutil
import base64
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
from cryptography.fernet import Fernet

from config import QUARANTINE_DIR
from database import db
from loguru import logger


class QuarantineManager:
    """Manages quarantined files securely"""
    
    def __init__(self, quarantine_dir: Path = QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._encryption_key = self._get_or_create_key()
        self._fernet = Fernet(self._encryption_key)
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key for quarantine"""
        key_file = self.quarantine_dir / ".qkey"
        
        if key_file.exists():
            return key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            key_file.write_bytes(key)
            # Hide the key file
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(key_file), 2)  # HIDDEN
            except:
                pass
            return key
    
    def quarantine_file(self, file_path: str, threat_name: str = "Unknown") -> Optional[str]:
        """
        Move a file to quarantine with encryption
        
        Args:
            file_path: Path to the infected file
            threat_name: Name of the detected threat
        
        Returns:
            Quarantine path if successful, None otherwise
        """
        try:
            source_path = Path(file_path)
            
            if not source_path.exists():
                logger.error(f"File not found for quarantine: {file_path}")
                return None
            
            # Generate unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = source_path.name.replace(".", "_")
            quarantine_name = f"{timestamp}_{safe_name}.quarantine"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Read and encrypt the file
            file_size = source_path.stat().st_size
            with open(source_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self._fernet.encrypt(file_data)
            
            # Create metadata
            metadata = {
                "original_path": str(source_path.absolute()),
                "original_name": source_path.name,
                "threat_name": threat_name,
                "quarantine_time": datetime.now().isoformat(),
                "file_size": file_size
            }
            
            # Write encrypted file with metadata
            metadata_json = json.dumps(metadata).encode()
            metadata_length = len(metadata_json)
            
            with open(quarantine_path, 'wb') as f:
                f.write(metadata_length.to_bytes(4, 'little'))
                f.write(metadata_json)
                f.write(encrypted_data)
            
            # Delete original file
            try:
                source_path.unlink()
                logger.info(f"Quarantined: {file_path} -> {quarantine_path}")
            except PermissionError:
                # If can't delete, try to make it unusable
                try:
                    source_path.rename(str(source_path) + ".quarantined")
                except:
                    logger.warning(f"Could not remove original file: {file_path}")
            
            # Add to database
            db.add_quarantine(
                original_path=str(source_path.absolute()),
                quarantine_path=str(quarantine_path),
                threat_name=threat_name,
                file_size=file_size,
                encryption_key=base64.b64encode(self._encryption_key).decode()
            )
            
            db.log_activity("quarantine", f"Quarantined: {source_path.name}", 
                           f"Threat: {threat_name}", severity="warning")
            
            return str(quarantine_path)
            
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return None
    
    def restore_file(self, quarantine_id: int, restore_path: str = None) -> Optional[str]:
        """
        Restore a file from quarantine
        
        Args:
            quarantine_id: Database ID of quarantined file
            restore_path: Optional custom restore path
        
        Returns:
            Restored file path if successful
        """
        try:
            # Get quarantine record
            items = db.get_quarantine_items()
            item = next((i for i in items if i['id'] == quarantine_id), None)
            
            if not item:
                logger.error(f"Quarantine item not found: {quarantine_id}")
                return None
            
            quarantine_path = Path(item['quarantine_path'])
            
            if not quarantine_path.exists():
                logger.error(f"Quarantine file not found: {quarantine_path}")
                return None
            
            # Read and decrypt
            with open(quarantine_path, 'rb') as f:
                metadata_length = int.from_bytes(f.read(4), 'little')
                metadata_json = f.read(metadata_length)
                encrypted_data = f.read()
            
            metadata = json.loads(metadata_json.decode())
            
            # Decrypt file
            decrypted_data = self._fernet.decrypt(encrypted_data)
            
            # Determine restore path
            if restore_path:
                target_path = Path(restore_path)
            else:
                target_path = Path(metadata['original_path'])
            
            # Ensure parent directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Handle existing file
            if target_path.exists():
                base = target_path.stem
                ext = target_path.suffix
                counter = 1
                while target_path.exists():
                    target_path = target_path.parent / f"{base}_restored_{counter}{ext}"
                    counter += 1
            
            # Write restored file
            with open(target_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update database
            db.restore_quarantine(quarantine_id)
            
            # Remove quarantine file
            quarantine_path.unlink()
            
            logger.info(f"Restored: {quarantine_path} -> {target_path}")
            db.log_activity("quarantine", f"Restored: {target_path.name}", severity="info")
            
            return str(target_path)
            
        except Exception as e:
            logger.error(f"Failed to restore quarantine item {quarantine_id}: {e}")
            return None
    
    def delete_quarantine(self, quarantine_id: int) -> bool:
        """Permanently delete a quarantined file"""
        try:
            items = db.get_quarantine_items()
            item = next((i for i in items if i['id'] == quarantine_id), None)
            
            if not item:
                return False
            
            quarantine_path = Path(item['quarantine_path'])
            
            if quarantine_path.exists():
                quarantine_path.unlink()
            
            db.restore_quarantine(quarantine_id)  # Mark as handled
            
            logger.info(f"Deleted quarantine item: {quarantine_id}")
            db.log_activity("quarantine", "Permanently deleted quarantine item", severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete quarantine item {quarantine_id}: {e}")
            return False
    
    def get_quarantine_info(self, quarantine_id: int) -> Optional[Dict]:
        """Get information about a quarantined file without restoring"""
        try:
            items = db.get_quarantine_items()
            item = next((i for i in items if i['id'] == quarantine_id), None)
            
            if not item:
                return None
            
            quarantine_path = Path(item['quarantine_path'])
            
            if not quarantine_path.exists():
                return None
            
            # Read metadata
            with open(quarantine_path, 'rb') as f:
                metadata_length = int.from_bytes(f.read(4), 'little')
                metadata_json = f.read(metadata_length)
            
            metadata = json.loads(metadata_json.decode())
            metadata['quarantine_id'] = quarantine_id
            metadata['quarantine_path'] = str(quarantine_path)
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to get quarantine info: {e}")
            return None
    
    def list_quarantine(self) -> List[Dict]:
        """List all quarantined items"""
        return db.get_quarantine_items()
    
    def get_stats(self) -> Dict:
        """Get quarantine statistics"""
        items = self.list_quarantine()
        total_size = sum(item.get('file_size', 0) for item in items)
        
        return {
            "count": len(items),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }
    
    def cleanup_old(self, days: int = 30) -> int:
        """Delete quarantine items older than specified days"""
        from datetime import timedelta
        
        items = self.list_quarantine()
        deleted = 0
        cutoff = datetime.now() - timedelta(days=days)
        
        for item in items:
            try:
                quarantine_time = datetime.fromisoformat(item['quarantine_time'])
                if quarantine_time < cutoff:
                    if self.delete_quarantine(item['id']):
                        deleted += 1
            except:
                pass
        
        if deleted:
            logger.info(f"Cleaned up {deleted} old quarantine items")
            db.log_activity("quarantine", f"Cleaned up {deleted} old items", severity="info")
        
        return deleted


# Global quarantine manager instance
quarantine_manager = QuarantineManager()
