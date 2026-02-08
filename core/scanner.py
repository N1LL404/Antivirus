"""
Windows 10 Antivirus - File Scanner Engine
Scans files for malware using signatures and heuristics
"""
import os
import hashlib
import threading
import queue
from pathlib import Path
from typing import Optional, Dict, List, Callable, Generator
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import SCAN_CONFIG, SUSPICIOUS_PATTERNS
from core.signatures import signature_db
from database import db
from loguru import logger


class ScanResult:
    """Represents the result of a file scan"""
    
    def __init__(self, file_path: str, is_threat: bool = False, 
                 threat_name: str = None, threat_type: str = None,
                 severity: str = None, hash_md5: str = None, 
                 hash_sha256: str = None, detection_method: str = None):
        self.file_path = file_path
        self.is_threat = is_threat
        self.threat_name = threat_name
        self.threat_type = threat_type
        self.severity = severity
        self.hash_md5 = hash_md5
        self.hash_sha256 = hash_sha256
        self.detection_method = detection_method
        self.scan_time = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "is_threat": self.is_threat,
            "threat_name": self.threat_name,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "hash_md5": self.hash_md5,
            "hash_sha256": self.hash_sha256,
            "detection_method": self.detection_method,
            "scan_time": self.scan_time.isoformat()
        }


class Scanner:
    """File scanner engine for malware detection"""
    
    def __init__(self):
        self.is_scanning = False
        self.scan_cancelled = False
        self.current_scan_id = None
        self.files_scanned = 0
        self.threats_found = 0
        self.current_file = ""
        self._lock = threading.Lock()
    
    def calculate_hashes(self, file_path: str) -> tuple:
        """Calculate MD5 and SHA256 hashes of a file"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except (IOError, PermissionError) as e:
            logger.debug(f"Cannot read file for hashing: {file_path} - {e}")
            return None, None
    
    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file for malware"""
        self.current_file = file_path
        
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            max_size = SCAN_CONFIG["max_file_size_mb"] * 1024 * 1024
            
            if file_size > max_size:
                logger.debug(f"Skipping large file: {file_path}")
                return ScanResult(file_path)
            
            # Calculate hashes
            md5_hash, sha256_hash = self.calculate_hashes(file_path)
            
            if not md5_hash:
                return ScanResult(file_path)
            
            # Check whitelist first
            if signature_db.check_whitelist(md5_hash) or signature_db.check_whitelist(sha256_hash or ""):
                logger.debug(f"Whitelisted file: {file_path}")
                return ScanResult(file_path, hash_md5=md5_hash, hash_sha256=sha256_hash)
            
            # Check hash signatures
            threat = signature_db.check_hash(md5_hash)
            if not threat and sha256_hash:
                threat = signature_db.check_hash(sha256_hash)
            
            if threat:
                logger.warning(f"THREAT DETECTED: {threat['threat_name']} in {file_path}")
                return ScanResult(
                    file_path=file_path,
                    is_threat=True,
                    threat_name=threat['threat_name'],
                    threat_type=threat['threat_type'],
                    severity=threat['severity'],
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    detection_method="signature"
                )
            
            # Heuristic analysis (pattern matching)
            heuristic_result = self._heuristic_scan(file_path)
            if heuristic_result:
                logger.warning(f"SUSPICIOUS: {heuristic_result} in {file_path}")
                return ScanResult(
                    file_path=file_path,
                    is_threat=True,
                    threat_name=heuristic_result,
                    threat_type="suspicious",
                    severity="medium",
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    detection_method="heuristic"
                )
            
            return ScanResult(file_path, hash_md5=md5_hash, hash_sha256=sha256_hash)
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return ScanResult(file_path)
    
    def _heuristic_scan(self, file_path: str) -> Optional[str]:
        """Perform heuristic analysis on a file"""
        try:
            # Only scan certain file types for patterns
            extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta']
            if not any(file_path.lower().endswith(ext) for ext in extensions):
                return None
            
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
            
            patterns = signature_db.get_patterns()
            for pattern, pattern_name in patterns:
                if pattern in content:
                    return f"Heuristic.{pattern_name}"
            
            # Additional suspicious pattern checks
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in content:
                    return f"Heuristic.SuspiciousCode"
            
            return None
            
        except Exception as e:
            logger.debug(f"Heuristic scan error for {file_path}: {e}")
            return None
    
    def _get_files_to_scan(self, paths: List[str], recursive: bool = True) -> Generator[str, None, None]:
        """Generate list of files to scan"""
        excluded_extensions = SCAN_CONFIG["excluded_extensions"]
        excluded_paths = [p.lower() for p in SCAN_CONFIG["excluded_paths"]]
        
        for path in paths:
            path = Path(path)
            
            if not path.exists():
                continue
            
            if path.is_file():
                yield str(path)
                continue
            
            # Directory scanning
            if recursive:
                file_iter = path.rglob('*')
            else:
                file_iter = path.glob('*')
            
            for file_path in file_iter:
                if self.scan_cancelled:
                    return
                
                if not file_path.is_file():
                    continue
                
                # Skip excluded paths
                if any(excl in str(file_path).lower() for excl in excluded_paths):
                    continue
                
                # Skip excluded extensions
                if any(str(file_path).lower().endswith(ext) for ext in excluded_extensions):
                    continue
                
                # Skip hidden files if configured
                if not SCAN_CONFIG["scan_hidden_files"]:
                    try:
                        import ctypes
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                        if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN
                            continue
                    except:
                        pass
                
                yield str(file_path)
    
    def scan(self, paths: List[str], scan_type: str = "custom",
             on_progress: Callable = None, on_threat: Callable = None,
             max_workers: int = 4) -> Dict:
        """
        Perform a scan on specified paths
        
        Args:
            paths: List of file/folder paths to scan
            scan_type: Type of scan (quick, full, custom)
            on_progress: Callback(files_scanned, current_file)
            on_threat: Callback(scan_result)
            max_workers: Number of parallel scan threads
        
        Returns:
            Scan summary dictionary
        """
        if self.is_scanning:
            logger.warning("Scan already in progress")
            return {"error": "Scan already in progress"}
        
        self.is_scanning = True
        self.scan_cancelled = False
        self.files_scanned = 0
        self.threats_found = 0
        threats = []
        
        # Start scan record in database
        self.current_scan_id = db.start_scan(scan_type)
        db.log_activity("scan", f"Started {scan_type} scan", severity="info")
        
        logger.info(f"Starting {scan_type} scan on {len(paths)} paths")
        
        try:
            files_to_scan = list(self._get_files_to_scan(paths))
            total_files = len(files_to_scan)
            
            logger.info(f"Found {total_files} files to scan")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.scan_file, f): f for f in files_to_scan}
                
                for future in as_completed(futures):
                    if self.scan_cancelled:
                        break
                    
                    result = future.result()
                    
                    with self._lock:
                        self.files_scanned += 1
                    
                    if result.is_threat:
                        with self._lock:
                            self.threats_found += 1
                            threats.append(result)
                        
                        # Add to database
                        db.add_threat(
                            file_path=result.file_path,
                            threat_name=result.threat_name,
                            threat_type=result.threat_type,
                            hash_md5=result.hash_md5,
                            hash_sha256=result.hash_sha256,
                            severity=result.severity
                        )
                        
                        if on_threat:
                            on_threat(result)
                    
                    # Progress callback
                    if on_progress and self.files_scanned % 10 == 0:
                        on_progress(self.files_scanned, total_files, result.file_path)
                    
                    # Update database periodically
                    if self.files_scanned % 100 == 0:
                        db.update_scan(self.current_scan_id, 
                                      files_scanned=self.files_scanned,
                                      threats_found=self.threats_found)
            
            # Finalize scan
            status = "cancelled" if self.scan_cancelled else "completed"
            db.update_scan(self.current_scan_id,
                          files_scanned=self.files_scanned,
                          threats_found=self.threats_found,
                          status=status)
            
            db.log_activity("scan", f"Completed {scan_type} scan: {self.files_scanned} files, {self.threats_found} threats")
            
            summary = {
                "scan_type": scan_type,
                "status": status,
                "files_scanned": self.files_scanned,
                "threats_found": self.threats_found,
                "threats": [t.to_dict() for t in threats]
            }
            
            logger.info(f"Scan completed: {self.files_scanned} files, {self.threats_found} threats")
            return summary
            
        finally:
            self.is_scanning = False
            self.current_scan_id = None
    
    def quick_scan(self, on_progress: Callable = None, on_threat: Callable = None) -> Dict:
        """Perform a quick scan of common locations"""
        paths = SCAN_CONFIG["quick_scan_paths"]
        return self.scan(paths, "quick", on_progress, on_threat)
    
    def full_scan(self, on_progress: Callable = None, on_threat: Callable = None) -> Dict:
        """Perform a full system scan"""
        # Get all drives
        import string
        drives = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        
        return self.scan(drives, "full", on_progress, on_threat, max_workers=2)
    
    def cancel_scan(self):
        """Cancel the current scan"""
        if self.is_scanning:
            self.scan_cancelled = True
            logger.info("Scan cancellation requested")
    
    def get_status(self) -> Dict:
        """Get current scan status"""
        return {
            "is_scanning": self.is_scanning,
            "files_scanned": self.files_scanned,
            "threats_found": self.threats_found,
            "current_file": self.current_file if self.is_scanning else None
        }


# Global scanner instance
scanner = Scanner()
