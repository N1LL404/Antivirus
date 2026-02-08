"""
Windows 10 Antivirus - Identity Guard
Protects against identity theft and data theft
"""
import os
import re
import json
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path
import threading

from database import db
from loguru import logger


class IdentityGuard:
    """Identity theft and data theft protection"""
    
    def __init__(self):
        self._sensitive_patterns = {
            'credit_card': [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',  # Visa
                r'\b(?:5[1-5][0-9]{14})\b',  # Mastercard
                r'\b(?:3[47][0-9]{13})\b',  # Amex
                r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',  # Discover
            ],
            'ssn': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # US SSN
                r'\b\d{9}\b',  # SSN without dashes (context needed)
            ],
            'phone': [
                r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US phone
                r'\b\+\d{1,3}[-.\s]?\d{9,12}\b',  # International
            ],
            'email': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'password_plain': [
                r'password\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                r'pwd\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
                r'pass\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
            ],
            'api_key': [
                r'api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
                r'secret[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
                r'(sk_live_[A-Za-z0-9]{24,})',  # Stripe
                r'(AKIA[0-9A-Z]{16})',  # AWS Access Key
            ],
        }
        
        # Sensitive file patterns
        self._sensitive_files = [
            'passwords.txt', 'credentials.txt', 'secrets.txt',
            'id_rsa', 'id_dsa', '.pem', '.key', '.pfx',
            'wallet.dat', 'keystore', '.env', 'config.json',
        ]
        
        self._monitoring_paths: List[str] = []
        self._alerts: List[Dict] = []
        self._lock = threading.Lock()
    
    def scan_text_for_sensitive_data(self, text: str, 
                                      source: str = "unknown") -> List[Dict]:
        """
        Scan text for sensitive data patterns
        
        Args:
            text: Text content to scan
            source: Source identifier (file path, clipboard, etc.)
        
        Returns:
            List of detected sensitive data items
        """
        findings = []
        
        for data_type, patterns in self._sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    # Mask the sensitive data for logging
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    masked = self._mask_sensitive_data(match, data_type)
                    
                    finding = {
                        "type": data_type,
                        "masked_value": masked,
                        "source": source,
                        "detected_at": datetime.now().isoformat()
                    }
                    findings.append(finding)
                    
                    logger.warning(f"🔐 Sensitive data detected: {data_type} in {source}")
        
        if findings:
            db.log_activity("identity", 
                           f"Sensitive data found: {len(findings)} items",
                           f"Source: {source}",
                           severity="warning")
            
            with self._lock:
                self._alerts.extend(findings)
        
        return findings
    
    def _mask_sensitive_data(self, value: str, data_type: str) -> str:
        """Mask sensitive data for safe display"""
        if data_type == 'credit_card':
            return f"****-****-****-{value[-4:]}" if len(value) >= 4 else "****"
        elif data_type == 'ssn':
            return f"***-**-{value[-4:]}" if len(value) >= 4 else "***"
        elif data_type == 'phone':
            return f"***-***-{value[-4:]}" if len(value) >= 4 else "***"
        elif data_type == 'email':
            if '@' in value:
                local, domain = value.split('@', 1)
                return f"{local[:2]}***@{domain}"
            return "***@***"
        else:
            return f"{value[:3]}...{value[-3:]}" if len(value) > 6 else "***"
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a file for sensitive data"""
        try:
            path = Path(file_path)
            
            if not path.exists() or not path.is_file():
                return []
            
            # Skip large files
            if path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return []
            
            # Read file content
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                return []
            
            return self.scan_text_for_sensitive_data(content, str(path))
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []
    
    def scan_clipboard(self) -> List[Dict]:
        """Scan clipboard for sensitive data"""
        try:
            import win32clipboard
            
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                    data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                    if isinstance(data, bytes):
                        data = data.decode('utf-8', errors='ignore')
                    return self.scan_text_for_sensitive_data(data, "clipboard")
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            logger.debug(f"Clipboard scan error: {e}")
        
        return []
    
    def check_data_exfiltration(self, text: str, destination: str) -> Tuple[bool, List[Dict]]:
        """
        Check if data being sent contains sensitive information
        
        Args:
            text: Data being transmitted
            destination: Where data is being sent (URL, email, etc.)
        
        Returns:
            Tuple of (is_blocked, findings)
        """
        findings = self.scan_text_for_sensitive_data(text, f"outbound to {destination}")
        
        if findings:
            logger.warning(f"⚠️ Potential data exfiltration blocked to {destination}")
            db.log_activity("identity", 
                           "Data exfiltration attempt blocked",
                           f"Destination: {destination}, Items: {len(findings)}",
                           severity="critical")
            return True, findings
        
        return False, []
    
    def find_sensitive_files(self, search_path: str = None) -> List[Dict]:
        """Find files that may contain sensitive data"""
        findings = []
        
        if not search_path:
            search_path = os.path.expanduser("~")
        
        try:
            for root, dirs, files in os.walk(search_path):
                # Skip system directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['Windows', 'Program Files']]
                
                for filename in files:
                    for sensitive_pattern in self._sensitive_files:
                        if sensitive_pattern.lower() in filename.lower():
                            file_path = os.path.join(root, filename)
                            findings.append({
                                "file_path": file_path,
                                "filename": filename,
                                "pattern_matched": sensitive_pattern,
                                "found_at": datetime.now().isoformat()
                            })
                            logger.info(f"Found sensitive file: {file_path}")
                            break
        
        except Exception as e:
            logger.error(f"Error scanning for sensitive files: {e}")
        
        if findings:
            db.log_activity("identity", 
                           f"Found {len(findings)} sensitive files",
                           severity="info")
        
        return findings
    
    def protect_browser_data(self) -> Dict:
        """Check browser data exposure risks"""
        risks = []
        
        browser_paths = {
            "Chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
            "Firefox": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
            "Edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
        }
        
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                # Check for login data files
                for root, dirs, files in os.walk(path):
                    for f in files:
                        if f in ['Login Data', 'logins.json', 'cookies.sqlite', 'Cookies']:
                            risks.append({
                                "browser": browser,
                                "data_type": f,
                                "path": os.path.join(root, f),
                                "risk": "Browser stores sensitive data locally"
                            })
                    break  # Only check top level
        
        return {
            "browsers_checked": list(browser_paths.keys()),
            "risks_found": len(risks),
            "details": risks
        }
    
    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent identity protection alerts"""
        with self._lock:
            return self._alerts[-limit:]
    
    def get_stats(self) -> Dict:
        """Get identity guard statistics"""
        with self._lock:
            alert_count = len(self._alerts)
        
        return {
            "total_alerts": alert_count,
            "patterns_monitored": sum(len(p) for p in self._sensitive_patterns.values()),
            "sensitive_file_patterns": len(self._sensitive_files)
        }


# Global identity guard instance
identity_guard = IdentityGuard()
