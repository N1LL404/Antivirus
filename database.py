"""
Windows 10 Antivirus - Database Layer
SQLite database for storing threats, quarantine, logs, and settings
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from config import MAIN_DB
from loguru import logger


class Database:
    """SQLite database manager for antivirus data"""
    
    def __init__(self, db_path: Path = MAIN_DB):
        self.db_path = db_path
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_type TEXT DEFAULT 'malware',
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action_taken TEXT DEFAULT 'detected',
                    severity TEXT DEFAULT 'medium',
                    is_resolved BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Quarantine table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    threat_name TEXT,
                    quarantine_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER,
                    is_restored BOOLEAN DEFAULT FALSE,
                    encryption_key TEXT
                )
            """)
            
            # Scan history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                )
            """)
            
            # Activity logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    severity TEXT DEFAULT 'info'
                )
            """)
            
            # Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Backup history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_path TEXT NOT NULL,
                    source_paths TEXT NOT NULL,
                    backup_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_count INTEGER,
                    total_size INTEGER,
                    is_encrypted BOOLEAN DEFAULT FALSE,
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            # Parental control logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS parental_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_account TEXT,
                    activity_type TEXT,
                    url_or_app TEXT,
                    action TEXT,
                    blocked BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Firewall rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    action TEXT DEFAULT 'block',
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Protected folders table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS protected_folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    folder_path TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    protection_level TEXT DEFAULT 'read_only',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            logger.info("Database initialized successfully")
    
    # ==================== Threats ====================
    
    def add_threat(self, file_path: str, threat_name: str, threat_type: str = "malware",
                   hash_md5: str = None, hash_sha256: str = None, 
                   severity: str = "medium") -> int:
        """Add a detected threat to the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threats (file_path, threat_name, threat_type, hash_md5, hash_sha256, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (file_path, threat_name, threat_type, hash_md5, hash_sha256, severity))
            return cursor.lastrowid
    
    def get_threats(self, limit: int = 100, include_resolved: bool = False) -> List[Dict]:
        """Get list of detected threats"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if include_resolved:
                cursor.execute("SELECT * FROM threats ORDER BY detection_time DESC LIMIT ?", (limit,))
            else:
                cursor.execute("SELECT * FROM threats WHERE is_resolved = FALSE ORDER BY detection_time DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def resolve_threat(self, threat_id: int, action: str = "quarantined"):
        """Mark a threat as resolved"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE threats SET is_resolved = TRUE, action_taken = ? WHERE id = ?
            """, (action, threat_id))
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM threats")
            total = cursor.fetchone()["total"]
            cursor.execute("SELECT COUNT(*) as resolved FROM threats WHERE is_resolved = TRUE")
            resolved = cursor.fetchone()["resolved"]
            cursor.execute("SELECT COUNT(*) as today FROM threats WHERE DATE(detection_time) = DATE('now')")
            today = cursor.fetchone()["today"]
            return {"total": total, "resolved": resolved, "active": total - resolved, "today": today}
    
    # ==================== Quarantine ====================
    
    def add_quarantine(self, original_path: str, quarantine_path: str, 
                       threat_name: str, file_size: int, encryption_key: str = None) -> int:
        """Add a quarantined file record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_size, encryption_key)
                VALUES (?, ?, ?, ?, ?)
            """, (original_path, quarantine_path, threat_name, file_size, encryption_key))
            return cursor.lastrowid
    
    def get_quarantine_items(self) -> List[Dict]:
        """Get all quarantined items"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine WHERE is_restored = FALSE ORDER BY quarantine_time DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def restore_quarantine(self, quarantine_id: int):
        """Mark quarantine item as restored"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE quarantine SET is_restored = TRUE WHERE id = ?", (quarantine_id,))
    
    # ==================== Scan History ====================
    
    def start_scan(self, scan_type: str) -> int:
        """Start a new scan and return its ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO scan_history (scan_type) VALUES (?)", (scan_type,))
            return cursor.lastrowid
    
    def update_scan(self, scan_id: int, files_scanned: int = None, 
                    threats_found: int = None, status: str = None):
        """Update scan progress"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            updates = []
            values = []
            if files_scanned is not None:
                updates.append("files_scanned = ?")
                values.append(files_scanned)
            if threats_found is not None:
                updates.append("threats_found = ?")
                values.append(threats_found)
            if status is not None:
                updates.append("status = ?")
                values.append(status)
                if status in ["completed", "cancelled", "error"]:
                    updates.append("end_time = CURRENT_TIMESTAMP")
            values.append(scan_id)
            cursor.execute(f"UPDATE scan_history SET {', '.join(updates)} WHERE id = ?", values)
    
    def get_scan_history(self, limit: int = 20) -> List[Dict]:
        """Get scan history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Activity Logs ====================
    
    def log_activity(self, category: str, action: str, details: str = None, severity: str = "info"):
        """Log an activity"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_logs (category, action, details, severity)
                VALUES (?, ?, ?, ?)
            """, (category, action, details, severity))
    
    def get_activity_logs(self, category: str = None, limit: int = 100) -> List[Dict]:
        """Get activity logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if category:
                cursor.execute("""
                    SELECT * FROM activity_logs WHERE category = ? 
                    ORDER BY timestamp DESC LIMIT ?
                """, (category, limit))
            else:
                cursor.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Settings ====================
    
    def set_setting(self, key: str, value: Any):
        """Set a setting value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            json_value = json.dumps(value)
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (key, json_value))
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["value"])
            return default
    
    # ==================== Firewall Rules ====================
    
    def add_firewall_rule(self, name: str, rule_type: str, target: str, action: str = "block") -> int:
        """Add a firewall rule"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO firewall_rules (rule_name, rule_type, target, action)
                VALUES (?, ?, ?, ?)
            """, (name, rule_type, target, action))
            return cursor.lastrowid
    
    def get_firewall_rules(self, enabled_only: bool = True) -> List[Dict]:
        """Get firewall rules"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if enabled_only:
                cursor.execute("SELECT * FROM firewall_rules WHERE enabled = TRUE")
            else:
                cursor.execute("SELECT * FROM firewall_rules")
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Protected Folders ====================
    
    def add_protected_folder(self, folder_path: str, password_hash: str = None, 
                             protection_level: str = "read_only") -> int:
        """Add a protected folder"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO protected_folders (folder_path, password_hash, protection_level)
                VALUES (?, ?, ?)
            """, (folder_path, password_hash, protection_level))
            return cursor.lastrowid
    
    def get_protected_folders(self) -> List[Dict]:
        """Get all protected folders"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM protected_folders")
            return [dict(row) for row in cursor.fetchall()]


# Global database instance
db = Database()
