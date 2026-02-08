"""
Windows 10 Antivirus - Malware Signature Database
Manages malware signatures for detection
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime

from config import SIGNATURES_DB, MALWARE_SIGNATURES, SUSPICIOUS_PATTERNS
from loguru import logger


class SignatureDatabase:
    """Manages malware signatures for detection"""
    
    def __init__(self, db_path: Path = SIGNATURES_DB):
        self.db_path = db_path
        self._init_database()
        self._load_default_signatures()
    
    def _init_database(self):
        """Initialize signature database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Hash signatures table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hash_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_value TEXT UNIQUE NOT NULL,
                hash_type TEXT DEFAULT 'md5',
                threat_name TEXT NOT NULL,
                threat_type TEXT DEFAULT 'malware',
                severity TEXT DEFAULT 'high',
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Pattern signatures table (for heuristic detection)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pattern_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern BLOB NOT NULL,
                pattern_name TEXT NOT NULL,
                threat_type TEXT DEFAULT 'suspicious',
                severity TEXT DEFAULT 'medium',
                description TEXT
            )
        """)
        
        # Whitelist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_value TEXT UNIQUE NOT NULL,
                file_path TEXT,
                reason TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("Signature database initialized")
    
    def _load_default_signatures(self):
        """Load default malware signatures"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Load hash signatures from config
        for hash_value, threat_name in MALWARE_SIGNATURES.items():
            try:
                hash_type = "sha256" if len(hash_value) == 64 else "md5"
                cursor.execute("""
                    INSERT OR IGNORE INTO hash_signatures (hash_value, hash_type, threat_name)
                    VALUES (?, ?, ?)
                """, (hash_value.lower(), hash_type, threat_name))
            except Exception as e:
                logger.debug(f"Signature already exists or error: {e}")
        
        # Load pattern signatures
        for i, pattern in enumerate(SUSPICIOUS_PATTERNS):
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO pattern_signatures (pattern, pattern_name, threat_type)
                    VALUES (?, ?, ?)
                """, (pattern, f"SuspiciousPattern_{i}", "heuristic"))
            except Exception as e:
                logger.debug(f"Pattern already exists or error: {e}")
        
        conn.commit()
        conn.close()
    
    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """Check if a hash matches known malware"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM hash_signatures WHERE hash_value = ?
        """, (file_hash.lower(),))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return dict(result)
        return None
    
    def check_whitelist(self, file_hash: str) -> bool:
        """Check if a hash is whitelisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM whitelist WHERE hash_value = ?", (file_hash.lower(),))
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def add_signature(self, hash_value: str, threat_name: str, 
                      hash_type: str = "md5", threat_type: str = "malware",
                      severity: str = "high") -> bool:
        """Add a new signature to the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO hash_signatures (hash_value, hash_type, threat_name, threat_type, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (hash_value.lower(), hash_type, threat_name, threat_type, severity))
            conn.commit()
            conn.close()
            logger.info(f"Added signature: {threat_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add signature: {e}")
            return False
    
    def add_to_whitelist(self, file_hash: str, file_path: str = None, reason: str = None) -> bool:
        """Add a hash to the whitelist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO whitelist (hash_value, file_path, reason)
                VALUES (?, ?, ?)
            """, (file_hash.lower(), file_path, reason))
            conn.commit()
            conn.close()
            logger.info(f"Added to whitelist: {file_hash[:16]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to add to whitelist: {e}")
            return False
    
    def get_patterns(self) -> List[Tuple[bytes, str]]:
        """Get all pattern signatures for heuristic detection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT pattern, pattern_name FROM pattern_signatures")
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_signature_count(self) -> Dict:
        """Get signature statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM hash_signatures")
        hash_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM pattern_signatures")
        pattern_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM whitelist")
        whitelist_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "hash_signatures": hash_count,
            "pattern_signatures": pattern_count,
            "whitelisted": whitelist_count
        }


# Global signature database instance
signature_db = SignatureDatabase()
