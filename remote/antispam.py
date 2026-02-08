"""
Windows 10 Antivirus - Anti-Spam
Email spam filtering
"""
import re
from typing import List, Dict, Tuple
from datetime import datetime

from database import db
from loguru import logger


class AntiSpam:
    """Email spam detection and filtering"""
    
    def __init__(self):
        self._spam_keywords = [
            'viagra', 'cialis', 'lottery', 'winner', 'inheritance',
            'nigerian prince', 'million dollars', 'act now', 'limited time',
            'free money', 'work from home', 'weight loss', 'click here',
            'unsubscribe', 'casino', 'betting', 'prescription'
        ]
        
        self._blocked_senders: set = set()
        self._whitelist: set = set()
        self._spam_count = 0
    
    def check_email(self, sender: str, subject: str, body: str) -> Tuple[bool, List[str]]:
        """Check if email is spam"""
        reasons = []
        
        # Check whitelist
        if sender.lower() in self._whitelist:
            return False, []
        
        # Check blocked senders
        if sender.lower() in self._blocked_senders:
            return True, ["Blocked sender"]
        
        combined = f"{subject} {body}".lower()
        
        # Check keywords
        for kw in self._spam_keywords:
            if kw in combined:
                reasons.append(f"Spam keyword: {kw}")
        
        # Check for excessive caps
        if sum(1 for c in subject if c.isupper()) > len(subject) * 0.5:
            reasons.append("Excessive capitals")
        
        # Check for suspicious links
        if re.findall(r'https?://[^\s]+', body):
            url_count = len(re.findall(r'https?://[^\s]+', body))
            if url_count > 5:
                reasons.append(f"Too many links ({url_count})")
        
        is_spam = len(reasons) >= 2
        
        if is_spam:
            self._spam_count += 1
            db.log_activity("spam", "Blocked spam", subject[:50], severity="info")
        
        return is_spam, reasons
    
    def add_to_blocklist(self, sender: str):
        """Block a sender"""
        self._blocked_senders.add(sender.lower())
    
    def add_to_whitelist(self, sender: str):
        """Whitelist a sender"""
        self._whitelist.add(sender.lower())
    
    def get_stats(self) -> Dict:
        """Get spam stats"""
        return {
            "spam_blocked": self._spam_count,
            "blocked_senders": len(self._blocked_senders),
            "whitelisted": len(self._whitelist)
        }


# Global anti-spam instance
anti_spam = AntiSpam()
