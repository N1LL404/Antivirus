"""
Windows 10 Antivirus - Anti-Phishing Protection
Protects against email and web-based phishing
"""
import re
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import requests

from config import PHISHING_DOMAINS
from database import db
from loguru import logger


class AntiPhishing:
    """Protection against phishing attacks"""
    
    def __init__(self):
        # Known phishing indicators
        self._phishing_domains = set(PHISHING_DOMAINS)
        self._phishing_keywords = [
            'verify your account', 'confirm your identity', 'suspended account',
            'unusual activity', 'update your information', 'click here immediately',
            'your account will be closed', 'unauthorized access', 'security alert',
            'password expired', 'confirm your password', 'verify your email',
            'limited time offer', 'act now', 'urgent action required',
            'your account has been compromised', 'reset your password',
            'you have won', 'claim your prize', 'lottery winner',
            'nigerian prince', 'inheritance', 'millions of dollars'
        ]
        
        # Suspicious TLDs often used in phishing
        self._suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
            '.xyz', '.top', '.work', '.click', '.link',
            '.info', '.biz', '.online', '.site', '.website'
        ]
        
        # Brand impersonation patterns
        self._brand_patterns = [
            (r'paypa[il1]', 'PayPal'),
            (r'amaz[o0]n', 'Amazon'),
            (r'app[il1]e', 'Apple'),
            (r'g[o0]{2}g[il1]e', 'Google'),
            (r'micr[o0]s[o0]ft', 'Microsoft'),
            (r'faceb[o0]{2}k', 'Facebook'),
            (r'netf[il1]ix', 'Netflix'),
            (r'dr[o0]pb[o0]x', 'Dropbox'),
            (r'[il1]nstagram', 'Instagram'),
            (r'wh[a4]ts[a4]pp', 'WhatsApp'),
        ]
        
        # Statistics
        self._blocked_urls = 0
        self._blocked_emails = 0
    
    def check_url(self, url: str) -> Tuple[bool, List[str]]:
        """
        Check if a URL is a phishing attempt
        
        Returns:
            Tuple of (is_phishing, reasons)
        """
        reasons = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_url = url.lower()
            
            # Check against known phishing domains
            if domain in self._phishing_domains:
                reasons.append("Known phishing domain")
            
            # Check for suspicious TLDs
            for tld in self._suspicious_tlds:
                if domain.endswith(tld):
                    reasons.append(f"Suspicious TLD: {tld}")
                    break
            
            # Check for IP address instead of domain
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                reasons.append("Uses IP address instead of domain")
            
            # Check for brand impersonation
            for pattern, brand in self._brand_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    # Check if it's not the official domain
                    official_domains = {
                        'PayPal': ['paypal.com'],
                        'Amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
                        'Apple': ['apple.com', 'icloud.com'],
                        'Google': ['google.com', 'gmail.com', 'googleapis.com'],
                        'Microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
                        'Facebook': ['facebook.com', 'fb.com'],
                        'Netflix': ['netflix.com'],
                        'Dropbox': ['dropbox.com'],
                        'Instagram': ['instagram.com'],
                        'WhatsApp': ['whatsapp.com'],
                    }
                    
                    if not any(domain.endswith(d) for d in official_domains.get(brand, [])):
                        reasons.append(f"Possible {brand} impersonation")
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'login.*verify', r'account.*update', r'secure.*login',
                r'confirm.*identity', r'reset.*password', r'unlock.*account',
                r'-login\.', r'\.login-', r'signin\.',
                r'\.co\.[a-z]{2}\.', # e.g., .co.uk.phishing.com
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, full_url, re.IGNORECASE):
                    reasons.append(f"Suspicious URL pattern")
                    break
            
            # Check for excessive subdomains (common in phishing)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                reasons.append(f"Excessive subdomains ({subdomain_count})")
            
            # Check for homograph attacks (look-alike characters)
            homograph_chars = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'}
            for fake, real in homograph_chars.items():
                if fake in domain and real in domain:
                    reasons.append("Possible homograph attack")
                    break
            
            is_phishing = len(reasons) > 0
            
            if is_phishing:
                self._blocked_urls += 1
                db.log_activity("phishing", f"Blocked URL: {domain}", 
                               ', '.join(reasons), severity="warning")
                logger.warning(f"🎣 Phishing URL detected: {url}")
            
            return is_phishing, reasons
            
        except Exception as e:
            logger.error(f"Error checking URL: {e}")
            return False, []
    
    def check_email_content(self, subject: str, body: str, 
                           sender: str = None) -> Tuple[bool, List[str]]:
        """
        Check if email content appears to be phishing
        
        Returns:
            Tuple of (is_phishing, reasons)
        """
        reasons = []
        combined_text = f"{subject} {body}".lower()
        
        # Check for phishing keywords
        keyword_matches = 0
        for keyword in self._phishing_keywords:
            if keyword.lower() in combined_text:
                keyword_matches += 1
                if keyword_matches >= 2:  # Multiple keywords = more suspicious
                    reasons.append(f"Contains phishing keywords")
                    break
        
        # Check sender domain if provided
        if sender:
            sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
            
            # Check for domain spoofing patterns
            for pattern, brand in self._brand_patterns:
                if re.search(pattern, sender_domain, re.IGNORECASE):
                    official = {
                        'PayPal': 'paypal.com',
                        'Amazon': 'amazon.com',
                        'Apple': 'apple.com',
                        'Google': 'google.com',
                        'Microsoft': 'microsoft.com',
                    }
                    if sender_domain != official.get(brand, ''):
                        reasons.append(f"Sender impersonating {brand}")
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediately', 'expires', 'suspended', 'limited time']
        if sum(1 for w in urgency_words if w in combined_text) >= 2:
            reasons.append("High urgency language")
        
        # Check for suspicious links in body
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+' 
        urls = re.findall(url_pattern, body)
        for url in urls[:5]:  # Check first 5 URLs
            is_phishing, url_reasons = self.check_url(url)
            if is_phishing:
                reasons.append(f"Contains phishing URL")
                break
        
        # Check for HTML tricks (hidden links, etc.)
        if '<a' in body.lower() and 'href' in body.lower():
            # Check for mismatched link text and href
            link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
            for href, text in re.findall(link_pattern, body, re.IGNORECASE):
                if text.startswith('http') and urlparse(href).netloc != urlparse(text).netloc:
                    reasons.append("Mismatched link text and URL")
                    break
        
        is_phishing = len(reasons) > 0
        
        if is_phishing:
            self._blocked_emails += 1
            db.log_activity("phishing", "Phishing email detected",
                           f"Subject: {subject[:50]}, Reasons: {', '.join(reasons)}", 
                           severity="warning")
            logger.warning(f"🎣 Phishing email detected: {subject[:50]}")
        
        return is_phishing, reasons
    
    def add_phishing_domain(self, domain: str):
        """Add a domain to the phishing list"""
        self._phishing_domains.add(domain.lower())
        logger.info(f"Added phishing domain: {domain}")
    
    def remove_domain(self, domain: str):
        """Remove a domain from the phishing list"""
        self._phishing_domains.discard(domain.lower())
    
    def get_stats(self) -> Dict:
        """Get phishing protection statistics"""
        return {
            "known_phishing_domains": len(self._phishing_domains),
            "blocked_urls": self._blocked_urls,
            "blocked_emails": self._blocked_emails
        }
    
    def safe_browse_check(self, url: str) -> Dict:
        """
        Extended URL check with additional analysis
        
        Returns detailed analysis of the URL
        """
        is_phishing, reasons = self.check_url(url)
        
        result = {
            "url": url,
            "is_phishing": is_phishing,
            "reasons": reasons,
            "risk_level": "high" if len(reasons) >= 2 else "medium" if reasons else "low",
            "recommendation": "BLOCK" if is_phishing else "ALLOW",
            "checked_at": datetime.now().isoformat()
        }
        
        # Additional analysis
        try:
            parsed = urlparse(url)
            result["domain"] = parsed.netloc
            result["scheme"] = parsed.scheme
            result["uses_https"] = parsed.scheme == 'https'
            
            if not result["uses_https"]:
                result["reasons"].append("Does not use HTTPS")
                if result["risk_level"] == "low":
                    result["risk_level"] = "medium"
        except:
            pass
        
        return result


# Global anti-phishing instance
anti_phishing = AntiPhishing()
