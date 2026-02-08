"""
Windows 10 Antivirus - Advanced Firewall
Network monitoring and connection blocking
"""
import socket
import threading
import time
from typing import List, Dict, Callable, Optional
from collections import defaultdict
from datetime import datetime
import psutil

from config import FIREWALL_CONFIG
from database import db
from loguru import logger


class ConnectionInfo:
    """Information about a network connection"""
    
    def __init__(self, local_addr: str, local_port: int, remote_addr: str, 
                 remote_port: int, status: str, pid: int, process_name: str):
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.status = status
        self.pid = pid
        self.process_name = process_name
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            "local": f"{self.local_addr}:{self.local_port}",
            "remote": f"{self.remote_addr}:{self.remote_port}",
            "status": self.status,
            "pid": self.pid,
            "process": self.process_name,
            "time": self.timestamp.isoformat()
        }


class AdvancedFirewall:
    """Advanced network firewall with monitoring and blocking"""
    
    def __init__(self):
        self.is_enabled = False
        self._monitor_thread = None
        self._blocked_ips = set(FIREWALL_CONFIG.get("blocked_ips", []))
        self._blocked_ports = set(FIREWALL_CONFIG.get("blocked_ports", []))
        self._allowed_apps = set(FIREWALL_CONFIG.get("allowed_apps", []))
        self._connection_log: List[ConnectionInfo] = []
        self._suspicious_connections: List[ConnectionInfo] = []
        self._on_suspicious: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Known suspicious ports
        self._suspicious_ports = {
            4444, 5555, 6666,  # Common reverse shell ports
            31337,  # Back Orifice
            12345, 12346,  # NetBus
            27374,  # SubSeven
            1080,  # SOCKS proxy (potential C2)
            3128,  # Squid proxy
            8080,  # HTTP proxy
            9001, 9030, 9050, 9051,  # Tor
        }
        
        # Known malicious IPs (sample - would be updated)
        self._malicious_ips = set()
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except:
            return "Unknown"
    
    def get_active_connections(self) -> List[Dict]:
        """Get all active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    local = conn.laddr
                    remote = conn.raddr if conn.raddr else ('', 0)
                    
                    connection = ConnectionInfo(
                        local_addr=local.ip if local else '',
                        local_port=local.port if local else 0,
                        remote_addr=remote[0] if remote else '',
                        remote_port=remote[1] if remote else 0,
                        status=conn.status,
                        pid=conn.pid or 0,
                        process_name=self._get_process_name(conn.pid) if conn.pid else 'Unknown'
                    )
                    connections.append(connection)
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
        
        return connections
    
    def _is_suspicious_connection(self, conn: ConnectionInfo) -> tuple:
        """Check if a connection is suspicious"""
        reasons = []
        
        # Check blocked IPs
        if conn.remote_addr in self._blocked_ips:
            reasons.append("Blocked IP")
        
        # Check blocked ports
        if conn.remote_port in self._blocked_ports:
            reasons.append("Blocked port")
        
        # Check suspicious ports
        if conn.remote_port in self._suspicious_ports:
            reasons.append(f"Suspicious port {conn.remote_port}")
        
        # Check malicious IPs
        if conn.remote_addr in self._malicious_ips:
            reasons.append("Known malicious IP")
        
        # Check for Tor connections
        if conn.remote_port in [9001, 9030, 9050, 9051]:
            reasons.append("Tor network detected")
        
        # Check if process is not in allowed list (if whitelist mode)
        if self._allowed_apps and conn.process_name.lower() not in [a.lower() for a in self._allowed_apps]:
            reasons.append("Unknown application")
        
        return bool(reasons), reasons
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        seen_connections = set()
        
        while self.is_enabled:
            try:
                connections = self.get_active_connections()
                
                for conn in connections:
                    # Create unique identifier
                    conn_id = f"{conn.remote_addr}:{conn.remote_port}:{conn.pid}"
                    
                    if conn_id not in seen_connections:
                        seen_connections.add(conn_id)
                        
                        # Log connection
                        with self._lock:
                            self._connection_log.append(conn)
                            # Keep only last 1000 connections
                            if len(self._connection_log) > 1000:
                                self._connection_log = self._connection_log[-1000:]
                        
                        # Check if suspicious
                        is_suspicious, reasons = self._is_suspicious_connection(conn)
                        
                        if is_suspicious:
                            with self._lock:
                                self._suspicious_connections.append(conn)
                            
                            logger.warning(f"🚨 Suspicious connection: {conn.process_name} -> "
                                         f"{conn.remote_addr}:{conn.remote_port} ({', '.join(reasons)})")
                            
                            db.log_activity("firewall", 
                                          f"Suspicious: {conn.process_name}",
                                          f"{conn.remote_addr}:{conn.remote_port} - {', '.join(reasons)}",
                                          severity="warning")
                            
                            if self._on_suspicious:
                                self._on_suspicious(conn, reasons)
                
                # Cleanup old seen connections
                if len(seen_connections) > 5000:
                    seen_connections.clear()
                    
            except Exception as e:
                logger.error(f"Firewall monitoring error: {e}")
            
            time.sleep(1)
    
    def start(self, on_suspicious: Callable = None):
        """Start firewall monitoring"""
        if self.is_enabled:
            logger.warning("Firewall already running")
            return
        
        self._on_suspicious = on_suspicious
        self.is_enabled = True
        
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        db.log_activity("firewall", "Firewall started", severity="info")
        logger.info("🔥 Firewall ENABLED")
    
    def stop(self):
        """Stop firewall monitoring"""
        self.is_enabled = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        
        db.log_activity("firewall", "Firewall stopped", severity="warning")
        logger.info("Firewall DISABLED")
    
    def block_ip(self, ip: str, reason: str = None):
        """Block an IP address"""
        self._blocked_ips.add(ip)
        db.add_firewall_rule(f"Block IP: {ip}", "ip", ip, "block")
        db.log_activity("firewall", f"Blocked IP: {ip}", reason, severity="warning")
        logger.info(f"Blocked IP: {ip}")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self._blocked_ips.discard(ip)
        logger.info(f"Unblocked IP: {ip}")
    
    def block_port(self, port: int, reason: str = None):
        """Block a port"""
        self._blocked_ports.add(port)
        db.add_firewall_rule(f"Block port: {port}", "port", str(port), "block")
        db.log_activity("firewall", f"Blocked port: {port}", reason, severity="warning")
        logger.info(f"Blocked port: {port}")
    
    def allow_app(self, app_name: str):
        """Add application to whitelist"""
        self._allowed_apps.add(app_name.lower())
        logger.info(f"Allowed app: {app_name}")
    
    def get_connection_log(self, limit: int = 100) -> List[Dict]:
        """Get connection log"""
        with self._lock:
            return [c.to_dict() for c in self._connection_log[-limit:]]
    
    def get_suspicious_log(self, limit: int = 50) -> List[Dict]:
        """Get suspicious connection log"""
        with self._lock:
            return [c.to_dict() for c in self._suspicious_connections[-limit:]]
    
    def get_network_stats(self) -> Dict:
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "bytes_sent_mb": round(net_io.bytes_sent / (1024 * 1024), 2),
                "bytes_recv_mb": round(net_io.bytes_recv / (1024 * 1024), 2),
            }
        except:
            return {}
    
    def get_status(self) -> Dict:
        """Get firewall status"""
        return {
            "enabled": self.is_enabled,
            "blocked_ips": list(self._blocked_ips),
            "blocked_ports": list(self._blocked_ports),
            "allowed_apps": list(self._allowed_apps),
            "suspicious_count": len(self._suspicious_connections),
            "network_stats": self.get_network_stats()
        }


# Global firewall instance
firewall = AdvancedFirewall()
