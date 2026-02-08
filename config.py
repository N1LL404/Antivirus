"""
Windows 10 Antivirus - Global Configuration
"""
import os
from pathlib import Path

# Application Info
APP_NAME = "eScan Antivirus"
APP_VERSION = "1.0.0"
APP_AUTHOR = "SYRAX Security"

# Base Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
BACKUP_DIR = DATA_DIR / "backups"
LOGS_DIR = DATA_DIR / "logs"
LOG_DIR = LOGS_DIR
SIGNATURES_DB = DATA_DIR / "signatures.db"
MAIN_DB = DATA_DIR / "antivirus.db"

# Create directories if they don't exist
for directory in [DATA_DIR, QUARANTINE_DIR, BACKUP_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Scanning Configuration
SCAN_CONFIG = {
    "max_file_size_mb": 100,  # Skip files larger than this
    "scan_archives": True,
    "scan_hidden_files": True,
    "excluded_extensions": [".iso", ".vmdk", ".vdi"],
    "excluded_paths": [
        "C:\\Windows\\WinSxS",
        "C:\\$Recycle.Bin",
        "C:\\ProgramData\\Microsoft\\Windows Defender",
        os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data"),
    ],
    "quick_scan_paths": [
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        "C:\\ProgramData",
        os.environ.get("TEMP", "C:\\Temp"),
    ],
}

# Real-time Protection
REALTIME_CONFIG = {
    "enabled": True,
    "monitor_paths": [
        os.path.expanduser("~"),
        "C:\\ProgramData",
    ],
    "scan_on_access": True,
    "scan_on_modify": True,
    "scan_on_create": True,
}

# Firewall Configuration
FIREWALL_CONFIG = {
    "enabled": True,
    "block_suspicious_ips": True,
    "log_connections": True,
    "blocked_ports": [4444, 5555, 6666],  # Common malware ports
    "blocked_ips": [],
    "allowed_apps": [],
}

# Backup Configuration
BACKUP_CONFIG = {
    "enabled": True,
    "compression": True,
    "encryption": True,
    "max_backups": 10,
    "default_schedule": "daily",
    "backup_folders": [
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Pictures"),
        os.path.expanduser("~\\Desktop"),
    ],
}

# Parental Control Configuration
PARENTAL_CONFIG = {
    "enabled": False,
    "blocked_categories": ["adult", "gambling", "violence"],
    "time_limits": {
        "weekday_hours": 4,
        "weekend_hours": 6,
    },
    "blocked_apps": [],
    "log_activity": True,
}

# Anti-Theft Configuration
ANTITHEFT_CONFIG = {
    "enabled": False,
    "server_url": "",  # Remote command server
    "check_interval_minutes": 5,
    "wipe_on_command": False,
}

# Gaming Mode Configuration
GAMING_CONFIG = {
    "enabled": True,
    "auto_detect": True,
    "suspend_scans": True,
    "suspend_notifications": True,
    "fullscreen_apps": [],
}

# UI Configuration
UI_CONFIG = {
    "theme": "dark",
    "accent_color": "#00D4AA",
    "danger_color": "#FF4757",
    "warning_color": "#FFA502",
    "success_color": "#2ED573",
    "window_width": 1200,
    "window_height": 800,
}

# Logging Configuration
LOG_CONFIG = {
    "level": "INFO",
    "rotation": "10 MB",
    "retention": "30 days",
    "format": "{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
}

# Known Malware Signatures (sample - will be expanded)
MALWARE_SIGNATURES = {
    # EICAR Test File (standard antivirus test)
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File-SHA256",
    
    # WannaCry Ransomware
    "db349b97c37d22f5ea1d1841e3c89eb4": "WannaCry-Worm-Loader",
    "84c82835a5d21bbcf75a61706d8ab549": "WannaCry-TaskSche",
    "7bf2b57f2a205768755c07f238fb32cc": "WannaCry-Decryptor",
    "f351e1fcca0c4ea05fc44d15a17f8b36": "WannaCry-Encryptor",
    
    # Emotet Botnet
    "e613de7a49077fb6459a272c93ef35bd": "Emotet-Malicious-Doc",
    "bc3532085a0b4febd9eed51aac2180d0": "Emotet-Loader-DLL",
    
    # Trickbot Banking Trojan
    "4f2139e3961202b1dfeae288aed5cb8f": "Trickbot-InternalFax-Doc",
    "d58cd6a8d6632edcb6d9354fb094d395": "Trickbot-Downloader",
    "6699fdf727451b58e3071957364fb5c4": "Trickbot-UPS-Invoice",
    
    # Zeus (Zbot) Banking Trojan
    "ea039a854d20d7734c5add48f1a51c34": "Zeus-Banking-Trojan",
    
    # LockBit Ransomware
    "7f0312a1f928c3aeab672ca8d5afc6a9": "LockBit-Ransomware",
    "eb9176b89f8a96d3963628b21b87c07d": "LockBit-Unpacked",
    "e818a9afd55693d556a47002a7b7ef31": "LockBit-5.0-Encryptor",
    
    # Stuxnet Worm
    "b4429d77586798064b56b0099f0ccd49": "Stuxnet-Component",
    "b65f8e25fb1f24ad166c24b69fa600a8": "Stuxnet-Encrypted-Resource",
    
    # Pulsar RAT
    "648c0ba2bb1cde47fa8812f254821a72": "Pulsar-RAT",
    "69392e0d2b877cb932ab709ebe758975": "Pulsar-RAT-Variant",

    # Petya/NotPetya Ransomware
    "af2379cc4d607a45ac44d62135fb7015": "Petya-Ransomware-Variant-1",
    "a2d6887d8a7b09b86a917a5c61674ab4": "Petya-Ransomware-Variant-2",
    "34f917aaba5684fbe56d3c57d48ef2a1aa7cf06d": "NotPetya-Payload-SHA1",

    # REvil (Sodinokibi) Ransomware
    "ccfde149220e87e97198c23fb8115d5a": "REvil-Sodinokibi-Executable",
    "bed6fc04aeb785815744706239a1f243": "REvil-Beta-Sample",

    # njRAT (Remote Access Trojan)
    "971339f61c09851c272523f50e7bb57b": "njRAT-Sample-1",
    "1d3baedd747f6f9bf92c81eb9f63b34b": "njRAT-Authorization-Exe",

    # Agent Tesla Spyware
    "e4117e6974363cac8b37e5e3ff5d07a6": "Agent-Tesla-Payload",

    # DarkSide Ransomware
    "c4da0137cbb99626fd44da707ae1bca8": "DarkSide-Ransomware",

    # GandCrab Ransomware
    "4302aac62e41f4355206d49257c3aaae": "GandCrab-v2.3.1",

    # Azorult Stealer
    "f32bd9317b8dc700e899aacc554a3b50": "Azorult-Stealer-Sample",
    "5ddac41b063bc265854f053fb026475f": "Azorult-Binary-Dump",

    # Formbook Stealer
    "161daa7d2a6b0dee089eab8beed53cad": "Formbook-Sample-1",
    "fe0ca4811ea529df63db2e2000700f3e": "Formbook-Sample-2",
    "3f97452832828085ff10d7c929d0c3e0": "Formbook-Dropped-File",

    # NanoCore RAT
    "dee4977684fa55f729571c25c975e10e": "NanoCore-RAT-Gen1",
    "5846c3588fbcf6a5078b7a2413da0345": "NanoCore-RAT-Gen2",

    # Cobalt Strike Beacon (Specific Sample)
    "222b8f27dbdfba8ddd559eeca27ea648": "Cobalt-Strike-Beacon-v4.4-Java",

    # Mimikatz (Hacktool)
    "62057620295220ab0eceaa5c7a1f2592": "Mimikatz-x64-Generic",

    # Ryuk Ransomware
    "1cb0c1248d3899358a375888bb4e8f3fe": "Ryuk-Ransomware-Sample-1",
    "2d4a7c85f23438de8ebb5f8d6e04e55fc": "Ryuk-Ransomware-Sample-2",

    # ILOVEYOU Worm
    "8e2c097ca623ca32723d57968b9d2525": "ILOVEYOU-Worm-VBS",
    
    # MyDoom Worm
    "53df39092394741514bc050f3d6a06a9": "MyDoom.A-Worm",
    
    # Sasser Worm
    "a73c16ccd0b9c4f20bc7842edd90fc20": "Sasser.A-Worm",
    "1a2c0e6130850f8fd9b9b5309413cd00": "Sasser.B-Worm",

    # Dridex Banking Trojan
    "72fe19810a9089cd1ec3ac5ddda22d3f": "Dridex-Trojan-Sample",
    
    # CryptoWall Ransomware
    "f31b1c58e0110b407ef1f99f2c8a5a63": "CryptoWall-2.0-Dropper",
    "47363b94cee907e2b8926c1be61150c7": "CryptoWall-3.0-Sample",
    
    # Cerber Ransomware
    "db073371dcmac628e69c2b91e1e18bd9": "Cerber-Ransomware-Payload",
    
    # TeslaCrypt Ransomware
    "a9ed5ec475f4f746d77576a7c48f15ac": "TeslaCrypt-2014-Sample",
    "209a288c68207d57e0ce6e60ebf60729": "TeslaCrypt-2015-Sample",
    
    # Ramnit Virus
    "56b2c3810dba2e939a8bb9fa36d3cf96": "Ramnit-Worm-Sample",
    
    # Conficker Worm
    "04199a5b981fd5a3d846d3f9d4c1d574": "Conficker-Worm-Sample",
    "c9e0917fe3231a652c014ad76b55b26a": "Conficker.exe-Sample",

    # BlackMatter Ransomware
    "598c53bfef81e489375f09792e487f1a": "BlackMatter-v1.2",
    "38035325b785329e3f618b2a0b90eb75": "BlackMatter-v2.0",

    # Conti Ransomware
    "0a49ed1c5419bb9752821d856f7ce4ff": "Conti-Ransomware-v2",
    "eb3fbab995fe3d4c57d4859f1268876c": "Conti-Dll-Component",

    # Melissa Virus
    "735eb4053434135544a143997f499bcf": "Melissa-Macro-Virus",

    # Flame Malware
    "b51424138d72d343f22d03438fc9ced5": "Flame-Main-Module-mssecmgr",
    "2afaab2840e4ba6af0e5fa744cd8f41f": "Flame-Wiper-Module",

    # Duqu Malware
    "574313e41f8fb121df94bd0c20e4eb14": "Duqu-Main-Component",
    "3fde1bbf3330e0bd0952077a390cef72": "Duqu-2.0-Driver",

    # Shamoon Wiper
    "41f8cd9ac3fb6b1771177e5770537518": "Shamoon-2018-Wiper",

    # DarkComet RAT
    "b5462c4312a587171c400953f8fd79f0": "DarkComet-Controller",
}

# Suspicious Patterns (heuristic detection)
SUSPICIOUS_PATTERNS = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"NtUnmapViewOfSection",
    b"WScript.Shell",
    b"powershell -enc",
    b"cmd /c",
    b"certutil -decode",
    b"bitsadmin /transfer",
]

# Phishing Domain Database (sample)
PHISHING_DOMAINS = [
    "secure-login-verify.com",
    "account-update-required.net",
    "banking-secure-login.com",
]

# Keylogger Signatures
KEYLOGGER_SIGNATURES = [
    "GetAsyncKeyState",
    "SetWindowsHookEx",
    "GetKeyboardState",
    "MapVirtualKey",
]
