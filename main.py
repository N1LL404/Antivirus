"""
Windows 10 Antivirus - Main Entry Point
eScan Antivirus Application
"""
import sys
import os
import ctypes
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from loguru import logger
from config import APP_NAME, DATA_DIR, LOG_DIR

# Configure logging
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    level="INFO",
    format="{time:HH:mm:ss} | <level>{level: <8}</level> | <level>{message}</level>"
)
logger.add(
    LOG_DIR / "escan_{time}.log",
    rotation="10 MB",
    retention="7 days",
    level="DEBUG",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {module}:{function}:{line} | {message}"
)


def is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def request_admin():
    """Request admin privileges"""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


def initialize_app():
    """Initialize application components"""
    logger.info(f"Starting {APP_NAME}...")
    
    # Create required directories
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    from database import db
    logger.info("Database initialized")
    
    # Load signatures
    from core.signatures import signature_db
    logger.info(f"Loaded {signature_db.get_signature_count()['hash_signatures']} signatures")
    
    return True


def start_protection():
    """Start background protection services"""
    from core.realtime import realtime_protection
    from core.usb_vaccine import usb_vaccine as usb_monitor
    from protection.firewall import firewall
    from protection.keylogger_detect import anti_keylogger
    from utilities.gaming_mode import gaming_mode
    
    # Start real-time protection
    realtime_protection.start()
    
    # Start USB monitoring
    usb_monitor.start_monitoring()
    
    # Start firewall monitoring
    firewall.start()
    
    # Start anti-keylogger
    anti_keylogger.start()
    
    # Start gaming mode auto-detection
    gaming_mode.start_auto_detect()
    
    logger.info("Protection services started")


def start_gui():
    """Start the GUI application"""
    from gui.dashboard import Dashboard
    from gui.tray import system_tray
    
    # Create main window
    app = Dashboard()
    
    # Start system tray
    def on_open():
        app.deiconify()
        app.focus_force()
    
    def on_scan(full=False):
        from core.scanner import scanner
        if full:
            scanner.full_scan()
        else:
            scanner.quick_scan()
    
    def on_exit():
        app.destroy()
    
    system_tray.start(
        on_open=on_open,
        on_scan=on_scan,
        on_exit=on_exit
    )
    
    # Handle window close - minimize to tray
    def on_close():
        app.withdraw()
    
    app.protocol("WM_DELETE_WINDOW", on_close)
    
    logger.info("GUI started")
    app.mainloop()


def main():
    """Main entry point"""
    try:
        # Check for admin (optional but recommended)
        if not is_admin():
            logger.warning("Running without admin privileges - some features may be limited")
        
        # Initialize
        if not initialize_app():
            logger.error("Failed to initialize application")
            sys.exit(1)
        
        # Start protection services
        start_protection()
        
        # Start GUI
        start_gui()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        logger.info("Application shutdown")


if __name__ == "__main__":
    main()
