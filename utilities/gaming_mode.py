"""
Windows 10 Antivirus - Gaming Mode
Suspends resource-intensive operations during gaming
"""
import threading
import time
from typing import List, Dict, Callable, Optional, Set
from datetime import datetime
import psutil
import ctypes

from database import db
from loguru import logger


class GamingMode:
    """Gaming mode - reduces system impact during gaming"""
    
    def __init__(self):
        self._is_active = False
        self._auto_detect = True
        self._monitor_thread = None
        self._suspended_operations: Set[str] = set()
        self._on_mode_change: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Known game processes
        self._game_processes = {
            # Popular games
            'GTA5.exe', 'GTAV.exe', 'FiveM.exe',
            'FortniteClient-Win64-Shipping.exe', 'FortniteClient.exe',
            'ModernWarfare.exe', 'BlackOpsColdWar.exe', 'cod.exe',
            'csgo.exe', 'cs2.exe', 'valorant.exe', 'VALORANT-Win64-Shipping.exe',
            'League of Legends.exe', 'LeagueClient.exe',
            'Overwatch.exe', 'Overwatch 2.exe',
            'Minecraft.exe', 'javaw.exe',  # Minecraft Java
            'RocketLeague.exe',
            'ApexLegends.exe', 'r5apex.exe',
            'PUBG.exe', 'TslGame.exe',
            'Destiny2.exe',
            'Warframe.x64.exe',
            'eldenring.exe', 'DarkSoulsIII.exe',
            'witcher3.exe', 'Cyberpunk2077.exe',
            'RDR2.exe', 'GTA4.exe',
            'NBA2K24.exe', 'FIFA24.exe',
            # Emulators
            'dolphin.exe', 'rpcs3.exe', 'yuzu.exe', 'Cemu.exe',
            'ePSXe.exe', 'pcsx2.exe', 'ppsspp.exe',
            'BlueStacks.exe', 'HD-Player.exe',
            # Game launchers (may indicate gaming)
            'steam.exe', 'EpicGamesLauncher.exe', 'Origin.exe',
            'Battle.net.exe', 'GalaxyClient.exe',
        }
        
        # Fullscreen detection
        self._check_fullscreen = True
    
    def _is_fullscreen_app_running(self) -> Optional[str]:
        """Check if any fullscreen application is running"""
        try:
            user32 = ctypes.windll.user32
            
            # Get foreground window
            hwnd = user32.GetForegroundWindow()
            
            if hwnd:
                # Get window rect
                rect = ctypes.wintypes.RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(rect))
                
                # Get screen size
                screen_width = user32.GetSystemMetrics(0)
                screen_height = user32.GetSystemMetrics(1)
                
                window_width = rect.right - rect.left
                window_height = rect.bottom - rect.top
                
                # Check if window covers entire screen
                if window_width >= screen_width and window_height >= screen_height:
                    # Get process name
                    pid = ctypes.wintypes.DWORD()
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    
                    try:
                        proc = psutil.Process(pid.value)
                        return proc.name()
                    except:
                        pass
        except:
            pass
        
        return None
    
    def _detect_games(self) -> List[str]:
        """Detect running game processes"""
        running_games = []
        
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name']
                if proc_name in self._game_processes:
                    running_games.append(proc_name)
            except:
                pass
        
        return running_games
    
    def enable(self, reason: str = "manual"):
        """Enable gaming mode"""
        if self._is_active:
            return
        
        with self._lock:
            self._is_active = True
        
        logger.info(f"🎮 Gaming Mode ENABLED (reason: {reason})")
        db.log_activity("gaming_mode", f"Enabled: {reason}", severity="info")
        
        if self._on_mode_change:
            self._on_mode_change(True, reason)
    
    def disable(self, reason: str = "manual"):
        """Disable gaming mode"""
        if not self._is_active:
            return
        
        with self._lock:
            self._is_active = False
            self._suspended_operations.clear()
        
        logger.info(f"Gaming Mode DISABLED (reason: {reason})")
        db.log_activity("gaming_mode", f"Disabled: {reason}", severity="info")
        
        if self._on_mode_change:
            self._on_mode_change(False, reason)
    
    def _monitor_loop(self):
        """Background monitoring for games"""
        last_game_detected = None
        
        while self._auto_detect:
            try:
                game_detected = False
                detected_game = None
                
                # Check for known game processes
                running_games = self._detect_games()
                if running_games:
                    game_detected = True
                    detected_game = running_games[0]
                
                # Check for fullscreen apps
                if not game_detected and self._check_fullscreen:
                    fullscreen_app = self._is_fullscreen_app_running()
                    if fullscreen_app and fullscreen_app not in ['explorer.exe', 'dwm.exe']:
                        game_detected = True
                        detected_game = fullscreen_app
                
                # Enable/disable based on detection
                if game_detected and not self._is_active:
                    self.enable(reason=f"Detected: {detected_game}")
                    last_game_detected = detected_game
                    
                elif not game_detected and self._is_active and last_game_detected:
                    # Wait a bit before disabling (game might be loading)
                    time.sleep(5)
                    
                    # Re-check
                    if not self._detect_games():
                        fullscreen = self._is_fullscreen_app_running()
                        if not fullscreen or fullscreen in ['explorer.exe', 'dwm.exe']:
                            self.disable(reason="No games detected")
                            last_game_detected = None
                
            except Exception as e:
                logger.error(f"Gaming mode monitor error: {e}")
            
            time.sleep(3)  # Check every 3 seconds
    
    def start_auto_detect(self, on_mode_change: Callable = None):
        """
        Start automatic game detection
        
        Args:
            on_mode_change: Callback(is_active: bool, reason: str)
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        
        self._auto_detect = True
        self._on_mode_change = on_mode_change
        
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Gaming mode auto-detection ENABLED")
    
    def stop_auto_detect(self):
        """Stop automatic game detection"""
        self._auto_detect = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        
        logger.info("Gaming mode auto-detection DISABLED")
    
    def add_game(self, process_name: str):
        """Add a process to the game list"""
        self._game_processes.add(process_name)
        logger.info(f"Added game: {process_name}")
    
    def remove_game(self, process_name: str):
        """Remove a process from the game list"""
        self._game_processes.discard(process_name)
        logger.info(f"Removed game: {process_name}")
    
    def suspend_operation(self, operation_name: str):
        """Mark an operation as suspended during gaming mode"""
        with self._lock:
            self._suspended_operations.add(operation_name)
    
    def resume_operation(self, operation_name: str):
        """Resume a suspended operation"""
        with self._lock:
            self._suspended_operations.discard(operation_name)
    
    def should_run(self, operation_name: str) -> bool:
        """
        Check if an operation should run
        
        Use this to check before running scans, updates, etc.
        
        Returns:
            True if operation should run (gaming mode not active)
        """
        return not self._is_active
    
    def get_game_list(self) -> List[str]:
        """Get list of known game processes"""
        return sorted(list(self._game_processes))
    
    def get_status(self) -> Dict:
        """Get gaming mode status"""
        return {
            "is_active": self._is_active,
            "auto_detect": self._auto_detect,
            "running_games": self._detect_games(),
            "suspended_operations": list(self._suspended_operations),
            "known_games": len(self._game_processes)
        }


# Global gaming mode instance
gaming_mode = GamingMode()
