"""
Windows 10 Antivirus - Backup Scheduler
Automated backup scheduling
"""
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Callable, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from config import BACKUP_CONFIG
from backup.ebackup import ebackup
from database import db
from loguru import logger


class BackupScheduler:
    """Automated backup scheduling"""
    
    def __init__(self):
        self._scheduler = BackgroundScheduler()
        self._jobs: Dict[str, Dict] = {}
        self._is_running = False
        self._on_backup_complete: Optional[Callable] = None
    
    def _run_backup(self, job_id: str, source_paths: List[str], 
                    compress: bool = True, encrypt: bool = False):
        """Execute scheduled backup"""
        try:
            logger.info(f"Running scheduled backup: {job_id}")
            
            result = ebackup.create_backup(
                source_paths=source_paths,
                backup_name=f"{job_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                compress=compress,
                encrypt=encrypt
            )
            
            if "error" not in result:
                db.log_activity("scheduler", f"Completed: {job_id}",
                               f"Files: {result.get('file_count', 0)}",
                               severity="info")
                
                if self._on_backup_complete:
                    self._on_backup_complete(job_id, result)
            else:
                db.log_activity("scheduler", f"Failed: {job_id}",
                               result.get("error"), severity="error")
                
        except Exception as e:
            logger.error(f"Scheduled backup error: {e}")
            db.log_activity("scheduler", f"Error: {job_id}", str(e), severity="error")
    
    def add_job(self, job_id: str, source_paths: List[str],
                schedule: str = "daily", time_str: str = "02:00",
                compress: bool = True, encrypt: bool = False) -> bool:
        """
        Add a scheduled backup job
        
        Args:
            job_id: Unique identifier for the job
            source_paths: Paths to backup
            schedule: 'hourly', 'daily', 'weekly', 'monthly'
            time_str: Time to run (HH:MM format)
            compress: Whether to compress
            encrypt: Whether to encrypt
        
        Returns:
            True if job was added
        """
        try:
            # Parse time
            hour, minute = map(int, time_str.split(':'))
            
            # Create trigger based on schedule
            if schedule == "hourly":
                trigger = CronTrigger(minute=minute)
            elif schedule == "daily":
                trigger = CronTrigger(hour=hour, minute=minute)
            elif schedule == "weekly":
                trigger = CronTrigger(day_of_week='sun', hour=hour, minute=minute)
            elif schedule == "monthly":
                trigger = CronTrigger(day=1, hour=hour, minute=minute)
            else:
                logger.error(f"Invalid schedule: {schedule}")
                return False
            
            # Add job to scheduler
            self._scheduler.add_job(
                self._run_backup,
                trigger=trigger,
                id=job_id,
                args=[job_id, source_paths, compress, encrypt],
                replace_existing=True
            )
            
            # Save job config
            self._jobs[job_id] = {
                "source_paths": source_paths,
                "schedule": schedule,
                "time": time_str,
                "compress": compress,
                "encrypt": encrypt,
                "created_at": datetime.now().isoformat()
            }
            
            logger.info(f"Added backup job: {job_id} ({schedule} at {time_str})")
            db.log_activity("scheduler", f"Added job: {job_id}", 
                           f"Schedule: {schedule} at {time_str}", severity="info")
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding job: {e}")
            return False
    
    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job"""
        try:
            if job_id in self._jobs:
                self._scheduler.remove_job(job_id)
                del self._jobs[job_id]
                logger.info(f"Removed backup job: {job_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing job: {e}")
            return False
    
    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job configuration"""
        return self._jobs.get(job_id)
    
    def list_jobs(self) -> List[Dict]:
        """List all scheduled jobs"""
        jobs = []
        
        for job_id, config in self._jobs.items():
            job_info = {
                "id": job_id,
                **config
            }
            
            # Get next run time
            scheduler_job = self._scheduler.get_job(job_id)
            if scheduler_job and scheduler_job.next_run_time:
                job_info["next_run"] = scheduler_job.next_run_time.isoformat()
            
            jobs.append(job_info)
        
        return jobs
    
    def run_job_now(self, job_id: str) -> bool:
        """Run a job immediately"""
        if job_id not in self._jobs:
            return False
        
        config = self._jobs[job_id]
        
        # Run in background
        thread = threading.Thread(
            target=self._run_backup,
            args=[job_id, config["source_paths"], 
                  config.get("compress", True), config.get("encrypt", False)],
            daemon=True
        )
        thread.start()
        
        return True
    
    def start(self, on_complete: Callable = None):
        """Start the scheduler"""
        if self._is_running:
            return
        
        self._on_backup_complete = on_complete
        self._scheduler.start()
        self._is_running = True
        
        logger.info("Backup scheduler started")
        db.log_activity("scheduler", "Scheduler started", severity="info")
    
    def stop(self):
        """Stop the scheduler"""
        if not self._is_running:
            return
        
        self._scheduler.shutdown(wait=False)
        self._is_running = False
        
        logger.info("Backup scheduler stopped")
    
    def pause_job(self, job_id: str):
        """Pause a scheduled job"""
        try:
            self._scheduler.pause_job(job_id)
            logger.info(f"Paused job: {job_id}")
        except:
            pass
    
    def resume_job(self, job_id: str):
        """Resume a paused job"""
        try:
            self._scheduler.resume_job(job_id)
            logger.info(f"Resumed job: {job_id}")
        except:
            pass
    
    def get_status(self) -> Dict:
        """Get scheduler status"""
        return {
            "is_running": self._is_running,
            "job_count": len(self._jobs),
            "jobs": self.list_jobs()
        }


# Global scheduler instance
backup_scheduler = BackupScheduler()
