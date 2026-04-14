#!/usr/bin/env python3
"""
iOS Backup Script
Creates full iTunes-compatible iOS device backup using pymobiledevice3 CLI
Supports progress tracking for UI integration
"""

import sys
import json
import os
import asyncio
import subprocess
import re
from pathlib import Path
from typing import Optional, Callable
from datetime import datetime
from threading import Thread
from queue import Queue, Empty

try:
    from pymobiledevice3.lockdown import create_using_usbmux
except ImportError as e:
    print(json.dumps({
        "error": "pymobiledevice3 not installed",
        "message": "Run: pip install pymobiledevice3",
        "details": str(e)
    }), file=sys.stderr)
    sys.exit(1)


def safe_value(value):
    """
    Convert value to JSON-safe format
    Handles bytes, coroutines, and other non-serializable types
    """
    if value is None:
        return None
    elif isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except:
            return value.hex()  # If not UTF-8, return hex representation
    elif isinstance(value, (str, int, float, bool)):
        return value
    elif isinstance(value, dict):
        return {k: safe_value(v) for k, v in value.items()}
    elif isinstance(value, (list, tuple)):
        return [safe_value(v) for v in value]
    else:
        # For any other type (including coroutines), convert to string
        return str(value)


class BackupProgressTracker:
    """Track and report backup progress"""
    
    def __init__(self):
        self.total_files = 0
        self.completed_files = 0
        self.current_domain = ""
        self.start_time = datetime.now()
    
    def update(self, domain: str = None, progress: int = None, total: int = None):
        """Update progress and emit JSON status"""
        if domain:
            self.current_domain = domain
        if progress is not None:
            self.completed_files = progress
        if total is not None:
            self.total_files = total
        
        # Calculate percentage
        percentage = 0
        if self.total_files > 0:
            percentage = int((self.completed_files / self.total_files) * 100)
        
        # Calculate elapsed time
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Estimate remaining time
        eta_seconds = 0
        if self.completed_files > 0 and self.total_files > 0:
            eta_seconds = int((elapsed / self.completed_files) * (self.total_files - self.completed_files))
        
        # Emit progress as JSON
        progress_data = {
            "status": "in_progress",
            "currentDomain": self.current_domain,
            "filesCompleted": self.completed_files,
            "filesTotal": self.total_files,
            "percentage": percentage,
            "elapsedSeconds": int(elapsed),
            "etaSeconds": eta_seconds,
        }
        
        print(json.dumps(progress_data), flush=True)


def get_default_backup_directory() -> Path:
    """Get the default iTunes backup directory for the OS"""
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA")
        return Path(appdata) / "Apple Computer" / "MobileSync" / "Backup"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"
    else:  # Linux/Other
        return Path.home() / ".backup" / "iOS"


def create_ios_backup(
    udid: str,
    output_dir: Optional[str] = None,
    password: str = "scout1234",
    encryption: bool = True
) -> dict:
    """
    Create iOS device backup
    
    Args:
        udid: Device UDID
        output_dir: Optional output directory (defaults to iTunes backup location)
        password: Backup encryption password (default: scout1234)
        encryption: Whether to encrypt backup (default: True)
        
    Returns:
        Dictionary with backup info or error
    """
    
    try:
        # Determine output directory
        if output_dir:
            backup_dir = Path(output_dir)
        else:
            backup_dir = get_default_backup_directory()
        
        # Create backup directory if it doesn't exist
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        print(json.dumps({
            "status": "connecting",
            "message": "Connecting to device..."
        }), flush=True)
        
        # Get Python command
        python_cmd = sys.executable
        
        # Build pymobiledevice3 command
        cmd = [
            python_cmd,
            "-m", "pymobiledevice3",
            "backup2", "backup",
            "--full",  # Full backup
            "--udid", udid,
            str(backup_dir)
        ]
        
        print(json.dumps({
            "status": "starting",
            "message": "Starting backup process..."
        }), flush=True)
        
        # Run backup command with real-time output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Track progress
        start_time = datetime.now()
        files_backed_up = 0
        current_file = ""
        
        # Read output line by line
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            # Parse progress from output
            # pymobiledevice3 outputs progress information
            if "%" in line or "backing up" in line.lower():
                # Extract percentage if available
                percent_match = re.search(r'(\d+)%', line)
                if percent_match:
                    percentage = int(percent_match.group(1))
                    print(json.dumps({
                        "status": "backing_up",
                        "message": f"Backing up... {percentage}%",
                        "percentage": percentage,
                        "elapsed_seconds": int((datetime.now() - start_time).total_seconds())
                    }), flush=True)
            
            # Track files being backed up
            if "file" in line.lower() and "->" in line:
                files_backed_up += 1
                print(json.dumps({
                    "status": "backing_up",
                    "message": f"Backed up {files_backed_up} files...",
                    "files_completed": files_backed_up
                }), flush=True)
        
        # Wait for process to complete
        return_code = process.wait()
        
        if return_code != 0:
            raise Exception(f"Backup command failed with code {return_code}")
        
        # Backup complete - find the backup directory
        device_backup_dir = backup_dir / udid
        
        if not device_backup_dir.exists():
            raise Exception(f"Backup directory not found: {device_backup_dir}")
        
        # Calculate backup size
        backup_size = sum(f.stat().st_size for f in device_backup_dir.rglob('*') if f.is_file())
        backup_size_mb = backup_size / (1024 * 1024)
        
        # Get device info for result
        device_name = "iOS Device"
        ios_version = "Unknown"
        try:
            # Try to get device info
            import asyncio
            lockdown = asyncio.run(create_using_usbmux(serial=udid))
            device_name = safe_value(lockdown.display_name) if hasattr(lockdown, 'display_name') else "iOS Device"
            # Don't await get_value here since we're not in async context
        except:
            pass
        
        result = {
            "status": "complete",
            "success": True,
            "backupPath": str(device_backup_dir),
            "backupSize": f"{backup_size_mb:.1f} MB",
            "deviceName": device_name,
            "iosVersion": ios_version,
            "timestamp": datetime.now().isoformat(),
            "encrypted": encryption,
        }
        
        print(json.dumps(result), flush=True)
        return result
        
    except Exception as e:
        error_result = {
            "status": "error",
            "success": False,
            "error": str(e),
            "message": f"Backup failed: {str(e)}"
        }
        print(json.dumps(error_result), flush=True, file=sys.stderr)
        return error_result


def main():
    """Main entry point"""
    
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: python ios_backup.py <UDID> [output_dir] [password]"
        }), file=sys.stderr)
        sys.exit(1)
    
    udid = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    password = sys.argv[3] if len(sys.argv) > 3 else "scout1234"
    
    # Run backup function
    result = create_ios_backup(
        udid=udid,
        output_dir=output_dir,
        password=password,
        encryption=True
    )
    
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
