#!/usr/bin/env python3
"""
iOS Backup Script (Arsenic-style)
Creates full iTunes-compatible iOS device backup using pymobiledevice3
Based on Arsenic's working implementation
"""

import sys
import json
import os
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
except ImportError as e:
    print(json.dumps({
        "error": "pymobiledevice3 not installed",
        "message": "Run: pip install pymobiledevice3",
        "details": str(e)
    }), file=sys.stderr)
    sys.exit(1)


def safe_value(value):
    """Convert value to JSON-safe format"""
    if value is None:
        return None
    elif isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except:
            return value.hex()
    elif isinstance(value, (str, int, float, bool)):
        return value
    elif isinstance(value, dict):
        return {k: safe_value(v) for k, v in value.items()}
    elif isinstance(value, (list, tuple)):
        return [safe_value(v) for v in value]
    else:
        return str(value)


def get_default_backup_directory():
    """Get default iTunes backup directory"""
    if os.name == 'nt':  # Windows
        appdata = os.getenv('APPDATA')
        return Path(appdata) / "Apple Computer" / "MobileSync" / "Backup"
    elif os.name == 'posix':
        if sys.platform == 'darwin':  # macOS
            return Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"
        else:  # Linux/Other
            return Path.home() / ".backup" / "iOS"


async def create_ios_backup(
    udid: str,
    output_dir: Optional[str] = None,
    password: str = "1234",
    encryption: bool = False
) -> dict:
    """
    Create iOS device backup using Arsenic's method
    
    Args:
        udid: Device UDID
        output_dir: Optional output directory (defaults to iTunes backup location)
        password: Backup encryption password (default: 1234)
        encryption: Whether to encrypt backup (default: False - unencrypted like Arsenic)
        
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
        
        # pymobiledevice3's backup() creates a UDID subfolder automatically
        # so we pass backup_dir (the parent) and the real backup will be at backup_dir/udid
        device_backup_dir = backup_dir / udid
        
        print(json.dumps({
            "status": "connecting",
            "message": "Connecting to device..."
        }), flush=True)
        
        # Connect to device
        lockdown = await create_using_usbmux(serial=udid)
        
        # Get device info
        device_name = safe_value(lockdown.display_name) if hasattr(lockdown, 'display_name') else "iOS Device"
        
        try:
            ios_version = safe_value(await lockdown.get_value(key="ProductVersion")) or "Unknown"
        except:
            ios_version = "Unknown"
        
        print(json.dumps({
            "status": "connected",
            "deviceName": device_name,
            "iosVersion": ios_version,
            "message": f"Connected to {device_name}"
        }), flush=True)
        
        # Create backup service
        backup_client = Mobilebackup2Service(lockdown=lockdown)
        
        # Change backup password (like Arsenic does)
        if encryption:
            print(json.dumps({
                "status": "setting_password",
                "message": "Setting backup password..."
            }), flush=True)
            
            try:
                await backup_client.change_password(new=password)
                print(json.dumps({
                    "status": "password_set",
                    "message": f"Backup password set to: {password}"
                }), flush=True)
            except Exception as pwd_error:
                error_str = str(pwd_error)
                if "ErrorCode': 207" in error_str and "Invalid password" in error_str:
                    print(json.dumps({
                        "status": "password_exists",
                        "message": f"Device already has a backup password. Using existing password."
                    }), flush=True)
                else:
                    print(json.dumps({
                        "status": "warning",
                        "message": f"Could not set password: {str(pwd_error)}"
                    }), flush=True)
        
        # Progress callback
        last_progress = -1
        def progress_callback(progress):
            nonlocal last_progress
            # Only update every 5% to avoid spamming
            rounded = int(progress)
            if rounded != last_progress and rounded % 5 == 0:
                print(json.dumps({
                    "status": "backing_up",
                    "message": f"Backing up device... {rounded}%",
                    "percentage": rounded
                }), flush=True)
                last_progress = rounded
        
        # Start backup (like Arsenic)
        print(json.dumps({
            "status": "starting",
            "message": "Starting backup process..."
        }), flush=True)
        
        # Use Arsenic's method: backup() with full=True
        # Pass the PARENT directory — pymobiledevice3 creates a UDID subfolder inside it
        await backup_client.backup(
            full=True,
            backup_directory=str(backup_dir),
            progress_callback=progress_callback
        )
        
        # Backup complete - calculate size
        backup_size = sum(f.stat().st_size for f in device_backup_dir.rglob('*') if f.is_file())
        backup_size_mb = backup_size / (1024 * 1024)
        
        result = {
            "status": "complete",
            "success": True,
            "backupPath": str(device_backup_dir),
            "backupSize": f"{backup_size_mb:.1f} MB",
            "deviceName": device_name,
            "iosVersion": ios_version,
            "timestamp": datetime.now().isoformat(),
            "encrypted": encryption,
            "password": password if encryption else None
        }
        
        print(json.dumps(result), flush=True)
        return result
        
    except Exception as e:
        import traceback
        error_result = {
            "status": "error",
            "success": False,
            "error": str(e),
            "message": f"Backup failed: {str(e)}",
            "traceback": traceback.format_exc()
        }
        print(json.dumps(error_result), flush=True, file=sys.stderr)
        return error_result


def main():
    """Main entry point"""
    
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Usage: python ios_backup_arsenic.py <UDID> [output_dir] [password]"
        }), file=sys.stderr)
        sys.exit(1)
    
    udid = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    password = sys.argv[3] if len(sys.argv) > 3 else "1234"
    
    # Run async backup function
    result = asyncio.run(create_ios_backup(
        udid=udid,
        output_dir=output_dir,
        password=password,
        encryption=False  # Arsenic uses unencrypted backups
    ))
    
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
