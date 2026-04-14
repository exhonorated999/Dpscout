#!/usr/bin/env python3
"""
iOS Device Info Script
Detects connected iOS devices and retrieves device information
Uses pymobiledevice3 for device communication
"""

import sys
import json
import asyncio
from typing import Dict, List, Optional

try:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.usbmux import list_devices
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


async def get_connected_devices() -> List[Dict]:
    """
    Get list of connected iOS devices with basic info
    
    Returns:
        List of device info dictionaries
    """
    devices = []
    
    try:
        # Get list of connected devices via usbmux (v9 API - async)
        device_list = await list_devices()
        
        for device in device_list:
            try:
                # Create lockdown client for this device
                # In pymobiledevice3 v9, device is a dict-like object
                udid = device.serial if hasattr(device, 'serial') else device.get('SerialNumber', device.get('UniqueDeviceID', 'Unknown'))
                lockdown = await create_using_usbmux(serial=udid)
                
                # Helper function to safely get value
                async def safe_get(key, domain=None, default="Unknown"):
                    try:
                        if domain:
                            val = await lockdown.get_value(domain=domain, key=key)
                        else:
                            val = await lockdown.get_value(key=key)
                        return safe_value(val) if val is not None else default
                    except:
                        return default
                
                # Get device values (all async in v9)
                device_info = {
                    "udid": safe_value(udid),
                    "deviceName": safe_value(lockdown.display_name),
                    "deviceModel": await safe_get("ProductType"),
                    "productType": await safe_get("ProductType"),
                    "iosVersion": await safe_get("ProductVersion"),
                    "buildVersion": await safe_get("BuildVersion"),
                    "serialNumber": await safe_get("SerialNumber"),
                    "imei": await safe_get("InternationalMobileEquipmentIdentity", default=""),
                    "phoneNumber": await safe_get("PhoneNumber", default=""),
                    "wifiAddress": await safe_get("WiFiAddress", default=""),
                    "bluetoothAddress": await safe_get("BluetoothAddress", default=""),
                    "hardwareModel": await safe_get("HardwareModel", default=""),
                    "deviceColor": await safe_get("DeviceColor", default=""),
                    "deviceClass": await safe_get("DeviceClass", default="iPhone"),
                    "connectionType": "USB",
                    "isTrusted": True,  # If we can connect, device is trusted
                }
                
                # Get storage info if available
                total_capacity = await safe_get("TotalDiskCapacity", domain="com.apple.disk_usage", default=None)
                available_capacity = await safe_get("AmountDataAvailable", domain="com.apple.disk_usage", default=None)
                
                if total_capacity and total_capacity != "Unknown":
                    try:
                        device_info["totalCapacity"] = f"{float(total_capacity) / (1024**3):.1f} GB"
                    except:
                        device_info["totalCapacity"] = "Unknown"
                else:
                    device_info["totalCapacity"] = "Unknown"
                    
                if available_capacity and available_capacity != "Unknown":
                    try:
                        device_info["availableCapacity"] = f"{float(available_capacity) / (1024**3):.1f} GB"
                    except:
                        device_info["availableCapacity"] = "Unknown"
                else:
                    device_info["availableCapacity"] = "Unknown"
                
                # Get battery level if available
                battery_level = await safe_get("BatteryCurrentCapacity", domain="com.apple.mobile.battery", default=None)
                if battery_level and battery_level != "Unknown":
                    device_info["batteryLevel"] = f"{battery_level}%"
                else:
                    device_info["batteryLevel"] = "Unknown"
                
                devices.append(device_info)
                
            except Exception as e:
                # Device found but couldn't get info (not paired/trusted)
                udid_fallback = device.serial if hasattr(device, 'serial') else str(device)
                devices.append({
                    "udid": udid_fallback,
                    "deviceName": "Unknown (Not Trusted)",
                    "deviceModel": "Unknown",
                    "productType": "Unknown",
                    "iosVersion": "Unknown",
                    "serialNumber": "Unknown",
                    "connectionType": "USB",
                    "isTrusted": False,
                    "error": f"Device not trusted or pairing failed: {str(e)}"
                })
    
    except Exception as e:
        print(json.dumps({
            "error": "Failed to enumerate devices",
            "message": str(e)
        }), file=sys.stderr)
        return []
    
    return devices


async def get_device_info(udid: str) -> Optional[Dict]:
    """
    Get detailed info for specific device by UDID
    
    Args:
        udid: Device UDID
        
    Returns:
        Device info dictionary with all required fields
    """
    try:
        lockdown = await create_using_usbmux(serial=udid)
        
        # Helper function to safely get value
        async def safe_get(key, domain=None, default="Unknown"):
            try:
                if domain:
                    val = await lockdown.get_value(domain=domain, key=key)
                else:
                    val = await lockdown.get_value(key=key)
                return safe_value(val) if val is not None else default
            except:
                return default
        
        # Get device values (same structure as get_connected_devices)
        device_info = {
            "udid": safe_value(udid),
            "deviceName": safe_value(lockdown.display_name),
            "deviceModel": await safe_get("ProductType"),
            "productType": await safe_get("ProductType"),
            "iosVersion": await safe_get("ProductVersion"),
            "buildVersion": await safe_get("BuildVersion"),
            "serialNumber": await safe_get("SerialNumber"),
            "imei": await safe_get("InternationalMobileEquipmentIdentity", default=""),
            "phoneNumber": await safe_get("PhoneNumber", default=""),
            "wifiAddress": await safe_get("WiFiAddress", default=""),
            "bluetoothAddress": await safe_get("BluetoothAddress", default=""),
            "hardwareModel": await safe_get("HardwareModel", default=""),
            "deviceColor": await safe_get("DeviceColor", default=""),
            "deviceClass": await safe_get("DeviceClass", default="iPhone"),
            "connectionType": "USB",
            "isTrusted": True,  # If we can connect, device is trusted
        }
        
        # Get storage info if available
        total_capacity = await safe_get("TotalDiskCapacity", domain="com.apple.disk_usage", default=None)
        available_capacity = await safe_get("AmountDataAvailable", domain="com.apple.disk_usage", default=None)
        
        if total_capacity and total_capacity != "Unknown":
            try:
                device_info["totalCapacity"] = f"{float(total_capacity) / (1024**3):.1f} GB"
            except:
                device_info["totalCapacity"] = "Unknown"
        else:
            device_info["totalCapacity"] = "Unknown"
            
        if available_capacity and available_capacity != "Unknown":
            try:
                device_info["availableCapacity"] = f"{float(available_capacity) / (1024**3):.1f} GB"
            except:
                device_info["availableCapacity"] = "Unknown"
        else:
            device_info["availableCapacity"] = "Unknown"
        
        # Get battery level if available
        battery_level = await safe_get("BatteryCurrentCapacity", domain="com.apple.mobile.battery", default=None)
        if battery_level and battery_level != "Unknown":
            device_info["batteryLevel"] = f"{battery_level}%"
        else:
            device_info["batteryLevel"] = "Unknown"
        
        return device_info
        
    except Exception as e:
        import traceback
        return {
            "error": "Failed to get device info",
            "udid": safe_value(udid),
            "message": str(e),
            "traceback": traceback.format_exc()
        }


async def main():
    """Main entry point"""
    
    # Check if specific UDID requested
    if len(sys.argv) > 1:
        udid = sys.argv[1]
        info = await get_device_info(udid)
        print(json.dumps(info, indent=2))
    else:
        # List all connected devices
        devices = await get_connected_devices()
        print(json.dumps({"devices": devices}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
