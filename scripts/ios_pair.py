#!/usr/bin/env python3
"""
iOS Explicit Pairing Script
============================

WHY THIS EXISTS
---------------
Scout previously "detected" trust by merely creating a lockdown client and
assuming success meant the device was trusted. It NEVER actively initiated
pairing, so the iOS "Trust This Computer" dialog only appeared when some other
Apple component (Apple Devices app / Apple Mobile Device Service) happened to
trigger it — which is why the prompt showed up inconsistently.

The Trust dialog is only presented when the host explicitly calls
lockdown.pair() while the device is UNLOCKED. This script does exactly that and
maps every failure mode to an actionable state the UI can show the examiner.

USAGE
-----
    python ios_pair.py <UDID>

Emits a single JSON object on stdout:
    {
      "udid": "...",
      "paired": true|false,
      "state": "already_paired" | "paired" | "prompt_shown"
             | "locked" | "denied" | "stale_record" | "no_device" | "error",
      "message": "human-readable, examiner-facing guidance"
    }

STATE MEANINGS
--------------
  already_paired  Device already trusts this computer. Nothing to do.
  paired          Pairing just completed successfully.
  prompt_shown    "Trust This Computer" is on the iPhone right now. The examiner
                  must tap Trust + enter the passcode, then Scout retries.
  locked          Device is locked. Unlock it and retry.
  denied          Examiner tapped "Don't Trust". Reconnect + retry.
  stale_record    A dead pairing record was blocking us; we cleared it. Retry.
  no_device       Device not found on USB.
  error           Unexpected failure (details in message).
"""

import sys
import json
import asyncio
from pathlib import Path

try:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.exceptions import (
        PasswordRequiredError,
        UserDeniedPairingError,
        PairingDialogResponsePendingError,
        InvalidHostIDError,
        NotTrustedError,
        NotPairedError,
        DeviceNotFoundError,
        ConnectionFailedError,
    )
except ImportError as e:  # pragma: no cover
    print(json.dumps({
        "paired": False,
        "state": "error",
        "message": "pymobiledevice3 not installed. Run scripts/setup_ios_environment.ps1.",
        "details": str(e),
    }))
    sys.exit(0)


def emit(obj: dict) -> None:
    print(json.dumps(obj))


async def _is_already_paired(udid: str) -> bool:
    """Return True if the device already trusts this host (no side effects)."""
    try:
        lockdown = await create_using_usbmux(serial=udid, autopair=False)
        # A protected value read only succeeds inside a validated session,
        # which requires an existing, valid pairing record.
        val = await lockdown.get_value(key="ProductVersion")
        return val is not None
    except (NotPairedError, NotTrustedError, InvalidHostIDError,
            PasswordRequiredError, PairingDialogResponsePendingError):
        return False
    except Exception:
        return False


def _clear_stale_pairing_records(udid: str) -> bool:
    """
    Best-effort removal of a dead pairing record that keeps raising
    InvalidHostIDError. On Windows, Apple Mobile Device Service stores records
    in %ProgramData%\\Apple\\Lockdown; pymobiledevice3 also keeps a cache.
    Returns True if at least one record was removed.
    """
    removed = False
    candidates = []

    programdata = None
    import os
    if os.name == "nt":
        programdata = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(Path(programdata) / "Apple" / "Lockdown")
    # pymobiledevice3 default cache locations
    candidates.append(Path.home() / ".pymobiledevice3")

    for base in candidates:
        try:
            if not base.exists():
                continue
            for rec in base.glob(f"*{udid}*"):
                try:
                    rec.unlink()
                    removed = True
                except Exception:
                    pass
        except Exception:
            pass
    return removed


async def _attempt_pair(udid: str) -> dict:
    """Explicitly initiate pairing. Maps every outcome to a UI state."""
    try:
        lockdown = await create_using_usbmux(serial=udid, autopair=False)
        await lockdown.pair()
        return {
            "udid": udid,
            "paired": True,
            "state": "paired",
            "message": "Pairing succeeded. The iPhone now trusts this computer.",
        }

    except PairingDialogResponsePendingError:
        # The most common "why didn't it work" case: the dialog IS showing.
        return {
            "udid": udid,
            "paired": False,
            "state": "prompt_shown",
            "message": ("'Trust This Computer' is now showing on the iPhone. "
                        "Tap Trust and enter the passcode, then click Connect again."),
        }

    except PasswordRequiredError:
        return {
            "udid": udid,
            "paired": False,
            "state": "locked",
            "message": ("iPhone is locked. Unlock it (enter passcode), keep it "
                        "unlocked, then click Connect again."),
        }

    except UserDeniedPairingError:
        return {
            "udid": udid,
            "paired": False,
            "state": "denied",
            "message": ("'Trust' was declined on the iPhone. Unplug/replug the "
                        "cable, unlock the phone, and tap Trust when prompted."),
        }

    except InvalidHostIDError:
        # Stale/dead pairing record. Clear it and retry pairing ONCE.
        cleared = _clear_stale_pairing_records(udid)
        try:
            lockdown = await create_using_usbmux(serial=udid, autopair=False)
            await lockdown.pair()
            return {
                "udid": udid,
                "paired": True,
                "state": "paired",
                "message": "Cleared a stale pairing record and re-paired successfully.",
            }
        except PairingDialogResponsePendingError:
            return {
                "udid": udid,
                "paired": False,
                "state": "prompt_shown",
                "message": ("Cleared a stale pairing record. 'Trust This Computer' "
                            "is now on the iPhone — tap Trust, then click Connect again."),
            }
        except Exception as e2:
            return {
                "udid": udid,
                "paired": False,
                "state": "stale_record",
                "message": ("A stale pairing record was blocking pairing. "
                            + ("It was cleared — unplug/replug the iPhone and retry. "
                               if cleared else
                               "Could not auto-clear it; on Windows delete the matching "
                               ".plist in C:\\ProgramData\\Apple\\Lockdown, then retry. ")),
                "details": str(e2),
            }

    except (DeviceNotFoundError, ConnectionFailedError) as e:
        return {
            "udid": udid,
            "paired": False,
            "state": "no_device",
            "message": ("iPhone not reachable over USB. Check the cable, ensure the "
                        "phone is unlocked, and that Apple Mobile Device Service is running."),
            "details": str(e),
        }

    except Exception as e:
        return {
            "udid": udid,
            "paired": False,
            "state": "error",
            "message": f"Unexpected pairing error: {e}",
            "details": str(e),
        }


async def main() -> None:
    if len(sys.argv) < 2:
        emit({"paired": False, "state": "error",
              "message": "No UDID provided to ios_pair.py."})
        return

    udid = sys.argv[1]

    if await _is_already_paired(udid):
        emit({
            "udid": udid,
            "paired": True,
            "state": "already_paired",
            "message": "Device already trusts this computer.",
        })
        return

    emit(await _attempt_pair(udid))


if __name__ == "__main__":
    asyncio.run(main())
