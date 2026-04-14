#!/usr/bin/env python3
"""
iOS Backup Decryption Script
Decrypts specific forensic databases from an encrypted iOS backup.
Uses iphone_backup_decrypt library for targeted extraction (fast).
"""

import sys
import json
import os
import shutil
import sqlite3
from pathlib import Path

try:
    from iphone_backup_decrypt import EncryptedBackup, RelativePath
except ImportError as e:
    print(json.dumps({
        "status": "error",
        "success": False,
        "error": "iphone_backup_decrypt not installed",
        "message": "Run: pip install iphone_backup_decrypt",
    }), flush=True)
    sys.exit(1)


# Key forensic files to extract from backup
FORENSIC_FILES = [
    # Safari history
    {"domain": "HomeDomain", "path": "Library/Safari/History.db", "name": "safari_history.db"},
    {"domain": "HomeDomain", "path": "Library/Safari/Bookmarks.db", "name": "safari_bookmarks.db"},
    # SMS/iMessage
    {"domain": "HomeDomain", "path": "Library/SMS/sms.db", "name": "sms.db"},
    # Address Book
    {"domain": "HomeDomain", "path": "Library/AddressBook/AddressBook.sqlitedb", "name": "addressbook.db"},
    # Notes
    {"domain": "AppDomainGroup-group.com.apple.notes", "path": "NoteStore.sqlite", "name": "notes.db"},
    # Call History
    {"domain": "HomeDomain", "path": "Library/CallHistoryDB/CallHistory.storedata", "name": "call_history.db"},
    # Photos database
    {"domain": "CameraRollDomain", "path": "Media/PhotoData/Photos.sqlite", "name": "photos.db"},
    # Voicemail
    {"domain": "HomeDomain", "path": "Library/Voicemail/voicemail.db", "name": "voicemail.db"},
]


def decrypt_backup(backup_path: str, password: str, output_dir: str = None) -> dict:
    """
    Decrypt specific forensic databases from an encrypted iOS backup.
    Much faster than full extraction - only decrypts the files we need.
    """
    backup_path = Path(backup_path)

    # Verify this is an encrypted backup
    manifest_plist = backup_path / "Manifest.plist"
    manifest_db = backup_path / "Manifest.db"

    if not manifest_plist.exists():
        return {"status": "error", "success": False, "error": f"Manifest.plist not found in {backup_path}"}
    if not manifest_db.exists():
        return {"status": "error", "success": False, "error": f"Manifest.db not found in {backup_path}"}

    # Check if already decrypted
    with open(manifest_db, 'rb') as f:
        header = f.read(16)
    if header.startswith(b"SQLite format 3"):
        print(json.dumps({
            "status": "info",
            "message": "Backup is not encrypted or already decrypted"
        }), flush=True)
        return {
            "status": "complete",
            "success": True,
            "decryptedPath": str(backup_path),
            "backupPath": str(backup_path),
            "message": "Backup is already decrypted",
            "alreadyDecrypted": True,
        }

    # Determine output directory
    if output_dir:
        out_path = Path(output_dir)
    else:
        out_path = backup_path.parent / (backup_path.name + "_decrypted")

    out_path.mkdir(parents=True, exist_ok=True)
    files_dir = out_path / "files"
    files_dir.mkdir(exist_ok=True)

    print(json.dumps({
        "status": "decrypting",
        "message": "Opening encrypted backup..."
    }), flush=True)

    try:
        backup = EncryptedBackup(backup_directory=str(backup_path), passphrase=password)
    except Exception as e:
        error_str = str(e).lower()
        if any(kw in error_str for kw in ["password", "incorrect", "wrong", "failed to decrypt"]):
            return {
                "status": "error",
                "success": False,
                "error": "incorrect_password",
                "message": "Wrong backup password. The device's backup encryption password is needed.",
            }
        return {
            "status": "error",
            "success": False,
            "error": str(e),
            "message": f"Failed to open encrypted backup: {e}",
        }

    # Step 1: Save decrypted Manifest.db
    print(json.dumps({
        "status": "decrypting",
        "message": "Decrypting Manifest.db..."
    }), flush=True)

    manifest_out = out_path / "Manifest.db"
    try:
        backup.save_manifest_file(str(manifest_out))
    except Exception as e:
        return {
            "status": "error",
            "success": False,
            "error": str(e),
            "message": f"Failed to decrypt Manifest.db: {e}",
        }

    # Copy metadata files
    for meta_file in ["Manifest.plist", "Info.plist", "Status.plist"]:
        src = backup_path / meta_file
        if src.exists():
            shutil.copy2(str(src), str(out_path / meta_file))

    # Step 2: Extract specific forensic databases
    extracted_count = 0

    for forensic_file in FORENSIC_FILES:
        domain = forensic_file["domain"]
        rel_path = forensic_file["path"]
        name = forensic_file["name"]

        # Build output path preserving directory structure
        domain_dir = files_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        rel_parts = Path(rel_path)
        (domain_dir / rel_parts.parent).mkdir(parents=True, exist_ok=True)
        out_file = domain_dir / rel_path

        try:
            backup.extract_file(
                relative_path=rel_path,
                domain_like=domain,
                output_filename=str(out_file)
            )
            extracted_count += 1
            print(json.dumps({
                "status": "decrypting",
                "message": f"Extracted {name} ({extracted_count}/{len(FORENSIC_FILES)})"
            }), flush=True)
        except Exception as e:
            # File might not exist in this backup - that's OK
            error_str = str(e)
            if "not found" not in error_str.lower() and "no such" not in error_str.lower():
                print(json.dumps({
                    "status": "warning",
                    "message": f"Could not extract {name}: {e}"
                }), flush=True)

    # Step 3: Try to extract Chrome history (dynamic domain name)
    try:
        conn = sqlite3.connect(str(manifest_out))
        cursor = conn.execute(
            "SELECT domain, relativePath FROM Files "
            "WHERE domain LIKE '%com.google.chrome%' AND relativePath LIKE '%History' LIMIT 5"
        )
        for row in cursor.fetchall():
            chrome_domain, chrome_path = row
            chrome_dir = files_dir / chrome_domain
            chrome_dir.mkdir(parents=True, exist_ok=True)
            chrome_parts = Path(chrome_path)
            (chrome_dir / chrome_parts.parent).mkdir(parents=True, exist_ok=True)
            chrome_out = chrome_dir / chrome_path
            try:
                backup.extract_file(
                    relative_path=chrome_path,
                    domain_like=chrome_domain,
                    output_filename=str(chrome_out)
                )
                extracted_count += 1
                print(json.dumps({
                    "status": "decrypting",
                    "message": f"Extracted Chrome History ({extracted_count} files total)"
                }), flush=True)
            except:
                pass
        conn.close()
    except Exception:
        pass

    result = {
        "status": "complete",
        "success": True,
        "decryptedPath": str(out_path),
        "backupPath": str(out_path),
        "manifestPath": str(manifest_out),
        "filesPath": str(files_dir),
        "fileCount": extracted_count,
        "message": f"Decrypted Manifest.db + {extracted_count} forensic databases.",
    }

    print(json.dumps(result), flush=True)
    return result


def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "error": "Usage: python ios_decrypt_backup.py <backup_path> <password> [output_dir]"
        }), file=sys.stderr)
        sys.exit(1)

    backup_path = sys.argv[1]
    password = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None

    result = decrypt_backup(backup_path, password, output_dir)

    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
