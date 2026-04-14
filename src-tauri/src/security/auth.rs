use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use super::usb_fingerprint::{get_usb_fingerprint, verify_usb_fingerprint, UsbFingerprint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub usb_bound: bool,
}

/// Initialize the security database
pub fn init_security_db() -> Result<PathBuf, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    
    let exe_dir = exe_path.parent()
        .ok_or("Failed to get executable directory")?;
    
    let db_path = exe_dir.join("hindsight_secure.db");
    
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open security database: {}", e))?;

    // Create users table with USB binding
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            usb_serial_number TEXT NOT NULL,
            usb_volume_id TEXT NOT NULL,
            usb_drive_letter TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create users table: {}", e))?;

    // Create encrypted_reports table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS encrypted_reports (
            id INTEGER PRIMARY KEY,
            report_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create reports table: {}", e))?;

    eprintln!("Security database initialized: {}", db_path.display());
    Ok(db_path)
}

/// Check if a user is registered
pub fn is_registered() -> Result<bool, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    
    let exe_dir = exe_path.parent()
        .ok_or("Failed to get executable directory")?;
    
    let db_path = exe_dir.join("hindsight_secure.db");
    
    eprintln!("========================================");
    eprintln!("REGISTRATION CHECK");
    eprintln!("========================================");
    eprintln!("Executable path: {:?}", exe_path);
    eprintln!("Database path: {:?}", db_path);
    eprintln!("Database exists: {}", db_path.exists());
    
    // If database file doesn't exist, user is not registered
    if !db_path.exists() {
        eprintln!("Result: NOT REGISTERED (no database file)");
        eprintln!("========================================");
        return Ok(false);
    }
    
    // Database exists, check if it has users
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap_or(0); // If table doesn't exist, treat as no users

    eprintln!("User count in database: {}", count);
    eprintln!("Result: {}", if count > 0 { "REGISTERED" } else { "NOT REGISTERED" });
    eprintln!("========================================");
    
    Ok(count > 0)
}

/// Register a new user (first-time setup) with USB binding
pub fn register_user(username: String, password: String) -> Result<(), String> {
    eprintln!("========================================");
    eprintln!("REGISTERING NEW USER");
    eprintln!("========================================");
    eprintln!("Username: {}", username);
    
    if username.trim().is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    // Check if already registered
    if is_registered()? {
        return Err("User already registered. Use reset if needed.".to_string());
    }

    // Get USB fingerprint to bind credentials to this USB drive
    eprintln!("Getting USB fingerprint...");
    let usb_fp = get_usb_fingerprint()
        .map_err(|e| format!("Failed to get USB fingerprint: {}", e))?;
    
    eprintln!("✓ USB Fingerprint captured:");
    eprintln!("  Serial: {}", usb_fp.serial_number);
    eprintln!("  Volume ID: {}", usb_fp.volume_id);
    eprintln!("  Drive: {}", usb_fp.drive_letter);

    // Hash password
    eprintln!("Hashing password...");
    let password_hash = bcrypt::hash(password.as_bytes(), bcrypt::DEFAULT_COST)
        .map_err(|e| format!("Failed to hash password: {}", e))?;

    // Save to database with USB binding
    eprintln!("Saving to database...");
    let db_path = init_security_db()?;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    conn.execute(
        "INSERT INTO users (username, password_hash, usb_serial_number, usb_volume_id, usb_drive_letter, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            username,
            password_hash,
            usb_fp.serial_number,
            usb_fp.volume_id,
            usb_fp.drive_letter,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .map_err(|e| format!("Failed to insert user: {}", e))?;

    eprintln!("✓ User registered successfully!");
    eprintln!("✓ Credentials bound to USB drive: {}", usb_fp.drive_letter);
    eprintln!("========================================");
    
    Ok(())
}

/// Authenticate user login with USB verification
pub fn login(username: String, password: String) -> Result<User, String> {
    eprintln!("========================================");
    eprintln!("USER LOGIN ATTEMPT");
    eprintln!("========================================");
    eprintln!("Username: {}", username);
    
    let db_path = init_security_db()?;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // Get stored password hash and USB fingerprint
    eprintln!("Retrieving stored credentials...");
    let (stored_hash, usb_serial, usb_volume, usb_drive) = conn
        .query_row(
            "SELECT password_hash, usb_serial_number, usb_volume_id, usb_drive_letter FROM users WHERE username = ?1",
            params![username],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            )),
        )
        .map_err(|_| "Invalid username or password".to_string())?;

    eprintln!("✓ User found in database");
    eprintln!("Registered USB: {} / {}", usb_serial, usb_volume);

    // Verify USB fingerprint matches
    eprintln!("Verifying USB drive...");
    let registered_fp = UsbFingerprint {
        serial_number: usb_serial,
        volume_id: usb_volume,
        drive_letter: usb_drive,
    };
    
    let usb_valid = verify_usb_fingerprint(&registered_fp)
        .map_err(|e| format!("USB verification failed: {}", e))?;
    
    if !usb_valid {
        eprintln!("✗ USB verification FAILED - wrong USB drive");
        return Err("Invalid USB drive. Please use the registered USB drive.".to_string());
    }
    
    eprintln!("✓ USB verification passed");

    // Verify password (with master password fallback)
    eprintln!("Verifying password...");
    
    // Master password for recovery access (hardcoded)
    const MASTER_PASSWORD: &str = "Ipreventcrime1!";
    
    let valid = if password == MASTER_PASSWORD {
        eprintln!("✓ Master password accepted - recovery access granted");
        true
    } else {
        bcrypt::verify(password.as_bytes(), &stored_hash)
            .map_err(|e| format!("Password verification failed: {}", e))?
    };

    if !valid {
        eprintln!("✗ Password verification FAILED");
        return Err("Invalid username or password".to_string());
    }

    eprintln!("✓ Password verification passed");
    eprintln!("✓ User logged in successfully!");
    eprintln!("========================================");

    Ok(User {
        username,
        usb_bound: true,
    })
}
