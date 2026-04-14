use aes_gcm::{
    aead::{Aead, KeyInit, rand_core::RngCore},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::OsRng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedReport {
    pub id: i64,
    pub report_name: String,
    pub created_at: String,
}

/// Derive 256-bit encryption key from password using SHA-256
fn derive_key_from_password(password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

/// Encrypt PDF data using AES-256-GCM
pub fn encrypt_pdf(pdf_data: Vec<u8>, password: String) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_bytes = derive_key_from_password(&password);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate random nonce
    let mut rng = OsRng;
    let nonce_bytes = rng.next_u64().to_le_bytes();
    let mut nonce_array = [0u8; 12];
    nonce_array[..8].copy_from_slice(&nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_array);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, pdf_data.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypt PDF data using AES-256-GCM
pub fn decrypt_pdf(encrypted_data: Vec<u8>, nonce: Vec<u8>, password: String) -> Result<Vec<u8>, String> {
    let key_bytes = derive_key_from_password(&password);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    if nonce.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }

    let nonce = Nonce::from_slice(&nonce);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption failed. Invalid password or corrupted data.".to_string())?;

    Ok(plaintext)
}

/// Save encrypted PDF report to database
pub fn save_encrypted_report(
    report_name: String,
    pdf_data: Vec<u8>,
    password: String,
) -> Result<i64, String> {
    let (encrypted_data, nonce) = encrypt_pdf(pdf_data, password)?;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    let exe_dir = exe_path.parent().ok_or("Failed to get executable directory")?;
    let db_path = exe_dir.join("hindsight_secure.db");

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    conn.execute(
        "INSERT INTO encrypted_reports (report_name, encrypted_data, nonce, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            report_name,
            encrypted_data,
            nonce,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .map_err(|e| format!("Failed to save report: {}", e))?;

    let report_id = conn.last_insert_rowid();

    eprintln!("Encrypted report saved: {} (ID: {})", report_name, report_id);
    Ok(report_id)
}

/// List all encrypted reports
pub fn list_encrypted_reports() -> Result<Vec<EncryptedReport>, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    let exe_dir = exe_path.parent().ok_or("Failed to get executable directory")?;
    let db_path = exe_dir.join("hindsight_secure.db");

    if !db_path.exists() {
        return Ok(vec![]);
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let mut stmt = conn
        .prepare("SELECT id, report_name, created_at FROM encrypted_reports ORDER BY created_at DESC")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let reports = stmt
        .query_map([], |row| {
            Ok(EncryptedReport {
                id: row.get(0)?,
                report_name: row.get(1)?,
                created_at: row.get(2)?,
            })
        })
        .map_err(|e| format!("Failed to query reports: {}", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to collect reports: {}", e))?;

    Ok(reports)
}

/// Load and decrypt a report
pub fn load_encrypted_report(report_id: i64, password: String) -> Result<Vec<u8>, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    let exe_dir = exe_path.parent().ok_or("Failed to get executable directory")?;
    let db_path = exe_dir.join("hindsight_secure.db");

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let (encrypted_data, nonce): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT encrypted_data, nonce FROM encrypted_reports WHERE id = ?1",
            params![report_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "Report not found".to_string())?;

    decrypt_pdf(encrypted_data, nonce, password)
}

/// Delete encrypted report
pub fn delete_encrypted_report(report_id: i64) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;
    let exe_dir = exe_path.parent().ok_or("Failed to get executable directory")?;
    let db_path = exe_dir.join("hindsight_secure.db");

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    conn.execute(
        "DELETE FROM encrypted_reports WHERE id = ?1",
        params![report_id],
    )
    .map_err(|e| format!("Failed to delete report: {}", e))?;

    eprintln!("Report deleted: {}", report_id);
    Ok(())
}
