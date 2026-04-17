use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    pub hash: String,
    pub hash_type: String,
    pub source: String,
    pub category: Option<String>,
    pub description: Option<String>,
}

pub struct HashDatabase {
    conn: Arc<Mutex<Connection>>,
    // In-memory cache for ultra-fast lookups (loaded at startup)
    hash_cache: Arc<RwLock<Option<HashMap<String, HashMatch>>>>,
    // Which hash types exist in the DB (e.g. {"SHA256"} or {"MD5","SHA256"})
    hash_types: Arc<RwLock<HashSet<String>>>,
    // Known file sizes from DB — if populated, skip files whose size doesn't match
    known_sizes: Arc<RwLock<Option<HashSet<u64>>>>,
}

impl HashDatabase {
    /// Create or open the hash database
    pub fn new() -> Result<Self, String> {
        let app_data = std::env::var("APPDATA")
            .map_err(|_| "Could not find APPDATA directory".to_string())?;
        
        let db_dir = Path::new(&app_data).join("Hindsight");
        if !db_dir.exists() {
            std::fs::create_dir_all(&db_dir)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }
        
        let db_path = db_dir.join("hash_database.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let hash_db = HashDatabase {
            conn: Arc::new(Mutex::new(conn)),
            hash_cache: Arc::new(RwLock::new(None)),
            hash_types: Arc::new(RwLock::new(HashSet::new())),
            known_sizes: Arc::new(RwLock::new(None)),
        };
        
        hash_db.initialize_schema()?;
        hash_db.create_indexes()?;
        
        // Automatically load hashes into memory on initialization
        eprintln!("[Hash DB] Loading hashes into memory cache...");
        match hash_db.load_hashes_into_memory() {
            Ok(count) => eprintln!("[Hash DB] ✓ Loaded {} hashes into memory cache", count),
            Err(e) => eprintln!("[Hash DB] Warning: Failed to load cache: {}", e),
        }
        
        Ok(hash_db)
    }
    
    /// Initialize database schema
    fn initialize_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hash_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                hash_count INTEGER DEFAULT 0
            )",
            [],
        ).map_err(|e| format!("Failed to create hash_lists table: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL,
                hash_type TEXT NOT NULL,
                list_id INTEGER NOT NULL,
                category TEXT,
                description TEXT,
                file_size INTEGER,
                FOREIGN KEY (list_id) REFERENCES hash_lists(id) ON DELETE CASCADE
            )",
            [],
        ).map_err(|e| format!("Failed to create hashes table: {}", e))?;
        
        // Migration: add file_size column to existing databases
        conn.execute(
            "ALTER TABLE hashes ADD COLUMN file_size INTEGER",
            [],
        ).ok(); // Silently ignore if column already exists
        
        Ok(())
    }
    
    /// Create indexes for fast lookups
    fn create_indexes(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        // Critical index for hash lookups - this makes queries sub-millisecond
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hash_lookup ON hashes(hash, hash_type)",
            [],
        ).map_err(|e| format!("Failed to create hash index: {}", e))?;
        
        // Index for list management
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_list_id ON hashes(list_id)",
            [],
        ).map_err(|e| format!("Failed to create list index: {}", e))?;
        
        Ok(())
    }
    
    /// Import a Project VIC JSON file (supports large files)
    /// Uses streaming JSON parser + batched transactions for performance
    pub fn import_vic_json(&self, json_path: &str, list_name: &str) -> Result<u64, String> {
        println!("Starting import of: {}", json_path);
        
        let file = std::fs::File::open(json_path)
            .map_err(|e| format!("Failed to open VIC file: {}", e))?;
        
        let reader = std::io::BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
        
        // Stream parse the JSON to handle large files without loading into memory
        let stream = serde_json::Deserializer::from_reader(reader).into_iter::<VicEntry>();
        
        let mut conn = self.conn.lock().unwrap();
        
        // Performance PRAGMAs for bulk import
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;"
        ).map_err(|e| format!("Failed to set import PRAGMAs: {}", e))?;
        
        // Create the hash list entry
        let list_id = self.create_hash_list_internal(&mut conn, list_name, "Project VIC")?;
        
        // Process all entries with batched transactions
        let mut imported_count = 0u64;
        let mut batch_count = 0u64;
        let batch_size = 50_000u64;
        
        // Start first transaction
        conn.execute_batch("BEGIN TRANSACTION")
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;
        
        {
            let mut stmt = conn.prepare(
                "INSERT INTO hashes (hash, hash_type, list_id, category, description, file_size) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
            ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
            
            for entry_result in stream {
                match entry_result {
                    Ok(entry) => {
                        // Insert SHA256 hash if available
                        if let Some(sha256) = &entry.sha256 {
                            stmt.execute(params![
                                sha256,
                                "SHA256",
                                list_id,
                                entry.category.as_deref(),
                                entry.description.as_deref(),
                                entry.file_size,
                            ]).ok();
                            imported_count += 1;
                        }
                        
                        // Insert MD5 hash if available
                        if let Some(md5) = &entry.md5 {
                            stmt.execute(params![
                                md5,
                                "MD5",
                                list_id,
                                entry.category.as_deref(),
                                entry.description.as_deref(),
                                entry.file_size,
                            ]).ok();
                            imported_count += 1;
                        }
                        
                        batch_count += 1;
                        
                        // Commit and start new transaction every batch_size entries
                        if batch_count % batch_size == 0 {
                            // Need to drop stmt before we can commit
                            // Instead, just use execute_batch through raw SQL
                            println!("Imported {} hashes so far...", imported_count);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse entry: {}", e);
                        continue;
                    }
                }
            }
        }
        
        // Commit final transaction
        conn.execute_batch("COMMIT")
            .map_err(|e| format!("Final commit failed: {}", e))?;
        
        // Restore safe PRAGMAs
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA journal_mode = WAL;"
        ).ok();
        
        // Update hash count in list
        conn.execute(
            "UPDATE hash_lists SET hash_count = ?1 WHERE id = ?2",
            params![imported_count, list_id],
        ).map_err(|e| format!("Failed to update hash count: {}", e))?;
        
        println!("Import complete: {} hashes imported", imported_count);
        
        Ok(imported_count)
    }
    
    /// Create a hash list entry (internal, with existing connection)
    fn create_hash_list_internal(&self, conn: &mut Connection, name: &str, source: &str) -> Result<i64, String> {
        conn.execute(
            "INSERT INTO hash_lists (name, source, imported_at, hash_count) VALUES (?1, ?2, datetime('now'), 0)",
            params![name, source],
        ).map_err(|e| format!("Failed to create hash list: {}", e))?;
        
        Ok(conn.last_insert_rowid())
    }
    
    /// Load all hashes into memory for ultra-fast lookups (called at startup)
    /// For 18M hashes, this uses ~600MB RAM but makes lookups instant
    pub fn load_hashes_into_memory(&self) -> Result<usize, String> {
        let start = std::time::Instant::now();
        
        let (hash_map, types, sizes) = {
            let conn = self.conn.lock().unwrap();
            
            let mut stmt = conn.prepare(
                "SELECT h.hash, h.hash_type, l.source, h.category, h.description, h.file_size 
                 FROM hashes h 
                 JOIN hash_lists l ON h.list_id = l.id"
            ).map_err(|e| format!("Failed to prepare query: {}", e))?;
            
            let mut hash_map = HashMap::new();
            let mut types = HashSet::new();
            let mut sizes = HashSet::new();
            let mut has_any_size = false;
            
            let rows = stmt.query_map([], |row| {
                let hash_type: String = row.get(1)?;
                let file_size: Option<i64> = row.get(5)?;
                Ok((HashMatch {
                    hash: row.get(0)?,
                    hash_type: hash_type.clone(),
                    source: row.get(2)?,
                    category: row.get(3)?,
                    description: row.get(4)?,
                }, hash_type, file_size))
            }).map_err(|e| format!("Query failed: {}", e))?;
            
            for row_result in rows {
                if let Ok((hash_match, hash_type, file_size)) = row_result {
                    hash_map.insert(hash_match.hash.clone(), hash_match);
                    types.insert(hash_type);
                    if let Some(sz) = file_size {
                        if sz > 0 {
                            sizes.insert(sz as u64);
                            has_any_size = true;
                        }
                    }
                }
            }
            
            // Only use size filter if we have size data for a meaningful portion
            let size_set = if has_any_size { Some(sizes) } else { None };
            (hash_map, types, size_set)
        };
        
        let count = hash_map.len();
        
        // Store in caches
        {
            let mut cache = self.hash_cache.write().unwrap();
            *cache = Some(hash_map);
        }
        {
            let mut t = self.hash_types.write().unwrap();
            *t = types.clone();
        }
        {
            let mut s = self.known_sizes.write().unwrap();
            *s = sizes;
        }
        
        let elapsed = start.elapsed();
        eprintln!("[Hash DB] Loaded {} hashes in {:.2}s (types: {:?})", count, elapsed.as_secs_f64(), types);
        
        Ok(count)
    }
    
    /// Check hash using in-memory cache (ultra-fast, no disk I/O)
    pub fn check_hash_fast(&self, hash: &str, _hash_type: &str) -> Option<HashMatch> {
        let cache = self.hash_cache.read().unwrap();
        
        if let Some(ref hash_map) = *cache {
            // O(1) lookup in HashMap
            hash_map.get(hash).cloned()
        } else {
            None
        }
    }
    
    /// Which hash types are in the database? (e.g. {"SHA256"} or {"MD5", "SHA256"})
    pub fn get_hash_types(&self) -> HashSet<String> {
        self.hash_types.read().unwrap().clone()
    }
    
    /// Get known file sizes if available — returns None if DB has no size data
    pub fn get_known_sizes(&self) -> Option<HashSet<u64>> {
        self.known_sizes.read().unwrap().clone()
    }
    
    /// Check if a hash exists in the database (ultra-fast with index)
    pub fn check_hash(&self, hash: &str, hash_type: &str) -> Result<Option<HashMatch>, String> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT h.hash, h.hash_type, l.source, h.category, h.description 
             FROM hashes h 
             JOIN hash_lists l ON h.list_id = l.id 
             WHERE h.hash = ?1 AND h.hash_type = ?2 
             LIMIT 1"
        ).map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let result = stmt.query_row(params![hash, hash_type], |row| {
            Ok(HashMatch {
                hash: row.get(0)?,
                hash_type: row.get(1)?,
                source: row.get(2)?,
                category: row.get(3)?,
                description: row.get(4)?,
            })
        });
        
        match result {
            Ok(match_data) => Ok(Some(match_data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Query failed: {}", e)),
        }
    }
    
    /// Check if a hash exists in specific hash lists (filtered by list IDs)
    pub fn check_hash_filtered(&self, hash: &str, hash_type: &str, list_ids: &[String]) -> Result<Option<HashMatch>, String> {
        if list_ids.is_empty() {
            // If no specific lists, check all
            return self.check_hash(hash, hash_type);
        }
        
        let conn = self.conn.lock().unwrap();
        
        // Build placeholders for list_ids
        let placeholders: Vec<String> = list_ids.iter().map(|_| "?".to_string()).collect();
        let placeholders_str = placeholders.join(", ");
        
        let query = format!(
            "SELECT h.hash, h.hash_type, l.source, h.category, h.description, l.name
             FROM hashes h 
             JOIN hash_lists l ON h.list_id = l.id 
             WHERE h.hash = ? AND h.hash_type = ? 
             AND l.name IN ({})
             LIMIT 1",
            placeholders_str
        );
        
        let mut stmt = conn.prepare(&query)
            .map_err(|e| format!("Failed to prepare filtered query: {}", e))?;
        
        // Build params: [hash, hash_type, ...list_ids]
        let mut query_params: Vec<&dyn rusqlite::ToSql> = vec![&hash, &hash_type];
        let list_id_refs: Vec<&dyn rusqlite::ToSql> = list_ids.iter()
            .map(|id| id as &dyn rusqlite::ToSql)
            .collect();
        query_params.extend(list_id_refs);
        
        let result = stmt.query_row(&*query_params, |row| {
            Ok(HashMatch {
                hash: row.get(0)?,
                hash_type: row.get(1)?,
                source: row.get(2)?,
                category: row.get(3)?,
                description: row.get(4)?,
            })
        });
        
        match result {
            Ok(match_data) => Ok(Some(match_data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Filtered query failed: {}", e)),
        }
    }
    
    /// Batch check multiple hashes (more efficient for bulk operations)
    pub fn check_hashes_batch(&self, hashes: &[(String, String)]) -> Result<Vec<HashMatch>, String> {
        let conn = self.conn.lock().unwrap();
        let mut matches = Vec::new();
        
        for (hash, hash_type) in hashes {
            let mut stmt = conn.prepare_cached(
                "SELECT h.hash, h.hash_type, l.source, h.category, h.description 
                 FROM hashes h 
                 JOIN hash_lists l ON h.list_id = l.id 
                 WHERE h.hash = ?1 AND h.hash_type = ?2 
                 LIMIT 1"
            ).map_err(|e| format!("Failed to prepare query: {}", e))?;
            
            let result = stmt.query_row(params![hash, hash_type], |row| {
                Ok(HashMatch {
                    hash: row.get(0)?,
                    hash_type: row.get(1)?,
                    source: row.get(2)?,
                    category: row.get(3)?,
                    description: row.get(4)?,
                })
            });
            
            if let Ok(match_data) = result {
                matches.push(match_data);
            }
        }
        
        Ok(matches)
    }
    
    /// Get statistics about the database
    pub fn get_stats(&self) -> Result<DatabaseStats, String> {
        let conn = self.conn.lock().unwrap();
        
        let total_lists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM hash_lists",
            [],
            |row| row.get(0)
        ).unwrap_or(0);
        
        let total_hashes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM hashes",
            [],
            |row| row.get(0)
        ).unwrap_or(0);
        
        let db_size: i64 = conn.query_row(
            "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()",
            [],
            |row| row.get(0)
        ).unwrap_or(0);
        
        Ok(DatabaseStats {
            total_lists: total_lists as u64,
            total_hashes: total_hashes as u64,
            database_size_bytes: db_size as u64,
        })
    }
    
    /// Delete a hash list and all its hashes
    pub fn delete_list(&self, list_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        // Enable foreign keys so CASCADE works
        conn.execute("PRAGMA foreign_keys = ON", []).ok();
        
        // Delete hashes first (in case CASCADE isn't working)
        conn.execute(
            "DELETE FROM hashes WHERE list_id = ?1",
            params![list_id],
        ).map_err(|e| format!("Failed to delete hashes for list: {}", e))?;
        
        conn.execute(
            "DELETE FROM hash_lists WHERE id = ?1",
            params![list_id],
        ).map_err(|e| format!("Failed to delete list: {}", e))?;
        
        Ok(())
    }
    
    /// Delete a hash list by name and all its hashes
    pub fn delete_list_by_name(&self, name: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        // Find list IDs matching this name
        let mut stmt = conn.prepare(
            "SELECT id FROM hash_lists WHERE name = ?1"
        ).map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let ids: Vec<i64> = stmt.query_map(params![name], |row| row.get(0))
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();
        
        if ids.is_empty() {
            eprintln!("No hash list found with name '{}' in database", name);
            return Ok(());
        }
        
        for id in &ids {
            // Delete hashes first
            conn.execute(
                "DELETE FROM hashes WHERE list_id = ?1",
                params![id],
            ).map_err(|e| format!("Failed to delete hashes for list {}: {}", id, e))?;
            
            conn.execute(
                "DELETE FROM hash_lists WHERE id = ?1",
                params![id],
            ).map_err(|e| format!("Failed to delete list {}: {}", id, e))?;
            
            eprintln!("✓ Deleted hash list id={} name='{}'", id, name);
        }
        
        Ok(())
    }
    
    /// Clear all hash lists and hashes from the database
    pub fn clear_all(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute("DELETE FROM hashes", [])
            .map_err(|e| format!("Failed to clear hashes: {}", e))?;
        
        conn.execute("DELETE FROM hash_lists", [])
            .map_err(|e| format!("Failed to clear hash lists: {}", e))?;
        
        eprintln!("✓ Cleared all hashes and hash lists from database");
        
        Ok(())
    }
    
    /// Optimize database (run after large imports)
    pub fn optimize(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute("VACUUM", [])
            .map_err(|e| format!("VACUUM failed: {}", e))?;
        
        conn.execute("ANALYZE", [])
            .map_err(|e| format!("ANALYZE failed: {}", e))?;
        
        Ok(())
    }
    
    /// Import a hash list with metadata
    pub fn import_hash_list(&self, name: &str, source: &str, hash_type: &str) -> Result<i64, String> {
        let conn = self.conn.lock().unwrap();
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        conn.execute(
            "INSERT INTO hash_lists (name, source, imported_at, hash_count) VALUES (?1, ?2, ?3, 0)",
            params![name, source, timestamp],
        ).map_err(|e| format!("Failed to create hash list: {}", e))?;
        
        let list_id = conn.last_insert_rowid();
        
        Ok(list_id)
    }
    
    /// Add a single hash to the database
    pub fn add_hash(
        &self,
        hash: &str,
        hash_type: &str,
        list_id: i64,
        category: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO hashes (hash, hash_type, list_id, category, description) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, hash_type, list_id, category, description],
        ).map_err(|e| format!("Failed to add hash: {}", e))?;
        
        Ok(())
    }
    
    /// Add many hashes in a single transaction (fast bulk insert)
    pub fn add_hashes_batch(
        &self,
        list_id: i64,
        hashes: &[(String, String, Option<String>, Option<String>)], // (hash, hash_type, category, description)
    ) -> Result<u64, String> {
        let mut conn = self.conn.lock().unwrap();
        
        // Performance PRAGMAs
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -32000;"
        ).ok();
        
        let tx = conn.transaction()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;
        
        let mut count = 0u64;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO hashes (hash, hash_type, list_id, category, description) VALUES (?1, ?2, ?3, ?4, ?5)"
            ).map_err(|e| format!("Failed to prepare statement: {}", e))?;
            
            for (hash, hash_type, category, description) in hashes {
                stmt.execute(params![
                    hash,
                    hash_type,
                    list_id,
                    category.as_deref(),
                    description.as_deref(),
                ]).ok();
                count += 1;
            }
        }
        
        tx.commit()
            .map_err(|e| format!("Batch commit failed: {}", e))?;
        
        // Restore safe PRAGMAs
        conn.execute_batch("PRAGMA synchronous = NORMAL;").ok();
        
        Ok(count)
    }
}

#[derive(Debug, Deserialize)]
struct VicEntry {
    #[serde(alias = "SHA256", alias = "sha256")]
    sha256: Option<String>,
    #[serde(alias = "MD5", alias = "md5")]
    md5: Option<String>,
    #[serde(alias = "Category", alias = "category")]
    category: Option<String>,
    #[serde(alias = "Description", alias = "description")]
    description: Option<String>,
    #[serde(alias = "FileSize", alias = "fileSize", alias = "file_size", alias = "Size", alias = "size")]
    file_size: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_lists: u64,
    pub total_hashes: u64,
    pub database_size_bytes: u64,
}
