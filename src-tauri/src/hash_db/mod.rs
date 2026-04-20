use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashSet;
use bloomfilter::Bloom;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    pub hash: String,
    pub hash_type: String,
    pub source: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub file_size: Option<i64>,
}

pub struct HashDatabase {
    conn: Arc<Mutex<Connection>>,
    // ── Tiered lookup (bloom → HashSet → SQLite) ──
    // Tier 1: Bloom filter — instant negative, ~26 MB for 14M hashes, 0.01% FPR
    bloom: Arc<RwLock<Option<Bloom<String>>>>,
    // Tier 2: HashSet of normalized hash strings — exact confirmation, ~1.1 GB for 14M
    hash_set: Arc<RwLock<Option<HashSet<String>>>>,
    // Tier 3: SQLite — full metadata lookup on confirmed match (rare path)
    // (uses self.conn)

    // Which hash types exist in the DB (e.g. {"SHA256"} or {"MD5","SHA256"})
    hash_types: Arc<RwLock<HashSet<String>>>,
    // Known file sizes from DB — if populated, skip files whose size doesn't match
    known_sizes: Arc<RwLock<Option<HashSet<u64>>>>,
    // Total hash count for bloom sizing
    hash_count: Arc<RwLock<usize>>,
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
            bloom: Arc::new(RwLock::new(None)),
            hash_set: Arc::new(RwLock::new(None)),
            hash_types: Arc::new(RwLock::new(HashSet::new())),
            known_sizes: Arc::new(RwLock::new(None)),
            hash_count: Arc::new(RwLock::new(0)),
        };
        
        hash_db.initialize_schema()?;
        hash_db.create_indexes()?;
        
        // NOTE: hashes are NOT loaded into memory here — call load_hashes_into_memory()
        // explicitly when needed (after import, after delete, before scan).
        // Loading 19M+ hashes (~1.7 GB) on every HashDatabase::new() would freeze the UI
        // since many commands create a new instance just for quick queries.
        
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
    
    /// Import a Project VIC JSON file (supports large files up to several GB)
    ///
    /// Handles three formats:
    ///   1. OData wrapper: {"@odata.context":"...", "value": [{...}, ...]}
    ///   2. Plain JSON array: [{...}, {...}, ...]
    ///   3. NDJSON: one JSON object per line
    ///
    /// Uses memory-mapped I/O + streaming object extraction — peak RAM ~50 MB
    /// regardless of file size. Inserts in 50K-entry batched transactions.
    pub fn import_vic_json<F>(&self, json_path: &str, list_name: &str, on_progress: F) -> Result<u64, String> 
    where F: Fn(u64, u64) // (imported_count, objects_scanned)
    {
        eprintln!("[VIC Import] Starting import of: {}", json_path);
        
        let file = std::fs::File::open(json_path)
            .map_err(|e| format!("Failed to open VIC file: {}", e))?;
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        eprintln!("[VIC Import] File size: {:.1} MB", file_size as f64 / (1024.0 * 1024.0));
        
        // Memory-map the file — OS pages in only what's needed (~50MB working set)
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap file: {}", e))?;
        let data = std::str::from_utf8(&mmap)
            .map_err(|e| format!("File is not valid UTF-8: {}", e))?;
        
        // Find the array of entries
        let array_start = if let Some(value_pos) = data.find("\"value\"") {
            // OData wrapper — find the [ after "value"
            data[value_pos..].find('[').map(|p| value_pos + p)
        } else if data.trim_start().starts_with('[') {
            data.find('[')
        } else {
            None
        };
        
        let search_from = match array_start {
            Some(pos) => pos + 1, // skip the opening [
            None => return Err("Could not find hash entries array in VIC JSON".to_string()),
        };
        
        // Setup database for bulk import
        let mut conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;"
        ).map_err(|e| format!("Failed to set import PRAGMAs: {}", e))?;
        
        let list_id = self.create_hash_list_internal(&mut conn, list_name, "Project VIC")?;
        
        // Stream objects using brace-counting extractor (handles strings correctly)
        let mut imported_count = 0u64;
        let mut batch: Vec<(String, String, Option<String>, Option<String>, Option<i64>)> = Vec::with_capacity(50_000);
        
        conn.execute_batch("BEGIN TRANSACTION")
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;
        
        let mut parse_errors = 0u64;
        let mut objects_seen = 0u64;
        for obj_str in Self::extract_json_objects(data, search_from) {
            objects_seen += 1;
            // Parse each entry individually — cheap because obj_str is a small slice
            let entry = match serde_json::from_str::<VicEntry>(obj_str) {
                Ok(e) => e,
                Err(e) => {
                    parse_errors += 1;
                    if parse_errors <= 3 {
                        eprintln!("[VIC Import] Parse error #{}: {} — entry: {}", 
                            parse_errors, e, &obj_str[..obj_str.len().min(200)]);
                    }
                    continue;
                }
            };
            // Import ONE hash per entry (priority: MD5 > SHA1 > SHA256)
            // MD5 is fastest to compute during scans and covers ~100% of VIC entries.
            // Importing all types would double DB size/RAM with zero benefit.
            let imported = if let Some(ref md5) = entry.md5 {
                if !md5.is_empty() {
                    batch.push(("MD5".to_string(), md5.clone(), entry.category.clone(), entry.description.clone(), entry.file_size));
                    true
                } else { false }
            } else { false };
            
            if !imported {
                let imported2 = if let Some(ref sha1) = entry.sha1 {
                    if !sha1.is_empty() {
                        batch.push(("SHA1".to_string(), sha1.clone(), entry.category.clone(), entry.description.clone(), entry.file_size));
                        true
                    } else { false }
                } else { false };
                
                if !imported2 {
                    if let Some(ref sha256) = entry.sha256 {
                        if !sha256.is_empty() {
                            batch.push(("SHA256".to_string(), sha256.clone(), entry.category.clone(), entry.description.clone(), entry.file_size));
                        }
                    }
                }
            }
            
            // Flush batch every 50K entries
            if batch.len() >= 50_000 {
                Self::flush_vic_batch(&conn, list_id, &batch, &mut imported_count)?;
                batch.clear();
                conn.execute_batch("COMMIT; BEGIN TRANSACTION").ok();
                on_progress(imported_count, objects_seen);
                eprintln!("[VIC Import] {} hashes imported...", imported_count);
            }
        }
        
        // Flush remaining batch
        if !batch.is_empty() {
            Self::flush_vic_batch(&conn, list_id, &batch, &mut imported_count)?;
        }
        
        conn.execute_batch("COMMIT")
            .map_err(|e| format!("Final commit failed: {}", e))?;
        
        conn.execute_batch("PRAGMA synchronous = NORMAL;").ok();
        
        conn.execute(
            "UPDATE hash_lists SET hash_count = ?1 WHERE id = ?2",
            params![imported_count, list_id],
        ).ok();
        
        if parse_errors > 0 {
            eprintln!("[VIC Import] Warning: {} parse errors out of {} objects", parse_errors, objects_seen);
        }
        eprintln!("[VIC Import] Complete: {} hashes imported from {} ({} objects scanned)", 
            imported_count, json_path, objects_seen);
        Ok(imported_count)
    }
    
    /// Extract JSON objects from a string starting at `from` position.
    /// Uses brace-counting with proper string handling (skips braces inside strings).
    /// Returns an iterator of `&str` slices, each containing one `{...}` object.
    fn extract_json_objects(data: &str, from: usize) -> VicObjectIter<'_> {
        VicObjectIter { data, pos: from }
    }
    
    /// Flush a batch of VIC entries to SQLite
    fn flush_vic_batch(
        conn: &Connection,
        list_id: i64,
        batch: &[(String, String, Option<String>, Option<String>, Option<i64>)],
        imported_count: &mut u64,
    ) -> Result<(), String> {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO hashes (hash, hash_type, list_id, category, description, file_size) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ).map_err(|e| format!("Prepare failed: {}", e))?;
        
        for (ht, hash, cat, desc, sz) in batch {
            stmt.execute(params![hash, ht, list_id, cat.as_deref(), desc.as_deref(), sz]).ok();
            *imported_count += 1;
        }
        Ok(())
    }
    
    /// Create a hash list entry (internal, with existing connection)
    fn create_hash_list_internal(&self, conn: &mut Connection, name: &str, source: &str) -> Result<i64, String> {
        conn.execute(
            "INSERT INTO hash_lists (name, source, imported_at, hash_count) VALUES (?1, ?2, datetime('now'), 0)",
            params![name, source],
        ).map_err(|e| format!("Failed to create hash list: {}", e))?;
        
        Ok(conn.last_insert_rowid())
    }
    
    /// Load hashes into bloom filter + HashSet for ultra-fast lookups.
    ///
    /// Memory profile for 14M hashes:
    ///   Bloom filter:  ~26 MB  (0.01% false positive rate)
    ///   HashSet:       ~1.1 GB (exact confirmation, no metadata)
    ///   Total:         ~1.1 GB vs ~5 GB for old HashMap<String, HashMatch>
    ///
    /// Lookup path:  bloom check (ns) → HashSet confirm (ns) → SQLite metadata (µs, rare)
    pub fn load_hashes_into_memory(&self) -> Result<usize, String> {
        let start = std::time::Instant::now();
        
        let (hash_strings, types, sizes) = {
            let conn = self.conn.lock().unwrap();
            
            // Only fetch hash, hash_type, file_size — skip metadata (source, category, desc)
            // Metadata is fetched from SQLite on the rare confirmed match
            let mut stmt = conn.prepare(
                "SELECT h.hash, h.hash_type, h.file_size FROM hashes h"
            ).map_err(|e| format!("Failed to prepare query: {}", e))?;
            
            let mut hash_strings: Vec<String> = Vec::new();
            let mut types = HashSet::new();
            let mut sizes = HashSet::new();
            let mut has_any_size = false;
            
            let rows = stmt.query_map([], |row| {
                let hash: String = row.get(0)?;
                let hash_type: String = row.get(1)?;
                let file_size: Option<i64> = row.get(2)?;
                Ok((hash, hash_type, file_size))
            }).map_err(|e| format!("Query failed: {}", e))?;
            
            for row_result in rows {
                if let Ok((hash, hash_type, file_size)) = row_result {
                    // Normalize to lowercase — scanner computes lowercase
                    let normalized = hash.to_lowercase();
                    if !normalized.is_empty() {
                        hash_strings.push(normalized);
                    }
                    types.insert(hash_type);
                    if let Some(sz) = file_size {
                        if sz > 0 {
                            sizes.insert(sz as u64);
                            has_any_size = true;
                        }
                    }
                }
            }
            
            let size_set = if has_any_size { Some(sizes) } else { None };
            (hash_strings, types, size_set)
        };
        
        let count = hash_strings.len();
        
        // Build bloom filter — sized for actual count (minimum 100 to avoid edge cases)
        let bloom_items = count.max(100);
        let fp_rate = 0.0001; // 0.01% false positive rate
        let mut bloom = Bloom::new_for_fp_rate(bloom_items, fp_rate);
        
        // Build HashSet + populate bloom
        let mut hash_set = HashSet::with_capacity(count);
        for h in &hash_strings {
            bloom.set(h);
            hash_set.insert(h.clone());
        }
        
        let bloom_size_bytes = bloom.number_of_bits() / 8;
        let hashset_est_bytes = (count * 88) as u64; // ~88 bytes per String entry in HashSet
        
        // Store in caches
        {
            let mut b = self.bloom.write().unwrap();
            *b = Some(bloom);
        }
        {
            let mut hs = self.hash_set.write().unwrap();
            *hs = Some(hash_set);
        }
        {
            let mut t = self.hash_types.write().unwrap();
            *t = types.clone();
        }
        {
            let mut s = self.known_sizes.write().unwrap();
            *s = sizes;
        }
        {
            let mut c = self.hash_count.write().unwrap();
            *c = count;
        }
        
        let elapsed = start.elapsed();
        eprintln!("[Hash DB] Loaded {} hashes in {:.2}s (types: {:?})", count, elapsed.as_secs_f64(), types);
        eprintln!("[Hash DB] Bloom: {} KB, HashSet: ~{} MB, total: ~{} MB", 
            bloom_size_bytes / 1024,
            hashset_est_bytes / (1024 * 1024),
            (bloom_size_bytes + hashset_est_bytes) / (1024 * 1024));
        
        Ok(count)
    }
    
    /// Tiered hash check: bloom filter → HashSet → SQLite metadata
    ///
    /// 1. Bloom filter (nanoseconds): eliminates 99.99% of non-matches
    /// 2. HashSet (nanoseconds): exact confirmation, no false positives
    /// 3. SQLite (microseconds): fetch metadata only on confirmed match
    pub fn check_hash_fast(&self, hash: &str, hash_type: &str) -> Option<HashMatch> {
        // Tier 1: Bloom filter — fast negative
        {
            let bloom = self.bloom.read().unwrap();
            if let Some(ref bf) = *bloom {
                if !bf.check(&hash.to_string()) {
                    return None; // Definitely not in DB
                }
            } else {
                return None; // No bloom loaded = no hashes
            }
        }
        
        // Tier 2: HashSet — exact confirmation (bloom may have false positive)
        {
            let hs = self.hash_set.read().unwrap();
            if let Some(ref set) = *hs {
                if !set.contains(hash) {
                    return None; // Bloom false positive
                }
            } else {
                return None;
            }
        }
        
        // Tier 3: Confirmed match — fetch full metadata from SQLite
        // This path is VERY rare (only actual CSAM matches)
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT h.hash, h.hash_type, l.source, h.category, h.description, h.file_size 
             FROM hashes h 
             JOIN hash_lists l ON h.list_id = l.id 
             WHERE LOWER(h.hash) = ?1 
             LIMIT 1"
        ).ok()?;
        
        stmt.query_row(params![hash], |row| {
            Ok(HashMatch {
                hash: row.get(0)?,
                hash_type: row.get(1)?,
                source: row.get(2)?,
                category: row.get(3)?,
                description: row.get(4)?,
                file_size: row.get(5)?,
            })
        }).ok()
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
            "SELECT h.hash, h.hash_type, l.source, h.category, h.description, h.file_size 
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
                file_size: row.get(5)?,
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
            "SELECT h.hash, h.hash_type, l.source, h.category, h.description, h.file_size
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
                file_size: row.get(5)?,
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
                "SELECT h.hash, h.hash_type, l.source, h.category, h.description, h.file_size 
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
                    file_size: row.get(5)?,
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
        
        // Use pre-computed hash_count from hash_lists table (instant)
        // instead of COUNT(*) on hashes table (full scan on 19M+ rows = 10-30s)
        let total_hashes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(hash_count), 0) FROM hash_lists",
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
    
    /// Get all hash lists from the database (metadata only)
    pub fn get_lists(&self) -> Result<Vec<DbHashListInfo>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, source, hash_count, imported_at FROM hash_lists ORDER BY id"
        ).map_err(|e| format!("Failed to query hash lists: {}", e))?;
        
        let lists = stmt.query_map([], |row| {
            Ok(DbHashListInfo {
                id: row.get(0)?,
                name: row.get::<_, String>(1)?,
                source: row.get::<_, String>(2).unwrap_or_default(),
                hash_count: row.get::<_, i64>(3).unwrap_or(0) as u64,
                imported_at: row.get::<_, String>(4).unwrap_or_default(),
            })
        }).map_err(|e| format!("Failed to read hash lists: {}", e))?;
        
        let mut result = Vec::new();
        for list in lists {
            if let Ok(l) = list { result.push(l); }
        }
        Ok(result)
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
            "SELECT id, hash_count FROM hash_lists WHERE name = ?1"
        ).map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let ids: Vec<(i64, i64)> = stmt.query_map(params![name], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1).unwrap_or(0)))
        })
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();
        
        if ids.is_empty() {
            eprintln!("No hash list found with name '{}' in database", name);
            return Ok(());
        }
        
        for (id, hash_count) in &ids {
            let start = std::time::Instant::now();
            eprintln!("[Delete] Removing {} hashes for list id={} name='{}'...", hash_count, id, name);
            
            // For large lists, delete in batches to avoid locking the DB for minutes
            // SQLite journal rollback on a single massive DELETE is the main bottleneck
            if *hash_count > 100_000 {
                // Batch delete: 50k rows at a time — much faster than one giant DELETE
                loop {
                    let deleted: usize = conn.execute(
                        "DELETE FROM hashes WHERE rowid IN (SELECT rowid FROM hashes WHERE list_id = ?1 LIMIT 50000)",
                        params![id],
                    ).map_err(|e| format!("Failed to delete hash batch for list {}: {}", id, e))?;
                    
                    if deleted == 0 { break; }
                    eprintln!("[Delete] ... removed batch of {} rows", deleted);
                }
            } else {
                conn.execute(
                    "DELETE FROM hashes WHERE list_id = ?1",
                    params![id],
                ).map_err(|e| format!("Failed to delete hashes for list {}: {}", id, e))?;
            }
            
            conn.execute(
                "DELETE FROM hash_lists WHERE id = ?1",
                params![id],
            ).map_err(|e| format!("Failed to delete list {}: {}", id, e))?;
            
            eprintln!("✓ Deleted hash list id={} name='{}' in {:.1}s", id, name, start.elapsed().as_secs_f64());
        }
        
        Ok(())
    }
    
    /// Reclaim disk space after large deletes
    pub fn vacuum(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        eprintln!("[VACUUM] Reclaiming disk space...");
        let start = std::time::Instant::now();
        conn.execute("VACUUM", [])
            .map_err(|e| format!("VACUUM failed: {}", e))?;
        eprintln!("✓ VACUUM completed in {:.1}s", start.elapsed().as_secs_f64());
        Ok(())
    }
    
    /// Clear all hash lists and hashes from the database
    pub fn clear_all(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        let start = std::time::Instant::now();
        eprintln!("[Clear] Dropping all hashes...");
        
        // DROP + recreate is orders of magnitude faster than DELETE for large tables
        conn.execute("DROP TABLE IF EXISTS hashes", [])
            .map_err(|e| format!("Failed to drop hashes table: {}", e))?;
        
        conn.execute("DELETE FROM hash_lists", [])
            .map_err(|e| format!("Failed to clear hash lists: {}", e))?;
        
        // Recreate hashes table
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
        ).map_err(|e| format!("Failed to recreate hashes table: {}", e))?;
        
        // Recreate indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hash_lookup ON hashes(hash, hash_type)",
            [],
        ).map_err(|e| format!("Failed to recreate hash index: {}", e))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_list_id ON hashes(list_id)",
            [],
        ).map_err(|e| format!("Failed to recreate list index: {}", e))?;
        
        // VACUUM to reclaim disk space
        eprintln!("[Clear] Running VACUUM...");
        conn.execute("VACUUM", [])
            .map_err(|e| format!("VACUUM failed: {}", e))?;
        
        eprintln!("✓ Cleared database in {:.1}s", start.elapsed().as_secs_f64());
        
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

/// Iterator that extracts `{...}` JSON objects from a string slice.
/// Handles strings correctly (braces inside "..." are ignored).
/// Designed for streaming through large VIC JSON arrays without loading all objects at once.
struct VicObjectIter<'a> {
    data: &'a str,
    pos: usize,
}

impl<'a> Iterator for VicObjectIter<'a> {
    type Item = &'a str;
    
    fn next(&mut self) -> Option<&'a str> {
        // Find next opening brace
        let remaining = &self.data[self.pos..];
        let start_offset = remaining.find('{')?;
        let abs_start = self.pos + start_offset;
        
        // Count braces to find matching }, respecting strings
        let mut depth = 0i32;
        let mut in_string = false;
        let mut prev_backslash = false;
        
        for (i, ch) in self.data[abs_start..].char_indices() {
            if prev_backslash {
                prev_backslash = false;
                continue;
            }
            match ch {
                '\\' if in_string => { prev_backslash = true; }
                '"' => { in_string = !in_string; }
                '{' if !in_string => { depth += 1; }
                '}' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        let end = abs_start + i + 1;
                        self.pos = end;
                        return Some(&self.data[abs_start..end]);
                    }
                }
                _ => {}
            }
        }
        None // Reached end of data without closing brace
    }
}

/// Deserialize a JSON value that might be a string, number, or bool into Option<String>.
/// VIC uses integer categories (0, 1, 2, 3) but we store as strings.
fn string_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    use serde::Deserialize;
    let val = Option::<serde_json::Value>::deserialize(d)?;
    Ok(val.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        _ => None,
    }))
}

#[derive(Debug, Deserialize)]
struct VicEntry {
    #[serde(alias = "SHA256", alias = "sha256")]
    sha256: Option<String>,
    #[serde(alias = "SHA1", alias = "sha1", alias = "Sha1")]
    sha1: Option<String>,
    #[serde(alias = "MD5", alias = "md5")]
    md5: Option<String>,
    #[serde(alias = "Category", alias = "category", default, deserialize_with = "string_or_number")]
    category: Option<String>,
    #[serde(alias = "Description", alias = "description", alias = "Series", alias = "series")]
    description: Option<String>,
    #[serde(alias = "FileSize", alias = "fileSize", alias = "file_size", alias = "Size", alias = "size", alias = "MediaSize", alias = "mediaSize")]
    file_size: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_lists: u64,
    pub total_hashes: u64,
    pub database_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbHashListInfo {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub hash_count: u64,
    pub imported_at: String,
}
