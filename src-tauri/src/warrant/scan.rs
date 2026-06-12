//! In-memory, ephemeral hash + keyword scanning for warrant cases.
//!
//! Results are cached per case in a process-global map and lost when Scout
//! exits.  They get embedded into the exported HTML report only if they
//! exist at export time.
//!
//! Hash scan: SHA-1 each file in `<case>/media/` and look it up via
//! [`crate::hash_db::HashDatabase`] (Project VIC + any imported lists).
//!
//! Keyword scan: takes a list of keyword-list NAMES (loaded via the same
//! `keyword_lists` directory as phone/PC scans), iterates every item in
//! the case, and matches against the item's textual fields.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use super::triage_state::{self, CaseDetail};

// ─── Public data shapes ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashHit {
    pub filename: String,
    pub sha1: String,
    pub size_bytes: u64,
    pub list_name: String,
    pub category: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashScanResult {
    pub ran_at: String,        // rfc3339
    pub files_scanned: usize,
    pub files_total: usize,    // includes non-images / unreadable
    pub duration_ms: u64,
    pub hits: Vec<HashHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordHit {
    pub item_id: String,
    pub section: String,
    pub keyword: String,
    pub field: String,           // which field matched (body_text / summary / etc.)
    pub snippet: String,         // surrounding context, ~120 chars
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeywordScanResult {
    pub ran_at: String,
    pub lists_used: Vec<String>,
    pub keyword_count: usize,
    pub items_scanned: usize,
    pub duration_ms: u64,
    pub hits: Vec<KeywordHit>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseScanResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_scan: Option<HashScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyword_scan: Option<KeywordScanResult>,
}

// ─── In-memory cache ─────────────────────────────────────────────────

fn cache() -> &'static Mutex<HashMap<String, CaseScanResults>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CaseScanResults>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn get_results(case_id: &str) -> CaseScanResults {
    cache()
        .lock()
        .ok()
        .and_then(|m| m.get(case_id).cloned())
        .unwrap_or_default()
}

pub fn store_hash(case_id: &str, r: HashScanResult) {
    if let Ok(mut m) = cache().lock() {
        m.entry(case_id.to_string()).or_default().hash_scan = Some(r);
    }
}

pub fn store_keyword(case_id: &str, r: KeywordScanResult) {
    if let Ok(mut m) = cache().lock() {
        m.entry(case_id.to_string()).or_default().keyword_scan = Some(r);
    }
}

pub fn clear(case_id: &str, scan_type: &str) {
    if let Ok(mut m) = cache().lock() {
        if let Some(entry) = m.get_mut(case_id) {
            match scan_type {
                "hash" => entry.hash_scan = None,
                "keyword" => entry.keyword_scan = None,
                _ => {
                    entry.hash_scan = None;
                    entry.keyword_scan = None;
                }
            }
        }
    }
}

// ─── Hash scan ───────────────────────────────────────────────────────

const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff", "heic", "heif"];
const VIDEO_EXTS: &[&str] = &["mp4", "mov", "avi", "mkv", "webm", "wmv", "flv", "m4v", "3gp"];

fn is_scannable_media(p: &Path) -> bool {
    p.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .map(|s| IMAGE_EXTS.contains(&s.as_str()) || VIDEO_EXTS.contains(&s.as_str()))
        .unwrap_or(false)
}

/// Compute the requested digests for a file in a single read pass.
/// Returns (size, md5, sha1, sha256) — each digest is `Some` iff the
/// matching `need_*` flag was true.
fn compute_file_hashes(
    path: &Path,
    need_md5: bool,
    need_sha1: bool,
    need_sha256: bool,
) -> std::io::Result<(u64, Option<String>, Option<String>, Option<String>)> {
    use md5::Md5;
    use sha2::Sha256;
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 65_536];
    let mut total: u64 = 0;
    let mut md5_h = if need_md5 { Some(Md5::new()) } else { None };
    let mut sha1_h = if need_sha1 { Some(Sha1::new()) } else { None };
    let mut sha256_h = if need_sha256 { Some(Sha256::new()) } else { None };

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        if let Some(h) = md5_h.as_mut() { h.update(&buf[..n]); }
        if let Some(h) = sha1_h.as_mut() { h.update(&buf[..n]); }
        if let Some(h) = sha256_h.as_mut() { h.update(&buf[..n]); }
        total += n as u64;
    }

    Ok((
        total,
        md5_h.map(|h| format!("{:x}", h.finalize())),
        sha1_h.map(|h| format!("{:x}", h.finalize())),
        sha256_h.map(|h| format!("{:x}", h.finalize())),
    ))
}

/// Run a hash scan against the case's media dir.  Reuses the global
/// [`crate::hash_db::HashDatabase`] and loads its hashes into memory
/// (bloom + HashSet) so the per-file check is sub-microsecond.
///
/// `allowed_lists`: if `Some(non-empty)`, only hits whose `list_name`
/// (case-insensitive) is in the set are kept.  `None` or empty = all lists.
pub fn run_hash_scan(case_id: &str, allowed_lists: Option<&[String]>) -> Result<HashScanResult, String> {
    let media_dir = triage_state::media_dir(case_id);
    if !media_dir.exists() {
        return Err(format!("media dir does not exist: {}", media_dir.display()));
    }
    let start = std::time::Instant::now();

    let db = crate::hash_db::HashDatabase::new()
        .map_err(|e| format!("failed to open hash database: {}", e))?;

    // CRITICAL: hashes are NOT loaded by ::new() — must explicitly load
    // before any check_hash_fast() call or the bloom filter is empty.
    let loaded = db
        .load_hashes_into_memory()
        .map_err(|e| format!("failed to load hashes into memory: {}", e))?;
    eprintln!("[warrant hash scan] loaded {} hashes into memory", loaded);

    if loaded == 0 {
        return Err(
            "Hash database is empty. Import a hash list (Project VIC or your own) \
             from the Hash Lists settings page first."
                .into(),
        );
    }

    // Discover which hash types the DB actually contains.  Some lists
    // only have SHA256 (Project VIC), some MD5, etc.  We compute only
    // what the DB needs.
    let db_types = db.get_hash_types();
    let need_md5 = db_types.iter().any(|t| t.eq_ignore_ascii_case("MD5"));
    let need_sha1 = db_types.iter().any(|t| t.eq_ignore_ascii_case("SHA1"));
    // Default to SHA256 if get_hash_types is empty (cold DB / migration).
    let need_sha256 = db_types.is_empty()
        || db_types.iter().any(|t| t.eq_ignore_ascii_case("SHA256"));
    eprintln!(
        "[warrant hash scan] types in db = {:?}, computing md5={} sha1={} sha256={}",
        db_types, need_md5, need_sha1, need_sha256
    );

    // Build a list of (computed_hash, db_hash_type_label) pairs we need
    // to check per file, where the db_hash_type_label preserves the
    // exact case the DB uses ("SHA1", "SHA256", "MD5") — the check_hash
    // SQL query uses an exact-match on hash_type.
    let label_for = |variant: &str| -> String {
        // Pick the casing actually stored in the DB if present.
        db_types
            .iter()
            .find(|t| t.eq_ignore_ascii_case(variant))
            .cloned()
            .unwrap_or_else(|| variant.to_string())
    };
    let lbl_md5 = label_for("MD5");
    let lbl_sha1 = label_for("SHA1");
    let lbl_sha256 = label_for("SHA256");

    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&media_dir).map_err(|e| e.to_string())? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let p = entry.path();
        if p.is_file() && is_scannable_media(&p) {
            files.push(p);
        }
    }
    let files_total = files.len();

    let mut hits: Vec<HashHit> = Vec::new();
    let mut scanned = 0usize;

    for path in &files {
        let (size, md5, sha1, sha256) =
            match compute_file_hashes(path, need_md5, need_sha1, need_sha256) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[warrant hash scan] read fail {}: {}", path.display(), e);
                    continue;
                }
            };
        scanned += 1;

        // Try every computed digest against the DB.  First hit wins.
        let attempts: [(Option<&str>, &str); 3] = [
            (sha256.as_deref(), lbl_sha256.as_str()),
            (sha1.as_deref(), lbl_sha1.as_str()),
            (md5.as_deref(), lbl_md5.as_str()),
        ];

        let mut matched: Option<(String, String, crate::hash_db::HashMatch)> = None;
        for (hash_opt, label) in attempts {
            let h = match hash_opt {
                Some(h) => h,
                None => continue,
            };
            // Fast path: bloom + hashset + exclusion list + final SQL.
            if let Some(m) = db.check_hash_fast(h, label) {
                matched = Some((h.to_string(), label.to_string(), m));
                break;
            }
        }

        if let Some((hash_str, _type_label, m)) = matched {
            // Optional filter: only keep hits from lists the user picked.
            if let Some(allowed) = allowed_lists {
                if !allowed.is_empty() {
                    let m_list = m.list_name.to_lowercase();
                    let m_src = m.source.to_lowercase();
                    let keep = allowed.iter().any(|n| {
                        let n = n.to_lowercase();
                        n == m_list || n == m_src
                    });
                    if !keep {
                        continue;
                    }
                }
            }
            let filename = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            hits.push(HashHit {
                filename,
                sha1: hash_str,
                size_bytes: size,
                list_name: m.list_name,
                category: m.category,
                description: m.description,
            });
        }
    }

    let result = HashScanResult {
        ran_at: chrono::Utc::now().to_rfc3339(),
        files_scanned: scanned,
        files_total,
        duration_ms: start.elapsed().as_millis() as u64,
        hits,
    };
    store_hash(case_id, result.clone());
    Ok(result)
}

// ─── Keyword scan ────────────────────────────────────────────────────

/// Load a specific keyword list by name from `<APPDATA>/Hindsight/keyword_lists`.
/// Returns the keywords inside (deduped, lowercased, blanks stripped).
fn load_list_by_name(dir: &Path, name: &str) -> Option<Vec<String>> {
    let path = dir.join(format!("{}.txt", name));
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let kw = line.trim();
        if kw.is_empty() || kw.starts_with('#') {
            continue;
        }
        let lower = kw.to_lowercase();
        if seen.insert(lower.clone()) {
            out.push(kw.to_string());
        }
    }
    Some(out)
}

fn snippet_around(haystack: &str, idx: usize, kw_len: usize) -> String {
    let start = idx.saturating_sub(40);
    let end = (idx + kw_len + 40).min(haystack.len());
    // Walk back/forward to char boundaries
    let mut s = start;
    while s > 0 && !haystack.is_char_boundary(s) {
        s -= 1;
    }
    let mut e = end;
    while e < haystack.len() && !haystack.is_char_boundary(e) {
        e += 1;
    }
    let mut out = String::new();
    if s > 0 {
        out.push('…');
    }
    out.push_str(&haystack[s..e].replace('\n', " "));
    if e < haystack.len() {
        out.push('…');
    }
    out
}

fn search_field(field_name: &str, text: &str, keywords: &[String], item: &super::WarrantItem, hits: &mut Vec<KeywordHit>) {
    let hay_lower = text.to_lowercase();
    for kw in keywords {
        let needle = kw.to_lowercase();
        if let Some(idx) = hay_lower.find(&needle) {
            hits.push(KeywordHit {
                item_id: item.id.clone(),
                section: item.section.clone(),
                keyword: kw.clone(),
                field: field_name.to_string(),
                snippet: snippet_around(text, idx, kw.len()),
            });
        }
    }
}

/// Run a keyword scan over the case items' textual content.
/// `list_names` is the set of keyword-list filenames (without `.txt`).
/// `keyword_dir` is the directory containing the lists.
pub fn run_keyword_scan(
    case_id: &str,
    list_names: &[String],
    keyword_dir: &Path,
) -> Result<KeywordScanResult, String> {
    if list_names.is_empty() {
        return Err("no keyword lists selected".into());
    }
    let start = std::time::Instant::now();

    let detail: CaseDetail = triage_state::load_case_detail(case_id)
        .map_err(|e| format!("could not load case: {}", e))?;

    // Merge keywords from all chosen lists (deduped, case-insensitive)
    let mut keywords: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut lists_used: Vec<String> = Vec::new();
    for name in list_names {
        match load_list_by_name(keyword_dir, name) {
            Some(kws) => {
                lists_used.push(name.clone());
                for kw in kws {
                    if seen.insert(kw.to_lowercase()) {
                        keywords.push(kw);
                    }
                }
            }
            None => {
                eprintln!("[warrant keyword scan] list not found: {}", name);
            }
        }
    }
    if keywords.is_empty() {
        return Err("selected lists contained no keywords".into());
    }

    let mut hits: Vec<KeywordHit> = Vec::new();
    let mut items_scanned = 0usize;

    for item in &detail.items {
        items_scanned += 1;
        if let Some(t) = &item.body_text {
            if !t.is_empty() {
                search_field("body_text", t, &keywords, item, &mut hits);
            }
        }
        if let Some(t) = &item.summary {
            if !t.is_empty() {
                search_field("summary", t, &keywords, item, &mut hits);
            }
        }
        if let Some(t) = &item.author {
            if !t.is_empty() {
                search_field("author", t, &keywords, item, &mut hits);
            }
        }
        if let Some(t) = &item.recipient {
            if !t.is_empty() {
                search_field("recipient", t, &keywords, item, &mut hits);
            }
        }
        if let Some(t) = &item.note {
            if !t.is_empty() {
                search_field("note", t, &keywords, item, &mut hits);
            }
        }
        // raw_fields — only scan strings
        if let serde_json::Value::Object(map) = &item.raw_fields {
            for (k, v) in map {
                if let serde_json::Value::String(s) = v {
                    if !s.is_empty() {
                        search_field(&format!("raw.{}", k), s, &keywords, item, &mut hits);
                    }
                }
            }
        }
    }

    // Cap total hits to keep payload sane
    const MAX_HITS: usize = 2000;
    if hits.len() > MAX_HITS {
        hits.truncate(MAX_HITS);
    }

    let result = KeywordScanResult {
        ran_at: chrono::Utc::now().to_rfc3339(),
        lists_used,
        keyword_count: keywords.len(),
        items_scanned,
        duration_ms: start.elapsed().as_millis() as u64,
        hits,
    };
    store_keyword(case_id, result.clone());
    Ok(result)
}
