//! Snapchat warrant-return parser.
//!
//! Format reference
//! ----------------
//! Snapchat law-enforcement responses are CSV-based productions.  A single
//! production is split across one or more "part" folders named like:
//!
//!   {username}-{caseId}-{requestId}-{partNum}-{date}/
//!
//! Each part folder contains a mix of CSVs and `chat~media_v4~...` media
//! files.  Common CSV filenames:
//!
//!   conversations.csv         — message log (always present)
//!   geo_locations.csv         — lat/lon timeline
//!   memories.csv              — saved memory snaps
//!   device_advertising_id.csv — device IDs
//!   subscriber_info.csv       — registration / contact info  (optional)
//!   login_history.csv         — login events with IPs        (optional)
//!   friends.csv               — friend list                  (optional)
//!   snap_history.csv          — snap activity                (optional)
//!   ai_conversations.csv      — MyAI bot chats               (optional)
//!   call_logs.csv             — voice/video call log         (optional)
//!
//! Each CSV starts with a multi-line legend "preamble" terminated by a
//! line of `=========` (any number of equals signs).  The next non-empty
//! line is the column-header row.
//!
//! Productions can be MASSIVE (multi-GB zips, thousands of media files
//! split across 4–6 part folders).  Investigators frequently point us at
//! a SINGLE part folder; we auto-discover sibling parts in the parent
//! directory using the `caseId-requestId` token pair from the folder name
//! so we don't silently miss most of the production.
//!
//! Media files follow the pattern:
//!   chat~media_v4~{YYYY-MM-DD-HH-MM-SSUTC}~{sender}~{recipient}~{saved|unsaved}~b~{token}~v4.{ext}
//!
//! The `media_id` column in `conversations.csv` (e.g. `b~Ei...`) matches
//! the `{token}` segment in the media filename, so we can link a chat row
//! to its photo/video on disk.
//!
//! This implementation is a Rust port of VIPER's
//! `modules/snapchat-warrant/snapchat-warrant-parser.js`.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct SnapchatWarrantParser;

// CSV filenames we have hard-coded handlers for (lowercase basenames).
const KNOWN_CSVS: &[&str] = &[
    "conversations.csv",
    "geo_locations.csv",
    "memories.csv",
    "device_advertising_id.csv",
    "subscriber_info.csv",
    "login_history.csv",
    "friends.csv",
    "snap_history.csv",
    "ai_conversations.csv",
    "call_logs.csv",
];

const IMAGE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp",
];
const VIDEO_EXTS: &[&str] = &[".mp4", ".mov", ".webm", ".m4v", ".avi", ".mkv"];
const AUDIO_EXTS: &[&str] = &[".aac", ".m4a", ".mp3", ".wav", ".ogg", ".opus"];

// ─── WarrantParser impl ─────────────────────────────────────────────────

impl WarrantParser for SnapchatWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Snapchat
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_snapchat_format(path));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        // Folder-agnostic detection.  Modern Snapchat productions may ship as
        // a flat zip, a nested zip, or the legacy part-folder layout, and they
        // moved the target-account identity out of `conversations.csv` into
        // `conversation_list.csv`.  So we match on BASENAME only and treat the
        // presence of either canonical file as a Snapchat signal.
        let mut conv_indices: Vec<usize> = Vec::new();
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().to_string();
            let base = name.rsplit('/').next().unwrap_or(&name).to_ascii_lowercase();

            // `conversation_list.csv` is Snapchat-specific — accept outright.
            if base == "conversation_list.csv" {
                return Ok(true);
            }
            if base == "conversations.csv" {
                conv_indices.push(i);
            }
            // Legacy signal: any path segment matching the part-folder pattern.
            for seg in name.split('/') {
                if extract_part_tokens(seg).is_some() {
                    return Ok(true);
                }
            }
        }

        // Sniff the head of any conversations.csv for Snapchat column markers.
        for i in conv_indices {
            let mut entry = zip.by_index(i)?;
            let mut head = vec![0u8; 4096];
            let read = entry.read(&mut head).unwrap_or(0);
            let head_str = String::from_utf8_lossy(&head[..read]);
            if head_looks_snapchat(&head_str) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        fs::create_dir_all(media_extract_dir)?;

        // ── Phase 1: collect part-folder contents into memory.
        //   - CSVs as decoded UTF-8 text
        //   - Media files extracted to disk
        let mut parts: Vec<RawPart> = if archive_path.is_dir() {
            collect_parts_from_dir(archive_path, media_extract_dir)?
        } else {
            collect_parts_from_zip(archive_path, media_extract_dir)?
        };

        if parts.is_empty() {
            return Err(ParseError::Other(
                "No Snapchat part folders found in input".into(),
            ));
        }

        // Sort parts by partNum so concatenation matches chronological intent.
        parts.sort_by(|a, b| {
            let na = extract_part_tokens(&a.folder)
                .map(|t| t.part_num)
                .unwrap_or(0);
            let nb = extract_part_tokens(&b.folder)
                .map(|t| t.part_num)
                .unwrap_or(0);
            na.cmp(&nb).then_with(|| a.folder.cmp(&b.folder))
        });

        // ── Phase 2: parse each part's CSVs into structured rows.
        let mut parsed_parts: Vec<ParsedPart> = Vec::with_capacity(parts.len());
        for part in &parts {
            parsed_parts.push(parse_one_part(part));
        }

        // ── Phase 3: merge across parts, dedupe, sort.
        let merged = merge_parts(&parsed_parts);

        // ── Phase 4: build media-token → filename index for linking.
        let media_filenames: Vec<String> = parts
            .iter()
            .flat_map(|p| p.media_files.iter().cloned())
            .collect();
        let media_index = build_media_index(&media_filenames);

        // ── Phase 5: emit WarrantItems.
        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let mut ctx = ParseCtx::default();
        ctx.target_account = merged
            .header
            .as_ref()
            .and_then(|h| h.target_username.clone());
        ctx.date_range = merged.header.as_ref().and_then(|h| h.date_range.clone());

        emit_bio(&merged, &mut ctx);
        emit_messages(&merged, &media_index, &mut ctx);
        emit_memories(&merged, &media_index, &mut ctx);
        emit_geo_locations(&merged, &mut ctx);
        emit_device_ads(&merged, &mut ctx);
        emit_login_history(&merged, &mut ctx);
        emit_friends(&merged, &mut ctx);
        emit_snap_history(&merged, &mut ctx);
        emit_call_logs(&merged, &mut ctx);
        emit_ai_chats(&merged, &mut ctx);

        // Photos / videos: surface any media file that wasn't linked to a
        // chat row (so investigators can still browse them in the gallery).
        backfill_unlinked_media(&media_filenames, &media_index, &merged, &mut ctx);

        let case = WarrantCase {
            case_id,
            provider: Provider::Snapchat,
            provider_display: "Snapchat".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.target_account.clone(),
            date_range: ctx.date_range.clone(),
            generated_at_source: None,
            media_root: Some(media_extract_dir.to_string_lossy().into_owned()),
        };

        Ok(ParsedReturn {
            case,
            items: ctx.items,
            default_buckets: self.default_buckets(),
        })
    }

    fn default_buckets(&self) -> Vec<BucketTemplate> {
        vec![
            BucketTemplate {
                name: "CSAM".into(),
                color: "#ef4444".into(),
                description: Some("Child sexual abuse material".into()),
            },
            BucketTemplate {
                name: "Snaps of Interest".into(),
                color: "#FFFC00".into(),
                description: Some("Chat snaps relevant to the investigation".into()),
            },
            BucketTemplate {
                name: "Memories".into(),
                color: "#a78bfa".into(),
                description: None,
            },
            BucketTemplate {
                name: "Contacts of Interest".into(),
                color: "#8b5cf6".into(),
                description: None,
            },
            BucketTemplate {
                name: "Unrelated".into(),
                color: "#6b7280".into(),
                description: None,
            },
            BucketTemplate {
                name: "Needs Follow-Up".into(),
                color: "#f59e0b".into(),
                description: None,
            },
        ]
    }
}

// ─── Internal types ─────────────────────────────────────────────────────

/// Raw on-disk view of a single Snapchat part folder.  Media has already
/// been written to the case media dir; we keep relative filenames here so
/// downstream code can build URLs / hyperlinks.
struct RawPart {
    folder: String,
    /// basename (lowercase) → file text.  Keys like `conversations.csv`.
    csvs: HashMap<String, String>,
    /// basenames of media files written to the case media dir.
    media_files: Vec<String>,
}

#[derive(Default)]
struct ParsedPart {
    header: Option<HeaderInfo>,
    conversations: Vec<HashMap<String, String>>,
    geo: Vec<HashMap<String, String>>,
    memories: Vec<HashMap<String, String>>,
    device_ads: Vec<HashMap<String, String>>,
    subscriber_info: Option<HashMap<String, String>>,
    login_history: Vec<HashMap<String, String>>,
    friends: Vec<HashMap<String, String>>,
    snap_history: Vec<HashMap<String, String>>,
    ai_chats: Vec<HashMap<String, String>>,
    call_logs: Vec<HashMap<String, String>>,
    /// Per-conversation metadata parsed from `conversation_list.csv`
    /// (introduced in modern Snapchat productions), keyed by lowercased id.
    conv_meta: HashMap<String, ConvMeta>,
    /// Target identity parsed from the conversation_list.csv legend line.
    cl_target_username: Option<String>,
    cl_target_user_id: Option<String>,
    other_csvs: HashMap<String, (Vec<String>, Vec<HashMap<String, String>>)>,
}

/// Conversation-level metadata from `conversation_list.csv`.  Modern Snapchat
/// productions moved `type` / `conversation_title` / group members out of
/// `conversations.csv` into this separate file; we join on conversation_id.
#[derive(Clone, Default)]
struct ConvMeta {
    ctype: String,
    title: Option<String>,
    members: Vec<String>,
    member_ids: Vec<String>,
}

#[derive(Default, Clone)]
struct HeaderInfo {
    target_username: Option<String>,
    email: Option<String>,
    user_id: Option<String>,
    date_range: Option<String>,
}

#[derive(Default)]
struct Merged {
    header: Option<HeaderInfo>,
    conversations: Vec<HashMap<String, String>>,
    geo: Vec<HashMap<String, String>>,
    memories: Vec<HashMap<String, String>>,
    device_ads: Vec<HashMap<String, String>>,
    subscriber_info: Option<HashMap<String, String>>,
    login_history: Vec<HashMap<String, String>>,
    friends: Vec<HashMap<String, String>>,
    snap_history: Vec<HashMap<String, String>>,
    ai_chats: Vec<HashMap<String, String>>,
    call_logs: Vec<HashMap<String, String>>,
    conv_meta: HashMap<String, ConvMeta>,
    cl_target_username: Option<String>,
    cl_target_user_id: Option<String>,
    #[allow(dead_code)]
    other_csvs: HashMap<String, (Vec<String>, Vec<HashMap<String, String>>)>,
}

#[derive(Default)]
struct ParseCtx {
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,
    target_account: Option<String>,
    date_range: Option<String>,
}

impl ParseCtx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct PartTokens {
    username: String,
    case_id: String,
    request_id: String,
    part_num: u32,
    date: String,
}

// ─── Collection: zip & folder → Vec<RawPart> ────────────────────────────

fn collect_parts_from_zip(
    zip_path: &Path,
    media_extract_dir: &Path,
) -> Result<Vec<RawPart>, ParseError> {
    let file = File::open(zip_path)?;
    let mut zip = ZipArchive::new(file)?;

    // Folder-agnostic: group every entry by its directory prefix.  Each
    // directory that contains at least one CSV or media file becomes a
    // RawPart.  This transparently handles:
    //   * flat productions            (everything at the zip root, dir = "")
    //   * legacy part folders         ({username}-{case}-{req}-{part}-{date}/)
    //   * arbitrarily nested layouts  (Production-XXX/username-.../...)
    // Multiple `conversations.csv` (one per part folder) are preserved
    // because each lives under a distinct directory key.
    let mut buckets: std::collections::BTreeMap<String, RawPart> = Default::default();

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let (dir, base) = match name.rsplit_once('/') {
            Some((d, b)) => (d.to_string(), b.to_string()),
            None => (String::new(), name.clone()),
        };
        let base_lower = base.to_ascii_lowercase();
        let is_csv = base_lower.ends_with(".csv");
        let is_media = is_media_basename(&base_lower);
        if !is_csv && !is_media {
            continue;
        }

        let bucket = buckets.entry(dir.clone()).or_insert_with(|| RawPart {
            folder: if dir.is_empty() {
                "production".into()
            } else {
                dir.clone()
            },
            csvs: HashMap::new(),
            media_files: Vec::new(),
        });

        if is_csv {
            let mut buf = String::new();
            if entry.read_to_string(&mut buf).is_ok() {
                // Last-writer-wins is fine within a single directory: Snapchat
                // never ships two files of the same basename in one folder.
                bucket.csvs.insert(base_lower, buf);
            }
        } else {
            let out_name = format!("{}~~{}", dir_key_tag(&dir), base);
            let out_path = media_extract_dir.join(&out_name);
            if let Ok(mut out) = File::create(&out_path) {
                if std::io::copy(&mut entry, &mut out).is_ok() {
                    bucket.media_files.push(out_name);
                }
            }
        }
    }

    Ok(buckets.into_values().collect())
}

/// Sanitize a directory prefix into a filesystem-safe, collision-resistant
/// tag used to namespace extracted media filenames.  Empty (zip root) → "root".
fn dir_key_tag(dir: &str) -> String {
    if dir.is_empty() {
        return "root".into();
    }
    let last = dir.rsplit('/').filter(|s| !s.is_empty()).next().unwrap_or(dir);
    let tag: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if tag.is_empty() {
        "part".into()
    } else {
        tag
    }
}

fn collect_parts_from_dir(
    dir: &Path,
    media_extract_dir: &Path,
) -> Result<Vec<RawPart>, ParseError> {
    // Folder-agnostic mirror of the zip collector.  Walk the tree and group
    // files by their parent directory; each directory holding a CSV or media
    // file becomes a RawPart.  When the caller points us at a single part
    // folder we also scan its parent so sibling parts are still discovered
    // (legacy behaviour), regardless of the old token-naming convention.
    let mut roots: Vec<PathBuf> = vec![dir.to_path_buf()];
    if dir.join("conversations.csv").exists() || dir.join("conversation_list.csv").exists() {
        // Caller pointed at a single part folder: add sibling part folders
        // (immediate children of the parent that themselves hold a Snapchat
        // CSV) so multi-part productions are still fully collected — without
        // recursively walking the entire parent tree.
        if let Some(parent) = dir.parent() {
            if let Ok(read) = fs::read_dir(parent) {
                for ent in read.flatten() {
                    let p = ent.path();
                    if p == dir || !p.is_dir() {
                        continue;
                    }
                    if p.join("conversations.csv").exists()
                        || p.join("conversation_list.csv").exists()
                    {
                        roots.push(p);
                    }
                }
            }
        }
    }

    let mut by_dir: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> = Default::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    for root in &roots {
        collect_files_grouped(root, 0, 6, &mut by_dir, &mut visited);
    }

    let mut parts: Vec<RawPart> = Vec::new();
    for (parent, files) in by_dir {
        let folder = parent
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "production".into());

        let mut csvs: HashMap<String, String> = HashMap::new();
        let mut media_files: Vec<String> = Vec::new();

        for p in files {
            let basename = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let lower_base = basename.to_lowercase();
            if lower_base.ends_with(".csv") {
                if let Ok(text) = fs::read_to_string(&p) {
                    csvs.insert(lower_base.clone(), text);
                }
            } else if is_media_basename(&lower_base) {
                let out_name = format!("{}~~{}", dir_key_tag(&folder), basename);
                let out_path = media_extract_dir.join(&out_name);
                if let Ok(mut src) = File::open(&p) {
                    if let Ok(mut dst) = File::create(&out_path) {
                        if std::io::copy(&mut src, &mut dst).is_ok() {
                            media_files.push(out_name);
                        }
                    }
                }
            }
        }

        if !csvs.is_empty() || !media_files.is_empty() {
            parts.push(RawPart {
                folder,
                csvs,
                media_files,
            });
        }
    }

    Ok(parts)
}

/// Recursively walk `dir`, grouping regular files under their parent
/// directory.  `visited` tracks directories already processed so overlapping
/// roots (a part folder and its parent) don't double-count.
fn collect_files_grouped(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    by_dir: &mut std::collections::BTreeMap<PathBuf, Vec<PathBuf>>,
    visited: &mut HashSet<PathBuf>,
) {
    if depth > max_depth {
        return;
    }
    let key = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(key) {
        return;
    }
    if let Ok(read) = fs::read_dir(dir) {
        for ent in read.flatten() {
            let p = ent.path();
            if p.is_file() {
                by_dir.entry(dir.to_path_buf()).or_default().push(p);
            } else if p.is_dir() {
                collect_files_grouped(&p, depth + 1, max_depth, by_dir, visited);
            }
        }
    }
}

fn dir_has_snapchat_format(dir: &Path) -> bool {
    let check_conv_preamble = |p: &Path| -> bool {
        let mut buf = vec![0u8; 4096];
        if let Ok(mut f) = File::open(p) {
            let n = f.read(&mut buf).unwrap_or(0);
            let s = String::from_utf8_lossy(&buf[..n]);
            return head_looks_snapchat(&s);
        }
        false
    };

    // Folder-agnostic: walk up to 4 levels and accept on the first
    // `conversation_list.csv` (Snapchat-specific) or a `conversations.csv`
    // whose head carries Snapchat column markers.  Also accept the legacy
    // part-folder naming convention on any directory name.
    let mut found = false;
    walk_check(dir, 0, 4, &mut |p| {
        if found {
            return;
        }
        let base = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if base == "conversation_list.csv" {
            found = true;
        } else if base == "conversations.csv" && check_conv_preamble(p) {
            found = true;
        }
    });
    if found {
        return true;
    }

    // Legacy part-folder naming anywhere in the tree.
    let mut part_like = false;
    walk_check_dirs(dir, 0, 4, &mut |p| {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if extract_part_tokens(name).is_some() {
                part_like = true;
            }
        }
    });
    part_like
}

/// Snapchat CSV head signature: identity markers from the legend preamble OR
/// the distinctive conversations.csv column header.
fn head_looks_snapchat(s: &str) -> bool {
    s.contains("Target username")
        || s.contains("User ID")
        || s.contains("conversation_id")
        || (s.contains("content_type") && s.contains("message_type"))
}

fn walk_check_dirs(dir: &Path, depth: usize, max_depth: usize, cb: &mut impl FnMut(&Path)) {
    if depth > max_depth {
        return;
    }
    if let Ok(read) = fs::read_dir(dir) {
        for ent in read.flatten() {
            let p = ent.path();
            if p.is_dir() {
                cb(&p);
                walk_check_dirs(&p, depth + 1, max_depth, cb);
            }
        }
    }
}

fn walk_check(dir: &Path, depth: usize, max_depth: usize, cb: &mut impl FnMut(&Path)) {
    if depth > max_depth {
        return;
    }
    if let Ok(read) = fs::read_dir(dir) {
        for ent in read.flatten() {
            let p = ent.path();
            if p.is_file() {
                cb(&p);
            } else if p.is_dir() {
                walk_check(&p, depth + 1, max_depth, cb);
            }
        }
    }
}

// ─── conversation_list.csv (modern productions) ─────────────────────────

/// Parse Snapchat's `conversation_list.csv`.  The file has one or more blocks;
/// each block begins with a header row starting `conversation_id,` (containing
/// `type`), optionally preceded by a legend line and the target-identity line.
/// Data rows are recognised by a UUID in the first column.  Returns the
/// per-conversation metadata plus the target username / user id if present.
fn parse_conversation_list(
    text: &str,
) -> (HashMap<String, ConvMeta>, Option<String>, Option<String>) {
    let mut meta: HashMap<String, ConvMeta> = HashMap::new();
    let mut target_user: Option<String> = None;
    let mut target_uid: Option<String> = None;

    if text.trim().is_empty() {
        return (meta, target_user, target_uid);
    }

    let lines: Vec<&str> = text.lines().collect();
    if let Some(first) = lines.first() {
        target_user = extract_quoted_after(first, "Target username");
        target_uid = extract_quoted_after(first, "User ID");
    }

    let mut i = 0usize;
    while i < lines.len() {
        let st = lines[i].trim();
        if !(st.starts_with("conversation_id,") && st.contains("type")) {
            i += 1;
            continue;
        }
        // Header row.
        let header: Vec<String> = parse_csv(lines[i])
            .into_iter()
            .next()
            .unwrap_or_default()
            .iter()
            .map(|s| s.trim().to_string())
            .collect();
        i += 1;

        while i < lines.len() {
            let raw = lines[i];
            let s = raw.trim();
            if s.is_empty() {
                i += 1;
                continue;
            }
            if s.starts_with("---") || s.starts_with("===") {
                break;
            }
            if s.starts_with("conversation_id,") && s.contains("type") {
                break; // next block's header
            }
            if s.starts_with('"') && s.contains("Legend") {
                i += 1;
                continue;
            }

            let row = parse_csv(raw).into_iter().next().unwrap_or_default();
            let cid = cell(&header, &row, "conversation_id");
            if !is_uuid(&cid) {
                i += 1;
                continue;
            }

            let m = ConvMeta {
                ctype: cell(&header, &row, "type"),
                title: {
                    let t = cell(&header, &row, "conversation_title");
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                },
                members: split_semi(&cell(&header, &row, "group_member_usernames")),
                member_ids: split_semi(&cell(&header, &row, "group_member_user_ids")),
            };

            let key = cid.to_lowercase();
            match meta.get(&key) {
                Some(prev) if !conv_meta_incoming_is_richer(prev, &m) => {}
                _ => {
                    meta.insert(key, m);
                }
            }
            i += 1;
        }
    }

    (meta, target_user, target_uid)
}

/// Prefer the conversation_list row with more real members / detail so nested
/// zips shipping sparse duplicate rows don't overwrite good metadata.
fn conv_meta_incoming_is_richer(existing: &ConvMeta, incoming: &ConvMeta) -> bool {
    let count = |m: &ConvMeta| m.members.iter().filter(|s| !s.trim().is_empty()).count();
    let ic = count(incoming);
    let ec = count(existing);
    if ic != ec {
        return ic > ec;
    }
    let detail = |m: &ConvMeta| (m.title.is_some() as usize) + m.member_ids.len();
    detail(incoming) > detail(existing)
}

/// Fetch a named column's trimmed value from a parsed CSV row.
fn cell(header: &[String], row: &[String], name: &str) -> String {
    header
        .iter()
        .position(|h| h == name)
        .and_then(|idx| row.get(idx))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

/// Split a semicolon-separated list, trimming and dropping empties.
fn split_semi(s: &str) -> Vec<String> {
    s.split(';')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Case-insensitive canonical-UUID check (8-4-4-4-12 hex).
fn is_uuid(s: &str) -> bool {
    let s = s.trim();
    if s.len() != 36 {
        return false;
    }
    for (i, c) in s.chars().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != '-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Extract a quoted value following `key`, tolerating both Snapchat's doubled
/// (`""value""`) and single (`"value"`) quoting styles.
fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let idx = line.find(key)?;
    let after = &line[idx + key.len()..];
    if let Some(s) = between(after, "\"\"", "\"\"") {
        if !s.trim().is_empty() {
            return Some(s.trim().to_string());
        }
    }
    if let Some(s) = between(after, "\"", "\"") {
        if !s.trim().is_empty() {
            return Some(s.trim().to_string());
        }
    }
    None
}

fn between(s: &str, open: &str, close: &str) -> Option<String> {
    let a = s.find(open)? + open.len();
    let rest = &s[a..];
    let b = rest.find(close)?;
    Some(rest[..b].to_string())
}

// ─── CSV Parsing ────────────────────────────────────────────────────────

/// Parse a Snapchat CSV: skip the legend preamble (ends with a line of `=`),
/// take the next non-empty row as the column header, then parse remaining
/// rows into HashMaps keyed by column name.
fn parse_snapchat_csv(text: &str) -> (Option<HeaderInfo>, Vec<String>, Vec<HashMap<String, String>>) {
    let rows = parse_csv(text);
    if rows.is_empty() {
        return (None, Vec::new(), Vec::new());
    }

    // Find the LAST line of `=` separator.
    let mut sep_idx: i32 = -1;
    for (i, row) in rows.iter().enumerate() {
        let first = row.first().map(|s| s.trim()).unwrap_or("");
        if !first.is_empty() && first.chars().all(|c| c == '=') {
            sep_idx = i as i32;
        }
    }

    // Build the preamble text so we can sniff the header info even when
    // the legend is wrapped in quoted lines.
    let preamble_text = if sep_idx >= 0 {
        let mut s = String::new();
        for row in &rows[..sep_idx as usize] {
            s.push_str(&row.join(","));
            s.push('\n');
        }
        s
    } else {
        text.chars().take(2000).collect::<String>()
    };

    let header = extract_header_info(&preamble_text);

    // Find the column-header row: first non-empty row after the separator.
    let mut header_idx: i32 = -1;
    let start = if sep_idx >= 0 { (sep_idx + 1) as usize } else { 0 };
    for i in start..rows.len() {
        let any_nonempty = rows[i].iter().any(|c| !c.trim().is_empty());
        if any_nonempty {
            header_idx = i as i32;
            break;
        }
    }

    if header_idx < 0 {
        return (header, Vec::new(), Vec::new());
    }

    let headers: Vec<String> = rows[header_idx as usize]
        .iter()
        .map(|s| s.trim().to_string())
        .collect();

    let mut data: Vec<HashMap<String, String>> = Vec::new();
    for row in &rows[(header_idx as usize + 1)..] {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let mut map: HashMap<String, String> = HashMap::with_capacity(headers.len());
        for (j, col) in headers.iter().enumerate() {
            let v = row.get(j).cloned().unwrap_or_default();
            map.insert(col.clone(), v);
        }
        data.push(map);
    }

    (header, headers, data)
}

/// Pull `Target username`, `email`, `User ID`, `Date range` out of the
/// CSV legend preamble.
fn extract_header_info(preamble: &str) -> Option<HeaderInfo> {
    let mut info = HeaderInfo::default();

    // "Target username "icecube086" and email "isaacm2326@gmail.com" is
    //  associated with User ID "d9295f18-...""
    if let Some(cap) = regex_capture(preamble, r#"Target username\s+"([^"]+)""#) {
        info.target_username = Some(cap);
    }
    if let Some(cap) = regex_capture(preamble, r#"email\s+"([^"]+)""#) {
        info.email = Some(cap);
    }
    if let Some(cap) = regex_capture(preamble, r#"User ID\s+"([^"]+)""#) {
        info.user_id = Some(cap);
    }
    if let Some(cap) = regex_capture(preamble, r"Date range searched:?\s*(.+)") {
        info.date_range = Some(cap.trim().to_string());
    }

    if info.target_username.is_some()
        || info.email.is_some()
        || info.user_id.is_some()
        || info.date_range.is_some()
    {
        Some(info)
    } else {
        None
    }
}

/// Tiny regex-capture helper using `regex_lite`-style hand-rolled patterns.
/// We only need three fixed shapes, so we hand-roll instead of adding a
/// `regex` dependency.
fn regex_capture(text: &str, pat: &str) -> Option<String> {
    // The hand-rolled patterns here all have the shape:
    //   prefix "([^"]+)"     → quoted-string capture
    //   prefix (.+)          → rest-of-line capture
    if let Some(prefix) = pat.strip_suffix(r#""([^"]+)""#) {
        // Find the literal prefix (escaping a few regex metas to literals).
        let lit_prefix = unescape_pat(prefix);
        let idx = text.find(&lit_prefix)?;
        let after = &text[idx + lit_prefix.len()..];
        let end = after.find('"')?;
        return Some(after[..end].to_string());
    }
    if let Some(prefix) = pat.strip_suffix("(.+)") {
        let lit_prefix = unescape_pat(prefix);
        let idx = text.find(&lit_prefix)?;
        let after = &text[idx + lit_prefix.len()..];
        let end = after.find('\n').unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    None
}

fn unescape_pat(pat: &str) -> String {
    // We only need to unescape `\s+` → whitespace tolerance hack: replace
    // with a single space and accept downstream `.find` mismatches.  For
    // robustness, normalise text whitespace where the prefix is matched.
    pat.replace(r"\s+", " ").replace(":?", "").replace(r"\b", "")
}

/// Tolerant state-machine CSV parser.  Handles multi-line quoted fields
/// and `""` escapes within quoted strings.  Matches VIPER's behaviour.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        if in_quotes {
            if ch == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] == '"' {
                    field.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
                i += 1;
                continue;
            }
            field.push(ch);
            i += 1;
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                i += 1;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                i += 1;
            }
            '\r' => {
                if i + 1 < bytes.len() && bytes[i + 1] == '\n' {
                    i += 1;
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                i += 1;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                i += 1;
            }
            _ => {
                field.push(ch);
                i += 1;
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

// ─── Per-part dispatcher ────────────────────────────────────────────────

fn parse_one_part(part: &RawPart) -> ParsedPart {
    let mut out = ParsedPart::default();

    for (basename, text) in &part.csvs {
        // conversation_list.csv has a bespoke two-block layout (no `====`
        // preamble) — parse it with its own reader, not parse_snapchat_csv.
        if basename == "conversation_list.csv" {
            let (cm, tgt_user, tgt_uid) = parse_conversation_list(text);
            for (k, v) in cm {
                match out.conv_meta.get(&k) {
                    Some(prev) if !conv_meta_incoming_is_richer(prev, &v) => {}
                    _ => {
                        out.conv_meta.insert(k, v);
                    }
                }
            }
            if out.cl_target_username.is_none() {
                out.cl_target_username = tgt_user;
            }
            if out.cl_target_user_id.is_none() {
                out.cl_target_user_id = tgt_uid;
            }
            continue;
        }

        let (hdr, headers, rows) = parse_snapchat_csv(text);
        if out.header.is_none() {
            if let Some(h) = hdr {
                out.header = Some(h);
            }
        }
        match basename.as_str() {
            "conversations.csv" => out.conversations = rows,
            "geo_locations.csv" => out.geo = rows,
            "memories.csv" => out.memories = rows,
            "device_advertising_id.csv" => out.device_ads = rows,
            "subscriber_info.csv" => {
                // subscriber_info is single-row; take the first.
                out.subscriber_info = rows.into_iter().next();
            }
            "login_history.csv" => out.login_history = rows,
            "friends.csv" => out.friends = rows,
            "snap_history.csv" => out.snap_history = rows,
            "ai_conversations.csv" => out.ai_chats = rows,
            "call_logs.csv" => out.call_logs = rows,
            other => {
                if !KNOWN_CSVS.contains(&other) {
                    out.other_csvs.insert(other.to_string(), (headers, rows));
                }
            }
        }
    }

    out
}

// ─── Cross-part merge + dedupe ──────────────────────────────────────────

fn merge_parts(parts: &[ParsedPart]) -> Merged {
    let mut m = Merged::default();
    for p in parts {
        if m.header.is_none() && p.header.is_some() {
            m.header = p.header.clone();
        }
        m.conversations.extend(p.conversations.iter().cloned());
        m.geo.extend(p.geo.iter().cloned());
        m.memories.extend(p.memories.iter().cloned());
        m.device_ads.extend(p.device_ads.iter().cloned());
        if m.subscriber_info.is_none() && p.subscriber_info.is_some() {
            m.subscriber_info = p.subscriber_info.clone();
        }
        m.login_history.extend(p.login_history.iter().cloned());
        m.friends.extend(p.friends.iter().cloned());
        m.snap_history.extend(p.snap_history.iter().cloned());
        m.ai_chats.extend(p.ai_chats.iter().cloned());
        m.call_logs.extend(p.call_logs.iter().cloned());
        for (k, v) in &p.other_csvs {
            let entry = m
                .other_csvs
                .entry(k.clone())
                .or_insert_with(|| (v.0.clone(), Vec::new()));
            entry.1.extend(v.1.iter().cloned());
        }
        // Merge conversation_list metadata, preferring the richer row.
        for (k, v) in &p.conv_meta {
            match m.conv_meta.get(k) {
                Some(prev) if !conv_meta_incoming_is_richer(prev, v) => {}
                _ => {
                    m.conv_meta.insert(k.clone(), v.clone());
                }
            }
        }
        if m.cl_target_username.is_none() {
            m.cl_target_username = p.cl_target_username.clone();
        }
        if m.cl_target_user_id.is_none() {
            m.cl_target_user_id = p.cl_target_user_id.clone();
        }
    }

    // Backfill target identity from conversation_list.csv when the
    // conversations.csv legend didn't carry it (modern productions).
    if m.cl_target_username.is_some() || m.cl_target_user_id.is_some() {
        let h = m.header.get_or_insert_with(HeaderInfo::default);
        if h.target_username.is_none() {
            h.target_username = m.cl_target_username.clone();
        }
        if h.user_id.is_none() {
            h.user_id = m.cl_target_user_id.clone();
        }
    }

    // Dedupe conversations by (conv_id, msg_id, timestamp, sender).
    let mut seen: HashSet<String> = HashSet::new();
    m.conversations.retain(|r| {
        let key = format!(
            "{}::{}::{}::{}",
            r.get("conversation_id").map(|s| s.as_str()).unwrap_or(""),
            r.get("message_id").map(|s| s.as_str()).unwrap_or(""),
            r.get("timestamp").map(|s| s.as_str()).unwrap_or(""),
            r.get("sender_user_id").map(|s| s.as_str()).unwrap_or(""),
        );
        seen.insert(key)
    });

    // Sort conversations + geo by timestamp ascending.
    m.conversations
        .sort_by_key(|r| parse_snap_ts(r.get("timestamp").map(|s| s.as_str()).unwrap_or("")));
    m.geo
        .sort_by_key(|r| parse_snap_ts(r.get("timestamp").map(|s| s.as_str()).unwrap_or("")));

    m
}

// ─── Section emitters ───────────────────────────────────────────────────

fn emit_bio(merged: &Merged, ctx: &mut ParseCtx) {
    let mut fields: Vec<Value> = Vec::new();
    let push = |fields: &mut Vec<Value>, label: &str, value: Option<&str>| {
        if let Some(v) = value.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            fields.push(json!({ "label": label, "value": v }));
        }
    };

    let hdr = merged.header.as_ref();
    push(
        &mut fields,
        "Target Username",
        hdr.and_then(|h| h.target_username.as_deref()),
    );
    push(&mut fields, "Email", hdr.and_then(|h| h.email.as_deref()));
    push(&mut fields, "User ID", hdr.and_then(|h| h.user_id.as_deref()));
    push(
        &mut fields,
        "Date Range",
        hdr.and_then(|h| h.date_range.as_deref()),
    );

    // Pull additional fields from subscriber_info.csv if available.
    if let Some(sub) = &merged.subscriber_info {
        for (k, v) in sub {
            // Skip empty values.
            if v.trim().is_empty() {
                continue;
            }
            // Pretty-case the label.
            let label = prettify_label(k);
            // Don't duplicate things already in the legend.
            let lk = label.to_lowercase();
            if fields.iter().any(|f| {
                f.get("label")
                    .and_then(|l| l.as_str())
                    .map(|s| s.to_lowercase() == lk)
                    .unwrap_or(false)
            }) {
                continue;
            }
            fields.push(json!({ "label": label, "value": v.trim() }));
        }
    }

    // Counts derived from CSVs the user will care about at a glance.
    if !merged.conversations.is_empty() {
        fields.push(json!({
            "label": "Messages",
            "value": merged.conversations.len().to_string(),
        }));
    }
    if !merged.memories.is_empty() {
        fields.push(json!({
            "label": "Memories",
            "value": merged.memories.len().to_string(),
        }));
    }
    if !merged.geo.is_empty() {
        fields.push(json!({
            "label": "Location Pings",
            "value": merged.geo.len().to_string(),
        }));
    }
    if !merged.friends.is_empty() {
        fields.push(json!({
            "label": "Friends",
            "value": merged.friends.len().to_string(),
        }));
    }
    if !merged.device_ads.is_empty() {
        fields.push(json!({
            "label": "Device IDs",
            "value": merged.device_ads.len().to_string(),
        }));
    }

    if fields.is_empty() {
        return;
    }

    let summary_bits: Vec<String> = ["Target Username", "Email", "User ID"]
        .iter()
        .filter_map(|wanted| {
            fields.iter().find_map(|f| {
                let l = f.get("label").and_then(|v| v.as_str())?;
                let v = f.get("value").and_then(|v| v.as_str())?;
                if l == *wanted {
                    Some(v.to_string())
                } else {
                    None
                }
            })
        })
        .collect();
    let summary = if summary_bits.is_empty() {
        format!("Account · {} fields", fields.len())
    } else {
        summary_bits.join(" · ")
    };

    let body_lines: Vec<String> = fields
        .iter()
        .filter_map(|f| {
            let l = f.get("label").and_then(|v| v.as_str())?;
            let v = f.get("value").and_then(|v| v.as_str())?;
            Some(format!("{}: {}", l, v))
        })
        .collect();

    let id = ctx.next_id("bio");
    ctx.items.push(WarrantItem {
        id,
        section: "bio".into(),
        section_display: "Account".into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(body_lines.join("\n")),
        summary: Some(summary),
        raw_fields: json!({
            "fields": fields,
            "source": "Snapchat warrant CSVs",
        }),
        attachments: Vec::new(),
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

fn emit_messages(
    merged: &Merged,
    media_index: &HashMap<String, String>,
    ctx: &mut ParseCtx,
) {
    let owner = ctx.target_account.clone();

    for row in &merged.conversations {
        let content_type = row.get("content_type").cloned().unwrap_or_default();
        let message_type = row.get("message_type").cloned().unwrap_or_default();
        let conv_id = row.get("conversation_id").cloned().unwrap_or_default();
        let msg_id = field(row, &["message_id"]);
        let mut title = row.get("conversation_title").cloned().unwrap_or_default();
        // Tolerate modern column aliases (sender/receiver/message/content_id).
        let sender = field(row, &["sender_username", "sender"]);
        let sender_uid = field(row, &["sender_user_id"]);
        let recipient = field(row, &["recipient_username", "receiver"]);
        let recipient_uid = field(row, &["recipient_user_id"]);
        let text = field(row, &["text", "message", "body"]);
        let media_id = field(row, &["media_id", "content_id"]);
        let is_saved = field(row, &["is_saved", "saved_by"]);
        let is_one = row.get("is_one_on_one").cloned().unwrap_or_default();
        let timestamp = row.get("timestamp").cloned().unwrap_or_default();
        let mut group_members = row.get("group_member_usernames").cloned().unwrap_or_default();
        let reactions = row.get("reactions").cloned().unwrap_or_default();

        // Join conversation_list.csv metadata (modern productions moved
        // type/title/members out of conversations.csv).
        let meta = merged.conv_meta.get(&conv_id.to_lowercase());
        if title.trim().is_empty() {
            if let Some(t) = meta.and_then(|m| m.title.clone()) {
                title = t;
            }
        }
        if group_members.trim().is_empty() {
            if let Some(m) = meta {
                if !m.members.is_empty() {
                    group_members = m.members.join(", ");
                }
            }
        }

        // Determine the conversation thread label.  For group chats use the
        // title (if any) or member list; for 1:1 use the non-owner.
        let is_group = if !is_one.trim().is_empty() {
            !matches!(is_one.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
        } else if let Some(m) = meta {
            m.ctype.eq_ignore_ascii_case("group")
        } else {
            // Unknown: default to a direct message unless members imply a group.
            meta.map(|m| m.members.len() > 2).unwrap_or(false)
        };
        let me = owner.clone().unwrap_or_default().to_lowercase();
        let thread_label: String = if is_group {
            if !title.trim().is_empty() {
                title.clone()
            } else if !group_members.trim().is_empty() {
                format!("Group: {}", truncate(&group_members, 60))
            } else {
                format!("Group {}", short_id(&conv_id))
            }
        } else if !recipient.is_empty() && recipient.to_lowercase() != me {
            recipient.clone()
        } else if !sender.is_empty() && sender.to_lowercase() != me {
            sender.clone()
        } else if let Some(other) = meta.and_then(|m| {
            m.members
                .iter()
                .find(|x| !x.trim().is_empty() && x.to_lowercase() != me)
                .cloned()
        }) {
            other
        } else if !recipient.is_empty() {
            recipient.clone()
        } else {
            format!("DM {}", short_id(&conv_id))
        };

        // Build the bubble body.  Empty text + media → "📎 photo/video".
        let linked_media = link_media(&media_id, media_index);

        let media_label = match linked_media.as_ref() {
            Some(name) => {
                let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                if is_video_ext(&ext) {
                    "🎥 video"
                } else if is_audio_ext(&ext) {
                    "🔊 audio"
                } else {
                    "🖼️ photo"
                }
            }
            None if !media_id.trim().is_empty() => match content_type.as_str() {
                "AudioSnap" => "🔊 audio snap (not in production)",
                "VoiceNote" => "🔊 voice note (not in production)",
                _ => "📎 media (not in production)",
            },
            None => "",
        };

        let body_for_display = if !text.trim().is_empty() {
            text.clone()
        } else if !media_label.is_empty() {
            format!("[{}]", media_label)
        } else if !content_type.trim().is_empty() {
            format!("[{}]", content_type)
        } else {
            String::new()
        };

        if body_for_display.is_empty() && linked_media.is_none() {
            // Skip totally empty rows (e.g. system markers with no content).
            continue;
        }

        let attachments = linked_media.iter().cloned().collect::<Vec<_>>();
        let id = ctx.next_id("msg");

        ctx.items.push(WarrantItem {
            id,
            section: "unified_messages".into(),
            section_display: "Messages".into(),
            timestamp: Some(timestamp.clone()),
            author: Some(if sender.is_empty() {
                "unknown".into()
            } else {
                sender.clone()
            }),
            recipient: Some(thread_label.clone()),
            body_text: if text.trim().is_empty() {
                None
            } else {
                Some(text.clone())
            },
            summary: Some(truncate(&body_for_display, 80)),
            raw_fields: json!({
                "contentType": content_type,
                "messageType": message_type,
                "conversationId": conv_id,
                "messageId": msg_id,
                "conversationTitle": title,
                "senderUsername": sender,
                "senderUserId": sender_uid,
                "recipientUsername": recipient,
                "recipientUserId": recipient_uid,
                "text": text,
                "mediaId": media_id,
                "linkedMedia": linked_media,
                "isSaved": is_saved,
                "isOneOnOne": is_one,
                "timestamp": timestamp,
                "groupMembers": group_members,
                "reactions": reactions,
                "thread": thread_label,
                "source": "conversations.csv",
            }),
            attachments,
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_memories(merged: &Merged, _media_index: &HashMap<String, String>, ctx: &mut ParseCtx) {
    for row in &merged.memories {
        let id_token = row.get("id").cloned().unwrap_or_default();
        let media_id = row.get("media_id").cloned().unwrap_or_default();
        let source_type = row.get("source_type").cloned().unwrap_or_default();
        let lat = row.get("latitude").cloned().unwrap_or_default();
        let lon = row.get("longitude").cloned().unwrap_or_default();
        let duration = row.get("duration").cloned().unwrap_or_default();
        let timestamp = row.get("timestamp").cloned().unwrap_or_default();
        let encrypted = row.get("encrypted").cloned().unwrap_or_default();

        let summary = format!(
            "{} memory · {}",
            if source_type.is_empty() {
                "NONE".to_string()
            } else {
                source_type.clone()
            },
            timestamp,
        );

        let id = ctx.next_id("mem");
        ctx.items.push(WarrantItem {
            id,
            section: "memories".into(),
            section_display: "Memories".into(),
            timestamp: Some(timestamp.clone()),
            author: ctx.target_account.clone(),
            recipient: None,
            body_text: Some(format!(
                "Memory {} ({}), {}",
                id_token, source_type, timestamp
            )),
            summary: Some(summary),
            raw_fields: json!({
                "id": id_token,
                "mediaId": media_id,
                "sourceType": source_type,
                "latitude": lat,
                "longitude": lon,
                "duration": duration,
                "timestamp": timestamp,
                "encrypted": encrypted,
                "source": "memories.csv",
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_geo_locations(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.geo {
        let lat_raw = row.get("latitude").cloned().unwrap_or_default();
        let lon_raw = row.get("longitude").cloned().unwrap_or_default();
        let timestamp = row.get("timestamp").cloned().unwrap_or_default();

        let lat = parse_lat_lon(&lat_raw);
        let lon = parse_lat_lon(&lon_raw);
        let accuracy = parse_accuracy(&lat_raw).or_else(|| parse_accuracy(&lon_raw));

        let summary = match (lat, lon) {
            (Some(a), Some(b)) => format!("{:.4}, {:.4} · {}", a, b, timestamp),
            _ => format!("Location · {}", timestamp),
        };

        let id = ctx.next_id("loc");
        ctx.items.push(WarrantItem {
            id,
            section: "location".into(),
            section_display: "Locations".into(),
            timestamp: Some(timestamp.clone()),
            author: ctx.target_account.clone(),
            recipient: None,
            body_text: Some(format!("{} | {}", lat_raw, lon_raw)),
            summary: Some(summary),
            raw_fields: json!({
                "latitude": lat,
                "longitude": lon,
                "accuracyMeters": accuracy,
                "latitudeRaw": lat_raw,
                "longitudeRaw": lon_raw,
                "timestamp": timestamp,
                "source": "geo_locations.csv",
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_device_ads(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.device_ads {
        let device_id = row.get("Device ID").cloned().unwrap_or_default();
        let os = row.get("OS").cloned().unwrap_or_default();
        let id_type = row.get("ID Type").cloned().unwrap_or_default();
        let hms = row.get("Is HMS?").cloned().unwrap_or_default();
        let recorded = row.get("Time Recorded").cloned().unwrap_or_default();

        let summary = format!("{} {} · {}", os, id_type, truncate(&device_id, 36));

        let id = ctx.next_id("dev");
        ctx.items.push(WarrantItem {
            id,
            section: "device_info".into(),
            section_display: "Device Info".into(),
            timestamp: Some(recorded.clone()),
            author: ctx.target_account.clone(),
            recipient: None,
            body_text: Some(format!("{} ({} {})", device_id, os, id_type)),
            summary: Some(summary),
            raw_fields: json!({
                "deviceId": device_id,
                "os": os,
                "idType": id_type,
                "isHms": hms,
                "timeRecorded": recorded,
                "source": "device_advertising_id.csv",
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_login_history(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.login_history {
        let timestamp = first_present(row, &["Time", "timestamp", "Login Time"]);
        let ip = first_present(row, &["IP", "IP Address", "ip"]);
        let success = first_present(row, &["Status", "Success", "Result"]);

        let summary = format!("{} · {}", ip.clone().unwrap_or_default(), timestamp.clone().unwrap_or_default());

        let id = ctx.next_id("login");
        ctx.items.push(WarrantItem {
            id,
            section: "login_history".into(),
            section_display: "Login History".into(),
            timestamp: timestamp.clone(),
            author: ctx.target_account.clone(),
            recipient: None,
            body_text: Some(format!(
                "IP {} {}",
                ip.clone().unwrap_or_default(),
                success.unwrap_or_default()
            )),
            summary: Some(truncate(&summary, 80)),
            raw_fields: serde_json::to_value(row).unwrap_or(Value::Null),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_friends(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.friends {
        let username = first_present(row, &["Username", "username", "friend_username"]);
        let user_id = first_present(row, &["User ID", "user_id"]);
        let added = first_present(row, &["Added", "Added Time", "timestamp"]);

        let summary = match (&username, &user_id) {
            (Some(u), _) => u.clone(),
            (None, Some(uid)) => short_id(uid),
            _ => "friend".into(),
        };

        let id = ctx.next_id("friend");
        ctx.items.push(WarrantItem {
            id,
            section: "friends".into(),
            section_display: "Friends".into(),
            timestamp: added.clone(),
            author: ctx.target_account.clone(),
            recipient: username.clone(),
            body_text: Some(format!(
                "{} ({})",
                username.clone().unwrap_or_default(),
                user_id.clone().unwrap_or_default()
            )),
            summary: Some(summary),
            raw_fields: serde_json::to_value(row).unwrap_or(Value::Null),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_snap_history(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.snap_history {
        let timestamp = first_present(row, &["timestamp", "Time", "Sent Time"]);
        let summary = format!("snap · {}", timestamp.clone().unwrap_or_default());
        let id = ctx.next_id("snap");
        ctx.items.push(WarrantItem {
            id,
            section: "snap_history".into(),
            section_display: "Snap History".into(),
            timestamp,
            author: ctx.target_account.clone(),
            recipient: None,
            body_text: None,
            summary: Some(summary),
            raw_fields: serde_json::to_value(row).unwrap_or(Value::Null),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_call_logs(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.call_logs {
        let timestamp = first_present(row, &["timestamp", "Time", "start_time"]);
        let other = first_present(row, &["recipient_username", "Username", "other_username"]);
        let duration = first_present(row, &["duration", "Duration"]);
        let direction = first_present(row, &["direction", "Direction", "type"]);

        let summary = format!(
            "{} call · {} · {}",
            direction.clone().unwrap_or_else(|| "?".into()),
            other.clone().unwrap_or_default(),
            timestamp.clone().unwrap_or_default(),
        );

        let id = ctx.next_id("call");
        ctx.items.push(WarrantItem {
            id,
            section: "call_logs".into(),
            section_display: "Call Logs".into(),
            timestamp,
            author: ctx.target_account.clone(),
            recipient: other,
            body_text: Some(format!(
                "{} ({})",
                direction.unwrap_or_default(),
                duration.unwrap_or_default()
            )),
            summary: Some(truncate(&summary, 80)),
            raw_fields: serde_json::to_value(row).unwrap_or(Value::Null),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_ai_chats(merged: &Merged, ctx: &mut ParseCtx) {
    for row in &merged.ai_chats {
        let timestamp = first_present(row, &["timestamp", "Time", "sent_time"]);
        let text = first_present(row, &["text", "message", "content"]).unwrap_or_default();
        let direction = first_present(row, &["direction", "sender", "from"]);
        let summary = format!(
            "{} · {}",
            direction.clone().unwrap_or_else(|| "MyAI".into()),
            truncate(&text, 60),
        );

        let id = ctx.next_id("aichat");
        ctx.items.push(WarrantItem {
            id,
            section: "ai_conversations".into(),
            section_display: "MyAI Chat".into(),
            timestamp,
            author: direction,
            recipient: Some("MyAI".into()),
            body_text: if text.trim().is_empty() { None } else { Some(text) },
            summary: Some(truncate(&summary, 80)),
            raw_fields: serde_json::to_value(row).unwrap_or(Value::Null),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn backfill_unlinked_media(
    media_filenames: &[String],
    media_index: &HashMap<String, String>,
    merged: &Merged,
    ctx: &mut ParseCtx,
) {
    // Collect filenames already referenced by a chat row.
    let linked: HashSet<String> = merged
        .conversations
        .iter()
        .filter_map(|r| {
            let m = r.get("media_id")?;
            link_media(m, media_index)
        })
        .collect();

    for filename in media_filenames {
        if linked.contains(filename) {
            continue;
        }
        // Parse the embedded filename to surface sender/recipient/ts.
        let meta = parse_media_filename(filename);
        let ext = filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_video = is_video_ext(&ext);
        let section = if is_video { "videos" } else { "photos" };
        let section_display = if is_video { "Videos" } else { "Photos" };

        let summary = match (meta.sender.as_deref(), meta.recipient.as_deref()) {
            (Some(s), Some(r)) => format!("{} → {} · {}", s, r, meta.timestamp.clone().unwrap_or_default()),
            _ => filename.clone(),
        };

        let id = ctx.next_id("photo");
        ctx.items.push(WarrantItem {
            id,
            section: section.into(),
            section_display: section_display.into(),
            timestamp: meta.timestamp.clone(),
            author: meta.sender.clone(),
            recipient: meta.recipient.clone(),
            body_text: Some(filename.clone()),
            summary: Some(summary),
            raw_fields: json!({
                "filename": filename,
                "sender": meta.sender,
                "recipient": meta.recipient,
                "timestamp": meta.timestamp,
                "savedFlag": meta.saved_flag,
                "mediaToken": meta.media_id_token,
                "source": "chat~media_v4~",
            }),
            attachments: vec![filename.clone()],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── Media filename parsing & linking ───────────────────────────────────

#[derive(Default, Clone, Debug)]
struct MediaMeta {
    sender: Option<String>,
    recipient: Option<String>,
    timestamp: Option<String>,
    saved_flag: Option<String>,
    media_id_token: Option<String>,
}

/// Pattern: `{partFolder}~~chat~media_v4~{ts}~{sender}~{recipient}~{saved|unsaved}~b~{token}~v4.{ext}`
fn parse_media_filename(name: &str) -> MediaMeta {
    // Strip our "{partFolder}~~" prefix if present.
    let stripped = match name.split_once("~~") {
        Some((_, rest)) => rest.to_string(),
        None => name.to_string(),
    };
    let mut meta = MediaMeta::default();
    let parts: Vec<&str> = stripped.split('~').collect();
    // chat / media_v4 / ts / sender / recipient / saved / b / token / v4.ext
    if parts.len() >= 9 && parts[0] == "chat" {
        meta.timestamp = Some(parts[2].to_string());
        if !parts[3].is_empty() {
            meta.sender = Some(parts[3].to_string());
        }
        if !parts[4].is_empty() {
            meta.recipient = Some(parts[4].to_string());
        }
        meta.saved_flag = Some(parts[5].to_string());
        if parts[6] == "b" && !parts[7].is_empty() {
            meta.media_id_token = Some(parts[7].to_string());
        }
    } else if parts.len() >= 4 && parts[0] == "memories" {
        // memories~~ts~owner~~~main-UUID~V4.jpg
        meta.timestamp = Some(parts[2].to_string());
        if !parts[3].is_empty() {
            meta.sender = Some(parts[3].to_string());
        }
    }
    meta
}

fn build_media_index(filenames: &[String]) -> HashMap<String, String> {
    let mut idx: HashMap<String, String> = HashMap::new();
    for f in filenames {
        let m = parse_media_filename(f);
        if let Some(tok) = m.media_id_token {
            idx.insert(tok.clone(), f.clone());
            if tok.len() > 24 {
                idx.insert(tok[tok.len() - 24..].to_string(), f.clone());
            }
        }
        // Also index every long token in the filename so we can match modern
        // media_id values (UUIDs, hex, base64) that don't follow the legacy
        // `chat~...~b~{token}~v4.ext` shape.  Don't clobber precise entries.
        let base = f.rsplit("~~").next().unwrap_or(f);
        for tok in media_tokens(base) {
            idx.entry(tok).or_insert_with(|| f.clone());
        }
    }
    idx
}

fn link_media(media_id: &str, idx: &HashMap<String, String>) -> Option<String> {
    let trimmed = media_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let token = trimmed.strip_prefix("b~").unwrap_or(trimmed);
    if let Some(name) = idx.get(token) {
        return Some(name.clone());
    }
    if token.len() > 24 {
        let suffix = &token[token.len() - 24..];
        if let Some(name) = idx.get(suffix) {
            return Some(name.clone());
        }
    }
    // Token-based fallback: media_id cells can pack several ids joined by `~`.
    for tok in media_tokens(media_id) {
        if let Some(name) = idx.get(&tok) {
            return Some(name.clone());
        }
    }
    None
}

/// Extract candidate matching tokens (UUIDs, hex, base64-ish runs) from a
/// media_id cell or a media filename.  Delimiters are anything that isn't a
/// letter, digit, underscore or hyphen so UUIDs stay intact.
fn media_tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|t| t.len() >= 16)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Return the first non-empty trimmed value among `keys` for a CSV row.
fn field(row: &HashMap<String, String>, keys: &[&str]) -> String {
    for k in keys {
        if let Some(v) = row.get(*k) {
            if !v.trim().is_empty() {
                return v.clone();
            }
        }
    }
    String::new()
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn extract_part_tokens(folder: &str) -> Option<PartTokens> {
    // {username}-{caseId}-{requestId}-{partNum}-{date}
    // username may contain underscores/dots; caseId/requestId/partNum/date are numeric.
    // We anchor on the trailing four numeric tokens.
    let segs: Vec<&str> = folder.split('-').collect();
    if segs.len() < 5 {
        return None;
    }
    // The last four segments must all be numeric and the date must be 6+ digits.
    let n = segs.len();
    let date = segs[n - 1];
    let part_num = segs[n - 2];
    let request_id = segs[n - 3];
    let case_id = segs[n - 4];
    if date.len() < 6 || !date.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !part_num.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !request_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !case_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let username = segs[..n - 4].join("-");
    if username.is_empty() {
        return None;
    }
    Some(PartTokens {
        username,
        case_id: case_id.to_string(),
        request_id: request_id.to_string(),
        part_num: part_num.parse().unwrap_or(0),
        date: date.to_string(),
    })
}

fn parse_lat_lon(cell: &str) -> Option<f64> {
    if cell.is_empty() {
        return None;
    }
    // "34.145 ± 39.66 meters" → 34.145
    let mut buf = String::new();
    let mut started = false;
    for ch in cell.chars() {
        if ch == '-' && !started {
            buf.push(ch);
            started = true;
        } else if ch.is_ascii_digit() || ch == '.' {
            buf.push(ch);
            started = true;
        } else if started {
            break;
        }
    }
    buf.parse::<f64>().ok().filter(|v| v.is_finite())
}

fn parse_accuracy(cell: &str) -> Option<f64> {
    // "34.145 ± 39.66 meters" → 39.66
    let pos = cell.find('±')?;
    let rest = &cell[pos + '±'.len_utf8()..];
    let mut buf = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            buf.push(ch);
        } else if !buf.is_empty() {
            break;
        }
    }
    buf.parse::<f64>().ok().filter(|v| v.is_finite())
}

/// Parse Snapchat timestamps like `Tue Dec 13 15:46:22 UTC 2022`.
fn parse_snap_ts(ts: &str) -> i64 {
    if ts.is_empty() {
        return 0;
    }
    // chrono's strptime equivalent: parse the format Snapchat uses.
    // The format is `%a %b %e %H:%M:%S %Z %Y`.
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%a %b %e %H:%M:%S UTC %Y") {
        return dt.and_utc().timestamp();
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%a %b %d %H:%M:%S UTC %Y") {
        return dt.and_utc().timestamp();
    }
    0
}

fn is_media_basename(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    IMAGE_EXTS
        .iter()
        .chain(VIDEO_EXTS.iter())
        .chain(AUDIO_EXTS.iter())
        .any(|ext| l.ends_with(ext))
}
fn is_video_ext(ext: &str) -> bool {
    let with_dot = if ext.starts_with('.') {
        ext.to_string()
    } else {
        format!(".{}", ext)
    };
    VIDEO_EXTS.iter().any(|e| with_dot.eq_ignore_ascii_case(e))
}
fn is_audio_ext(ext: &str) -> bool {
    let with_dot = if ext.starts_with('.') {
        ext.to_string()
    } else {
        format!(".{}", ext)
    };
    AUDIO_EXTS.iter().any(|e| with_dot.eq_ignore_ascii_case(e))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn short_id(s: &str) -> String {
    let take = s.chars().take(8).collect::<String>();
    take
}

fn first_present(row: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = row.get(*k) {
            if !v.trim().is_empty() {
                return Some(v.clone());
            }
        }
    }
    None
}

fn prettify_label(k: &str) -> String {
    // "device_advertising_id" → "Device Advertising ID"
    let mut s = String::new();
    let mut cap_next = true;
    for ch in k.chars() {
        if ch == '_' || ch == '-' {
            s.push(' ');
            cap_next = true;
        } else if cap_next {
            s.extend(ch.to_uppercase());
            cap_next = false;
        } else {
            s.push(ch);
        }
    }
    s
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zip() -> Option<PathBuf> {
        let p = PathBuf::from(
            r"C:\Users\JUSTI\Desktop\New VIPER Evidence Support Files\Production-235112678-2023012602-0f463615.zip",
        );
        if p.exists() {
            Some(p)
        } else {
            None
        }
    }

    #[test]
    fn snapchat_accepts_sample_zip() {
        let Some(zip) = sample_zip() else {
            eprintln!("skip — sample zip not present");
            return;
        };
        let parser = SnapchatWarrantParser;
        assert!(
            parser.accepts(&zip).unwrap(),
            "parser should accept Snapchat sample zip"
        );
    }

    #[test]
    fn snapchat_parses_sample_zip() {
        let Some(zip) = sample_zip() else {
            eprintln!("skip — sample zip not present");
            return;
        };
        let parser = SnapchatWarrantParser;
        let tmp = std::env::temp_dir().join("scout_snapchat_test_media");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let res = parser.parse(&zip, &tmp).expect("parse should succeed");

        let bio = res.items.iter().filter(|i| i.section == "bio").count();
        let msgs = res
            .items
            .iter()
            .filter(|i| i.section == "unified_messages")
            .count();
        let geo = res.items.iter().filter(|i| i.section == "location").count();
        let mem = res.items.iter().filter(|i| i.section == "memories").count();
        let dev = res
            .items
            .iter()
            .filter(|i| i.section == "device_info")
            .count();
        let photos = res
            .items
            .iter()
            .filter(|i| i.section == "photos" || i.section == "videos")
            .count();
        let linked_msgs = res
            .items
            .iter()
            .filter(|i| i.section == "unified_messages" && !i.attachments.is_empty())
            .count();

        eprintln!(
            "bio={bio} msgs={msgs} geo={geo} mem={mem} dev={dev} photos={photos} linked={linked_msgs} total={}",
            res.items.len()
        );

        assert!(bio >= 1, "expected a bio item");
        assert!(msgs >= 1, "expected message items");
        assert!(geo >= 1, "expected location items");
        assert!(photos >= 1, "expected photo/video items");
        assert!(linked_msgs >= 1, "expected at least one chat row linked to media");
        assert_eq!(res.case.provider_display, "Snapchat");
        assert!(res.case.target_account.is_some());
    }

    fn write(p: &Path, name: &str, content: &[u8]) {
        fs::write(p.join(name), content).unwrap();
    }

    /// End-to-end: modern flat production (no part folders) with a separate
    /// conversation_list.csv.  Exercises folder-agnostic collection, the
    /// conversation_list join (DM vs group + target identity) and media token
    /// linking.  This is the layout that broke the legacy parser.
    #[test]
    fn accepts_and_parses_modern_flat_production() {
        let base = std::env::temp_dir().join("scout_snap_modern_test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let conv_list = "\"Target username \"\"johndoe\"\" is associated with User ID \"\"11111111-1111-1111-1111-111111111111\"\"\"\n\
conversation_id,type,creator_user_id,creation_time\n\
aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,oneonone,11111111-1111-1111-1111-111111111111,Tue Dec 13 15:00:00 UTC 2022\n\
---\n\
conversation_id,type,conversation_title,group_member_usernames,group_member_user_ids\n\
bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,group,Squad Chat,johndoe;alice;bob,111;222;333\n";
        write(&base, "conversation_list.csv", conv_list.as_bytes());

        let conversations = "\"Snapchat law enforcement response legend.\"\n\
============================================\n\
conversation_id,message_id,content_type,message_type,timestamp,sender_username,recipient_username,text,media_id\n\
aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,m1,TEXT,text,Tue Dec 13 15:46:22 UTC 2022,alice,johndoe,hey there,\n\
bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,m2,MEDIA,media,Tue Dec 13 15:47:00 UTC 2022,johndoe,,,b~TESTMEDIATOKEN1234567890\n";
        write(&base, "conversations.csv", conversations.as_bytes());

        write(
            &base,
            "chat~media_v4~2022-12-13~johndoe~~saved~b~TESTMEDIATOKEN1234567890~v4.jpg",
            b"jpegdata",
        );

        let parser = SnapchatWarrantParser;
        assert!(
            parser.accepts(&base).unwrap(),
            "should accept modern flat production dir"
        );

        let media = std::env::temp_dir().join("scout_snap_modern_media");
        let _ = fs::remove_dir_all(&media);
        let res = parser.parse(&base, &media).expect("parse modern production");

        // Target identity comes from conversation_list.csv legend line.
        assert_eq!(res.case.target_account.as_deref(), Some("johndoe"));

        let msgs: Vec<_> = res
            .items
            .iter()
            .filter(|i| i.section == "unified_messages")
            .collect();
        assert_eq!(msgs.len(), 2, "expected two messages");

        let conv_of = |i: &&WarrantItem| {
            i.raw_fields
                .get("conversationId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let dm = msgs
            .iter()
            .find(|i| conv_of(i).starts_with("aaaa"))
            .expect("dm present");
        // DM must NOT be mislabeled as a group.
        assert_eq!(
            dm.recipient.as_deref(),
            Some("alice"),
            "1:1 thread should resolve to the non-owner, not a group"
        );

        let grp = msgs
            .iter()
            .find(|i| conv_of(i).starts_with("bbbb"))
            .expect("group present");
        assert_eq!(grp.recipient.as_deref(), Some("Squad Chat"));
        assert!(
            !grp.attachments.is_empty(),
            "group media message should link its photo"
        );

        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&media);
    }

    #[test]
    fn conversation_list_parse_target_and_types() {
        let text = "\"Target username \"\"neo\"\" is associated with User ID \"\"22222222-2222-2222-2222-222222222222\"\"\"\n\
conversation_id,type\n\
cccccccc-cccc-cccc-cccc-cccccccccccc,oneonone\n\
---\n\
conversation_id,type,conversation_title,group_member_usernames\n\
dddddddd-dddd-dddd-dddd-dddddddddddd,group,Trinity Crew,neo;trinity;morpheus\n";
        let (meta, user, uid) = parse_conversation_list(text);
        assert_eq!(user.as_deref(), Some("neo"));
        assert_eq!(uid.as_deref(), Some("22222222-2222-2222-2222-222222222222"));
        assert_eq!(
            meta.get("cccccccc-cccc-cccc-cccc-cccccccccccc")
                .map(|m| m.ctype.as_str()),
            Some("oneonone")
        );
        let g = meta.get("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();
        assert_eq!(g.ctype, "group");
        assert_eq!(g.title.as_deref(), Some("Trinity Crew"));
        assert_eq!(g.members, vec!["neo", "trinity", "morpheus"]);
    }

    #[test]
    fn helpers_uuid_tokens_quotes() {
        assert!(is_uuid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("aaaaaaaaaaaa"));

        // Token extraction keeps UUIDs whole and drops short noise.
        let toks = media_tokens("b~AbCdEf0123456789XYZ~more");
        assert!(toks.contains(&"abcdef0123456789xyz".to_string()));

        assert_eq!(
            extract_quoted_after("x Target username \"\"kilo\"\" y", "Target username").as_deref(),
            Some("kilo")
        );
        assert_eq!(
            extract_quoted_after("Target username \"solo\"", "Target username").as_deref(),
            Some("solo")
        );
    }
}
