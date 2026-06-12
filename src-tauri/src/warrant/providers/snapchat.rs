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

        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let raw_name = entry.name().to_string();
            let lower = raw_name.to_lowercase();

            // Strongest signal: any conversations.csv with the Snapchat preamble.
            if lower.ends_with("conversations.csv") {
                let mut head = vec![0u8; 1024];
                let read = entry.read(&mut head).unwrap_or(0);
                let head_str = String::from_utf8_lossy(&head[..read]);
                if head_str.contains("Target username") || head_str.contains("User ID") {
                    return Ok(true);
                }
            }
        }

        // Fallback: the part-folder naming convention is distinctive enough.
        let file = File::open(path)?;
        let mut zip = ZipArchive::new(file)?;
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            let name = entry.name().to_string();
            let top = name.split('/').next().unwrap_or("");
            if extract_part_tokens(top).is_some() {
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
    other_csvs: HashMap<String, (Vec<String>, Vec<HashMap<String, String>>)>,
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

    // First pass: figure out which top-level segments are part folders.
    // A part folder is one whose name matches the username-case-req-part-date
    // pattern OR whose top dir contains a conversations.csv.
    let mut top_has_conv: HashSet<String> = HashSet::new();
    let mut names_by_top: HashMap<String, Vec<String>> = HashMap::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let segs: Vec<&str> = name.split('/').collect();
        if segs.len() < 2 {
            continue;
        }
        let top = segs[0].to_string();
        let lower = name.to_lowercase();
        if lower.ends_with("/conversations.csv") {
            top_has_conv.insert(top.clone());
        }
        names_by_top.entry(top).or_default().push(name);
    }

    // Strip an enclosing wrapper folder if present.  Some productions are
    // zipped as `Production-XXX/{username-...-N-date}/...` where the top
    // level is a single wrapper directory that contains the actual parts.
    let wrapper = detect_wrapper_dir(&names_by_top, &top_has_conv);

    let mut parts: Vec<RawPart> = Vec::new();
    let target_tops: Vec<String> = if let Some(w) = &wrapper {
        // Re-bucket using the SECOND segment as the "top".
        let mut second_to_files: HashMap<String, Vec<String>> = HashMap::new();
        for (_top, files) in &names_by_top {
            for f in files {
                let segs: Vec<&str> = f.split('/').collect();
                if segs.len() >= 3 && segs[0] == w.as_str() {
                    second_to_files
                        .entry(segs[1].to_string())
                        .or_default()
                        .push(f.clone());
                }
            }
        }
        let seconds: Vec<String> = second_to_files.keys().cloned().collect();
        names_by_top = second_to_files;
        top_has_conv.clear();
        for (sec, files) in &names_by_top {
            if files
                .iter()
                .any(|n| n.to_lowercase().ends_with("/conversations.csv"))
            {
                top_has_conv.insert(sec.clone());
            }
        }
        seconds
    } else {
        names_by_top.keys().cloned().collect()
    };

    let prefix_strip = wrapper.as_deref().map(|s| format!("{}/", s));

    for top in target_tops {
        if !top_has_conv.contains(&top) && extract_part_tokens(&top).is_none() {
            continue;
        }
        let mut csvs: HashMap<String, String> = HashMap::new();
        let mut media_files: Vec<String> = Vec::new();

        for entry_name in names_by_top.get(&top).cloned().unwrap_or_default() {
            // Re-prefix with wrapper if we stripped it.
            let real_name = match &prefix_strip {
                Some(p) => format!("{}{}", p, entry_name),
                None => entry_name.clone(),
            };
            let mut entry = zip.by_name(&real_name)?;
            let basename = entry_name
                .rsplit('/')
                .next()
                .unwrap_or(&entry_name)
                .to_string();
            let lower_base = basename.to_lowercase();

            if lower_base.ends_with(".csv") {
                let mut buf = String::new();
                if entry.read_to_string(&mut buf).is_ok() {
                    csvs.insert(lower_base.clone(), buf);
                }
            } else if is_media_basename(&lower_base) {
                // Prefix with part folder to avoid filename collisions across parts.
                let out_name = format!("{}~~{}", top, basename);
                let out_path = media_extract_dir.join(&out_name);
                if let Ok(mut out) = File::create(&out_path) {
                    if std::io::copy(&mut entry, &mut out).is_ok() {
                        media_files.push(out_name);
                    }
                }
            }
        }

        if !csvs.is_empty() || !media_files.is_empty() {
            parts.push(RawPart {
                folder: top,
                csvs,
                media_files,
            });
        }
    }

    Ok(parts)
}

fn collect_parts_from_dir(
    dir: &Path,
    media_extract_dir: &Path,
) -> Result<Vec<RawPart>, ParseError> {
    // The user might point us at:
    //   (a) the part folder itself (conversations.csv directly inside);
    //   (b) a parent that contains multiple part subfolders;
    //   (c) a "wrapper" parent that contains a single Production-* folder
    //       which contains the parts (nested 2 deep).
    let mut candidate_parts: Vec<PathBuf> = Vec::new();

    let has_conv_here = dir.join("conversations.csv").exists();
    if has_conv_here {
        candidate_parts.push(dir.to_path_buf());
        // Discover sibling parts in the parent dir (VIPER behaviour).
        if let Some(parent) = dir.parent() {
            if let Some(my_tokens) = dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(extract_part_tokens)
            {
                if let Ok(read) = fs::read_dir(parent) {
                    for ent in read.flatten() {
                        if !ent
                            .file_type()
                            .map(|t| t.is_dir())
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let p = ent.path();
                        if p == dir {
                            continue;
                        }
                        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                            if let Some(t) = extract_part_tokens(name) {
                                if t.case_id == my_tokens.case_id
                                    && t.request_id == my_tokens.request_id
                                    && p.join("conversations.csv").exists()
                                {
                                    candidate_parts.push(p);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Walk one level deep first; if nothing, walk two levels deep.
        walk_for_part_dirs(dir, 0, 3, &mut candidate_parts);
    }

    candidate_parts.sort();
    candidate_parts.dedup();

    let mut parts: Vec<RawPart> = Vec::new();
    for part_dir in candidate_parts {
        let folder = part_dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "part".into());

        let mut csvs: HashMap<String, String> = HashMap::new();
        let mut media_files: Vec<String> = Vec::new();

        if let Ok(read) = fs::read_dir(&part_dir) {
            for ent in read.flatten() {
                let p = ent.path();
                if !p.is_file() {
                    continue;
                }
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
                    let out_name = format!("{}~~{}", folder, basename);
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

fn walk_for_part_dirs(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    if dir.join("conversations.csv").exists() {
        out.push(dir.to_path_buf());
        // Don't recurse further once we've found a part folder.
        return;
    }
    if let Ok(read) = fs::read_dir(dir) {
        for ent in read.flatten() {
            if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk_for_part_dirs(&ent.path(), depth + 1, max_depth, out);
            }
        }
    }
}

/// Detect a single wrapper folder (e.g. `Production-XXX/`) whose immediate
/// children look like Snapchat part folders.  Returns the wrapper name to
/// strip, or None if no wrapper is present.
fn detect_wrapper_dir(
    names_by_top: &HashMap<String, Vec<String>>,
    _top_has_conv: &HashSet<String>,
) -> Option<String> {
    if names_by_top.len() != 1 {
        return None;
    }
    let top = names_by_top.keys().next()?;
    // If THIS top is itself a part folder (matches the tokens pattern), don't strip.
    if extract_part_tokens(top).is_some() {
        return None;
    }
    // Check whether the second-level segments look like part folders.
    let mut second_part_count = 0;
    for n in names_by_top.get(top)? {
        let segs: Vec<&str> = n.split('/').collect();
        if segs.len() >= 3 && extract_part_tokens(segs[1]).is_some() {
            second_part_count += 1;
            if second_part_count >= 2 {
                return Some(top.clone());
            }
        }
    }
    // Single inner part folder also counts.
    if second_part_count >= 1 {
        return Some(top.clone());
    }
    None
}

fn dir_has_snapchat_format(dir: &Path) -> bool {
    let check_conv_preamble = |p: &Path| -> bool {
        let mut buf = vec![0u8; 1024];
        if let Ok(mut f) = File::open(p) {
            let n = f.read(&mut buf).unwrap_or(0);
            let s = String::from_utf8_lossy(&buf[..n]);
            return s.contains("Target username") || s.contains("User ID");
        }
        false
    };

    let here = dir.join("conversations.csv");
    if here.exists() && check_conv_preamble(&here) {
        return true;
    }

    // Walk up to 3 levels deep looking for any conversations.csv with the
    // Snapchat preamble.  Production layouts on USB drives often nest 2-3
    // levels (USB → Production-XXX → username-... → conversations.csv).
    let mut found = false;
    walk_check(dir, 0, 3, &mut |p| {
        if p.file_name().and_then(|n| n.to_str()) == Some("conversations.csv")
            && check_conv_preamble(p)
        {
            found = true;
        }
    });
    found
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
        let msg_id = row.get("message_id").cloned().unwrap_or_default();
        let title = row.get("conversation_title").cloned().unwrap_or_default();
        let sender = row.get("sender_username").cloned().unwrap_or_default();
        let sender_uid = row.get("sender_user_id").cloned().unwrap_or_default();
        let recipient = row.get("recipient_username").cloned().unwrap_or_default();
        let recipient_uid = row.get("recipient_user_id").cloned().unwrap_or_default();
        let text = row.get("text").cloned().unwrap_or_default();
        let media_id = row.get("media_id").cloned().unwrap_or_default();
        let is_saved = row.get("is_saved").cloned().unwrap_or_default();
        let is_one = row.get("is_one_on_one").cloned().unwrap_or_default();
        let timestamp = row.get("timestamp").cloned().unwrap_or_default();
        let group_members = row.get("group_member_usernames").cloned().unwrap_or_default();
        let reactions = row.get("reactions").cloned().unwrap_or_default();

        // Determine the conversation thread label.  For group chats use the
        // title (if any) or sorted member list; for 1:1 use the non-owner.
        let is_group = !matches!(is_one.to_ascii_lowercase().as_str(), "true" | "1" | "yes");
        let thread_label: String = if is_group {
            if !title.trim().is_empty() {
                title.clone()
            } else if !group_members.trim().is_empty() {
                format!("Group: {}", truncate(&group_members, 60))
            } else {
                format!("Group {}", short_id(&conv_id))
            }
        } else {
            let me = owner.clone().unwrap_or_default().to_lowercase();
            if !recipient.is_empty() && recipient.to_lowercase() != me {
                recipient.clone()
            } else if !sender.is_empty() && sender.to_lowercase() != me {
                sender.clone()
            } else {
                recipient.clone()
            }
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
    None
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
}
