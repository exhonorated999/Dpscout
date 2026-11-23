//! Project VIC / VICS JSON hash sets.
//!
//! Real exports (e.g. `VIC_US_2026_4_FS.json`, ~10 GB, ~18.8M entries) are an
//! OData wrapper around one flat array of Media objects:
//!
//! ```text
//! {"@odata.context":".../$metadata#Media","value":[
//!   {"MediaID":1,"Category":0,"MD5":"ADEB…","SHA1":"2B03…","MediaSize":2835,…,
//!    "Exifs":[{"MD5":"…","PropertyName":"Software",…}]}, …]}
//! ```
//!
//! Also accepted: a plain array, NDJSON / concatenated objects, and a
//! `#Cases` wrapper whose case objects carry a nested `"Media":[…]` array.
//!
//! Everything works on raw bytes so a 10 GB file is never validated or copied
//! as one string — each object is parsed on its own, and a malformed one only
//! costs that entry.  Hash values are validated and typed by length (the same
//! rule as the TXT importer), never trusted from the field name alone.

use super::txt_format;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use std::fmt;

/// One hash to insert.
#[derive(Debug, Clone, PartialEq)]
pub struct VicHash {
    /// Lowercase hex.
    pub hash: String,
    pub hash_type: &'static str,
    pub category: Option<String>,
    pub description: Option<String>,
    pub file_size: Option<i64>,
}

/// Where the entries are, decided from the start of the file.
#[derive(Debug, PartialEq)]
pub enum Layout {
    /// Byte offset to start iterating objects from.
    Entries(usize),
    /// Not JSON at all — one hash per line.  The caller hands it to the TXT importer.
    PlainText,
}

#[derive(Debug, Default, Clone)]
pub struct VicStats {
    /// Objects examined (media entries, plus case objects for `#Cases` files).
    pub entries: u64,
    pub imported: u64,
    /// MD5 / SHA1 / SHA256, `txt_format::HASH_TYPES` order.
    pub by_type: [u64; 3],
    pub no_hash: u64,
    pub invalid: u64,
    pub parse_errors: u64,
    pub first_invalid: Option<String>,
}

impl VicStats {
    /// The type most of the imported hashes have (MD5 if nothing was imported).
    pub fn dominant_type(&self) -> &'static str {
        let idx = (0..3).max_by_key(|i| self.by_type[*i]).unwrap_or(0);
        if self.by_type[idx] == 0 { "MD5" } else { txt_format::HASH_TYPES[idx] }
    }

    /// User-facing explanation for an import that found nothing usable.
    pub fn nothing_imported_message(&self) -> String {
        if self.entries == 0 {
            return "No valid hashes found in file — no Project VIC entries were found in this JSON file."
                .to_string();
        }
        let mut msg = format!(
            "No valid hashes found in file. Scanned {} entries: {} had no MD5/SHA1/SHA256 value, \
             {} had an invalid hash, {} could not be read.",
            self.entries, self.no_hash, self.invalid, self.parse_errors
        );
        if let Some(bad) = &self.first_invalid {
            msg.push_str(&format!(" First invalid value: \"{}\".", bad));
        }
        msg
    }
}

const UTF16_MESSAGE: &str = "This file is saved as UTF-16 (\"Unicode\"). Re-save it as UTF-8 \
     (Notepad: File → Save As, Encoding: UTF-8), then import it again.";

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Decide how to read `data`.  Never scans more than the wrapper's preamble
/// for OData files, so this is instant even on 10 GB.
pub fn detect_layout(data: &[u8]) -> Result<Layout, String> {
    if data.starts_with(&[0xFF, 0xFE])
        || data.starts_with(&[0xFE, 0xFF])
        || (data.len() >= 2 && (data[0] == 0 || data[1] == 0))
    {
        return Err(UTF16_MESSAGE.to_string());
    }
    let mut i = if data.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    match data.get(i) {
        None => Err("No valid hashes found in file — the file is empty.".to_string()),
        Some(b'[') => Ok(Layout::Entries(i + 1)),
        Some(b'{') => Ok(Layout::Entries(wrapper_array_start(data, i).unwrap_or(i))),
        Some(b) if b.is_ascii_hexdigit() || *b == b'#' || *b == b'/' => Ok(Layout::PlainText),
        Some(_) => Err("This is not a Project VIC JSON file (it does not start with { or [).".to_string()),
    }
}

/// Key names that wrap the entries array in exports we know of.
fn is_wrapper_key(k: &[u8]) -> bool {
    ["value", "hashes", "entries", "data", "media", "items", "results"]
        .iter()
        .any(|w| k.eq_ignore_ascii_case(w.as_bytes()))
}

fn is_hash_key(k: &[u8]) -> bool {
    ["md5", "sha1", "sha256", "hash"].iter().any(|w| k.eq_ignore_ascii_case(w.as_bytes()))
}

/// For an object starting at `open` (a `{`), find the array holding the
/// entries and return the offset just past its `[`.  `None` means the object
/// is itself an entry (NDJSON / concatenated objects) or has no array.
///
/// Walks only depth-1 keys, stops at the first known wrapper key, and gives
/// up on unknown keys after 64 MB so an OData file is never read twice.
fn wrapper_array_start(data: &[u8], open: usize) -> Option<usize> {
    const GIVE_UP_AFTER: usize = 64 << 20;
    let mut depth = 0i32;
    let mut i = open;
    let mut fallback: Option<usize> = None;
    while i < data.len() {
        match data[i] {
            b'"' => {
                let start = i + 1;
                let end = string_end(data, start)?;
                i = end + 1;
                if depth == 1 {
                    let mut j = i;
                    while j < data.len() && is_ws(data[j]) {
                        j += 1;
                    }
                    if data.get(j) != Some(&b':') {
                        continue; // a string value, not a key
                    }
                    let key = &data[start..end];
                    if is_hash_key(key) {
                        return None; // the object is an entry itself
                    }
                    j += 1;
                    while j < data.len() && is_ws(data[j]) {
                        j += 1;
                    }
                    if data.get(j) == Some(&b'[') {
                        if is_wrapper_key(key) {
                            return Some(j + 1);
                        }
                        fallback.get_or_insert(j + 1);
                    }
                }
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return fallback;
                }
            }
            _ => {}
        }
        i += 1;
        if i - open > GIVE_UP_AFTER {
            return fallback;
        }
    }
    fallback
}

/// Index of the closing quote of a JSON string whose content starts at `from`.
fn string_end(data: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < data.len() {
        match data[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Yields each top-level `{…}` object from `pos` on, stopping at the `]`
/// that closes the enclosing array.  Braces inside strings are ignored.
/// Works on bytes: `{ } " \` are ASCII and never appear inside a UTF-8
/// multi-byte sequence.
pub struct ObjectIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ObjectIter<'a> {
    pub fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }
}

impl<'a> Iterator for ObjectIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let data = self.data;
        // Skip separators; stop at the array's closing bracket.
        while self.pos < data.len() {
            match data[self.pos] {
                b'{' => break,
                b']' => {
                    self.pos = data.len();
                    return None;
                }
                _ => self.pos += 1,
            }
        }
        let start = self.pos;
        if start >= data.len() {
            return None;
        }
        let mut depth = 0i32;
        let mut in_string = false;
        let mut i = start;
        while i < data.len() {
            let b = data[i];
            if in_string {
                match b {
                    b'\\' => i += 1,
                    b'"' => in_string = false,
                    _ => {}
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            self.pos = i + 1;
                            return Some(&data[start..=i]);
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        self.pos = data.len();
        None // truncated file: unterminated last object
    }
}

// ── Per-entry parsing ─────────────────────────────────────────────────────

/// Field names, matched case-insensitively without allocating.
enum Key {
    Md5,
    Sha1,
    Sha256,
    Hash,
    Category,
    Description,
    Series,
    Size,
    Media,
    Other,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Key;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a field name")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Key, E> {
                let k = |n: &str| s.eq_ignore_ascii_case(n);
                Ok(if k("md5") {
                    Key::Md5
                } else if k("sha1") {
                    Key::Sha1
                } else if k("sha256") {
                    Key::Sha256
                } else if k("hash") {
                    Key::Hash
                } else if k("category") {
                    Key::Category
                } else if k("description") {
                    Key::Description
                } else if k("series") {
                    Key::Series
                } else if k("mediasize") || k("filesize") || k("file_size") || k("size") {
                    Key::Size
                } else if k("media") {
                    Key::Media
                } else {
                    Key::Other
                })
            }
        }
        d.deserialize_identifier(V)
    }
}

/// An entry's interesting fields.  The first occurrence of each wins, so a
/// record carrying both `Series` and `Description` (or `Size` and
/// `MediaSize`) is still read — serde aliases would reject it as a duplicate.
#[derive(Default)]
struct RawEntry {
    md5: Option<serde_json::Value>,
    sha1: Option<serde_json::Value>,
    sha256: Option<serde_json::Value>,
    hash: Option<serde_json::Value>,
    category: Option<serde_json::Value>,
    description: Option<serde_json::Value>,
    series: Option<serde_json::Value>,
    size: Option<serde_json::Value>,
    has_media: bool,
}

impl<'de> Deserialize<'de> for RawEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawEntry;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a Project VIC entry object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawEntry, A::Error> {
                let mut e = RawEntry::default();
                while let Some(key) = map.next_key::<Key>()? {
                    let slot = match key {
                        Key::Md5 => &mut e.md5,
                        Key::Sha1 => &mut e.sha1,
                        Key::Sha256 => &mut e.sha256,
                        Key::Hash => &mut e.hash,
                        Key::Category => &mut e.category,
                        Key::Description => &mut e.description,
                        Key::Series => &mut e.series,
                        Key::Size => &mut e.size,
                        Key::Media => {
                            e.has_media = true;
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                        Key::Other => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    if slot.is_some() {
                        map.next_value::<IgnoredAny>()?;
                    } else {
                        *slot = Some(map.next_value()?);
                    }
                }
                Ok(e)
            }
        }
        d.deserialize_map(V)
    }
}

fn as_text(v: &Option<serde_json::Value>) -> Option<String> {
    match v.as_ref()? {
        serde_json::Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[derive(Debug, PartialEq)]
pub enum Entry {
    Hash(VicHash),
    /// No hash field at all; `has_media` marks a `#Cases` case object.
    NoHash { has_media: bool },
    /// Had hash field(s), none of them valid hex of a supported length.
    Invalid(String),
}

/// Parse one object.  Priority MD5 > SHA1 > SHA256 > generic `hash`: one hash
/// per entry (VIC carries MD5 for ~100% of entries, and importing every type
/// would double the database and RAM for no extra matches — the scanner
/// computes whatever types the database holds).  A value is typed by its
/// length, so a mislabelled field still imports correctly.
pub fn parse_entry(obj: &[u8]) -> Result<Entry, String> {
    let raw: RawEntry = serde_json::from_slice(obj).map_err(|e| e.to_string())?;
    let mut first_invalid = None;
    for cand in [&raw.md5, &raw.sha1, &raw.sha256, &raw.hash] {
        let Some(text) = as_text(cand) else { continue };
        if let Some(hash_type) = txt_format::classify(&text) {
            return Ok(Entry::Hash(VicHash {
                hash: text.to_ascii_lowercase(),
                hash_type,
                category: as_text(&raw.category),
                description: as_text(&raw.description).or_else(|| as_text(&raw.series)),
                file_size: match raw.size.as_ref() {
                    Some(serde_json::Value::Number(n)) => n.as_i64(),
                    Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
                    _ => None,
                },
            }));
        }
        first_invalid.get_or_insert(text.chars().take(80).collect::<String>());
    }
    Ok(match first_invalid {
        Some(bad) => Entry::Invalid(bad),
        None => Entry::NoHash { has_media: raw.has_media },
    })
}

/// Stream every valid hash in `data` to `on_hash(hash, entries_so_far)`.
/// `data` must not be [`Layout::PlainText`] (that is an error here).
pub fn for_each_hash<F>(data: &[u8], mut on_hash: F) -> Result<VicStats, String>
where
    F: FnMut(VicHash, u64) -> Result<(), String>,
{
    let start = match detect_layout(data)? {
        Layout::Entries(pos) => pos,
        Layout::PlainText => {
            return Err("This file is a plain-text hash list, not Project VIC JSON. \
                        Use \"Import TXT Hash List\" instead."
                .to_string())
        }
    };
    let mut stats = VicStats::default();
    for obj in ObjectIter::new(data, start) {
        if let Some(case_media) = handle(obj, &mut stats, &mut on_hash)? {
            // `#Cases` layout: the case object wraps its own Media array.
            for media in ObjectIter::new(obj, case_media) {
                handle(media, &mut stats, &mut on_hash)?;
            }
        }
    }
    Ok(stats)
}

/// Process one object; returns the offset of a nested Media array to descend into.
fn handle<F>(obj: &[u8], stats: &mut VicStats, on_hash: &mut F) -> Result<Option<usize>, String>
where
    F: FnMut(VicHash, u64) -> Result<(), String>,
{
    stats.entries += 1;
    match parse_entry(obj) {
        Ok(Entry::Hash(h)) => {
            let idx = txt_format::HASH_TYPES.iter().position(|t| *t == h.hash_type).unwrap_or(0);
            stats.by_type[idx] += 1;
            stats.imported += 1;
            on_hash(h, stats.entries)?;
        }
        Ok(Entry::NoHash { has_media: true }) => {
            stats.entries -= 1; // a case wrapper, not a media entry
            return Ok(wrapper_array_start(obj, 0));
        }
        Ok(Entry::NoHash { .. }) => stats.no_hash += 1,
        Ok(Entry::Invalid(bad)) => {
            stats.invalid += 1;
            stats.first_invalid.get_or_insert(bad);
        }
        Err(e) => {
            stats.parse_errors += 1;
            if stats.parse_errors <= 3 {
                let preview = String::from_utf8_lossy(&obj[..obj.len().min(200)]);
                eprintln!("[VIC Import] Parse error #{}: {} — entry: {}", stats.parse_errors, e, preview);
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(data: &str) -> (Vec<VicHash>, VicStats) {
        let mut out = Vec::new();
        let stats = for_each_hash(data.as_bytes(), |h, _| {
            out.push(h);
            Ok(())
        })
        .unwrap();
        (out, stats)
    }

    // First records of the real VIC_US_2026_4_FS.json, verbatim.
    const ODATA: &str = r#"{"@odata.context":"http://github.com/VICSDATAMODEL/ProjectVic/DataModels/2.0.xml/Default/$metadata#Media","value":[{"MediaID":1,"Category":0,"MD5":"ADEBF3FA3C9BE7F73825E1CB9E2DEA09","SHA1":"2B037F69C566DFDB3A5A79E5360D085959BDDE4C","MediaSize":2835,"DateUpdated":"2023-06-07T02:31:49.8300Z","IsPrecategorized":"false"},{"MediaID":2,"Category":0,"MD5":"192DB5CECD7AC2A2FD02F903A27A5FCD","SHA1":"1407C5674DC7DA55419C64C5375907991EC6011F","MediaSize":4190,"DateUpdated":"2023-06-07T02:31:49.8300Z","IsPrecategorized":"false","Exifs":[{"MD5":"192DB5CECD7AC2A2FD02F903A27A5FCD","PropertyName":"Software","PropertyValue":"Adobe Fireworks CS4"}]},{"MediaID":3,"Category":1,"MD5":"AE4B09805ED8BFF47779566F3FF2C430","SHA1":"A80A637026458B6A3F9E96E140838259232459D6","MediaSize":4751,"DateUpdated":"2023-06-07T02:31:49.8300Z","Series":"CA/SWEET SUGAR","IsPrecategorized":"false","OffenderIdentified":"true","VictimIdentified":"true","IsDistributed":"true"}]}"#;

    const MD5: &str = "adebf3fa3c9be7f73825e1cb9e2dea09";
    const SHA1: &str = "2b037f69c566dfdb3a5a79e5360d085959bdde4c";
    const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn real_odata_records_import_md5_with_metadata() {
        let (hashes, stats) = collect(ODATA);
        assert_eq!(stats.entries, 3, "nested Exifs objects must not count as entries");
        assert_eq!(stats.imported, 3);
        assert_eq!(stats.dominant_type(), "MD5");
        assert_eq!(hashes[0].hash, MD5);
        assert_eq!(hashes[0].hash_type, "MD5");
        assert_eq!(hashes[0].category.as_deref(), Some("0"));
        assert_eq!(hashes[0].file_size, Some(2835));
        assert_eq!(hashes[2].description.as_deref(), Some("CA/SWEET SUGAR"));
    }

    #[test]
    fn layouts_bom_array_ndjson_and_cases() {
        let entry = format!(r#"{{"SHA1":"{}"}}"#, SHA1.to_uppercase());
        for data in [
            format!("\u{feff}[{entry},{entry}]"),
            format!("{entry}\n{entry}\n"),
            format!(r#"{{"meta":{{"x":[1]}},"Hashes":[{entry},{entry}]}}"#),
            format!(r#"{{"@odata.context":"…#Cases","value":[{{"CaseID":"7","Media":[{entry},{entry}],"Victims":[{{"Name":"x"}}]}}]}}"#),
        ] {
            let (hashes, stats) = collect(&data);
            assert_eq!(stats.imported, 2, "{data}");
            assert!(hashes.iter().all(|h| h.hash == SHA1 && h.hash_type == "SHA1"), "{data}");
            assert_eq!(stats.dominant_type(), "SHA1");
        }
    }

    #[test]
    fn duplicates_case_and_mislabels_are_tolerated() {
        let data = format!(
            r#"[{{"md5":"","Sha1":"{SHA1}","Series":"S","Description":"D","Size":"5","MediaSize":9}},
                {{"MD5":"{SHA256}"}},
                {{"MD5":null,"SHA1":"nothex","hash":"{MD5}"}}]"#
        );
        let (hashes, stats) = collect(&data);
        assert_eq!(stats.imported, 3);
        assert_eq!((hashes[0].hash_type, hashes[0].description.as_deref(), hashes[0].file_size), ("SHA1", Some("D"), Some(5)));
        assert_eq!(hashes[1].hash_type, "SHA256", "typed by length, not field name");
        assert_eq!(hashes[2].hash_type, "MD5");
    }

    #[test]
    fn nothing_usable_is_reported_not_silently_accepted() {
        let (_, stats) = collect(r#"{"value":[{"MediaID":1},{"MD5":"xyz"},{"MD5":12}, {"bad json"}]}"#);
        assert_eq!((stats.imported, stats.no_hash, stats.invalid, stats.parse_errors), (0, 1, 2, 1));
        let msg = stats.nothing_imported_message();
        assert!(msg.starts_with("No valid hashes found") && msg.contains("xyz"), "{msg}");

        let (_, empty) = collect(r#"{"value":[]}"#);
        assert!(empty.nothing_imported_message().contains("no Project VIC entries"));
    }

    #[test]
    fn plain_text_utf16_and_garbage_are_recognised() {
        assert_eq!(detect_layout(format!("# header\n{SHA1}\n").as_bytes()), Ok(Layout::PlainText));
        assert_eq!(detect_layout(format!("\u{feff}{SHA1}\n").as_bytes()), Ok(Layout::PlainText));
        assert!(detect_layout(&[0xFF, 0xFE, b'{', 0]).unwrap_err().contains("UTF-16"));
        assert!(detect_layout(b"<html>").is_err());
        assert!(detect_layout(b"  ").is_err());
        assert!(for_each_hash(SHA1.as_bytes(), |_, _| Ok(())).unwrap_err().contains("TXT"));
    }

    #[test]
    fn invalid_utf8_costs_one_entry_not_the_import() {
        let mut data = format!(r#"[{{"MD5":"{MD5}"}},{{"Series":""#).into_bytes();
        data.extend_from_slice(&[0xC3, 0x28]);
        data.extend_from_slice(format!(r#""}},{{"MD5":"{MD5}"}}]"#).as_bytes());
        let stats = for_each_hash(&data, |_, _| Ok(())).unwrap();
        assert_eq!((stats.imported, stats.parse_errors), (2, 1));
    }

    #[test]
    fn braces_and_quotes_inside_strings_do_not_split_objects() {
        let data = format!(r#"[{{"Series":"a}}{{\"b]","MD5":"{MD5}"}},{{"MD5":"{MD5}"}}]"#);
        let (_, stats) = collect(&data);
        assert_eq!((stats.entries, stats.imported), (2, 2));
    }

    /// Full pass over a real export when `SCOUT_VIC_JSON` points at one, e.g.
    /// `VIC_US_2026_4_FS.json`.  No database involved.  Skipped otherwise.
    #[test]
    fn real_export_if_provided() {
        let Ok(path) = std::env::var("SCOUT_VIC_JSON") else { return };
        let file = std::fs::File::open(&path).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
        let started = std::time::Instant::now();
        let stats = for_each_hash(&mmap, |_, _| Ok(())).unwrap();
        eprintln!("{path}: {stats:?} in {:.1}s", started.elapsed().as_secs_f64());
        assert!(stats.imported > 0);
        assert_eq!(stats.parse_errors, 0);
    }
}
