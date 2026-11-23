//! Plain-text hash lists: one hash per line, optional `#` / `//` comments,
//! optional trailing columns (`hash  filename`, `hash,filename`).
//!
//! The import used to trust whatever hash type the user typed into a prompt
//! that defaulted to SHA256.  Project VIC "cleaned" SHA1 exports are 40-char
//! lines, so accepting the default silently rejected all ~18.8M of them and
//! failed with "No valid hashes found".  The length of a hex hash identifies
//! its type unambiguously, so we sniff the file and use what it contains.

use std::io::BufRead;

/// Data lines inspected when sniffing — enough to be robust against a few
/// junk lines, small enough to be instant on a 770 MB file.
pub const SNIFF_SAMPLE_LINES: usize = 2_000;

/// Supported hash types, in `Sniff::counts` order.
pub const HASH_TYPES: [&str; 3] = ["MD5", "SHA1", "SHA256"];

pub fn expected_len(hash_type: &str) -> Option<usize> {
    match hash_type {
        "MD5" => Some(32),
        "SHA1" => Some(40),
        "SHA256" => Some(64),
        _ => None,
    }
}

fn type_index_for_len(len: usize) -> Option<usize> {
    match len {
        32 => Some(0),
        40 => Some(1),
        64 => Some(2),
        _ => None,
    }
}

/// The hash token of one line, or `None` for blank / comment lines.
/// Strips a UTF-8 BOM so the first hash of a Notepad-saved file isn't lost.
pub fn hash_token(line: &str) -> Option<&str> {
    let line = line.trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    line.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .find(|t| !t.is_empty())
}

/// `Some(type)` if `token` is a valid hex hash of a supported length.
pub fn classify(token: &str) -> Option<&'static str> {
    if !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    type_index_for_len(token.len()).map(|i| HASH_TYPES[i])
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Sniff {
    /// Data (non-blank, non-comment) lines inspected.
    pub sampled: usize,
    /// Valid MD5 / SHA1 / SHA256 lines among them.
    pub counts: [usize; 3],
    /// Data lines that are not a valid hash of any supported type.
    pub invalid: usize,
    /// First invalid line, for the error message.
    pub first_invalid: Option<String>,
    /// The file starts with `{` or `[` — it is JSON (e.g. a Project VIC
    /// export), not a line-per-hash list.  Nothing else is filled in.
    pub json: bool,
}

impl Sniff {
    /// The type that more than half of the sampled lines have.
    pub fn detected(&self) -> Option<&'static str> {
        let (idx, &best) = self.counts.iter().enumerate().max_by_key(|(_, c)| **c)?;
        (best > 0 && best * 2 > self.sampled).then(|| HASH_TYPES[idx])
    }

    pub fn count_of(&self, hash_type: &str) -> usize {
        HASH_TYPES.iter().position(|t| *t == hash_type).map(|i| self.counts[i]).unwrap_or(0)
    }
}

/// Never reads more than this while sniffing, however long the lines are.
const SNIFF_MAX_BYTES: u64 = 16 << 20;

/// Inspect up to `max_lines` data lines.  Errors only on UTF-16 files, which
/// the line reader can't decode (every line would just be skipped).
pub fn sniff<R: BufRead>(mut reader: R, max_lines: usize) -> Result<Sniff, String> {
    let head = reader.fill_buf().map_err(|e| format!("Failed to read file: {}", e))?;
    if head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]) {
        return Err("This file is saved as UTF-16 (\"Unicode\"). Open it in Notepad, \
                    choose File → Save As, set Encoding to UTF-8, then import it again."
            .to_string());
    }
    // A VIC JSON export is a single ~10 GB line; detect it from the first
    // bytes instead of reading that "line".
    let body = head.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(head);
    if matches!(body.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{') | Some(b'[')) {
        return Ok(Sniff { json: true, ..Sniff::default() });
    }

    let mut s = Sniff::default();
    // Invalid UTF-8 lines are skipped by the importer too; read lossily here.
    let mut buf = Vec::new();
    let mut reader = reader.take(SNIFF_MAX_BYTES);
    while s.sampled < max_lines {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let Some(token) = hash_token(&line) else { continue };
        s.sampled += 1;
        match classify(token) {
            Some(t) => s.counts[HASH_TYPES.iter().position(|x| *x == t).unwrap()] += 1,
            None => {
                s.invalid += 1;
                if s.first_invalid.is_none() {
                    s.first_invalid = Some(token.chars().take(80).collect());
                }
            }
        }
    }
    Ok(s)
}

/// Decide which hash type to import as.  Returns `(type, corrected)` where
/// `corrected` means the file's contents overrode the user's choice.
pub fn resolve_hash_type(requested: &str, s: &Sniff) -> Result<(&'static str, bool), String> {
    let requested_len = expected_len(requested)
        .ok_or_else(|| format!("Invalid hash type: {}", requested))?;
    let requested: &'static str = HASH_TYPES.iter().find(|t| **t == requested).unwrap();

    if s.sampled == 0 {
        return Err("No hashes found in file — it is empty or contains only comments.".to_string());
    }
    if let Some(found) = s.detected() {
        return Ok((found, found != requested));
    }
    if s.count_of(requested) > 0 {
        return Ok((requested, false));
    }
    let example = s.first_invalid.as_deref().map(|l| format!(" First line: \"{}\".", l)).unwrap_or_default();
    Err(format!(
        "No valid hashes found in file. Expected one {} hash ({} hex characters) per line.{}",
        requested, requested_len, example
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sniff_str(s: &str) -> Sniff {
        sniff(s.as_bytes(), SNIFF_SAMPLE_LINES).unwrap()
    }

    const SHA1: &str = "2b037f69c566dfdb3a5a79e5360d085959bdde4c";
    const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
    const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn project_vic_sha1_export_is_detected_even_if_user_picked_sha256() {
        // Header copied from the real VIC_US_2026_4_FS.json_SHA1.txt export.
        let file = format!(
            "# SHA1 hashes extracted from Project VIC: VIC_US_2026_4_FS.json.bak\r\n\
             # Generated: 2026-04-27 11:23:08\r\n\
             # Hash type: SHA1 (40 hex characters, lowercase)\r\n#\r\n{SHA1}\r\n{SHA1}\r\n"
        );
        let s = sniff_str(&file);
        assert_eq!(s.sampled, 2);
        assert_eq!(s.detected(), Some("SHA1"));
        assert_eq!(resolve_hash_type("SHA256", &s), Ok(("SHA1", true)));
        assert_eq!(resolve_hash_type("SHA1", &s), Ok(("SHA1", false)));
    }

    #[test]
    fn tokens_handle_bom_columns_and_comments() {
        assert_eq!(hash_token("\u{feff}ABC  file.jpg"), Some("ABC"));
        assert_eq!(hash_token("abc,file.jpg"), Some("abc"));
        assert_eq!(hash_token("  abc;x "), Some("abc"));
        assert_eq!(hash_token("# comment"), None);
        assert_eq!(hash_token("// comment"), None);
        assert_eq!(hash_token("   "), None);
        assert_eq!(classify(MD5), Some("MD5"));
        assert_eq!(classify(&SHA256.to_uppercase()), Some("SHA256"));
        assert_eq!(classify("zz"), None);
        assert_eq!(classify(&SHA1.replace('2', "g")), None);
    }

    #[test]
    fn majority_wins_and_ties_fall_back_to_the_user_choice() {
        let s = sniff_str(&format!("{MD5}\n{MD5}\n{MD5}\njunk\n"));
        assert_eq!(resolve_hash_type("SHA1", &s), Ok(("MD5", true)));

        let tie = sniff_str(&format!("{MD5}\n{SHA1}\n"));
        assert_eq!(tie.detected(), None);
        assert_eq!(resolve_hash_type("SHA1", &tie), Ok(("SHA1", false)));
    }

    #[test]
    fn useless_files_get_a_specific_message() {
        let empty = sniff_str("# only comments\n\n");
        assert!(resolve_hash_type("SHA1", &empty).unwrap_err().contains("empty"));

        let junk = sniff_str("filename,hash\nhello world\n");
        let err = resolve_hash_type("SHA1", &junk).unwrap_err();
        assert!(err.contains("40 hex characters") && err.contains("filename"), "{err}");

        assert!(resolve_hash_type("CRC32", &junk).is_err());
    }

    #[test]
    fn utf16_files_are_rejected_with_instructions() {
        let bytes: &[u8] = &[0xFF, 0xFE, b'a', 0, b'b', 0];
        assert!(sniff(bytes, 10).unwrap_err().contains("UTF-16"));
    }

    #[test]
    fn json_is_recognised_without_reading_its_one_giant_line() {
        for head in ["{\"@odata.context\":\"x\",\"value\":[", "\u{feff}  \r\n[{\"MD5\":", "\n{\"SHA1\":"] {
            let s = sniff_str(head);
            assert!(s.json, "{head:?}");
            assert_eq!(s.sampled, 0);
        }
        assert!(!sniff_str(&format!("# {{ not json\n{SHA1}\n")).json);
    }

    /// Runs against a real export when `SCOUT_HASH_TXT` points at one, e.g.
    /// the Project VIC `VIC_US_2026_4_FS.json_SHA1.txt`.  Skipped otherwise.
    #[test]
    fn real_export_if_provided() {
        let Ok(path) = std::env::var("SCOUT_HASH_TXT") else { return };
        let open = || std::io::BufReader::new(std::fs::File::open(&path).unwrap());
        let s = sniff(open(), SNIFF_SAMPLE_LINES).unwrap();
        let (ty, _) = resolve_hash_type("SHA256", &s).unwrap();
        let want = expected_len(ty).unwrap();
        let (mut ok, mut bad) = (0u64, 0u64);
        for line in open().lines() {
            let line = line.unwrap();
            if let Some(tok) = hash_token(&line) {
                if tok.len() == want && classify(tok).is_some() { ok += 1 } else { bad += 1 }
            }
        }
        eprintln!("{path}: detected {ty}, {ok} valid, {bad} invalid");
        assert!(ok > 0);
    }
}
