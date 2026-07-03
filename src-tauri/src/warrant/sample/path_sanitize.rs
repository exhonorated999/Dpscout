// path_sanitize.rs
//
// Path scrubbing for sample envelopes.
//
// User policy (decided 2026-06-19): filenames are NOT useful for parser
// authoring because they change per-case/per-account.  Parsers should
// branch on location (directory layout) + file type (extension/format),
// never on the leaf filename itself.
//
// Behavior:
//   * Leaf filename is replaced with `file_NNN.ext`, NNN sequential
//     per (sanitized) parent directory.
//   * Each directory component is inspected; if it matches a PII shape
//     (email/phone/UUID/long high-entropy id) it is replaced with a
//     `<redacted-*>` placeholder.  Otherwise it passes through verbatim
//     because structural folder names like `Messages`, `Attachments`,
//     `Media`, `user_data` are exactly what parser-authoring needs.
//
// This module is intentionally dependency-free so it can be unit-tested
// in isolation.

use std::collections::HashMap;
use std::path::{Component, Path};

/// Stateful sanitizer — keeps a per-parent-directory counter so leaf
/// filenames in the same folder get `file_001`, `file_002`, ... and
/// stay distinct across the envelope.
#[derive(Default)]
pub struct PathSanitizer {
    counters: HashMap<String, usize>,
    /// Per-parent set of already-emitted structural leaf names, so two
    /// files that preserve the same record-type stem stay distinct.
    used_leaves: HashMap<String, std::collections::HashSet<String>>,
}

impl PathSanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a relative path and return its sanitized form.  The returned
    /// string always uses forward slashes.
    pub fn sanitize(&mut self, rel: &Path) -> String {
        // Split into ordered string components, ignoring root / prefix
        // (we should only ever be given a relative path, but be safe).
        let parts: Vec<String> = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                Component::CurDir => None,
                Component::ParentDir => Some("..".to_string()),
                Component::RootDir | Component::Prefix(_) => None,
            })
            .collect();

        if parts.is_empty() {
            // Should not happen for a real file, but be defensive.
            return "file_000".to_string();
        }

        // Last is filename; everything before is directory chain.
        let (dirs_in, leaf_in) = parts.split_at(parts.len() - 1);
        let leaf_in = &leaf_in[0];

        // Sanitize directories.
        let dirs_out: Vec<String> = dirs_in
            .iter()
            .map(|d| sanitize_dir_component(d))
            .collect();

        // Pull extension off the original leaf (preserved — it's part of
        // "file type" which the user explicitly wants kept).
        let ext = Path::new(leaf_in)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());

        let parent_key = dirs_out.join("/");

        // Prefer preserving a *structural* record-type stem.  Some
        // providers (notably X / Twitter) encode the record type in the
        // leaf filename itself — `account.txt`, `tweets.txt`,
        // `direct-messages.txt`, `follower.txt` — rather than in the
        // directory layout.  We keep the stem ONLY when it matches a
        // known, non-PII warrant record vocabulary (after stripping any
        // leading numeric account-id prefix).  Everything else keeps the
        // privacy-first `file_NNN.ext` numbering.
        let leaf_out = if let Some(stem) = structural_leaf_stem(leaf_in) {
            let base = match &ext {
                Some(e) if !e.is_empty() => format!("{}.{}", stem, e),
                _ => stem,
            };
            self.dedupe_leaf(&parent_key, base)
        } else {
            let n = self.counters.entry(parent_key.clone()).or_insert(0);
            *n += 1;
            match &ext {
                Some(e) if !e.is_empty() => format!("file_{:03}.{}", n, e),
                _ => format!("file_{:03}", n),
            }
        };

        if dirs_out.is_empty() {
            leaf_out
        } else {
            format!("{}/{}", parent_key, leaf_out)
        }
    }

    /// Ensure a preserved structural leaf name is unique within its parent
    /// directory; on collision append `_2`, `_3`, …
    fn dedupe_leaf(&mut self, parent_key: &str, base: String) -> String {
        let set = self
            .used_leaves
            .entry(parent_key.to_string())
            .or_default();
        if set.insert(base.clone()) {
            return base;
        }
        let (stem, ext) = split_ext(&base);
        let mut i = 2usize;
        loop {
            let cand = match &ext {
                Some(e) => format!("{}_{}.{}", stem, i, e),
                None => format!("{}_{}", stem, i),
            };
            if set.insert(cand.clone()) {
                return cand;
            }
            i += 1;
        }
    }
}

// ─── Directory-component sanitizer ───────────────────────────────────────

fn sanitize_dir_component(s: &str) -> String {
    // The trimmed inspection token — but emit the sanitized form, not
    // the trimmed form, so unusual whitespace is preserved (rare).
    let t = s.trim();
    if t.is_empty() {
        return s.to_string();
    }

    if looks_like_email(t) {
        return "<redacted-email>".to_string();
    }
    if looks_like_uuid(t) {
        return "<redacted-uuid>".to_string();
    }
    if looks_like_phone(t) {
        return "<redacted-phone>".to_string();
    }
    if looks_like_high_entropy_id(t) {
        return "<redacted-id>".to_string();
    }
    s.to_string()
}

// An email-shaped fragment anywhere in the component is enough.
fn looks_like_email(s: &str) -> bool {
    // crude but adequate: something@something.something
    let mut it = s.splitn(2, '@');
    let local = it.next().unwrap_or("");
    let rest = match it.next() {
        Some(r) => r,
        None => return false,
    };
    if local.is_empty() || rest.is_empty() {
        return false;
    }
    let has_dot = rest.split('@').next().unwrap_or("").contains('.');
    has_dot
}

fn looks_like_uuid(s: &str) -> bool {
    // 8-4-4-4-12 hex
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn looks_like_phone(s: &str) -> bool {
    // Must be predominantly digits and have at least 10 digits, with
    // optional + or punctuation. Refuse if there is any letter.
    let mut digits = 0usize;
    let mut has_letter = false;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            has_letter = true;
            break;
        }
        if c.is_ascii_digit() {
            digits += 1;
        }
    }
    !has_letter && digits >= 10 && digits <= 15
}

fn looks_like_high_entropy_id(s: &str) -> bool {
    // Reject anything short or with whitespace.
    if s.len() < 16 || s.contains(char::is_whitespace) {
        return false;
    }
    // Must be made up of hex / base64-ish characters only.
    let ok = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '/' || c == '='
    });
    if !ok {
        return false;
    }
    // Heuristic: a structural folder like `user_data` or `messages` is
    // long but has vowel-rich repeating shape.  An id like
    // `a1b2c3d4e5f60718` has a much higher digit ratio AND no English
    // vowel structure.  Use a small ruleset:
    //   * if at least 40% of chars are digits OR
    //   * if it looks like all-hex and is at least 24 chars,
    //   treat it as an id.
    let n = s.len() as f32;
    let digit_ratio =
        s.chars().filter(|c| c.is_ascii_digit()).count() as f32 / n;
    if digit_ratio >= 0.40 {
        return true;
    }
    let is_all_hex = s.chars().all(|c| c.is_ascii_hexdigit());
    if is_all_hex && s.len() >= 24 {
        return true;
    }
    // Also catch all-uppercase 20+ char tokens (common for opaque IDs)
    let upper = s
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .count();
    if upper as f32 / n >= 0.85 && s.len() >= 20 {
        return true;
    }
    false
}

// ─── Structural leaf-name preservation ───────────────────────────────────

/// Known warrant record-type filename stems (lower-case, extension-free).
/// These are structural — they identify a record type, contain no PII, and
/// are exactly what a parser author needs to see.  Preserved verbatim; any
/// leaf not in this set keeps the privacy-first `file_NNN` numbering.
///
/// Heavily weighted toward X / Twitter productions (where the record type
/// lives in the filename), plus a handful of common structural leaves used
/// by other providers.
const RECORD_STEMS: &[&str] = &[
    // ── X / Twitter ──
    "account",
    "account-limited",
    "account-creation-ip",
    "account-label",
    "account-suspension",
    "account-timezone",
    "expanded-profile",
    "verified-organization",
    "ageinfo",
    "screen-name-change",
    "timezone",
    "email-address-change",
    "phone-number",
    "tweets",
    "deleted-tweets",
    "tweet-headers",
    "deleted-tweet-headers",
    "moment",
    "article",
    "community-tweet",
    "community_tweet",
    "note-tweet",
    "direct-messages",
    "deleted-direct-messages",
    "direct-messages-group",
    "deleted-direct-messages-group",
    "message-event",
    "grok-chat-item",
    "audio-video-calls",
    "follower",
    "following",
    "like",
    "block",
    "mute",
    "lists",
    "lists-created",
    "lists-member",
    "lists-subscribed",
    "saved-search",
    "ad-impressions",
    "ad-engagements",
    "ad-mobile-conversions-attributed",
    "personalization",
    "ads-revenue-sharing",
    "catalog",
    "commerce",
    "product",
    "shop",
    "shopify",
    "community-note",
    "spaces",
    "periscope",
    "ip-audit",
    "device",
    "device-token",
    "sso",
    "key-registry",
    "connected-application",
    "connected-app-permissions",
    "user-directory",
    // ── Common structural leaves from other providers ──
    "conversations",
    "messages",
    "subscriber_info",
    "login_history",
    "friends",
    "snap_history",
    "ai_conversations",
    "call_logs",
    "memories",
    "geo_locations",
    "device_advertising_id",
    "readme",
    "index",
    "manifest",
];

/// Return a cleaned, structural leaf *stem* (no extension) when the leaf
/// filename is a recognised record-type token safe to preserve, else
/// `None` (the caller then applies `file_NNN` numbering).
fn structural_leaf_stem(leaf_in: &str) -> Option<String> {
    let stem = Path::new(leaf_in).file_stem().and_then(|s| s.to_str())?;
    let core = strip_numeric_id_prefix(stem);
    if core.is_empty() {
        return None;
    }
    // Defence-in-depth: never preserve a PII-shaped stem even if it somehow
    // collides with the vocabulary.
    if looks_like_email(core)
        || looks_like_uuid(core)
        || looks_like_phone(core)
        || looks_like_high_entropy_id(core)
    {
        return None;
    }
    let lower = core.to_ascii_lowercase();
    if RECORD_STEMS.contains(&lower.as_str()) {
        // Preserve the original casing (e.g. `README`), matched case-insensitively.
        Some(core.to_string())
    } else {
        None
    }
}

/// Strip a leading numeric account-id prefix: `1234567890-account` →
/// `account`.  Only strips when the head is ≥4 digits and something follows.
fn strip_numeric_id_prefix(stem: &str) -> &str {
    if let Some((head, rest)) = stem.split_once('-') {
        if head.len() >= 4
            && !rest.is_empty()
            && head.chars().all(|c| c.is_ascii_digit())
        {
            return rest;
        }
    }
    stem
}

fn split_ext(name: &str) -> (String, Option<String>) {
    let p = Path::new(name);
    match p.extension().and_then(|e| e.to_str()) {
        Some(e) => {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
            (stem.to_string(), Some(e.to_string()))
        }
        None => (name.to_string(), None),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &str) -> String {
        let mut sa = PathSanitizer::new();
        sa.sanitize(Path::new(p))
    }

    #[test]
    fn strips_leaf_with_extension() {
        let out = s("Messages/gamerboychris@yahoo.com_Inbox.html");
        assert_eq!(out, "Messages/file_001.html");
    }

    #[test]
    fn strips_leaf_no_extension() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("Messages/SOMEFILE"));
        assert_eq!(out, "Messages/file_001");
    }

    #[test]
    fn redacts_email_dir() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("Yahoo/gamerboychris@yahoo.com_84073/Messages/x.html"));
        assert_eq!(out, "Yahoo/<redacted-email>/Messages/file_001.html");
    }

    #[test]
    fn redacts_uuid_dir() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new(
            "exports/550e8400-e29b-41d4-a716-446655440000/a.csv",
        ));
        assert_eq!(out, "exports/<redacted-uuid>/file_001.csv");
    }

    #[test]
    fn redacts_phone_dir() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("sms/+15551234567/a.html"));
        assert_eq!(out, "sms/<redacted-phone>/file_001.html");
    }

    #[test]
    fn redacts_high_entropy_id_dir() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("users/a1b2c3d4e5f60718abcdef00/data.json"));
        assert_eq!(out, "users/<redacted-id>/file_001.json");
    }

    #[test]
    fn keeps_structural_dirs() {
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("Messages/Inbox/Attachments/file.bin"));
        assert_eq!(out, "Messages/Inbox/Attachments/file_001.bin");
    }

    #[test]
    fn per_parent_sequential_numbering() {
        let mut sa = PathSanitizer::new();
        assert_eq!(sa.sanitize(Path::new("A/x.html")), "A/file_001.html");
        assert_eq!(sa.sanitize(Path::new("A/y.html")), "A/file_002.html");
        assert_eq!(sa.sanitize(Path::new("B/z.html")), "B/file_001.html");
        assert_eq!(sa.sanitize(Path::new("A/q.html")), "A/file_003.html");
    }

    #[test]
    fn root_level_file() {
        // README is a recognised structural manifest — preserved verbatim
        // (it's the content catalog in an X production).
        let mut sa = PathSanitizer::new();
        let out = sa.sanitize(Path::new("README.txt"));
        assert_eq!(out, "README.txt");
    }

    #[test]
    fn email_without_dot_not_redacted() {
        // be conservative — don't treat "foo@bar" as an email
        assert_eq!(sanitize_dir_component("foo@bar"), "foo@bar");
    }

    #[test]
    fn short_id_not_redacted() {
        // "abc123" is short, should pass through
        assert_eq!(sanitize_dir_component("abc123"), "abc123");
    }

    #[test]
    fn english_word_not_treated_as_id() {
        assert_eq!(sanitize_dir_component("messages"), "messages");
        assert_eq!(sanitize_dir_component("Attachments"), "Attachments");
        assert_eq!(sanitize_dir_component("user_data_backup"), "user_data_backup");
    }

    // ── Structural leaf-name preservation (X / Twitter) ──

    #[test]
    fn preserves_x_record_type_leaf() {
        assert_eq!(s("tweets.txt"), "tweets.txt");
        assert_eq!(s("direct-messages.txt"), "direct-messages.txt");
        assert_eq!(s("follower.txt"), "follower.txt");
        assert_eq!(s("ad-impressions.txt"), "ad-impressions.txt");
    }

    #[test]
    fn strips_numeric_account_prefix_on_leaf() {
        // `<accountId>-account.txt` → `account.txt`
        assert_eq!(s("1234567890-account.txt"), "account.txt");
        assert_eq!(
            s("999888777-direct-messages-group.txt"),
            "direct-messages-group.txt"
        );
    }

    #[test]
    fn distinguishes_follower_from_following() {
        // The whole point: these differ ONLY by filename.
        let mut sa = PathSanitizer::new();
        assert_eq!(sa.sanitize(Path::new("follower.txt")), "follower.txt");
        assert_eq!(sa.sanitize(Path::new("following.txt")), "following.txt");
    }

    #[test]
    fn non_vocab_leaf_still_numbered() {
        // Unknown / opaque leaves keep the privacy-first numbering.
        assert_eq!(s("random-notes.txt"), "file_001.txt");
        assert_eq!(s("IMG_2093.jpg"), "file_001.jpg");
    }

    #[test]
    fn media_named_by_id_is_numbered_not_preserved() {
        // X media: `<tweetId>-<token>.jpg` → not a record stem → numbered.
        assert_eq!(
            s("2009594515716546639-Ab12Cd.jpg"),
            "file_001.jpg"
        );
    }

    #[test]
    fn dedupes_duplicate_structural_leaves() {
        let mut sa = PathSanitizer::new();
        assert_eq!(sa.sanitize(Path::new("A/tweets.txt")), "A/tweets.txt");
        assert_eq!(sa.sanitize(Path::new("A/tweets.txt")), "A/tweets_2.txt");
    }
}
