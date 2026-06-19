//! Value-format inference.
//!
//! Given a sequence of raw string values seen at the same JSON path or CSV
//! column, decide what **kind** of string this is — without ever recording
//! the values themselves.
//!
//! The output is a single short tag like `"iso8601_timestamp"`,
//! `"unix_ms"`, `"email"`, etc.  Parser authors use these tags to skip the
//! "what format is this timestamp?" guess-work that would otherwise
//! require seeing real evidence.
//!
//! Strict rule: this module **only** examines the value strings.  The
//! inferred tag is the only thing that leaves this module — never the
//! values themselves.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringStats {
    /// Number of values examined.
    pub n: usize,
    /// Minimum byte length seen (None if n == 0).
    pub min_len: Option<usize>,
    /// Maximum byte length seen.
    pub max_len: Option<usize>,
    /// Best-guess inferred semantic tag (see `infer_tag`).
    pub inferred: Option<String>,
}

impl StringStats {
    pub fn record(&mut self, v: &str) {
        self.n += 1;
        let len = v.len();
        self.min_len = Some(self.min_len.map_or(len, |x| x.min(len)));
        self.max_len = Some(self.max_len.map_or(len, |x| x.max(len)));
    }
    pub fn finalize_with(&mut self, samples: &[&str]) {
        self.inferred = infer_tag_from_samples(samples);
    }
}

/// Inspect up to N samples and return a single tag, or None if we can't
/// confidently classify.  "Confidently" = at least 80% of non-empty samples
/// match the candidate.
pub fn infer_tag_from_samples(samples: &[&str]) -> Option<String> {
    let non_empty: Vec<&str> = samples
        .iter()
        .copied()
        .filter(|s| !s.is_empty())
        .collect();
    if non_empty.is_empty() {
        return None;
    }
    let threshold = ((non_empty.len() as f32) * 0.80).ceil() as usize;
    let threshold = threshold.max(1);

    // Candidate matchers, tried in order from most specific to least.
    let candidates: &[(&str, fn(&str) -> bool)] = &[
        ("iso8601_timestamp", is_iso8601),
        ("rfc2822_timestamp", is_rfc2822),
        ("uuid", is_uuid),
        ("sha256_hex", is_sha256_hex),
        ("sha1_hex", is_sha1_hex),
        ("md5_hex", is_md5_hex),
        ("email", is_email),
        ("phone_e164", is_phone_e164),
        ("phone_us10", is_phone_us10),
        ("url", is_url),
        ("ipv4", is_ipv4),
        ("ipv6", is_ipv6),
        ("base64", is_base64ish),
        ("unix_ms", is_unix_ms_string),
        ("unix_seconds", is_unix_seconds_string),
        ("integer_string", is_int_string),
        ("float_string", is_float_string),
        ("boolean_string", is_bool_string),
        ("hex_string", is_hex_string),
    ];

    for (tag, fun) in candidates {
        let hits = non_empty.iter().filter(|s| fun(s)).count();
        if hits >= threshold {
            return Some((*tag).to_string());
        }
    }

    // Fallback: bucket by length distribution
    let min = non_empty.iter().map(|s| s.len()).min().unwrap_or(0);
    let max = non_empty.iter().map(|s| s.len()).max().unwrap_or(0);
    Some(format!("string({}..{})", min, max))
}

// ─── Matchers (no value capture; just classification) ────────────────────

fn is_iso8601(s: &str) -> bool {
    // YYYY-MM-DD optionally followed by T HH:MM:SS, fractional secs, tz
    let b = s.as_bytes();
    if b.len() < 10 { return false; }
    let ymd = b[0].is_ascii_digit() && b[1].is_ascii_digit()
        && b[2].is_ascii_digit() && b[3].is_ascii_digit()
        && b[4] == b'-'
        && b[5].is_ascii_digit() && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit() && b[9].is_ascii_digit();
    if !ymd { return false; }
    if b.len() == 10 { return true; }
    if b[10] != b'T' && b[10] != b' ' { return false; }
    // Reasonable bounds
    s.len() <= 40
}

fn is_rfc2822(s: &str) -> bool {
    // "Mon, 19 Jun 2026 16:02:08 +0000" style
    let lower = s.to_ascii_lowercase();
    let days = ["mon,", "tue,", "wed,", "thu,", "fri,", "sat,", "sun,"];
    if !days.iter().any(|d| lower.starts_with(d)) { return false; }
    s.len() >= 25 && s.len() <= 40
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 { return false; }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => if *c != b'-' { return false; },
            _ => if !c.is_ascii_hexdigit() { return false; },
        }
    }
    true
}

fn is_sha256_hex(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }
fn is_sha1_hex(s: &str) -> bool { s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) }
fn is_md5_hex(s: &str) -> bool { s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()) }

fn is_email(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 5 || bytes.len() > 254 { return false; }
    let at = match s.find('@') { Some(i) => i, None => return false };
    let dot = match s[at..].find('.') { Some(i) => i, None => return false };
    at > 0 && dot > 0 && dot < s.len() - at - 1
        && !s.contains(' ') && !s.contains(',')
}

fn is_phone_e164(s: &str) -> bool {
    if !s.starts_with('+') { return false; }
    let rest = &s[1..];
    rest.len() >= 8 && rest.len() <= 15 && rest.bytes().all(|b| b.is_ascii_digit())
}

fn is_phone_us10(s: &str) -> bool {
    // Require at least one non-digit separator so pure 10-digit strings
    // (which are far more likely to be unix-second timestamps) don't get
    // mis-classified as phone numbers.
    let has_separator = s.chars().any(|c| matches!(c, '-' | '.' | ' ' | '(' | ')' | '+'));
    if !has_separator { return false; }
    let only_digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if only_digits.len() == 10 { return true; }
    if only_digits.len() == 11 && only_digits.starts_with('1') { return true; }
    false
}

fn is_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://"))
        && s.len() >= 10
        && !s.contains(' ')
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return false; }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

fn is_ipv6(s: &str) -> bool {
    // very loose: contains :: or at least 2 colons and all-hex/colon chars
    let has_double = s.contains("::");
    let colons = s.bytes().filter(|&b| b == b':').count();
    (has_double || colons >= 2)
        && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        && s.len() >= 3
        && s.len() <= 45
}

fn is_base64ish(s: &str) -> bool {
    if s.len() < 16 { return false; }
    let mut padding_ok = true;
    let pad_count = s.bytes().filter(|&b| b == b'=').count();
    if pad_count > 2 { padding_ok = false; }
    padding_ok
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
                || b == b'-' || b == b'_'
        })
}

fn is_int_string(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() { return false; }
    let start = if b[0] == b'-' || b[0] == b'+' { 1 } else { 0 };
    if start >= b.len() { return false; }
    b[start..].iter().all(|c| c.is_ascii_digit())
}

fn is_unix_seconds_string(s: &str) -> bool {
    if !is_int_string(s) { return false; }
    // 9–11 digits covers years ~1973–5138 in seconds
    let n = s.trim_start_matches('-').trim_start_matches('+').len();
    n >= 9 && n <= 11
}

fn is_unix_ms_string(s: &str) -> bool {
    if !is_int_string(s) { return false; }
    let n = s.trim_start_matches('-').trim_start_matches('+').len();
    n >= 12 && n <= 14
}

fn is_float_string(s: &str) -> bool {
    s.parse::<f64>().is_ok() && (s.contains('.') || s.contains('e') || s.contains('E'))
}

fn is_bool_string(s: &str) -> bool {
    matches!(s, "true" | "false" | "True" | "False" | "TRUE" | "FALSE"
        | "yes" | "no" | "Yes" | "No" | "Y" | "N" | "1" | "0")
}

fn is_hex_string(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && s.len() >= 8
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_basic() {
        assert!(is_iso8601("2026-06-19"));
        assert!(is_iso8601("2026-06-19T16:02:08Z"));
        assert!(is_iso8601("2026-06-19T16:02:08.123+00:00"));
        assert!(!is_iso8601("06/19/2026"));
        assert!(!is_iso8601("not a date"));
    }
    #[test]
    fn uuid_check() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000"));
    }
    #[test]
    fn email_check() {
        assert!(is_email("foo@bar.com"));
        assert!(is_email("a.b+c@example.co.uk"));
        assert!(!is_email("not-email"));
        assert!(!is_email("@no.com"));
    }
    #[test]
    fn unix_ms_vs_seconds() {
        assert!(is_unix_seconds_string("1781883803"));
        assert!(is_unix_ms_string("1781883803123"));
        assert!(!is_unix_seconds_string("1781883803123")); // too long
    }
    #[test]
    fn infer_from_samples_unix_ms() {
        let s = ["1781883803123", "1781883803456", "1781883803999"];
        let s_refs: Vec<&str> = s.iter().copied().collect();
        assert_eq!(infer_tag_from_samples(&s_refs).as_deref(), Some("unix_ms"));
    }
    #[test]
    fn infer_from_samples_email() {
        let s = ["a@b.com", "c@d.com", "e@f.com"];
        let s_refs: Vec<&str> = s.iter().copied().collect();
        assert_eq!(infer_tag_from_samples(&s_refs).as_deref(), Some("email"));
    }
    #[test]
    fn infer_fallback_string_range() {
        let s = ["alpha", "bravo", "charlie-delta"];
        let s_refs: Vec<&str> = s.iter().copied().collect();
        let tag = infer_tag_from_samples(&s_refs).unwrap();
        assert!(tag.starts_with("string("), "got: {}", tag);
    }
    #[test]
    fn empty_returns_none() {
        let s: [&str; 0] = [];
        assert!(infer_tag_from_samples(&s).is_none());
    }
}
