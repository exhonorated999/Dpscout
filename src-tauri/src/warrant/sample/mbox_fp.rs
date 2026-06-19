//! MBOX / EML structural fingerprint.
//!
//! For a UNIX mbox stream we capture:
//! - Total message count (boundary `From ` lines)
//! - Set of unique header NAMES observed + per-name frequency
//! - MIME multipart shape distribution (depth, child counts)
//! - Counts of common content-types (text/plain, text/html, multipart/*, etc.)
//! - Whether messages carry X-* custom headers, which providers stash
//!   useful info in (e.g. X-Yahoo-Newman-Id, X-YMail-OSG)
//!
//! **Never captured**: header values, message bodies, From/To addresses,
//! subjects, message-IDs.
//!
//! For EML (single message), same structure applies but `message_count`
//! will be 1.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_HEADER_NAME_LEN: usize = 80;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MboxFingerprint {
    pub message_count: usize,
    pub header_names: BTreeMap<String, usize>,
    pub content_types: BTreeMap<String, usize>,
    pub mime_part_counts: PartCountStats,
    pub has_attachments_count: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartCountStats {
    pub min: usize,
    pub max: usize,
    pub sum: usize,
    pub n: usize,
}

impl PartCountStats {
    fn record(&mut self, k: usize) {
        if self.n == 0 || k < self.min { self.min = k; }
        if k > self.max { self.max = k; }
        self.sum += k;
        self.n += 1;
    }
}

pub fn inspect(bytes: &[u8]) -> Value {
    let mut fp = MboxFingerprint::default();
    walk(bytes, &mut fp);
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

pub fn inspect_single_message(bytes: &[u8]) -> Value {
    // Treat as a single message by prepending a synthetic boundary line.
    let mut wrapped: Vec<u8> = b"From wrapper@local Mon Jan 01 00:00:00 2000\n".to_vec();
    wrapped.extend_from_slice(bytes);
    let mut fp = MboxFingerprint::default();
    walk(&wrapped, &mut fp);
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

fn walk(bytes: &[u8], fp: &mut MboxFingerprint) {
    // Iterate line-by-line; state machine: scanning for boundary,
    // collecting headers, then body (skipped).
    let text = String::from_utf8_lossy(bytes);
    let mut in_message = false;
    let mut in_headers = false;
    let mut current_ct: Option<String> = None;
    let mut current_has_attach = false;
    let mut current_parts: usize = 0;
    let mut last_header: Option<String> = None;

    for line in text.split('\n') {
        let trimmed = line.trim_end_matches('\r');

        if trimmed.starts_with("From ") && (trimmed.contains(' ') || trimmed == "From ") {
            // New message boundary.
            if in_message {
                finalize_message(fp, current_ct.take(),
                    current_has_attach, current_parts);
            }
            fp.message_count += 1;
            in_message = true;
            in_headers = true;
            current_ct = None;
            current_has_attach = false;
            current_parts = 0;
            last_header = None;
            continue;
        }

        if !in_message {
            continue;
        }

        if in_headers {
            if trimmed.is_empty() {
                in_headers = false;
                last_header = None;
                continue;
            }

            // Continuation line? (starts with whitespace)
            if trimmed.starts_with(' ') || trimmed.starts_with('\t') {
                // Ignore continuation content; we already counted the header.
                continue;
            }
            // Standard header: "Name: value"
            if let Some(idx) = trimmed.find(':') {
                let name = &trimmed[..idx];
                if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN {
                    continue;
                }
                let lower = name.to_ascii_lowercase();
                *fp.header_names.entry(lower.clone()).or_insert(0) += 1;
                last_header = Some(lower.clone());

                // Pull out content-type bucket from value (but don't store value).
                if lower == "content-type" {
                    let val = trimmed[idx + 1..].trim();
                    let ct_main = val
                        .split(';').next().unwrap_or("")
                        .trim().to_ascii_lowercase();
                    if !ct_main.is_empty() {
                        *fp.content_types.entry(ct_main.clone()).or_insert(0) += 1;
                        current_ct = Some(ct_main);
                    }
                } else if lower == "content-disposition" {
                    let val = trimmed[idx + 1..].trim().to_ascii_lowercase();
                    if val.starts_with("attachment") {
                        current_has_attach = true;
                    }
                }
            }
        } else {
            // In body. We don't read content; we only:
            //  - count multipart boundary occurrences in multipart/*
            //  - watch for `Content-Disposition: attachment` lines INSIDE
            //    MIME part headers (no values captured — just the marker).
            if let Some(ref ct) = current_ct {
                if ct.starts_with("multipart/") && trimmed.starts_with("--") {
                    current_parts += 1;
                }
            }
            // Cheap substring check — works for nested part headers regardless
            // of how deep the multipart nesting goes.
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("content-disposition:")
                && lower.contains("attachment")
            {
                current_has_attach = true;
            }
        }
    }

    if in_message {
        finalize_message(fp, current_ct, current_has_attach, current_parts);
    }
}

fn finalize_message(
    fp: &mut MboxFingerprint,
    ct: Option<String>,
    has_attach: bool,
    parts: usize,
) {
    if has_attach { fp.has_attachments_count += 1; }
    let is_multipart = ct.as_deref().map(|s| s.starts_with("multipart/"))
        .unwrap_or(false);
    if is_multipart {
        // boundary lines appear at start+each part+end, so subtract 1
        let count = parts.saturating_sub(1);
        fp.mime_part_counts.record(count);
    } else {
        fp.mime_part_counts.record(1);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build(content: &str) -> MboxFingerprint {
        let raw = inspect(content.as_bytes());
        serde_json::from_value(raw).unwrap()
    }

    #[test]
    fn counts_messages_and_header_names() {
        let mbox = "From alice@x.com Mon Jan 01 00:00:00 2024\n\
            From: alice@x.com\n\
            To: bob@y.com\n\
            Subject: Hello\n\
            Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
            X-Yahoo-Newman-Id: abc123\n\
            Content-Type: text/plain\n\
            \n\
            body content here\n\
            \n\
            From carol@x.com Tue Jan 02 00:00:00 2024\n\
            From: carol@x.com\n\
            To: dave@y.com\n\
            Content-Type: multipart/mixed; boundary=xyz\n\
            \n\
            --xyz\n\
            Content-Type: text/plain\n\
            \n\
            part1\n\
            --xyz\n\
            Content-Type: image/jpeg\n\
            Content-Disposition: attachment; filename=evidence.jpg\n\
            \n\
            JFIFstuff\n\
            --xyz--\n";
        let fp = build(mbox);
        assert_eq!(fp.message_count, 2);
        assert!(fp.header_names.contains_key("from"));
        assert!(fp.header_names.contains_key("subject"));
        assert!(fp.header_names.contains_key("x-yahoo-newman-id"));
        assert!(fp.content_types.contains_key("text/plain"));
        assert!(fp.content_types.contains_key("multipart/mixed"));
    }

    #[test]
    fn no_values_or_addresses_leak() {
        let mbox = "From alice@victim-domain.com Mon Jan 01 00:00:00 2024\n\
            From: alice@victim-domain.com\n\
            To: suspect@perp.org\n\
            Subject: Highly sensitive case details\n\
            X-Custom: leak-me\n\
            \n\
            body must not leak either\n";
        let raw = inspect(mbox.as_bytes());
        let s = serde_json::to_string(&raw).unwrap();
        assert!(!s.contains("alice@victim-domain.com"), "leaked from addr");
        assert!(!s.contains("suspect@perp.org"), "leaked to addr");
        assert!(!s.contains("Highly sensitive"), "leaked subject");
        assert!(!s.contains("leak-me"), "leaked custom value");
        assert!(!s.contains("body must not"), "leaked body");
        // Header NAMES are fine
        assert!(s.contains("x-custom"));
    }

    #[test]
    fn detects_attachment() {
        let mbox = "From a Mon Jan 01 00:00:00 2024\n\
            Content-Type: multipart/mixed\n\
            \n\
            --b\n\
            Content-Disposition: attachment; filename=x.jpg\n\
            \n\
            \n";
        let fp = build(mbox);
        assert_eq!(fp.has_attachments_count, 1);
    }
}
