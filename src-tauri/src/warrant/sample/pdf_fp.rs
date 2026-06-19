//! PDF structural fingerprint.
//!
//! Lightweight, pure-Rust PDF inspection — we only look at the catalog and
//! count pages.  No text extraction, no fonts unless trivially recoverable
//! from the header.  Warrant returns rarely use PDF for structured data;
//! this is here mostly to flag attachments and give parser authors a
//! sense of "this folder has 12 PDFs of size ~3 MB each."
//!
//! **Never captured**: page text, form fields with values, annotations,
//! embedded images.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfFingerprint {
    pub version: String,
    pub page_count_estimate: usize,
    pub has_xref: bool,
    pub has_encrypt: bool,
    pub has_acroform: bool,
}

pub fn inspect(bytes: &[u8]) -> Value {
    let mut fp = PdfFingerprint::default();
    if bytes.starts_with(b"%PDF-") {
        let end = std::cmp::min(8, bytes.len());
        fp.version = String::from_utf8_lossy(&bytes[..end]).into_owned();
    } else {
        fp.version = "(not pdf)".into();
        return serde_json::to_value(fp).unwrap_or(Value::Null);
    }

    // Cheap textual scans across the byte stream — PDF is mostly ASCII
    // commands even when the content streams are binary.
    fp.page_count_estimate = count_substr(bytes, b"/Type /Page")
        + count_substr(bytes, b"/Type/Page");
    // Subtract /Pages entries which match both
    let pages_index = count_substr(bytes, b"/Type /Pages")
        + count_substr(bytes, b"/Type/Pages");
    fp.page_count_estimate = fp.page_count_estimate.saturating_sub(pages_index);

    fp.has_xref = find_substr(bytes, b"\nxref\n").is_some()
        || find_substr(bytes, b"\nstartxref\n").is_some();
    fp.has_encrypt = find_substr(bytes, b"/Encrypt").is_some();
    fp.has_acroform = find_substr(bytes, b"/AcroForm").is_some();

    serde_json::to_value(fp).unwrap_or(Value::Null)
}

fn count_substr(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() { return 0; }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pdf_header() {
        let bytes = b"%PDF-1.5\n%more stuff";
        let raw = inspect(bytes);
        let fp: PdfFingerprint = serde_json::from_value(raw).unwrap();
        assert!(fp.version.starts_with("%PDF-1.5"));
    }
    #[test]
    fn non_pdf_returns_marker() {
        let bytes = b"not a pdf at all";
        let raw = inspect(bytes);
        let fp: PdfFingerprint = serde_json::from_value(raw).unwrap();
        assert_eq!(fp.version, "(not pdf)");
    }
    #[test]
    fn no_text_leak() {
        let secret = "case content embedded text 12345";
        let mut bytes: Vec<u8> = b"%PDF-1.4\n".to_vec();
        bytes.extend_from_slice(secret.as_bytes());
        bytes.extend_from_slice(b"\nxref\n");
        let raw = inspect(&bytes);
        let s = serde_json::to_string(&raw).unwrap();
        assert!(!s.contains(secret), "PDF text leaked: {}", s);
    }
}
