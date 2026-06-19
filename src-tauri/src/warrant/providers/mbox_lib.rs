//! Shared MBOX / RFC822 email parsing utilities.
//!
//! Used by any provider whose warrant return ships `.mbox` files —
//! currently Google Takeout / LERS Mail.MessageContent and Yahoo Mail
//! (when the production contains an .mbox export rather than per-message
//! HTML).  Both providers iterate the messages this module emits and turn
//! each into a `WarrantItem` in their own way (subscriber email, section
//! key, attachment storage strategy etc.).
//!
//! This file deliberately has zero knowledge of `WarrantItem`, `ParseCtx`,
//! or any provider — it only operates on `&str` / `&[u8]` and returns the
//! lightweight [`EmailMsg`] struct.

use base64::Engine;

#[derive(Debug, Default, Clone)]
pub struct EmailMsg {
    pub from: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub bcc: Option<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub labels: Option<String>,
    pub received_ips: Vec<String>,
    pub body_text: Option<String>,
    /// (filename, mime_type, bytes)
    pub attachments: Vec<(String, String, Vec<u8>)>,
}

/// Split an mbox file into raw RFC822 message blobs.  Each message starts
/// with a line beginning `From ` (the "From envelope" line).
pub fn split_mbox(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut started = false;
    for line in text.lines() {
        if line.starts_with("From ") {
            if started && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            started = true;
            // skip the envelope line itself
            continue;
        }
        if started {
            current.push_str(line);
            current.push('\n');
        }
    }
    if started && !current.is_empty() {
        out.push(current);
    }
    out
}

pub fn parse_email_message(raw: &str) -> EmailMsg {
    let mut msg = EmailMsg::default();

    // Split headers from body at the first blank line.
    let (hdr_text, body_text_raw) = match raw.find("\n\n") {
        Some(i) => (&raw[..i], &raw[i + 2..]),
        None => (raw, ""),
    };

    // Unfold continuation lines.
    let headers = unfold_headers(hdr_text);

    for (name, val) in &headers {
        let lname = name.to_lowercase();
        let decoded = decode_mime_header(val);
        match lname.as_str() {
            "from" => msg.from = Some(decoded),
            "to" => msg.to = Some(decoded),
            "cc" => msg.cc = Some(decoded),
            "bcc" => msg.bcc = Some(decoded),
            "subject" => msg.subject = Some(decoded),
            "date" => msg.date = Some(decoded),
            "message-id" => msg.message_id = Some(decoded),
            // Both Gmail and Yahoo prefix label headers with their brand.
            "x-gmail-labels" | "x-ymail-osg" | "x-ymailosg" => msg.labels = Some(decoded),
            "received" => {
                // Extract bracketed IPv4 / IPv6 addresses.
                for ip in extract_ips(&decoded) {
                    if !msg.received_ips.contains(&ip) {
                        msg.received_ips.push(ip);
                    }
                }
            }
            _ => {}
        }
    }

    // Decode MIME body.
    let content_type = header_value(&headers, "content-type").unwrap_or_default();
    let cte = header_value(&headers, "content-transfer-encoding")
        .unwrap_or_default()
        .to_lowercase();

    if content_type.to_lowercase().contains("multipart/") {
        let boundary = parse_boundary(&content_type);
        if let Some(b) = boundary {
            let parts = split_multipart(body_text_raw, &b);
            for p in parts {
                let p_headers = unfold_headers(&p.headers);
                let p_ct = header_value(&p_headers, "content-type").unwrap_or_default();
                let p_cte = header_value(&p_headers, "content-transfer-encoding")
                    .unwrap_or_default()
                    .to_lowercase();
                let p_cd = header_value(&p_headers, "content-disposition").unwrap_or_default();

                let (filename, _ext) = parse_attachment_filename(&p_ct, &p_cd);
                let is_attachment = p_cd.to_lowercase().contains("attachment") || filename.is_some();

                if is_attachment {
                    if let Some(fname) = filename {
                        let mime = first_token_before_semi(&p_ct).to_string();
                        let decoded = decode_body(&p.body, &p_cte);
                        msg.attachments.push((fname, mime, decoded));
                    }
                    continue;
                }

                // First text/plain part wins as the body.
                if msg.body_text.is_none() && p_ct.to_lowercase().contains("text/plain") {
                    let decoded = decode_body(&p.body, &p_cte);
                    let s = decode_text_charset(&decoded, &p_ct);
                    msg.body_text = Some(s);
                }
            }
            if msg.body_text.is_none() {
                // Fall back to first text/html part stripped to text.
                for p in split_multipart(body_text_raw, &b) {
                    let p_headers = unfold_headers(&p.headers);
                    let p_ct = header_value(&p_headers, "content-type").unwrap_or_default();
                    if p_ct.to_lowercase().contains("text/html") {
                        let p_cte = header_value(&p_headers, "content-transfer-encoding")
                            .unwrap_or_default()
                            .to_lowercase();
                        let decoded = decode_body(&p.body, &p_cte);
                        let html_text = decode_text_charset(&decoded, &p_ct);
                        msg.body_text = Some(strip_html_to_text(&html_text));
                        break;
                    }
                }
            }
        }
    } else {
        // Single-part body.
        let decoded = decode_body(body_text_raw.as_bytes(), &cte);
        let txt = decode_text_charset(&decoded, &content_type);
        if content_type.to_lowercase().contains("text/html") {
            msg.body_text = Some(strip_html_to_text(&txt));
        } else {
            msg.body_text = Some(txt);
        }
    }

    msg
}

fn unfold_headers(hdr_text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in hdr_text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim_start());
                continue;
            }
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_string();
            let val = line[idx + 1..].trim().to_string();
            out.push((name, val));
        }
    }
    out
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let lname = name.to_lowercase();
    for (n, v) in headers {
        if n.to_lowercase() == lname {
            return Some(v.clone());
        }
    }
    None
}

fn extract_ips(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Naive IP extraction (IPv4 + IPv6 inside brackets).
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'[' {
            if let Some(end) = s[i + 1..].find(']') {
                let candidate = &s[i + 1..i + 1 + end];
                if candidate.contains(':') || candidate.split('.').count() == 4 {
                    out.push(candidate.to_string());
                }
                i += end + 2;
                continue;
            }
        }
        // IPv4 outside brackets
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let sub = &s[start..i];
            if sub.split('.').filter(|p| !p.is_empty()).count() == 4
                && sub.split('.').all(|p| p.parse::<u32>().map(|n| n <= 255).unwrap_or(false))
            {
                out.push(sub.to_string());
            }
            continue;
        }
        i += 1;
    }
    out
}

fn parse_boundary(content_type: &str) -> Option<String> {
    let ct = content_type.to_lowercase();
    let idx = ct.find("boundary=")?;
    let rest = &content_type[idx + "boundary=".len()..];
    let mut s = rest.trim().to_string();
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            return Some(s[1..1 + end].to_string());
        }
    }
    if let Some(end) = s.find(';') {
        s.truncate(end);
    }
    Some(s.trim().trim_matches('"').to_string())
}

struct MimePart {
    headers: String,
    body: Vec<u8>,
}

fn split_multipart(body: &str, boundary: &str) -> Vec<MimePart> {
    let dash_boundary = format!("--{}", boundary);
    let mut parts: Vec<MimePart> = Vec::new();
    let mut current_body: Vec<&str> = Vec::new();
    let mut current_headers: Vec<&str> = Vec::new();
    let mut in_headers = false;
    let mut started = false;

    for line in body.lines() {
        if line == dash_boundary || line == format!("{}--", dash_boundary) {
            if started {
                let hdr = current_headers.join("\n");
                let body_text = current_body.join("\n");
                parts.push(MimePart {
                    headers: hdr,
                    body: body_text.into_bytes(),
                });
            }
            current_body.clear();
            current_headers.clear();
            in_headers = true;
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            current_headers.push(line);
        } else {
            current_body.push(line);
        }
    }

    if started && (!current_headers.is_empty() || !current_body.is_empty()) {
        let hdr = current_headers.join("\n");
        let body_text = current_body.join("\n");
        parts.push(MimePart {
            headers: hdr,
            body: body_text.into_bytes(),
        });
    }

    parts
}

fn parse_attachment_filename(ct: &str, cd: &str) -> (Option<String>, Option<String>) {
    let find_name = |s: &str, key: &str| -> Option<String> {
        let lower = s.to_lowercase();
        let idx = lower.find(key)?;
        let rest = &s[idx + key.len()..];
        let mut name = rest.trim().to_string();
        if name.starts_with('"') {
            if let Some(end) = name[1..].find('"') {
                return Some(name[1..1 + end].to_string());
            }
        }
        if let Some(end) = name.find(';') {
            name.truncate(end);
        }
        Some(name.trim().to_string())
    };

    if let Some(n) = find_name(cd, "filename=") {
        let ext = n.rsplit('.').next().map(|s| s.to_string());
        return (Some(n), ext);
    }
    if let Some(n) = find_name(ct, "name=") {
        let ext = n.rsplit('.').next().map(|s| s.to_string());
        return (Some(n), ext);
    }
    (None, None)
}

fn first_token_before_semi(s: &str) -> &str {
    s.split(';').next().unwrap_or(s).trim()
}

fn decode_body(raw: &[u8], cte: &str) -> Vec<u8> {
    let cte = cte.trim().to_lowercase();
    match cte.as_str() {
        "base64" => {
            // Strip whitespace, decode permissively.
            let cleaned: String = raw
                .iter()
                .filter(|b| !b.is_ascii_whitespace())
                .map(|b| *b as char)
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(cleaned.as_bytes())
                .unwrap_or_else(|_| raw.to_vec())
        }
        "quoted-printable" => decode_quoted_printable(raw),
        _ => raw.to_vec(),
    }
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if c == b'=' {
            // Soft line break: '=\r\n' or '=\n'
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < input.len() && input[i + 1] == b'\r' && input[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 2 < input.len() {
                let hex = std::str::from_utf8(&input[i + 1..i + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn decode_text_charset(bytes: &[u8], content_type: &str) -> String {
    let ct = content_type.to_lowercase();
    let charset = if let Some(idx) = ct.find("charset=") {
        let rest = &content_type[idx + "charset=".len()..];
        let mut cs = rest.trim().to_string();
        if cs.starts_with('"') {
            if let Some(end) = cs[1..].find('"') {
                cs = cs[1..1 + end].to_string();
            }
        }
        if let Some(end) = cs.find(';') {
            cs.truncate(end);
        }
        cs.trim().to_lowercase()
    } else {
        "utf-8".to_string()
    };

    if charset == "utf-8" || charset == "us-ascii" || charset.is_empty() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // Best-effort: lossily decode as UTF-8 — most modern Gmail/Yahoo
    // bodies are UTF-8 anyway.
    String::from_utf8_lossy(bytes).into_owned()
}

fn decode_mime_header(s: &str) -> String {
    // RFC 2047 encoded-word decoding: =?charset?Q?text?= or =?charset?B?text?=
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = match after.find("?=") {
            Some(i) => i,
            None => {
                out.push_str(&rest[start..]);
                rest = "";
                break;
            }
        };
        let body = &after[..end];
        // Split: charset?enc?text
        let parts: Vec<&str> = body.splitn(3, '?').collect();
        if parts.len() == 3 {
            let _charset = parts[0];
            let enc = parts[1].to_lowercase();
            let text = parts[2];
            let decoded = match enc.as_str() {
                "b" => base64::engine::general_purpose::STANDARD
                    .decode(text.as_bytes())
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| text.to_string()),
                "q" => {
                    // Q encoding: '=' for hex, '_' for space
                    let mut s = String::new();
                    let bytes = text.as_bytes();
                    let mut i = 0;
                    while i < bytes.len() {
                        let b = bytes[i];
                        if b == b'_' {
                            s.push(' ');
                            i += 1;
                        } else if b == b'=' && i + 2 < bytes.len() {
                            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                            if let Ok(v) = u8::from_str_radix(hex, 16) {
                                s.push(v as char);
                            }
                            i += 3;
                        } else {
                            s.push(b as char);
                            i += 1;
                        }
                    }
                    s
                }
                _ => text.to_string(),
            };
            out.push_str(&decoded);
        } else {
            out.push_str(&rest[start..start + 2 + end + 2]);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

fn strip_html_to_text(html: &str) -> String {
    // Very crude — strip tags + collapse whitespace.  Good enough for triage.
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
            continue;
        }
        if c == '>' {
            in_tag = false;
            out.push(' ');
            continue;
        }
        if !in_tag {
            out.push(c);
        }
    }
    let mut prev_ws = false;
    let mut compact = String::with_capacity(out.len());
    for c in out.chars() {
        if c.is_whitespace() {
            if !prev_ws {
                compact.push(' ');
            }
            prev_ws = true;
        } else {
            compact.push(c);
            prev_ws = false;
        }
    }
    compact.trim().to_string()
}

// ─── Unit smoke test ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a single fake mbox message and assert that core fields
    /// (From, To, Subject, body, attachment) come back correctly.  Useful
    /// to catch refactor regressions without needing a real production.
    #[test]
    fn parse_simple_multipart_mbox() {
        let mbox = "From bogus@yahoo.com Wed Jun 19 12:00:00 2025\r\n\
            From: alice@yahoo.com\r\n\
            To: bob@yahoo.com\r\n\
            Subject: hello\r\n\
            Date: Wed, 19 Jun 2025 12:00:00 +0000\r\n\
            Content-Type: multipart/mixed; boundary=\"AAA\"\r\n\
            \n\
            --AAA\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \n\
            this is the body\r\n\
            --AAA\r\n\
            Content-Type: image/png; name=\"pic.png\"\r\n\
            Content-Disposition: attachment; filename=\"pic.png\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \n\
            aGVsbG8=\r\n\
            --AAA--\r\n";
        let msgs = split_mbox(mbox);
        assert_eq!(msgs.len(), 1, "expected 1 message");
        let m = parse_email_message(&msgs[0]);
        assert_eq!(m.from.as_deref(), Some("alice@yahoo.com"));
        assert_eq!(m.to.as_deref(), Some("bob@yahoo.com"));
        assert_eq!(m.subject.as_deref(), Some("hello"));
        assert!(m.body_text.as_deref().unwrap_or("").contains("this is the body"));
        assert_eq!(m.attachments.len(), 1, "expected 1 attachment");
        let (fname, _mime, bytes) = &m.attachments[0];
        assert_eq!(fname, "pic.png");
        assert_eq!(bytes, b"hello");
    }
}
