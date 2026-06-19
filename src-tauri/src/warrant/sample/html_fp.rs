//! HTML structural fingerprint.
//!
//! Walks the DOM via `scraper` and captures:
//! - Per-tag occurrence counts
//! - Per-tag unique class/id combinations (capped)
//! - Table structures (rows + per-row column counts)
//! - Form input fields (name + type, no values)
//! - Anchor target structure (count of href/src by URL scheme bucket)
//! - Max depth
//!
//! **Never captured**: text nodes, attribute values other than class/id/
//! input-name/input-type/href-scheme, image data, scripts.
//!
//! The user picked "minimal redaction" so we KEEP class names and ids
//! verbatim (no digit-normalization).

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::MAX_NODES_PER_FILE;

const MAX_CLASS_COMBOS_PER_TAG: usize = 32;
const MAX_IDS_PER_TAG: usize = 32;
const MAX_FORM_FIELDS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HtmlFingerprint {
    pub doctype: String,
    pub tag_counts: BTreeMap<String, usize>,
    pub class_combos: BTreeMap<String, BTreeSet<String>>,
    pub ids: BTreeMap<String, BTreeSet<String>>,
    pub tables: TableStats,
    pub forms: Vec<FormInfo>,
    pub anchor_schemes: BTreeMap<String, usize>,
    pub max_depth: usize,
    pub element_count: usize,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableStats {
    pub n: usize,
    pub rows_min: usize,
    pub rows_max: usize,
    pub rows_sum: usize,
    pub cols_min: usize,
    pub cols_max: usize,
    /// First N tables: column-count distribution per row (no headers/text).
    pub samples: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FormInfo {
    pub method: String,
    pub action_scheme: String,
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FormField {
    pub name: String,
    pub input_type: String,
}

// ─── Entry points ────────────────────────────────────────────────────────

pub fn inspect(bytes: &[u8]) -> Value {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).to_string(),
    };
    let mut fp = HtmlFingerprint::default();
    fp.doctype = sniff_doctype(&text);

    let doc = Html::parse_document(&text);
    walk(&doc, &mut fp);
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

pub fn inspect_xml(bytes: &[u8]) -> Value {
    // For XML we use the same tree-walker; scraper treats it as a fragment.
    let text = String::from_utf8_lossy(bytes).to_string();
    let mut fp = HtmlFingerprint::default();
    fp.doctype = "xml".into();
    let doc = Html::parse_fragment(&text);
    walk(&doc, &mut fp);
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

fn sniff_doctype(text: &str) -> String {
    let head: String = text.chars().take(256).collect();
    let lower = head.to_ascii_lowercase();
    if let Some(i) = lower.find("<!doctype") {
        let tail = &head[i..];
        let end = tail.find('>').unwrap_or(tail.len()).min(80);
        tail[..end].replace('\n', " ").to_string()
    } else {
        "(none)".into()
    }
}

// ─── Walker ──────────────────────────────────────────────────────────────

fn walk(doc: &Html, fp: &mut HtmlFingerprint) {
    use scraper::node::Node;

    // Iterative depth-tracked walk via explicit stack of (node, depth).
    // Avoids recursion / closure type issues with ego_tree types.
    let mut stack: Vec<(_, usize)> = vec![(doc.tree.root(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if fp.element_count >= MAX_NODES_PER_FILE {
            fp.truncated = true;
            break;
        }
        if depth > fp.max_depth {
            fp.max_depth = depth;
        }

        if let Node::Element(el) = node.value() {
            fp.element_count += 1;
            let tag = el.name().to_string();
            *fp.tag_counts.entry(tag.clone()).or_insert(0) += 1;
            if let Some(cls) = el.attr("class") {
                let combos = fp.class_combos.entry(tag.clone()).or_default();
                if combos.len() < MAX_CLASS_COMBOS_PER_TAG {
                    combos.insert(cls.trim().to_string());
                }
            }
            if let Some(id) = el.attr("id") {
                let ids = fp.ids.entry(tag.clone()).or_default();
                if ids.len() < MAX_IDS_PER_TAG {
                    ids.insert(id.to_string());
                }
            }
            if tag == "a" {
                if let Some(href) = el.attr("href") {
                    *fp.anchor_schemes
                        .entry(scheme_bucket(href))
                        .or_insert(0) += 1;
                }
            }
            if tag == "img" {
                if let Some(src) = el.attr("src") {
                    *fp.anchor_schemes
                        .entry(format!("img:{}", scheme_bucket(src)))
                        .or_insert(0) += 1;
                }
            }
        }

        // Push children — only Element/Document/Fragment, never Text/Comment
        for child in node.children() {
            match child.value() {
                Node::Element(_) | Node::Document | Node::Fragment => {
                    stack.push((child, depth + 1));
                }
                _ => {}
            }
        }
    }

    // Walk tables specifically for row/column distribution.
    let table_sel = Selector::parse("table").unwrap();
    let tr_sel = Selector::parse("tr").unwrap();
    let cell_sel = Selector::parse("td, th").unwrap();
    for (i, t) in doc.select(&table_sel).enumerate() {
        fp.tables.n += 1;
        let mut rows: Vec<usize> = Vec::new();
        for tr in t.select(&tr_sel) {
            let cols = tr.select(&cell_sel).count();
            rows.push(cols);
        }
        let row_count = rows.len();
        let col_min = rows.iter().copied().min().unwrap_or(0);
        let col_max = rows.iter().copied().max().unwrap_or(0);
        if fp.tables.n == 1 || row_count < fp.tables.rows_min {
            fp.tables.rows_min = row_count;
        }
        if row_count > fp.tables.rows_max { fp.tables.rows_max = row_count; }
        fp.tables.rows_sum += row_count;
        if fp.tables.n == 1 || col_min < fp.tables.cols_min { fp.tables.cols_min = col_min; }
        if col_max > fp.tables.cols_max { fp.tables.cols_max = col_max; }
        if i < 8 {
            fp.tables.samples.push(rows);
        }
    }

    // Walk forms for input fields (name + type, no values).
    let form_sel = Selector::parse("form").unwrap();
    let input_sel = Selector::parse("input, select, textarea").unwrap();
    for f in doc.select(&form_sel) {
        let el = f.value();
        let method = el.attr("method").unwrap_or("").to_ascii_lowercase();
        let action_scheme = el.attr("action").map(scheme_bucket).unwrap_or_else(|| "none".into());
        let mut fields = Vec::new();
        for inp in f.select(&input_sel) {
            if fields.len() >= MAX_FORM_FIELDS { break; }
            let iel = inp.value();
            fields.push(FormField {
                name: iel.attr("name").unwrap_or("").to_string(),
                input_type: iel.attr("type")
                    .unwrap_or(iel.name())
                    .to_string(),
            });
        }
        fp.forms.push(FormInfo {
            method,
            action_scheme,
            fields,
        });
        if fp.forms.len() >= 32 { break; }
    }
}

fn scheme_bucket(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    let lower = lower.trim();
    if lower.is_empty() { return "empty".into(); }
    if lower.starts_with("https://") { return "https".into(); }
    if lower.starts_with("http://") { return "http".into(); }
    if lower.starts_with("mailto:") { return "mailto".into(); }
    if lower.starts_with("tel:") { return "tel".into(); }
    if lower.starts_with("data:") { return "data".into(); }
    if lower.starts_with("javascript:") { return "javascript".into(); }
    if lower.starts_with('#') { return "fragment".into(); }
    if lower.starts_with('/') { return "rooted_relative".into(); }
    if lower.contains("://") {
        let scheme: String = lower.chars().take_while(|c| *c != ':').collect();
        return scheme;
    }
    "relative".into()
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build(html: &str) -> HtmlFingerprint {
        let raw = inspect(html.as_bytes());
        serde_json::from_value(raw).unwrap()
    }

    #[test]
    fn basic_tag_counts() {
        let fp = build(r#"<!DOCTYPE html><html><body><div></div><div></div><span></span></body></html>"#);
        assert_eq!(fp.tag_counts.get("div").copied(), Some(2));
        assert_eq!(fp.tag_counts.get("span").copied(), Some(1));
        assert!(fp.tag_counts.contains_key("body"));
    }

    #[test]
    fn captures_class_and_id() {
        let fp = build(r#"<html><body>
            <div class="message _2pi3">hi</div>
            <div class="message _2pi3">there</div>
            <div class="message _2lej">heya</div>
            <span id="header"></span>
        </body></html>"#);
        let div_classes = &fp.class_combos["div"];
        assert!(div_classes.contains("message _2pi3"));
        assert!(div_classes.contains("message _2lej"));
        assert!(fp.ids.get("span").unwrap().contains("header"));
    }

    #[test]
    fn no_text_content_leaks() {
        let secret = "Alice's victim statement";
        let html = format!(
            r#"<html><body><div class="msg">{}</div></body></html>"#,
            secret
        );
        let raw = inspect(html.as_bytes());
        let raw_str = serde_json::to_string(&raw).unwrap();
        assert!(!raw_str.contains(secret), "text node leaked!");
    }

    #[test]
    fn table_dims() {
        let fp = build(r#"<html><body><table>
            <tr><th>a</th><th>b</th><th>c</th></tr>
            <tr><td>1</td><td>2</td><td>3</td></tr>
            <tr><td>4</td><td>5</td><td>6</td></tr>
        </table></body></html>"#);
        assert_eq!(fp.tables.n, 1);
        assert_eq!(fp.tables.cols_max, 3);
        assert_eq!(fp.tables.rows_max, 3);
        // No text leak in samples — they're just column COUNTS per row
        let raw = serde_json::to_string(&fp.tables.samples).unwrap();
        assert!(!raw.contains('a') && !raw.contains('1'),
            "table samples leaked text: {}", raw);
    }

    #[test]
    fn forms_capture_field_names_no_values() {
        let fp = build(r#"<html><body><form method="POST" action="/submit">
            <input type="text" name="username" value="alice"/>
            <input type="password" name="password" value="supersecret"/>
            <input type="submit" name="go" value="Go"/>
        </form></body></html>"#);
        assert_eq!(fp.forms.len(), 1);
        let f = &fp.forms[0];
        assert_eq!(f.method, "post");
        let names: Vec<&str> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"username"));
        assert!(names.contains(&"password"));
        let raw = serde_json::to_string(&fp).unwrap();
        assert!(!raw.contains("alice"));
        assert!(!raw.contains("supersecret"));
    }

    #[test]
    fn anchor_scheme_buckets() {
        let fp = build(r#"<html><body>
            <a href="https://example.com">a</a>
            <a href="https://other.com">b</a>
            <a href="mailto:foo@bar.com">c</a>
            <a href="/relative">d</a>
        </body></html>"#);
        assert_eq!(fp.anchor_schemes.get("https").copied(), Some(2));
        assert_eq!(fp.anchor_schemes.get("mailto").copied(), Some(1));
        assert_eq!(fp.anchor_schemes.get("rooted_relative").copied(), Some(1));
    }
}
