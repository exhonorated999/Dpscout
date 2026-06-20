//! HTML structural fingerprint.
//!
//! Walks the DOM via `scraper` and captures:
//! - Per-tag occurrence counts
//! - Per-tag unique class/id combinations (capped)
//! - Table structures (rows + per-row column counts)
//! - Form input fields (name + type, no values)
//! - Anchor target structure (count of href/src by URL scheme bucket)
//! - Max depth
//! - `<title>` text + `<meta name="...">` content (PII-scrubbed)
//! - Repeating text vocabulary (labels + sentinel phrases, PII-scrubbed)
//! - Per-id structural skeleton (immediate-child tag counts + class combos)
//!
//! **Never captured**: arbitrary text nodes, attribute values other than
//! class/id/input-name/input-type/href-scheme/title/meta-content, image
//! data, scripts.  Text that does pass through (title, meta, vocab) is
//! filtered by `is_pii_safe` so emails, URLs, ≥4-digit runs, UUIDs, and
//! oversize blobs are rejected before they leave the local machine.

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::MAX_NODES_PER_FILE;

const MAX_CLASS_COMBOS_PER_TAG: usize = 32;
const MAX_IDS_PER_TAG: usize = 32;
const MAX_FORM_FIELDS: usize = 64;
const MAX_TITLE_LEN: usize = 200;
const MAX_META_ENTRIES: usize = 32;
const MAX_META_VALUE_LEN: usize = 200;
const MAX_LABEL_LEN: usize = 40;
const MAX_SENTINEL_LEN: usize = 120;
const MIN_REPEAT_COUNT: usize = 2;
const MAX_LABEL_ENTRIES: usize = 60;
const MAX_SENTINEL_ENTRIES: usize = 24;
const MAX_SKELETON_DEPTH: usize = 3;

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
    /// `<title>` text content (PII-scrubbed, ≤200 chars). Empty when absent
    /// or rejected by the scrubber.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title_text: String,
    /// `<meta name="...">` → `content` pairs (PII-scrubbed). Identifies the
    /// provider for free in many returns ("Facebook Legal Request", etc.).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta_tags: BTreeMap<String, String>,
    /// Short repeating text tokens (length 2-40, count ≥2). These are the
    /// field labels a parser author needs to map into a normalized schema
    /// (`Author`, `Sent`, `Body`, `Posted`, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_vocab: Vec<LabelEntry>,
    /// Longer repeating phrases (length 5-120, count ≥2). Catches boiler-
    /// plate sentinels like "No responsive records located".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sentinel_phrases: Vec<LabelEntry>,
    /// Per-id structural skeleton — for each id we kept in `ids`, capture
    /// a small shape of the subtree so a parser can learn the repeating
    /// row template per bucket without seeing values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_id_skeleton: BTreeMap<String, IdSkeleton>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelEntry {
    pub text: String,
    pub count: usize,
}

/// Tiny shape blob describing the subtree rooted at an element with an id.
/// Keeps `tag_counts` for direct + near-descendants and a small set of
/// `class_combos`, plus a couple of useful raw counts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdSkeleton {
    /// Element tag of the node carrying this id (e.g. "div").
    pub tag: String,
    /// Class string on the id-bearing element itself, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// Tag occurrence within the subtree (depth ≤ MAX_SKELETON_DEPTH).
    pub child_tag_counts: BTreeMap<String, usize>,
    /// Class combos seen on direct children only (capped).
    pub child_class_combos: BTreeSet<String>,
    /// Total descendants visited (depth ≤ MAX_SKELETON_DEPTH).
    pub descendant_count: usize,
    /// Specifically: number of `<br>` descendants — useful because Meta /
    /// many providers separate field rows with `<br>`.
    pub br_count: usize,
    /// Number of nested `div_table`-style siblings (proxy for "rows").
    /// We just count direct children regardless of class — the parser
    /// author cross-references with `child_class_combos`.
    pub direct_child_count: usize,
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

    // Soft cap on unique text tokens we count before reducing them into
    // label_vocab / sentinel_phrases. Bounds memory in pathological pages.
    const MAX_TEXT_COUNTER_ENTRIES: usize = 20_000;
    let mut text_counter: HashMap<String, usize> = HashMap::new();

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

            // Special-case <title>: join direct text children.
            if tag == "title" && fp.title_text.is_empty() {
                let mut combined = String::new();
                for child in node.children() {
                    if let Node::Text(t) = child.value() {
                        if !combined.is_empty() { combined.push(' '); }
                        combined.push_str(&t.text);
                    }
                }
                let trimmed = combined.trim();
                if !trimmed.is_empty()
                    && trimmed.len() <= MAX_TITLE_LEN
                    && is_pii_safe(trimmed)
                {
                    fp.title_text = trimmed.to_string();
                }
            }

            // Special-case <meta name="..." content="...">. Also accept
            // OpenGraph "property" as a name source.
            if tag == "meta" && fp.meta_tags.len() < MAX_META_ENTRIES {
                let name = el.attr("name").or_else(|| el.attr("property"));
                let content = el.attr("content");
                if let (Some(n), Some(c)) = (name, content) {
                    let n = n.trim();
                    let c = c.trim();
                    if !n.is_empty()
                        && !c.is_empty()
                        && c.len() <= MAX_META_VALUE_LEN
                        && is_pii_safe(c)
                    {
                        fp.meta_tags
                            .entry(n.to_string())
                            .or_insert_with(|| c.to_string());
                    }
                }
            }

            // Collect direct text children (leaves) into the token counter.
            // This is intentionally narrow: text inside descendants is
            // counted when the descendant element itself is visited. That
            // gives us the label/value separator that legal-return HTML
            // uses ("Author", "Sent", "Body", ...).
            if text_counter.len() < MAX_TEXT_COUNTER_ENTRIES
                && tag != "script"
                && tag != "style"
                && tag != "title"
                && tag != "meta"
            {
                for child in node.children() {
                    if let Node::Text(t) = child.value() {
                        let s = t.text.trim();
                        if s.is_empty() { continue; }
                        let len = s.chars().count();
                        if len < 2 || len > MAX_SENTINEL_LEN { continue; }
                        // Cap before insert so we don't grow past the bound.
                        if text_counter.len() >= MAX_TEXT_COUNTER_ENTRIES
                            && !text_counter.contains_key(s)
                        {
                            continue;
                        }
                        *text_counter.entry(s.to_string()).or_insert(0) += 1;
                    }
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

    // Reduce text_counter → label_vocab + sentinel_phrases.
    reduce_text_counter(text_counter, fp);

    // Build per-id structural skeleton for each safe id.
    build_id_skeletons(doc, fp);

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

// ─── Helpers: PII scrubber, text reducer, id-skeleton builder ────────────

/// Reject strings that look like they carry user PII: emails, URLs, runs
/// of 4+ digits (phone numbers, account numbers, timestamps), dotted-quad
/// IPv4 addresses, or full UUIDs. Conservative — when in doubt, drop.
fn is_pii_safe(s: &str) -> bool {
    if s.is_empty() { return false; }
    if s.contains('@') { return false; }
    if s.contains("://") { return false; }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("www.") { return false; }
    let mut digit_run: usize = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digit_run += 1;
            if digit_run >= 4 { return false; }
        } else {
            digit_run = 0;
        }
    }
    if contains_dotted_quad(s) { return false; }
    if looks_like_uuid_anywhere(s) { return false; }
    true
}

/// Detect IPv4-style `D.D.D.D` anywhere in `s` where each `D` is 1–3
/// digits. Catches addresses that slip past the digit-run filter because
/// the dots break the run into ≤3-digit groups.
fn contains_dotted_quad(s: &str) -> bool {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n < 7 { return false; } // shortest possible: 1.1.1.1
    'outer: for start in 0..n {
        let mut pos = start;
        for group in 0..4 {
            let g_start = pos;
            while pos < n && bytes[pos].is_ascii_digit() && pos - g_start < 3 {
                pos += 1;
            }
            if pos == g_start { continue 'outer; }
            if group < 3 {
                if pos >= n || bytes[pos] != b'.' { continue 'outer; }
                pos += 1;
            }
        }
        return true;
    }
    false
}

/// True when the string looks like a UI label: every word starts with an
/// uppercase letter (joiners like `of`, `to`, `for`, `the` allowed mid-
/// phrase), optionally with a trailing colon. Reject free-form sentences
/// like `"this is a photo upload"` (subject-content text).
fn looks_like_label(s: &str) -> bool {
    let core = s.strip_suffix(':').unwrap_or(s).trim();
    if core.is_empty() { return false; }
    const JOINERS: &[&str] = &[
        "of", "to", "in", "for", "and", "or", "the", "a", "an",
        "on", "at", "by", "with", "from", "as",
    ];
    let mut first = true;
    for word in core.split_whitespace() {
        let c = match word.chars().next() {
            Some(c) => c,
            None => continue,
        };
        if !c.is_ascii_uppercase() {
            if first { return false; }
            let lw = word.to_ascii_lowercase();
            if !JOINERS.iter().any(|j| *j == lw) { return false; }
        }
        first = false;
    }
    !first
}

/// True when a string starts with a capital letter — used as a weak
/// signal that the text is boilerplate (a sentinel) rather than free-
/// form subject content. Subject-content text in legal returns is almost
/// always lowercase or starts with a number/punctuation.
fn looks_like_sentinel_shape(s: &str) -> bool {
    matches!(s.trim().chars().next(), Some(c) if c.is_ascii_uppercase())
}

fn looks_like_uuid_anywhere(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 36 { return false; }
    let max_start = bytes.len() - 36;
    'outer: for i in 0..=max_start {
        for (j, &b) in bytes[i..i + 36].iter().enumerate() {
            let want_dash = matches!(j, 8 | 13 | 18 | 23);
            if want_dash {
                if b != b'-' { continue 'outer; }
            } else if !(b as char).is_ascii_hexdigit() {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Drain the per-walk text counter into `label_vocab` (short tokens) and
/// `sentinel_phrases` (long phrases). Both are PII-scrubbed and capped.
fn reduce_text_counter(
    counter: HashMap<String, usize>,
    fp: &mut HtmlFingerprint,
) {
    let mut items: Vec<(String, usize)> = counter
        .into_iter()
        .filter(|(_, c)| *c >= MIN_REPEAT_COUNT)
        .collect();
    // Highest-count first; stable order on ties.
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (text, count) in items {
        if !is_pii_safe(&text) { continue; }
        let len = text.chars().count();
        if len <= MAX_LABEL_LEN {
            // Short text: only accept it as a LABEL if it looks like
            // one. Anything else that's at least sentinel-shape goes
            // into the sentinel bucket; pure content text is dropped.
            if looks_like_label(&text) {
                if fp.label_vocab.len() < MAX_LABEL_ENTRIES {
                    fp.label_vocab.push(LabelEntry { text, count });
                }
            } else if len >= 5 && looks_like_sentinel_shape(&text) {
                if fp.sentinel_phrases.len() < MAX_SENTINEL_ENTRIES {
                    fp.sentinel_phrases.push(LabelEntry { text, count });
                }
            }
            // else: drop — looks like free-form subject content.
        } else if len <= MAX_SENTINEL_LEN && looks_like_sentinel_shape(&text) {
            if fp.sentinel_phrases.len() < MAX_SENTINEL_ENTRIES {
                fp.sentinel_phrases.push(LabelEntry { text, count });
            }
        }
        if fp.label_vocab.len() >= MAX_LABEL_ENTRIES
            && fp.sentinel_phrases.len() >= MAX_SENTINEL_ENTRIES
        {
            break;
        }
    }
}

/// Build a small structural blob for each id we captured. Only ids whose
/// names are CSS-selector-safe (alnum + `-`/`_`, starting with a letter)
/// are processed — anything else is silently skipped. Cap total entries.
fn build_id_skeletons(doc: &Html, fp: &mut HtmlFingerprint) {
    const MAX_ID_SKELETONS: usize = 30;
    let mut all_ids: Vec<String> = Vec::new();
    for ids in fp.ids.values() {
        for id in ids {
            all_ids.push(id.clone());
        }
    }
    all_ids.sort();
    all_ids.dedup();

    for id in all_ids {
        if fp.per_id_skeleton.len() >= MAX_ID_SKELETONS { break; }
        if !id_is_selector_safe(&id) { continue; }
        let sel_str = format!("#{}", id);
        let sel = match Selector::parse(&sel_str) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Some(root) = doc.select(&sel).next() else { continue; };
        let root_el = root.value();
        let mut skel = IdSkeleton {
            tag: root_el.name().to_string(),
            class: root_el
                .attr("class")
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            ..Default::default()
        };
        // Direct-child stats.
        for child in root.children() {
            if let scraper::node::Node::Element(el) = child.value() {
                skel.direct_child_count += 1;
                if let Some(cls) = el.attr("class") {
                    if skel.child_class_combos.len() < MAX_CLASS_COMBOS_PER_TAG {
                        skel.child_class_combos.insert(cls.trim().to_string());
                    }
                }
            }
        }
        // Bounded depth walk for descendant tag counts + <br> count.
        let mut stack: Vec<(_, usize)> = vec![(*root, 0usize)];
        while let Some((node, depth)) = stack.pop() {
            if depth >= MAX_SKELETON_DEPTH { continue; }
            for child in node.children() {
                if let scraper::node::Node::Element(el) = child.value() {
                    let tag = el.name();
                    skel.descendant_count += 1;
                    *skel.child_tag_counts
                        .entry(tag.to_string())
                        .or_insert(0) += 1;
                    if tag == "br" {
                        skel.br_count += 1;
                    }
                    stack.push((child, depth + 1));
                    if skel.descendant_count >= 4096 {
                        // Pathological case — bail out for this id.
                        stack.clear();
                        break;
                    }
                }
            }
        }
        fp.per_id_skeleton.insert(id, skel);
    }
}

fn id_is_selector_safe(id: &str) -> bool {
    if id.is_empty() || id.len() > 80 { return false; }
    let first = id.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' { return false; }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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

    #[test]
    fn captures_title_when_pii_safe() {
        let fp = build(r#"<html><head><title>Facebook Legal Request</title></head><body></body></html>"#);
        assert_eq!(fp.title_text, "Facebook Legal Request");
    }

    #[test]
    fn rejects_title_with_email() {
        let fp = build(r#"<html><head><title>Records for jane@example.com</title></head><body></body></html>"#);
        assert!(fp.title_text.is_empty(),
            "title with email leaked: {}", fp.title_text);
    }

    #[test]
    fn rejects_title_with_long_digit_run() {
        let fp = build(r#"<html><head><title>Case 1234567 Records</title></head><body></body></html>"#);
        assert!(fp.title_text.is_empty(),
            "title with PII digits leaked: {}", fp.title_text);
    }

    #[test]
    fn captures_meta_tags() {
        let fp = build(r#"<html><head>
            <meta name="generator" content="Facebook Records">
            <meta name="application-name" content="Records Export">
            <meta property="og:type" content="website">
        </head><body></body></html>"#);
        assert_eq!(fp.meta_tags.get("generator").map(String::as_str),
            Some("Facebook Records"));
        assert_eq!(fp.meta_tags.get("og:type").map(String::as_str),
            Some("website"));
    }

    #[test]
    fn label_vocab_captures_repeating_labels() {
        let fp = build(r#"<html><body>
            <div class="div_table">Author<div>x</div></div>
            <div class="div_table">Author<div>y</div></div>
            <div class="div_table">Author<div>z</div></div>
            <div class="div_table">Body<div>p</div></div>
            <div class="div_table">Body<div>q</div></div>
        </body></html>"#);
        let labels: Vec<&str> = fp.label_vocab.iter().map(|l| l.text.as_str()).collect();
        assert!(labels.contains(&"Author"), "missing Author: {:?}", labels);
        assert!(labels.contains(&"Body"), "missing Body: {:?}", labels);
        let author = fp.label_vocab.iter().find(|l| l.text == "Author").unwrap();
        assert_eq!(author.count, 3);
    }

    #[test]
    fn label_vocab_drops_single_occurrences() {
        let fp = build(r#"<html><body>
            <div>Alice's victim statement</div>
            <span>One unique value</span>
        </body></html>"#);
        // Both appear only once → should not surface.
        let texts: Vec<&str> = fp.label_vocab.iter().map(|l| l.text.as_str()).collect();
        assert!(!texts.iter().any(|t| t.contains("Alice")));
        assert!(!texts.iter().any(|t| t.contains("unique")));
    }

    #[test]
    fn label_vocab_drops_pii_even_when_repeating() {
        let fp = build(r#"<html><body>
            <div>jane@example.com</div>
            <div>jane@example.com</div>
            <div>jane@example.com</div>
        </body></html>"#);
        let texts: Vec<&str> = fp.label_vocab.iter().map(|l| l.text.as_str()).collect();
        assert!(texts.is_empty() || !texts.iter().any(|t| t.contains('@')),
            "PII email leaked into label_vocab: {:?}", texts);
    }

    #[test]
    fn sentinel_phrases_capture_long_repeating_text() {
        let fp = build(r#"<html><body>
            <p>No responsive records located in this section.</p>
            <p>No responsive records located in this section.</p>
        </body></html>"#);
        let sentinels: Vec<&str> = fp.sentinel_phrases.iter().map(|s| s.text.as_str()).collect();
        assert!(sentinels.iter().any(|s| s.contains("No responsive records")),
            "sentinel missing: {:?}", sentinels);
    }

    #[test]
    fn per_id_skeleton_builds_for_safe_ids() {
        let fp = build(r#"<html><body>
            <div id="property-messages" class="bucket">
                <div class="row">Author</div>
                <div class="row">Body</div>
                <br/>
                <div class="row">Sent</div>
            </div>
        </body></html>"#);
        let skel = fp.per_id_skeleton.get("property-messages").expect("id missing");
        assert_eq!(skel.tag, "div");
        assert_eq!(skel.class, "bucket");
        assert!(skel.descendant_count > 0);
        assert_eq!(skel.br_count, 1);
        assert!(skel.child_class_combos.contains("row"));
    }

    #[test]
    fn per_id_skeleton_skips_unsafe_ids() {
        // ID containing characters that aren't selector-safe must not crash
        // the builder and must not appear in per_id_skeleton.
        let fp = build(r#"<html><body>
            <div id="user@1234567">x</div>
            <div id="safe-id">y</div>
        </body></html>"#);
        assert!(fp.per_id_skeleton.get("user@1234567").is_none());
        assert!(fp.per_id_skeleton.get("safe-id").is_some());
    }

    #[test]
    fn pii_scrubber_rules() {
        assert!(is_pii_safe("Author"));
        assert!(is_pii_safe("Sent on"));
        assert!(is_pii_safe("Body"));
        assert!(!is_pii_safe("foo@bar.com"));
        assert!(!is_pii_safe("https://example.com"));
        assert!(!is_pii_safe("Case 1234567"));
        assert!(!is_pii_safe("550e8400-e29b-41d4-a716-446655440000"));
        // Three digits in a row is OK (could be HTTP 200 / code 404 in
        // boilerplate).
        assert!(is_pii_safe("Code 200 OK"));
    }

    #[test]
    fn pii_scrubber_rejects_dotted_quad_ip() {
        // Specific leak from v0.9.4: dotted IPs slipped through because
        // the dots reset the 4-consecutive-digit counter.
        assert!(!is_pii_safe("57.132.133.127"));
        assert!(!is_pii_safe("192.168.0.1"));
        assert!(!is_pii_safe("IP was 10.0.0.5 today"));
        // Version strings with 4 dotted parts also caught — acceptable
        // false-positive (we'd rather drop signal than leak).
        assert!(!is_pii_safe("Version 1.2.3.4"));
        // Three-part dotted (no full IPv4) is fine.
        assert!(is_pii_safe("v1.2.3"));
    }

    #[test]
    fn label_shape_accepts_real_labels_rejects_sentences() {
        assert!(looks_like_label("Author"));
        assert!(looks_like_label("About Me"));
        assert!(looks_like_label("Linked Media File:"));
        assert!(looks_like_label("Posts To Other Walls"));
        assert!(looks_like_label("Date of Birth"));
        // Subject content — must be rejected
        assert!(!looks_like_label("this is a photo upload"));
        assert!(!looks_like_label("false"));
        assert!(!looks_like_label("image/jpeg"));
    }

    #[test]
    fn label_vocab_drops_subject_content_sentences() {
        // Repro of the v0.9.4 leak: lowercase caption text repeated
        // exactly twice slipped into label_vocab. With the label-shape
        // gate this must be dropped (or routed to sentinel — also OK
        // since sentinel-shape requires uppercase first char).
        let fp = build(r#"<html><body>
            <div>this is a photo upload</div>
            <div>this is a photo upload</div>
        </body></html>"#);
        let bad: Vec<_> = fp.label_vocab.iter()
            .chain(fp.sentinel_phrases.iter())
            .filter(|l| l.text == "this is a photo upload")
            .collect();
        assert!(bad.is_empty(),
            "subject caption leaked: {:?}", bad);
    }

    #[test]
    fn label_vocab_drops_ip_address() {
        let fp = build(r#"<html><body>
            <div>57.132.133.127</div>
            <div>57.132.133.127</div>
            <div>57.132.133.127</div>
        </body></html>"#);
        let bad: Vec<_> = fp.label_vocab.iter()
            .chain(fp.sentinel_phrases.iter())
            .filter(|l| l.text.contains("57.132.133.127"))
            .collect();
        assert!(bad.is_empty(),
            "IP leaked: {:?}", bad);
    }
}
