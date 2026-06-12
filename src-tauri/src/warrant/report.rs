//! Interactive HTML report exporter.
//!
//! Produces a self-describing folder:
//!
//! ```text
//! <dest>/<case_id>_warrant_report/
//! ├── index.html        # single-file interactive viewer
//! └── media/            # full-res linked_media copied from the case
//! ```
//!
//! The HTML embeds case data + thumbnails (base64, max 200px) inline so the
//! detective only needs the folder — no server, no install, just a double
//! click.  Clicking a thumbnail opens the full-res file via the relative
//! `media/<name>` path which the browser hands off to the OS for non-image
//! types (or renders in a new tab for JPGs).

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use image::{ImageFormat, ImageReader};

use super::triage_state::{self, Bucket, CaseDetail};
use super::WarrantItem;

const THUMB_MAX_DIM: u32 = 200;

#[derive(Debug)]
pub enum ReportError {
    State(triage_state::StateError),
    Io(std::io::Error),
    Json(serde_json::Error),
    Other(String),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::State(e) => write!(f, "state error: {}", e),
            ReportError::Io(e) => write!(f, "I/O error: {}", e),
            ReportError::Json(e) => write!(f, "JSON error: {}", e),
            ReportError::Other(s) => write!(f, "report error: {}", s),
        }
    }
}

impl From<triage_state::StateError> for ReportError {
    fn from(e: triage_state::StateError) -> Self {
        ReportError::State(e)
    }
}
impl From<std::io::Error> for ReportError {
    fn from(e: std::io::Error) -> Self {
        ReportError::Io(e)
    }
}
impl From<serde_json::Error> for ReportError {
    fn from(e: serde_json::Error) -> Self {
        ReportError::Json(e)
    }
}

/// Top-level entry point.  `dest_dir` is the parent the user picked
/// (typically a USB drive root); we create a uniquely-named subfolder
/// inside it and return the path.  Folder name format:
///
///   `Scout_Report_<provider>_<target>_<YYYYMMDD_HHMMSS>/`
///
/// — provider/target are sanitized to ASCII alphanumerics and a trailing
/// timestamp guarantees uniqueness so multiple exports never collide.
pub fn export_report(case_id: &str, dest_dir: &Path) -> Result<PathBuf, ReportError> {
    if !dest_dir.exists() {
        return Err(ReportError::Other(format!(
            "destination does not exist: {}",
            dest_dir.display()
        )));
    }

    let detail = triage_state::load_case_detail(case_id)?;

    // Build a friendly, unique folder name.
    let provider_slug = sanitize_for_folder(&detail.case.provider_display);
    let target_slug = detail
        .case
        .target_account
        .as_deref()
        .map(sanitize_for_folder)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let folder_name = format!("Scout_Report_{}_{}_{}", provider_slug, target_slug, ts);

    let folder = dest_dir.join(folder_name);
    write_single_return_report(case_id, &folder, &detail)?;
    Ok(folder)
}

/// Like [`export_report`] but with an explicit, caller-controlled target
/// folder.  Used by the investigation-level exporter so it can name each
/// per-return subfolder in numbered order.  `folder` must NOT exist yet —
/// it's created here.
pub fn export_report_to_folder(case_id: &str, folder: &Path) -> Result<(), ReportError> {
    let detail = triage_state::load_case_detail(case_id)?;
    write_single_return_report(case_id, folder, &detail)
}

/// Shared body of single-return report rendering.  Creates `folder`,
/// copies media, builds thumbnails, writes `index.html`.
fn write_single_return_report(
    case_id: &str,
    folder: &Path,
    detail: &triage_state::CaseDetail,
) -> Result<(), ReportError> {
    fs::create_dir_all(folder)?;

    // ─── Copy media into the report folder ─────────────────────────────
    let src_media = triage_state::media_dir(case_id);
    let dst_media = folder.join("media");
    fs::create_dir_all(&dst_media)?;
    if src_media.exists() {
        copy_dir_contents(&src_media, &dst_media)?;
    }

    // ─── Build thumbnail map ───────────────────────────────────────────
    let mut thumb_map = std::collections::BTreeMap::<String, String>::new();
    for item in &detail.items {
        for att in &item.attachments {
            if thumb_map.contains_key(att) {
                continue;
            }
            let src = src_media.join(att);
            if !src.exists() {
                continue;
            }
            if let Ok(url) = generate_thumb_data_url(&src) {
                thumb_map.insert(att.clone(), url);
            }
        }
    }

    // ─── Write index.html ──────────────────────────────────────────────
    let html = build_html(detail, &thumb_map)?;
    fs::write(folder.join("index.html"), html)?;
    Ok(())
}

/// Collapse a free-form string (provider name, target account, etc.) into
/// a safe Windows folder fragment.  Keeps `[A-Za-z0-9]`, replaces other
/// runs with `_`, and truncates to a sane length.
fn sanitize_for_folder(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_underscore = true; // suppress leading separator
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.len() > 40 {
        out.truncate(40);
        while out.ends_with('_') {
            out.pop();
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            let target = dst.join(entry.file_name());
            fs::copy(&p, &target)?;
        }
        // We don't expect nested dirs under linked_media, so flat copy is fine.
    }
    Ok(())
}

/// Read image, resize to THUMB_MAX_DIM keeping aspect, JPEG-encode at q70,
/// return `data:image/jpeg;base64,...`.
pub fn generate_thumb_data_url(path: &Path) -> Result<String, ReportError> {
    let img = ImageReader::open(path)
        .map_err(|e| ReportError::Other(format!("open {}: {}", path.display(), e)))?
        .with_guessed_format()
        .map_err(|e| ReportError::Other(format!("guess {}: {}", path.display(), e)))?
        .decode()
        .map_err(|e| ReportError::Other(format!("decode {}: {}", path.display(), e)))?;

    let (w, h) = (img.width(), img.height());
    let resized = if w > THUMB_MAX_DIM || h > THUMB_MAX_DIM {
        img.thumbnail(THUMB_MAX_DIM, THUMB_MAX_DIM)
    } else {
        img
    };

    let mut buf = Vec::new();
    resized
        .to_rgb8()
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
        .map_err(|e| ReportError::Other(format!("encode: {}", e)))?;

    Ok(format!("data:image/jpeg;base64,{}", B64.encode(&buf)))
}

// ─── End-to-end test ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warrant::{providers::meta::MetaWarrantParser, triage_state, WarrantParser as _};

    fn sample_zip() -> Option<PathBuf> {
        let p = PathBuf::from(
            r"C:\Users\JUSTI\Downloads\26-123456_DA_Export_2026-05-28(2)\Warrants\Production\Clean Data Archive for Distribution[4] (1).zip",
        );
        if p.exists() { Some(p) } else { None }
    }

    #[test]
    fn full_meta_round_trip() {
        let Some(zip) = sample_zip() else {
            eprintln!("Sample zip not present — skipping");
            return;
        };

        // Generate a unique case_id and let the parser write linked_media
        // straight into the case's media/ dir.
        let case_id = format!("test-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let case_dir = triage_state::case_dir(&case_id);
        let case_media = case_dir.join("media");
        std::fs::create_dir_all(&case_media).unwrap();

        let parser = MetaWarrantParser::new();
        let mut parsed = parser.parse(&zip, &case_media).unwrap();
        parsed.case.case_id = case_id.clone();
        parsed.case.media_root = Some("media".to_string());

        // Create case files
        let _summary = triage_state::create_case(&parsed).unwrap();

        // Export to a temp folder
        let work = std::env::temp_dir().join("scout_warrant_report_test");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let report_dir = export_report(&case_id, &work).unwrap();
        eprintln!("report dir: {}", report_dir.display());

        // Sanity checks
        let html_path = report_dir.join("index.html");
        assert!(html_path.exists(), "index.html should exist");
        let html = std::fs::read_to_string(&html_path).unwrap();
        assert!(html.contains("DATAPILOT SCOUT · WARRANT REPORT"));
        assert!(html.contains("\"items\":"), "data JSON should be inlined");
        assert!(html.len() > 30_000, "HTML should be substantial ({} bytes)", html.len());

        let media_dir = report_dir.join("media");
        assert!(media_dir.exists(), "media/ dir should exist");
        let media_count = std::fs::read_dir(&media_dir).unwrap().count();
        eprintln!("media files copied: {}, html bytes: {}", media_count, html.len());
        assert!(media_count > 0, "should have copied at least one media file");

        // Cleanup
        let _ = std::fs::remove_dir_all(&case_dir);
        let _ = std::fs::remove_dir_all(&work);
    }
}

// ─── HTML builder ────────────────────────────────────────────────────────

fn build_html(
    detail: &CaseDetail,
    thumbs: &std::collections::BTreeMap<String, String>,
) -> Result<String, ReportError> {
    // Pull cached scan results (if any) for this case so the report can
    // show "Hash Scan" / "Keyword Scan" overview cards.
    let scan_results = super::scan::get_results(&detail.case.case_id);

    // The data the embedded JS consumes — same shape the live UI sees,
    // plus a `thumbs` lookup table keyed by attachment filename.
    let data = serde_json::json!({
        "case": detail.case,
        "items": detail.items,
        "buckets": detail.buckets,
        "thumbs": thumbs,
        "scanResults": scan_results,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
    });
    let data_json = serde_json::to_string(&data)?;

    let case_label = escape_html(
        detail
            .case
            .target_account
            .as_deref()
            .unwrap_or(&detail.case.provider_display),
    );

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Warrant Triage Report — {case_label}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{css}</style>
</head>
<body>
<header class="topbar">
  <div class="brand">DATAPILOT SCOUT · WARRANT REPORT</div>
  <div class="case-meta" id="case-meta"></div>
  <div class="topbar-actions">
    <button id="btn-export-flags" class="tb-btn" title="Download your reviewer flags/notes/buckets as a JSON file">📥 Export My Flags</button>
    <button id="btn-import-flags" class="tb-btn" title="Load a previously-saved reviewer flags JSON file">📤 Import Flags</button>
    <input id="file-import" type="file" accept="application/json,.json" style="display:none">
    <button id="btn-clear-flags" class="tb-btn tb-btn-danger" title="Erase all reviewer annotations on this browser">🧹 Clear</button>
    <button id="btn-toggle-sidebar" class="tb-btn" title="Toggle filters">☰ Filters</button>
  </div>
</header>

<div class="layout">
  <aside class="sidebar" id="sidebar">
    <section>
      <h3>Search</h3>
      <input id="search" placeholder="Search everything…" />
    </section>
    <section>
      <h3>Sections</h3>
      <ul id="section-list" class="filter-list"></ul>
    </section>
    <section>
      <h3>Triage <span class="legend-hint" title="🚩 = analyst's flag · ⭐ = your flag">?</span></h3>
      <ul id="triage-list" class="filter-list"></ul>
    </section>
    <section>
      <h3>Analyst Buckets</h3>
      <ul id="bucket-list" class="filter-list"></ul>
    </section>
    <section>
      <h3>
        <span>My Buckets</span>
        <button id="btn-new-rbucket" class="mini-btn" title="Create a new reviewer bucket">+ New</button>
      </h3>
      <ul id="rbucket-list" class="filter-list"></ul>
    </section>
  </aside>

  <main class="centerpane" id="centerpane">
    <!-- Overview view -->
    <section id="overview-view" class="overview-view">
      <div class="overview-scroll" id="overview-scroll"></div>
    </section>

    <!-- Item-list view -->
    <section id="itemlist-view" class="itemlist hidden">
      <div class="itemlist-header">
        <span id="result-count"></span>
        <button id="clear-filters" class="link-btn" style="display:none">Clear filters</button>
      </div>
      <div id="items"></div>
    </section>
  </main>

  <aside class="detail" id="detail">
    <div class="detail-empty">Select an item to view details.</div>
  </aside>
</div>

<div id="lightbox" class="lightbox hidden" onclick="closeLightbox(event)">
  <img id="lightbox-img" alt="">
  <div class="lightbox-meta" id="lightbox-meta"></div>
</div>

<div id="modal" class="modal hidden">
  <div class="modal-body">
    <div class="modal-header"><span id="modal-title"></span><button class="modal-x" id="modal-x-btn">&times;</button></div>
    <div id="modal-content"></div>
  </div>
</div>

<div id="toast" class="toast hidden"></div>

<script id="report-data" type="application/json">{data_json}</script>
<script>{js}</script>
</body>
</html>"#,
        case_label = case_label,
        css = REPORT_CSS,
        data_json = data_json.replace("</script>", r"<\/script>"), // safety
        js = REPORT_JS,
    ))
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

// Silence "dead code" on items not yet used here — we may add a per-item
// pretty printer later.
#[allow(dead_code)]
fn _retain_warrant_item_type(_: &WarrantItem, _: &Bucket) {}

// ─── Embedded CSS ────────────────────────────────────────────────────────

const REPORT_CSS: &str = r#"
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: #070b17; color: #e2e8f0;
  display: flex; flex-direction: column; height: 100vh;
}
.topbar {
  display: flex; align-items: center; gap: 16px; padding: 12px 20px;
  background: linear-gradient(180deg, rgba(74,122,255,0.1), transparent);
  border-bottom: 1px solid rgba(74,122,255,0.2); flex-shrink: 0;
}
.brand {
  font-weight: 700; letter-spacing: 0.1em; font-size: 13px;
  color: #5dcfff; white-space: nowrap;
}
.case-meta { flex: 1; display: flex; gap: 14px; flex-wrap: wrap; font-size: 12px; color: #94a3b8; }
.case-meta strong { color: #e2e8f0; font-weight: 600; }
.case-meta .pill {
  background: rgba(74,122,255,0.18); color: #93b7ff;
  padding: 3px 10px; border-radius: 12px; font-weight: 600;
  border: 1px solid rgba(74,122,255,0.35);
}
.topbar-actions { display: flex; gap: 8px; align-items: center; }
.topbar-actions .tb-btn {
  background: transparent; border: 1px solid rgba(93,207,255,0.4);
  color: #5dcfff; padding: 7px 12px; border-radius: 6px; cursor: pointer;
  font-size: 11px; white-space: nowrap; transition: background 0.12s, border-color 0.12s;
}
.topbar-actions .tb-btn:hover { background: rgba(93,207,255,0.1); border-color: #5dcfff; }
.topbar-actions .tb-btn-danger { border-color: rgba(239,68,68,0.5); color: #f87171; }
.topbar-actions .tb-btn-danger:hover { background: rgba(239,68,68,0.1); border-color: #f87171; }
.layout { display: grid; grid-template-columns: 260px 1fr 380px; flex: 1; min-height: 0; }
.sidebar { background: #0a0e1c; border-right: 1px solid rgba(74,122,255,0.12);
  padding: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 18px; }
.sidebar section h3 {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em;
  color: #64748b; margin: 0 0 8px; font-weight: 600;
  display: flex; align-items: center; justify-content: space-between; gap: 6px;
}
.sidebar section h3 .legend-hint {
  display: inline-flex; align-items: center; justify-content: center;
  width: 14px; height: 14px; border-radius: 50%; background: rgba(93,207,255,0.18);
  color: #5dcfff; font-size: 10px; font-weight: 700; cursor: help;
}
.mini-btn {
  background: rgba(93,207,255,0.12); border: 1px solid rgba(93,207,255,0.3);
  color: #5dcfff; padding: 2px 8px; border-radius: 4px; cursor: pointer;
  font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
}
.mini-btn:hover { background: rgba(93,207,255,0.22); }
.sidebar input {
  width: 100%; background: #111827; color: #e2e8f0;
  border: 1px solid rgba(74,122,255,0.25); border-radius: 6px;
  padding: 8px 10px; font-size: 13px; outline: none;
}
.sidebar input:focus { border-color: #5dcfff; }
.filter-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
.filter-list li {
  display: flex; align-items: center; justify-content: space-between;
  padding: 7px 10px; border-radius: 5px; cursor: pointer; font-size: 13px;
  color: #cbd5e1; transition: background 0.12s ease;
}
.filter-list li:hover { background: rgba(74,122,255,0.08); }
.filter-list li.active { background: rgba(93,207,255,0.14); color: #5dcfff; font-weight: 500; }
.filter-list .count {
  font-size: 11px; color: #64748b;
  background: rgba(100,116,139,0.18); padding: 1px 7px; border-radius: 10px;
}
.filter-list li.active .count { color: #5dcfff; background: rgba(93,207,255,0.18); }
.filter-list .bucket-dot { width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; flex-shrink: 0; }
.filter-list .bucket-row { gap: 6px; }
.filter-list .bucket-row .label { flex: 1; }

.itemlist { background: #0c1220; display: flex; flex-direction: column; overflow: hidden; }
.itemlist-header {
  padding: 10px 18px; font-size: 12px; color: #94a3b8;
  border-bottom: 1px solid rgba(74,122,255,0.08);
  display: flex; justify-content: space-between; align-items: center; flex-shrink: 0;
}
.link-btn { background: transparent; border: 0; color: #5dcfff; cursor: pointer; font-size: 12px; padding: 0; }
.link-btn:hover { text-decoration: underline; }
#items { overflow-y: auto; flex: 1; }
.item-row {
  display: flex; gap: 14px; padding: 10px 18px;
  border-bottom: 1px solid rgba(74,122,255,0.06);
  cursor: pointer; transition: background 0.12s ease; align-items: center;
}
.item-row:hover { background: rgba(74,122,255,0.06); }
.item-row.selected { background: rgba(74,122,255,0.14); border-left: 3px solid #5dcfff; padding-left: 15px; }
.item-row.flagged { background: rgba(239,68,68,0.04); }
.item-row.flagged.selected { background: rgba(239,68,68,0.12); border-left-color: #ef4444; }
.thumb {
  width: 64px; height: 64px; object-fit: cover; border-radius: 6px;
  flex-shrink: 0; background: #111827; cursor: pointer;
}
.thumb-placeholder {
  width: 64px; height: 64px; background: linear-gradient(135deg,#1e293b,#0f172a);
  border-radius: 6px; flex-shrink: 0; display: flex; align-items: center;
  justify-content: center; color: #5dcfff; font-size: 22px; font-weight: 600;
}
.item-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
.item-headline {
  display: flex; align-items: center; gap: 10px; font-size: 12px; color: #94a3b8;
}
.item-section {
  color: #5dcfff; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.05em; font-size: 11px;
}
.item-ts { color: #64748b; }
.item-summary {
  color: #e2e8f0; font-size: 13px; line-height: 1.4;
  overflow: hidden; text-overflow: ellipsis;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
}
.item-people { font-size: 11px; color: #94a3b8; font-family: 'Consolas', monospace; }

/* ─── Email inbox row ──────────────────────────────────────────── */
.item-row-email {
  display: grid;
  grid-template-columns: 40px 1fr auto;
  gap: 12px;
  align-items: flex-start;
}
.email-avatar {
  width: 36px; height: 36px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  color: white; font-weight: 700; font-size: 14px;
  flex-shrink: 0;
}
.email-body { min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.email-row-top { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.email-sender { color: #f1f5f9; font-weight: 600; font-size: 13px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-date { color: #64748b; font-size: 11px; flex-shrink: 0; }
.email-subject { color: #e2e8f0; font-size: 13px; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-preview { color: #94a3b8; font-size: 12px; line-height: 1.4;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-route { color: #475569; font-size: 10px; margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-flags { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; flex-shrink: 0; }

/* ─── Email Gmail-style detail card ────────────────────────────── */
.email-detail-card {
  background: #0d1322;
  border: 1px solid rgba(74,122,255,0.18);
  border-radius: 8px;
  padding: 18px 20px;
  margin-bottom: 16px;
}
.email-detail-subject {
  color: #f1f5f9; font-size: 18px; font-weight: 600;
  margin-bottom: 8px; line-height: 1.3;
}
.email-detail-labels { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.email-detail-label {
  display: inline-block; padding: 2px 8px; border-radius: 10px;
  background: rgba(93,207,255,0.12); color: #5dcfff;
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;
}
.email-detail-header {
  display: flex; gap: 12px; padding-bottom: 12px; margin-bottom: 14px;
  border-bottom: 1px solid rgba(74,122,255,0.12);
}
.email-detail-avatar {
  width: 40px; height: 40px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  color: white; font-weight: 700; font-size: 16px;
  flex-shrink: 0;
}
.email-detail-meta { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.email-detail-row { display: flex; gap: 8px; font-size: 12px; line-height: 1.5; }
.email-detail-key { color: #64748b; min-width: 44px; text-align: right; }
.email-detail-val { color: #e2e8f0; word-break: break-word; min-width: 0; }
.email-detail-val .mono { font-family: 'Consolas', monospace; color: #93b7ff; }
.email-detail-body {
  color: #cbd5e1; font-size: 14px; line-height: 1.65;
  white-space: pre-wrap; word-break: break-word;
}
.bucket-chip {
  font-size: 10px; padding: 3px 8px; border-radius: 10px; color: white;
  font-weight: 600; white-space: nowrap; flex-shrink: 0;
  text-transform: uppercase; letter-spacing: 0.05em;
}

.detail {
  background: #0a0e1c; border-left: 1px solid rgba(74,122,255,0.12);
  padding: 16px; overflow-y: auto;
}
.detail-empty { padding: 40px 20px; text-align: center; color: #64748b; font-size: 13px; }
.detail-header { display: flex; justify-content: space-between; align-items: flex-end;
  padding-bottom: 10px; border-bottom: 1px solid rgba(74,122,255,0.12); margin-bottom: 14px; }
.detail-section-label { color: #5dcfff; font-size: 14px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; }
.detail-id { color: #475569; font-family: 'Consolas', monospace; font-size: 10px; }
.detail-bucket-bar {
  display: flex; align-items: center; gap: 8px; font-size: 12px;
  color: #94a3b8; margin-bottom: 14px; padding: 10px 12px;
  background: #111827; border-radius: 6px; border: 1px solid rgba(74,122,255,0.12);
}
.detail-bucket-bar .chip {
  font-size: 11px; padding: 3px 8px; border-radius: 10px; color: white; font-weight: 600;
}
.detail-bucket-bar .flag { color: #ef4444; font-weight: 600; }
.detail-note {
  background: #111827; padding: 10px 12px; border-radius: 6px;
  border: 1px solid rgba(234,179,8,0.25); margin-bottom: 14px;
  font-size: 12px; color: #fde68a; line-height: 1.5; white-space: pre-wrap;
}
.detail-note .label { font-size: 10px; text-transform: uppercase;
  color: #ca8a04; margin-bottom: 4px; font-weight: 700; letter-spacing: 0.08em; }
.detail-section { margin-bottom: 14px; }
.detail-section > label { font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.08em; color: #64748b; margin-bottom: 6px; display: block; font-weight: 600; }
.attachment-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.attachment-tile {
  display: flex; gap: 8px; align-items: center; padding: 8px;
  background: #111827; border: 1px solid rgba(74,122,255,0.18);
  border-radius: 5px; cursor: pointer; font-size: 11px; color: #cbd5e1;
  text-decoration: none; overflow: hidden;
}
.attachment-tile:hover { background: rgba(74,122,255,0.12); border-color: #5dcfff; }
.attachment-tile img { width: 40px; height: 40px; object-fit: cover; border-radius: 4px; flex-shrink: 0; }
.attachment-tile .att-name {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: 'Consolas', monospace; font-size: 10px;
}
.detail-fields table { width: 100%; border-collapse: collapse; font-size: 11px; }
.detail-fields tr { border-bottom: 1px solid rgba(74,122,255,0.06); }
.detail-fields td { padding: 5px 8px; vertical-align: top; }
.detail-fields td.key {
  color: #5dcfff; font-family: 'Consolas', monospace; font-weight: 500;
  width: 110px; word-break: break-all;
}
.detail-fields td.val { color: #e2e8f0; word-break: break-word; white-space: pre-wrap; }

.lightbox {
  position: fixed; inset: 0; background: rgba(7,11,23,0.94); z-index: 999;
  display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 12px;
  cursor: zoom-out;
}
.lightbox.hidden { display: none; }
.lightbox img { max-width: 92vw; max-height: 86vh; border-radius: 8px;
  box-shadow: 0 12px 48px rgba(74,122,255,0.4); }
.lightbox-meta { color: #94a3b8; font-size: 12px; font-family: 'Consolas', monospace; }

/* Scrollbars */
.sidebar::-webkit-scrollbar, #items::-webkit-scrollbar, .detail::-webkit-scrollbar { width: 8px; }
.sidebar::-webkit-scrollbar-thumb, #items::-webkit-scrollbar-thumb, .detail::-webkit-scrollbar-thumb {
  background: rgba(74,122,255,0.25); border-radius: 4px;
}

@media (max-width: 980px) {
  .layout { grid-template-columns: 220px 1fr; }
  .detail { display: none; }
}

/* Print: hide chrome */
@media print {
  .sidebar, .detail, .topbar-actions { display: none !important; }
  .layout { grid-template-columns: 1fr; }
  body { background: white; color: black; }
  .item-row { break-inside: avoid; }
}

/* ─── Centerpane + overview ─────────────────────────────────────── */
.centerpane { background: #0c1220; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.hidden { display: none !important; }
.overview-view { flex: 1; min-height: 0; overflow: hidden; display: flex; }
.overview-scroll { flex: 1; min-height: 0; overflow-y: auto; padding: 20px 24px 32px; }

.ov-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 16px; align-items: stretch;
}
.ov-card {
  background: #0a0e1c; border: 1px solid rgba(74,122,255,0.18); border-radius: 10px;
  padding: 16px 18px; display: flex; flex-direction: column; gap: 10px;
  box-shadow: 0 4px 18px rgba(0,0,0,0.25);
}
.ov-card-wide { grid-column: 1 / -1; }
.ov-card-header { display: flex; align-items: center; gap: 10px; }
.ov-card-header h3 { margin: 0; font-size: 13px; letter-spacing: 0.06em;
  text-transform: uppercase; color: #cbd5e1; font-weight: 700; }
.ov-card-icon { font-size: 18px; line-height: 1; }
.ov-card-subtle { color: #64748b; font-size: 11px; }

.ov-kv { margin: 0; display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; font-size: 12px; }
.ov-kv dt { color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-size: 10px; padding-top: 2px; }
.ov-kv dd { margin: 0; color: #e2e8f0; word-break: break-word; }
.ov-kv dd.mono { font-family: 'Consolas', monospace; font-size: 12px; color: #93b7ff; }

.ov-tiles {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 10px;
}
.ov-tile {
  background: #111827; border: 1px solid rgba(74,122,255,0.18); border-radius: 8px;
  padding: 12px 10px; cursor: pointer; text-align: center;
  transition: background 0.12s, transform 0.12s, border-color 0.12s;
  display: flex; flex-direction: column; gap: 4px; align-items: center;
}
.ov-tile:hover { background: rgba(74,122,255,0.12); transform: translateY(-2px); border-color: #5dcfff; }
.ov-tile-icon { font-size: 24px; line-height: 1; }
.ov-tile-count { font-size: 20px; font-weight: 700; color: #e2e8f0; }
.ov-tile-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: #94a3b8; }

.ov-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.ov-stat {
  background: #111827; border: 1px solid rgba(74,122,255,0.18); border-radius: 8px;
  padding: 12px; text-align: center; cursor: pointer; transition: background 0.12s;
}
.ov-stat:hover { background: rgba(74,122,255,0.12); }
.ov-stat-num { font-size: 22px; font-weight: 700; }
.ov-stat-num.flag { color: #ef4444; }
.ov-stat-num.good { color: #22c55e; }
.ov-stat-num.warn { color: #eab308; }
.ov-stat-num.cyan { color: #5dcfff; }
.ov-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: #94a3b8; margin-top: 2px; }

.ov-bucket-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.ov-bchip {
  display: inline-flex; align-items: center; gap: 6px;
  background: #111827; border: 1px solid rgba(74,122,255,0.2); border-radius: 14px;
  padding: 4px 10px 4px 6px; font-size: 11px; color: #cbd5e1; cursor: pointer;
}
.ov-bchip:hover { border-color: #5dcfff; }
.ov-bchip .dot { width: 8px; height: 8px; border-radius: 50%; }
.ov-bchip .ct { color: #94a3b8; font-weight: 600; }

.ov-empty { color: #64748b; font-style: italic; font-size: 12px; }

/* Structured bio sections (Subscriber Info, Hangouts, Chat) inside dl */
.ov-kv dt.ov-bio-section {
  grid-column: 1 / -1; margin-top: 10px; padding-top: 8px;
  border-top: 1px dashed rgba(93,207,255,0.25);
  color: #5dcfff; font-size: 10px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em;
}
.ov-kv dt.ov-bio-section + dd { display: none; }

/* "Categories With No Records Returned" chips under Triage card */
.ov-no-records {
  margin-top: 12px; padding-top: 10px;
  border-top: 1px dashed rgba(148,163,184,0.15);
}
.ov-no-records-title { margin-bottom: 6px; }
.ov-no-records-chips { display: flex; flex-wrap: wrap; gap: 4px; }
.ov-no-records-chip {
  display: inline-flex; align-items: center;
  padding: 2px 8px; border-radius: 10px;
  background: rgba(148,163,184,0.08);
  border: 1px solid rgba(148,163,184,0.15);
  color: #94a3b8; font-family: 'Consolas', monospace;
  font-size: 10px;
}

.ov-myflag-list { display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto; }
.ov-myflag-row {
  display: flex; align-items: center; gap: 8px; padding: 6px 8px;
  background: #111827; border: 1px solid rgba(74,122,255,0.15); border-radius: 6px;
  cursor: pointer; font-size: 12px;
}
.ov-myflag-row:hover { border-color: #5dcfff; background: rgba(74,122,255,0.08); }
.ov-myflag-row .icon { flex-shrink: 0; }
.ov-myflag-row .text { flex: 1; min-width: 0; color: #e2e8f0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ov-myflag-row .meta { color: #64748b; font-size: 10px; }

/* ─── Reviewer controls in detail pane ───────────────────────────── */
.reviewer-block {
  margin-top: 18px; padding-top: 14px;
  border-top: 1px dashed rgba(234,179,8,0.4);
}
.reviewer-block .reviewer-label {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
  color: #fbbf24; font-weight: 700; margin-bottom: 8px;
  display: flex; align-items: center; gap: 6px;
}
.reviewer-block .reviewer-label .badge {
  background: rgba(251,191,36,0.18); border: 1px solid rgba(251,191,36,0.45);
  color: #fde68a; padding: 1px 7px; border-radius: 10px; font-size: 9px;
}
.reviewer-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.reviewer-flag-btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: transparent; border: 1px solid rgba(251,191,36,0.4);
  color: #fbbf24; padding: 6px 12px; border-radius: 6px; cursor: pointer;
  font-size: 12px; font-weight: 600;
}
.reviewer-flag-btn:hover { background: rgba(251,191,36,0.1); }
.reviewer-flag-btn.active {
  background: rgba(251,191,36,0.2); border-color: #fbbf24; color: #fde68a;
}
.reviewer-bucket-select {
  background: #111827; color: #e2e8f0; border: 1px solid rgba(74,122,255,0.3);
  border-radius: 6px; padding: 6px 10px; font-size: 12px; cursor: pointer;
  flex: 1; min-width: 0;
}
.reviewer-note-input {
  width: 100%; min-height: 70px; background: #111827; color: #fde68a;
  border: 1px solid rgba(251,191,36,0.3); border-radius: 6px;
  padding: 8px 10px; font-size: 12px; font-family: inherit; resize: vertical;
  outline: none; line-height: 1.4;
}
.reviewer-note-input:focus { border-color: #fbbf24; }
.reviewer-status { font-size: 10px; color: #64748b; margin-top: 4px; min-height: 12px; }

/* Reviewer indicators on item rows */
.item-row.reviewer-flagged { box-shadow: inset 3px 0 0 #fbbf24; }
.item-row.reviewer-flagged.selected { box-shadow: inset 3px 0 0 #fbbf24, inset 5px 0 0 #5dcfff; }
.reviewer-chip {
  font-size: 9px; padding: 2px 6px; border-radius: 8px; color: white;
  font-weight: 700; white-space: nowrap; flex-shrink: 0;
  text-transform: uppercase; letter-spacing: 0.05em;
  border: 1px solid rgba(255,255,255,0.2);
}

/* ─── Modal ────────────────────────────────────────────────────── */
.modal {
  position: fixed; inset: 0; background: rgba(7,11,23,0.7);
  z-index: 1000; display: flex; align-items: center; justify-content: center;
  backdrop-filter: blur(2px);
}
.modal.hidden { display: none; }
.modal-body {
  background: #0a0e1c; border: 1px solid rgba(74,122,255,0.3);
  border-radius: 10px; padding: 18px 20px; min-width: 320px; max-width: 520px;
  max-height: 80vh; overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0,0,0,0.6);
}
.modal-header { display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid rgba(74,122,255,0.15); }
.modal-header span { color: #5dcfff; font-size: 14px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.05em; }
.modal-x {
  background: transparent; border: 0; color: #64748b; font-size: 18px;
  cursor: pointer; padding: 0 6px;
}
.modal-x:hover { color: #e2e8f0; }
.modal-content label {
  display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: #94a3b8; margin: 10px 0 4px; font-weight: 600;
}
.modal-content input[type=text], .modal-content input[type=color] {
  width: 100%; background: #111827; color: #e2e8f0;
  border: 1px solid rgba(74,122,255,0.3); border-radius: 6px;
  padding: 8px 10px; font-size: 13px;
}
.modal-content input[type=color] { padding: 2px; height: 36px; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
.modal-actions .btn {
  background: transparent; border: 1px solid rgba(93,207,255,0.4); color: #5dcfff;
  padding: 7px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;
}
.modal-actions .btn-primary { background: #5dcfff; color: #070b17; border-color: #5dcfff; }
.modal-actions .btn-primary:hover { background: #93dfff; }
.modal-actions .btn:hover { background: rgba(93,207,255,0.1); }
.modal-actions .btn-danger { border-color: rgba(239,68,68,0.5); color: #f87171; }
.modal-actions .btn-danger:hover { background: rgba(239,68,68,0.1); }

/* ─── Toast ────────────────────────────────────────────────────── */
.toast {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
  background: #0a0e1c; border: 1px solid rgba(93,207,255,0.4); color: #e2e8f0;
  padding: 10px 18px; border-radius: 8px; font-size: 12px;
  z-index: 2000; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  animation: toast-in 0.2s ease-out;
}
.toast.hidden { display: none; }
.toast.error { border-color: rgba(239,68,68,0.5); color: #f87171; }
.toast.success { border-color: rgba(34,197,94,0.5); color: #4ade80; }
@keyframes toast-in {
  from { opacity: 0; transform: translate(-50%, 8px); }
  to { opacity: 1; transform: translate(-50%, 0); }
}

/* Sidebar reviewer-bucket rows: add a small "✕" delete control */
.filter-list li .rb-del {
  margin-left: 6px; color: #64748b; cursor: pointer; padding: 0 4px;
  border-radius: 4px; font-size: 11px;
}
.filter-list li .rb-del:hover { color: #ef4444; background: rgba(239,68,68,0.1); }
"#;

const REPORT_JS: &str = r#"
(() => {
  const DATA = JSON.parse(document.getElementById('report-data').textContent);
  const SECTION_LABELS = {
    unified_messages: 'Messages',
    photos: 'Photos',
    status_updates: 'Status Updates',
    wallposts: 'Wall Posts',
    posts_to_other_walls: 'Posts to Others',
    shares: 'Shares',
    ip_addresses: 'IP Addresses',
    registration_ip: 'Registration IP',
    about_me: 'About',
    bio: 'Bio',
    ncmec_reports: 'NCMEC Reports',
    request_parameters: 'Request Parameters',
  };
  const SECTION_ICONS = {
    unified_messages: '\u{1F4AC}',
    photos: '\u{1F4F7}',
    status_updates: '\u{1F4DD}',
    wallposts: '\u{1F4CC}',
    posts_to_other_walls: '\u{1F4E4}',
    shares: '\u{1F517}',
    ip_addresses: '\u{1F310}',
    registration_ip: '\u{1F4E1}',
    about_me: '\u{1F464}',
    bio: '\u{1F464}',
    ncmec_reports: '\u{26A0}',
    request_parameters: '\u{1F4CB}',
  };
  const REVIEWER_PALETTE = [
    '#fbbf24', '#f87171', '#a78bfa', '#34d399', '#22d3ee', '#fb923c', '#f472b6', '#94a3b8',
  ];

  const CASE_ID = (DATA.case && DATA.case.caseId) || 'unknown';
  const LS_KEY = 'scout-warrant-reviewer-' + CASE_ID;
  const STATE_VERSION = 1;

  function loadReviewer() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return defaultReviewer();
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        return {
          version: STATE_VERSION,
          flags: parsed.flags && typeof parsed.flags === 'object' ? parsed.flags : {},
          buckets: Array.isArray(parsed.buckets) ? parsed.buckets : [],
          reviewerName: typeof parsed.reviewerName === 'string' ? parsed.reviewerName : '',
          updatedAt: parsed.updatedAt || null,
        };
      }
    } catch (e) { console.warn('reviewer load failed', e); }
    return defaultReviewer();
  }
  function defaultReviewer() {
    return { version: STATE_VERSION, flags: {}, buckets: [], reviewerName: '', updatedAt: null };
  }
  function saveReviewer() {
    state.reviewer.updatedAt = new Date().toISOString();
    try { localStorage.setItem(LS_KEY, JSON.stringify(state.reviewer)); }
    catch (e) { toast('Could not save to browser storage: ' + e.message, 'error'); }
  }
  function getFlag(itemId) {
    return state.reviewer.flags[itemId] || { flagged: false, note: '', bucket: null };
  }
  function setFlag(itemId, patch) {
    const cur = getFlag(itemId);
    const next = Object.assign({}, cur, patch);
    if (!next.flagged && !next.note && !next.bucket) {
      delete state.reviewer.flags[itemId];
    } else {
      state.reviewer.flags[itemId] = next;
    }
    saveReviewer();
  }
  function newRBucket(name, color) {
    const id = 'rb_' + Math.random().toString(36).slice(2, 10);
    state.reviewer.buckets.push({ id, name: name.trim(), color });
    saveReviewer();
    return id;
  }
  function deleteRBucket(id) {
    state.reviewer.buckets = state.reviewer.buckets.filter(b => b.id !== id);
    for (const k of Object.keys(state.reviewer.flags)) {
      if (state.reviewer.flags[k].bucket === id) {
        state.reviewer.flags[k].bucket = null;
        if (!state.reviewer.flags[k].flagged && !state.reviewer.flags[k].note) {
          delete state.reviewer.flags[k];
        }
      }
    }
    if (state.bucketFilter === id) state.bucketFilter = null;
    saveReviewer();
  }

  const state = {
    view: 'overview',
    sectionFilter: null,
    bucketFilter: null,
    search: '',
    selectedId: null,
    reviewer: loadReviewer(),
  };

  const analystBucketsById = Object.fromEntries(DATA.buckets.map(b => [b.id, b]));
  function rbucketsById() {
    return Object.fromEntries(state.reviewer.buckets.map(b => [b.id, b]));
  }

  function renderTopbar() {
    const c = DATA.case;
    const meta = document.getElementById('case-meta');
    const bits = [`<span class="pill" onclick="window._goOverview()">${escapeHtml(c.providerDisplay)}</span>`];
    if (c.targetAccount) bits.push(`Target: <strong>${escapeHtml(c.targetAccount)}</strong>`);
    if (c.dateRange) bits.push(escapeHtml(c.dateRange));
    bits.push(`\u{1F4E6} ${escapeHtml(c.sourceFilename)}`);
    meta.innerHTML = bits.join('');
  }
  window._goOverview = function() {
    state.view = 'overview'; state.sectionFilter = null; state.bucketFilter = null;
    rerender();
  };

  function renderSidebar() {
    const sectionCounts = {};
    let unbucketed = 0, flagged = 0, myFlagged = 0;
    const bucketCounts = {};
    const rbucketCounts = {};
    for (const it of DATA.items) {
      sectionCounts[it.section] = (sectionCounts[it.section] || 0) + 1;
      if (!it.bucket) unbucketed++;
      else bucketCounts[it.bucket] = (bucketCounts[it.bucket] || 0) + 1;
      if (it.isFlagged) flagged++;
      const rf = state.reviewer.flags[it.id];
      if (rf) {
        if (rf.flagged) myFlagged++;
        if (rf.bucket) rbucketCounts[rf.bucket] = (rbucketCounts[rf.bucket] || 0) + 1;
      }
    }
    const sections = Object.keys(sectionCounts).sort((a,b) => sectionCounts[b]-sectionCounts[a]);

    const sectionList = document.getElementById('section-list');
    sectionList.innerHTML = '';
    sectionList.appendChild(makeFilterRow(
      '\u{1F4CA} Overview', '', state.view === 'overview',
      () => { state.view = 'overview'; state.sectionFilter = null; state.bucketFilter = null; rerender(); }
    ));
    sectionList.appendChild(makeFilterRow(
      'All sections', DATA.items.length,
      state.view === 'items' && state.sectionFilter === null && state.bucketFilter === null,
      () => { state.view = 'items'; state.sectionFilter = null; state.bucketFilter = null; rerender(); }
    ));
    for (const s of sections) {
      sectionList.appendChild(makeFilterRow(
        (SECTION_ICONS[s] ? SECTION_ICONS[s] + ' ' : '') + (SECTION_LABELS[s] || s),
        sectionCounts[s],
        state.view === 'items' && state.sectionFilter === s,
        () => {
          state.view = 'items';
          state.sectionFilter = state.sectionFilter === s ? null : s;
          rerender();
        }
      ));
    }

    const triageList = document.getElementById('triage-list');
    triageList.innerHTML = '';
    triageList.appendChild(makeFilterRow(
      '\u{1F6A9} Analyst Flagged', flagged,
      state.view === 'items' && state.bucketFilter === 'flagged',
      () => { state.view = 'items'; state.bucketFilter = state.bucketFilter === 'flagged' ? null : 'flagged'; rerender(); }
    ));
    triageList.appendChild(makeFilterRow(
      '\u{2B50} My Flagged', myFlagged,
      state.view === 'items' && state.bucketFilter === 'my-flagged',
      () => { state.view = 'items'; state.bucketFilter = state.bucketFilter === 'my-flagged' ? null : 'my-flagged'; rerender(); }
    ));
    triageList.appendChild(makeFilterRow(
      'Unbucketed (analyst)', unbucketed,
      state.view === 'items' && state.bucketFilter === 'unbucketed',
      () => { state.view = 'items'; state.bucketFilter = state.bucketFilter === 'unbucketed' ? null : 'unbucketed'; rerender(); }
    ));

    const bucketList = document.getElementById('bucket-list');
    bucketList.innerHTML = '';
    if (!DATA.buckets.length) {
      bucketList.innerHTML = '<li style="color:#475569;font-style:italic;font-size:12px;padding:4px 10px">No analyst buckets.</li>';
    }
    for (const b of DATA.buckets) {
      const li = document.createElement('li');
      const active = state.view === 'items' && state.bucketFilter === b.id;
      li.className = 'bucket-row' + (active ? ' active' : '');
      li.innerHTML = `<span class="bucket-dot" style="background:${escapeAttr(b.color)}"></span>
        <span class="label">${escapeHtml(b.name)}</span>
        <span class="count">${bucketCounts[b.id] || 0}</span>`;
      li.onclick = () => {
        state.view = 'items';
        state.bucketFilter = state.bucketFilter === b.id ? null : b.id;
        rerender();
      };
      bucketList.appendChild(li);
    }

    const rbucketList = document.getElementById('rbucket-list');
    rbucketList.innerHTML = '';
    if (!state.reviewer.buckets.length) {
      rbucketList.innerHTML = '<li style="color:#475569;font-style:italic;font-size:12px;padding:4px 10px">No personal buckets yet. Click + New.</li>';
    }
    for (const b of state.reviewer.buckets) {
      const li = document.createElement('li');
      const active = state.view === 'items' && state.bucketFilter === b.id;
      li.className = 'bucket-row' + (active ? ' active' : '');
      li.innerHTML = `<span class="bucket-dot" style="background:${escapeAttr(b.color)}"></span>
        <span class="label">${escapeHtml(b.name)}</span>
        <span class="count">${rbucketCounts[b.id] || 0}</span>
        <span class="rb-del" title="Delete bucket">\u2715</span>`;
      li.onclick = (ev) => {
        if (ev.target.classList && ev.target.classList.contains('rb-del')) {
          ev.stopPropagation();
          if (confirm(`Delete bucket "${b.name}"? Items assigned to it will become unbucketed.`)) {
            deleteRBucket(b.id);
            rerender();
          }
          return;
        }
        state.view = 'items';
        state.bucketFilter = state.bucketFilter === b.id ? null : b.id;
        rerender();
      };
      rbucketList.appendChild(li);
    }
  }

  function makeFilterRow(label, count, active, onclick) {
    const li = document.createElement('li');
    li.className = active ? 'active' : '';
    const countHtml = count === '' || count === null ? '' : `<span class="count">${count}</span>`;
    li.innerHTML = `<span>${label}</span>${countHtml}`;
    li.onclick = onclick;
    return li;
  }

  function getFilteredItems() {
    const q = state.search.trim().toLowerCase();
    return DATA.items.filter(it => {
      if (state.sectionFilter && it.section !== state.sectionFilter) return false;
      const f = state.bucketFilter;
      if (f === 'unbucketed' && it.bucket) return false;
      if (f === 'flagged' && !it.isFlagged) return false;
      if (f === 'my-flagged' && !(state.reviewer.flags[it.id] && state.reviewer.flags[it.id].flagged)) return false;
      if (f && f !== 'unbucketed' && f !== 'flagged' && f !== 'my-flagged') {
        const rf = state.reviewer.flags[it.id];
        const matchesAnalyst = it.bucket === f;
        const matchesReviewer = rf && rf.bucket === f;
        if (!matchesAnalyst && !matchesReviewer) return false;
      }
      if (q) {
        const rf = state.reviewer.flags[it.id];
        const hay = [
          it.summary, it.bodyText, it.author, it.recipient, it.note,
          rf && rf.note,
          ...Object.values(it.rawFields || {}).filter(v => typeof v === 'string')
        ].filter(Boolean).join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function renderItemList() {
    const items = getFilteredItems();
    const container = document.getElementById('items');
    container.innerHTML = '';
    document.getElementById('result-count').textContent =
      `${items.length} of ${DATA.items.length}`;
    const hasFilter = !!(state.sectionFilter || state.bucketFilter || state.search);
    document.getElementById('clear-filters').style.display = hasFilter ? '' : 'none';

    if (!items.length) {
      container.innerHTML = '<div style="padding:40px;text-align:center;color:#64748b;font-size:13px">No items match the current filters.</div>';
      return;
    }

    const frag = document.createDocumentFragment();
    for (const it of items) frag.appendChild(renderRow(it));
    container.appendChild(frag);
  }

  // ─── Email helpers (Gmail-style inbox row + detail) ─────────────
  function parseAddress(raw) {
    if (!raw) return { name: '', addr: '' };
    const s = String(raw).trim();
    const m = s.match(/^"?([^"<]+?)"?\s*<([^>]+)>\s*$/);
    if (m) return { name: m[1].trim(), addr: m[2].trim() };
    return { name: '', addr: s };
  }
  function emailPreview(body, max) {
    max = max || 140;
    if (!body) return '';
    let t = String(body);
    // Strip MIME boundary/header noise and quoted replies for the preview.
    t = t.replace(/\r\n/g, '\n');
    const stop = t.search(/(^|\n)>\s|(^|\n)On .+wrote:|(^|\n)-----Original Message-----/i);
    if (stop > 0) t = t.slice(0, stop);
    t = t.replace(/\n+/g, ' ').replace(/\s{2,}/g, ' ').trim();
    if (t.length > max) t = t.slice(0, max - 1) + '\u2026';
    return t;
  }
  function fmtEmailDate(s) {
    if (!s) return '';
    const d = new Date(s);
    if (isNaN(d.getTime())) return String(s).slice(0, 16);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    if (sameDay) return d.toTimeString().slice(0,5);
    const sameYear = d.getFullYear() === now.getFullYear();
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return sameYear
      ? months[d.getMonth()] + ' ' + d.getDate()
      : months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
  }
  function avatarInitial(name, addr) {
    const s = (name || addr || '?').trim();
    return s ? s.charAt(0).toUpperCase() : '?';
  }
  function avatarColor(seed) {
    const palette = ['#4A7AFF','#5DCFFF','#a855f7','#ec4899','#f59e0b','#10b981','#ef4444','#6366f1'];
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    return palette[h % palette.length];
  }

  function renderEmailRow(it) {
    const rb = rbucketsById();
    const rf = state.reviewer.flags[it.id];
    const row = document.createElement('div');
    row.className = 'item-row item-row-email';
    if (state.selectedId === it.id) row.classList.add('selected');
    if (it.isFlagged) row.classList.add('flagged');
    if (rf && rf.flagged) row.classList.add('reviewer-flagged');

    const rfm = it.rawFields || {};
    const from = parseAddress(rfm.from || it.author);
    const to = parseAddress(rfm.to || it.recipient);
    const subject = rfm.subject || it.summary || '(no subject)';
    const date = fmtEmailDate(rfm.date || it.timestamp);
    const preview = emailPreview(it.bodyText, 160);
    const seed = (from.addr || from.name || 'x').toLowerCase();

    const analystChip = it.bucket && analystBucketsById[it.bucket]
      ? `<div class="bucket-chip" style="background:${escapeAttr(analystBucketsById[it.bucket].color)}">${escapeHtml(analystBucketsById[it.bucket].name)}</div>`
      : '';
    const reviewerChip = rf && rf.bucket && rb[rf.bucket]
      ? `<div class="reviewer-chip" style="background:${escapeAttr(rb[rf.bucket].color)}">${escapeHtml(rb[rf.bucket].name)}</div>`
      : '';

    row.innerHTML = `
      <div class="email-avatar" style="background:${avatarColor(seed)}">${escapeHtml(avatarInitial(from.name, from.addr))}</div>
      <div class="email-body">
        <div class="email-row-top">
          <span class="email-sender">${escapeHtml(from.name || from.addr || '(unknown)')}</span>
          <span class="email-date">${escapeHtml(date)}</span>
        </div>
        <div class="email-subject">${escapeHtml(subject)}</div>
        ${preview ? `<div class="email-preview">${escapeHtml(preview)}</div>` : ''}
        ${(from.addr || to.addr) ? `<div class="email-route mono">${escapeHtml(from.addr || '')}${to.addr ? ' \u2192 ' + escapeHtml(to.addr) : ''}</div>` : ''}
      </div>
      <div class="email-flags">
        ${it.isFlagged ? '<span title="Analyst flag">\u{1F6A9}</span>' : ''}
        ${rf && rf.flagged ? '<span title="Your flag">\u{2B50}</span>' : ''}
        ${reviewerChip}
        ${analystChip}
      </div>
    `;
    row.onclick = () => { state.selectedId = it.id; rerender(); };
    return row;
  }

  function renderRow(it) {
    if (it.section === 'emails') return renderEmailRow(it);
    const rb = rbucketsById();
    const rf = state.reviewer.flags[it.id];
    const row = document.createElement('div');
    row.className = 'item-row';
    if (state.selectedId === it.id) row.classList.add('selected');
    if (it.isFlagged) row.classList.add('flagged');
    if (rf && rf.flagged) row.classList.add('reviewer-flagged');

    const firstAtt = it.attachments[0];
    const thumb = firstAtt ? DATA.thumbs[firstAtt] : null;
    const label = SECTION_LABELS[it.section] || it.section;

    let thumbHtml;
    if (thumb) {
      thumbHtml = `<img class="thumb" src="${escapeAttr(thumb)}" alt=""
                       onclick="event.stopPropagation(); openLightbox('${escapeJs(firstAtt)}')">`;
    } else {
      thumbHtml = `<div class="thumb-placeholder">${escapeHtml(label.charAt(0))}</div>`;
    }

    const people = (it.author || it.recipient)
      ? `<div class="item-people">${escapeHtml(it.author || '')}${it.recipient ? ' \u2192 ' + escapeHtml(it.recipient) : ''}</div>`
      : '';

    const analystChip = it.bucket && analystBucketsById[it.bucket]
      ? `<div class="bucket-chip" style="background:${escapeAttr(analystBucketsById[it.bucket].color)}">${escapeHtml(analystBucketsById[it.bucket].name)}</div>`
      : '';
    const reviewerChip = rf && rf.bucket && rb[rf.bucket]
      ? `<div class="reviewer-chip" style="background:${escapeAttr(rb[rf.bucket].color)}">${escapeHtml(rb[rf.bucket].name)}</div>`
      : '';

    row.innerHTML = `
      ${thumbHtml}
      <div class="item-main">
        <div class="item-headline">
          <span class="item-section">${escapeHtml(label)}</span>
          ${it.timestamp ? `<span class="item-ts">${escapeHtml(it.timestamp)}</span>` : ''}
          ${it.isFlagged ? '<span title="Analyst flag">\u{1F6A9}</span>' : ''}
          ${rf && rf.flagged ? '<span title="Your flag">\u{2B50}</span>' : ''}
        </div>
        <div class="item-summary">${escapeHtml(it.summary || it.bodyText || '\u2014')}</div>
        ${people}
      </div>
      ${reviewerChip}
      ${analystChip}
    `;
    row.onclick = () => { state.selectedId = it.id; rerender(); };
    return row;
  }

  function renderDetail() {
    const detail = document.getElementById('detail');
    if (state.view !== 'items') {
      detail.innerHTML = '<div class="detail-empty">Open a section to view items.</div>';
      return;
    }
    const it = DATA.items.find(x => x.id === state.selectedId);
    if (!it) {
      detail.innerHTML = '<div class="detail-empty">Select an item to view details.</div>';
      return;
    }
    if (it.section === 'emails') { renderEmailDetail(it, detail); return; }
    const label = SECTION_LABELS[it.section] || it.section;
    const bucket = it.bucket ? analystBucketsById[it.bucket] : null;
    const rf = getFlag(it.id);

    const chip = bucket
      ? `<span class="chip" style="background:${escapeAttr(bucket.color)}">${escapeHtml(bucket.name)}</span>`
      : '<span style="color:#475569">\u2014 Unassigned \u2014</span>';

    const flag = it.isFlagged ? '<span class="flag">\u{1F6A9} Analyst flagged</span>' : '';

    const note = it.note
      ? `<div class="detail-note"><div class="label">Investigator note</div>${escapeHtml(it.note)}</div>`
      : '';

    const attachments = it.attachments.length
      ? `<div class="detail-section">
           <label>Attachments (${it.attachments.length})</label>
           <div class="attachment-grid">${it.attachments.map(a => renderAttachment(a)).join('')}</div>
         </div>`
      : '';

    const fields = Object.entries(it.rawFields || {}).map(([k, v]) =>
      `<tr><td class="key">${escapeHtml(k)}</td><td class="val">${renderValue(v)}</td></tr>`
    ).join('');

    const bucketOptions = ['<option value="">\u2014 No bucket \u2014</option>']
      .concat(state.reviewer.buckets.map(b =>
        `<option value="${escapeAttr(b.id)}" ${rf.bucket === b.id ? 'selected' : ''}>${escapeHtml(b.name)}</option>`
      ))
      .concat(['<option value="__new__">+ Create new bucket\u2026</option>'])
      .join('');

    detail.innerHTML = `
      <div class="detail-header">
        <div class="detail-section-label">${escapeHtml(label)}</div>
        <div class="detail-id">${escapeHtml(it.id)}</div>
      </div>
      <div class="detail-bucket-bar">
        <span>Analyst bucket:</span>${chip}
        <span style="flex:1"></span>
        ${flag}
      </div>
      ${note}
      ${attachments}
      <div class="detail-section detail-fields">
        <label>All fields</label>
        <table><tbody>${fields}</tbody></table>
      </div>

      <div class="reviewer-block">
        <div class="reviewer-label">
          Your annotations
          <span class="badge">SAVED LOCALLY</span>
        </div>
        <div class="reviewer-row">
          <button id="rv-flag" class="reviewer-flag-btn ${rf.flagged ? 'active' : ''}">
            <span>${rf.flagged ? '\u{2B50} Flagged' : '\u2606 Flag this'}</span>
          </button>
          <select id="rv-bucket" class="reviewer-bucket-select">${bucketOptions}</select>
        </div>
        <textarea id="rv-note" class="reviewer-note-input"
          placeholder="Add a private note (saved in this browser)\u2026">${escapeHtml(rf.note || '')}</textarea>
        <div class="reviewer-status" id="rv-status"></div>
      </div>
    `;

    document.getElementById('rv-flag').onclick = () => {
      setFlag(it.id, { flagged: !getFlag(it.id).flagged });
      flashStatus(); renderDetail(); renderSidebar(); renderItemList();
    };
    document.getElementById('rv-bucket').onchange = (e) => {
      const v = e.target.value;
      if (v === '__new__') {
        openNewBucketModal((newId) => {
          if (newId) setFlag(it.id, { bucket: newId });
          flashStatus(); rerender();
        });
        e.target.value = rf.bucket || '';
        return;
      }
      setFlag(it.id, { bucket: v || null });
      flashStatus(); renderDetail(); renderSidebar(); renderItemList();
    };
    const noteEl = document.getElementById('rv-note');
    let noteTimer = null;
    noteEl.oninput = (e) => {
      clearTimeout(noteTimer);
      noteTimer = setTimeout(() => {
        setFlag(it.id, { note: e.target.value });
        flashStatus();
      }, 250);
    };
  }

  // ─── Email-style detail panel (Gmail-ish header + large body) ────
  function renderEmailDetail(it, detail) {
    const rf = getFlag(it.id);
    const bucket = it.bucket ? analystBucketsById[it.bucket] : null;
    const chip = bucket
      ? `<span class="chip" style="background:${escapeAttr(bucket.color)}">${escapeHtml(bucket.name)}</span>`
      : '<span style="color:#475569">\u2014 Unassigned \u2014</span>';
    const flag = it.isFlagged ? '<span class="flag">\u{1F6A9} Analyst flagged</span>' : '';
    const note = it.note
      ? `<div class="detail-note"><div class="label">Investigator note</div>${escapeHtml(it.note)}</div>`
      : '';

    const rfm = it.rawFields || {};
    const from = parseAddress(rfm.from || it.author);
    const to = parseAddress(rfm.to || it.recipient);
    const cc = rfm.cc ? String(rfm.cc) : '';
    const bcc = rfm.bcc ? String(rfm.bcc) : '';
    const subject = rfm.subject || it.summary || '(no subject)';
    const date = rfm.date || it.timestamp || '';
    const labels = Array.isArray(rfm.labels) ? rfm.labels
                 : (rfm.labels ? String(rfm.labels).split(',').map(s => s.trim()) : []);
    const body = it.bodyText || '';
    const seed = (from.addr || from.name || 'x').toLowerCase();

    const attachments = it.attachments.length
      ? `<div class="detail-section">
           <label>Attachments (${it.attachments.length})</label>
           <div class="attachment-grid">${it.attachments.map(a => renderAttachment(a)).join('')}</div>
         </div>`
      : '';

    const fields = Object.entries(rfm).map(([k, v]) =>
      `<tr><td class="key">${escapeHtml(k)}</td><td class="val">${renderValue(v)}</td></tr>`
    ).join('');

    const bucketOptions = ['<option value="">\u2014 No bucket \u2014</option>']
      .concat(state.reviewer.buckets.map(b =>
        `<option value="${escapeAttr(b.id)}" ${rf.bucket === b.id ? 'selected' : ''}>${escapeHtml(b.name)}</option>`
      ))
      .concat(['<option value="__new__">+ Create new bucket\u2026</option>'])
      .join('');

    detail.innerHTML = `
      <div class="detail-bucket-bar">
        <span>Analyst bucket:</span>${chip}
        <span style="flex:1"></span>
        ${flag}
      </div>
      ${note}
      <div class="email-detail-card">
        <div class="email-detail-subject">${escapeHtml(subject)}</div>
        ${labels.length ? `<div class="email-detail-labels">${labels.map(l => `<span class="email-detail-label">${escapeHtml(l)}</span>`).join('')}</div>` : ''}
        <div class="email-detail-header">
          <div class="email-detail-avatar" style="background:${avatarColor(seed)}">${escapeHtml(avatarInitial(from.name, from.addr))}</div>
          <div class="email-detail-meta">
            <div class="email-detail-row"><span class="email-detail-key">From:</span><span class="email-detail-val">${escapeHtml(from.name || '')} ${from.addr ? `<span class="mono">&lt;${escapeHtml(from.addr)}&gt;</span>` : ''}</span></div>
            <div class="email-detail-row"><span class="email-detail-key">To:</span><span class="email-detail-val mono">${escapeHtml(to.addr || rfm.to || '')}</span></div>
            ${cc ? `<div class="email-detail-row"><span class="email-detail-key">Cc:</span><span class="email-detail-val mono">${escapeHtml(cc)}</span></div>` : ''}
            ${bcc ? `<div class="email-detail-row"><span class="email-detail-key">Bcc:</span><span class="email-detail-val mono">${escapeHtml(bcc)}</span></div>` : ''}
            <div class="email-detail-row"><span class="email-detail-key">Date:</span><span class="email-detail-val">${escapeHtml(date)}</span></div>
          </div>
        </div>
        <div class="email-detail-body">${escapeHtml(body)}</div>
      </div>
      ${attachments}
      <div class="detail-section detail-fields">
        <label>All fields</label>
        <table><tbody>${fields}</tbody></table>
      </div>

      <div class="reviewer-block">
        <div class="reviewer-label">
          Your annotations
          <span class="badge">SAVED LOCALLY</span>
        </div>
        <div class="reviewer-row">
          <button id="rv-flag" class="reviewer-flag-btn ${rf.flagged ? 'active' : ''}">
            <span>${rf.flagged ? '\u{2B50} Flagged' : '\u2606 Flag this'}</span>
          </button>
          <select id="rv-bucket" class="reviewer-bucket-select">${bucketOptions}</select>
        </div>
        <textarea id="rv-note" class="reviewer-note-input"
          placeholder="Add a private note (saved in this browser)\u2026">${escapeHtml(rf.note || '')}</textarea>
        <div class="reviewer-status" id="rv-status"></div>
      </div>
    `;

    document.getElementById('rv-flag').onclick = () => {
      setFlag(it.id, { flagged: !getFlag(it.id).flagged });
      flashStatus(); renderDetail(); renderSidebar(); renderItemList();
    };
    document.getElementById('rv-bucket').onchange = (e) => {
      const v = e.target.value;
      if (v === '__new__') {
        openNewBucketModal((newId) => {
          if (newId) setFlag(it.id, { bucket: newId });
          flashStatus(); rerender();
        });
        e.target.value = rf.bucket || '';
        return;
      }
      setFlag(it.id, { bucket: v || null });
      flashStatus(); renderDetail(); renderSidebar(); renderItemList();
    };
    const noteEl2 = document.getElementById('rv-note');
    let noteTimer2 = null;
    noteEl2.oninput = (e) => {
      clearTimeout(noteTimer2);
      noteTimer2 = setTimeout(() => {
        setFlag(it.id, { note: e.target.value });
        flashStatus();
      }, 250);
    };
  }

  function flashStatus() {
    const el = document.getElementById('rv-status');
    if (!el) return;
    const t = new Date().toLocaleTimeString();
    el.textContent = `Saved \u00B7 ${t}`;
    setTimeout(() => { if (el.textContent.startsWith('Saved')) el.textContent = ''; }, 2000);
  }

  function renderAttachment(filename) {
    const thumb = DATA.thumbs[filename];
    const href = `media/${encodeURIComponent(filename)}`;
    const inner = thumb
      ? `<img src="${escapeAttr(thumb)}" alt=""><span class="att-name">${escapeHtml(filename)}</span>`
      : `<span style="font-size:16px">\u{1F4CE}</span><span class="att-name">${escapeHtml(filename)}</span>`;
    if (thumb) {
      return `<a class="attachment-tile" onclick="event.preventDefault(); openLightbox('${escapeJs(filename)}')" href="${escapeAttr(href)}" title="${escapeAttr(filename)}">${inner}</a>`;
    }
    return `<a class="attachment-tile" target="_blank" href="${escapeAttr(href)}" title="${escapeAttr(filename)}">${inner}</a>`;
  }

  function renderValue(v) {
    if (v == null) return '<span style="color:#475569;font-style:italic">\u2014</span>';
    if (typeof v === 'string') return escapeHtml(v);
    if (typeof v === 'number' || typeof v === 'boolean') return escapeHtml(String(v));
    return `<pre style="margin:0;font-size:10px;color:#94a3b8;background:#0a0e1c;padding:6px;border-radius:4px;max-height:200px;overflow:auto">${escapeHtml(JSON.stringify(v, null, 2))}</pre>`;
  }

  function fmtDate(s) {
    if (!s) return '\u2014';
    try {
      const d = new Date(s);
      if (isNaN(d.getTime())) return s;
      return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
    } catch { return s; }
  }

  function renderOverview() {
    const c = DATA.case || {};
    const itemsBySection = {};
    const itemsByBucket = { unbucketed: 0 };
    let analystFlagged = 0;
    for (const it of DATA.items) {
      itemsBySection[it.section] = (itemsBySection[it.section] || 0) + 1;
      if (!it.bucket) itemsByBucket.unbucketed++;
      else itemsByBucket[it.bucket] = (itemsByBucket[it.bucket] || 0) + 1;
      if (it.isFlagged) analystFlagged++;
    }
    const totalBucketed = DATA.items.length - itemsByBucket.unbucketed;
    const sectionsSorted = Object.keys(itemsBySection).sort(
      (a,b) => itemsBySection[b] - itemsBySection[a]
    );

    const myFlags = state.reviewer.flags;
    const myFlaggedIds = Object.keys(myFlags).filter(k => myFlags[k].flagged);
    const myBucketedIds = Object.keys(myFlags).filter(k => myFlags[k].bucket);
    const myNoteIds = Object.keys(myFlags).filter(k => myFlags[k].note && myFlags[k].note.trim());

    const bioItems = DATA.items.filter(i => i.section === 'bio');
    const reqParamsItems = DATA.items.filter(i => i.section === 'request_parameters');

    // ── Parse structured bio fields (raw_fields.fields = [{section}|{label,value}])
    //    so we can route Subscriber Info → Account card,
    //    Hangouts/Chat → Bio card, and No-Records → Triage card.
    const bioGroups = {};         // section title → [{label,value}]
    let bioFallbackText = '';     // pre-structured legacy bio dumps
    {
      let current = null;
      for (const bi of bioItems) {
        const rf = bi.rawFields || {};
        const arr = Array.isArray(rf.fields) ? rf.fields : null;
        if (arr) {
          for (const f of arr) {
            if (f && typeof f === 'object' && typeof f.section === 'string') {
              current = f.section;
              if (!bioGroups[current]) bioGroups[current] = [];
            } else if (f && typeof f === 'object' && typeof f.label === 'string') {
              if (!current) current = 'Bio';
              if (!bioGroups[current]) bioGroups[current] = [];
              bioGroups[current].push({ label: f.label, value: String(f.value ?? '') });
            }
          }
        } else if (bi.bodyText) {
          bioFallbackText += (bioFallbackText ? '\n\n' : '') + bi.bodyText;
        }
      }
    }
    const subscriberRows = bioGroups['Subscriber Information'] || [];
    const noRecordsRows  = bioGroups['Categories With No Records Returned'] || [];
    const BIO_ROUTED_AWAY = new Set([
      'Subscriber Information',
      'Categories With No Records Returned',
      'Imported From',
    ]);
    const bioCardGroups = Object.entries(bioGroups)
      .filter(([k, v]) => !BIO_ROUTED_AWAY.has(k) && v.length > 0);

    const subscriberRowsHtml = subscriberRows.length
      ? subscriberRows.map(r =>
          `<dt>${escapeHtml(r.label)}</dt><dd>${escapeHtml(r.value)}</dd>`
        ).join('')
      : '';

    const accountCard = `
      <section class="ov-card">
        <header class="ov-card-header">
          <span class="ov-card-icon">\u{1F4CB}</span><h3>Account</h3>
        </header>
        <dl class="ov-kv">
          <dt>Service</dt><dd>${escapeHtml(c.providerDisplay || '\u2014')}</dd>
          <dt>Target ID</dt><dd class="mono">${escapeHtml(c.targetAccount || '\u2014')}</dd>
          <dt>Date Range</dt><dd>${escapeHtml(c.dateRange || '\u2014')}</dd>
          <dt>Generated</dt><dd>${escapeHtml(c.generatedAtSource || '\u2014')}</dd>
          <dt>Imported</dt><dd>${fmtDate(c.importedAt)}</dd>
          ${subscriberRows.length ? `<dt class="ov-bio-section">Subscriber Information</dt><dd></dd>${subscriberRowsHtml}` : ''}
        </dl>
      </section>`;

    let bioBody;
    if (bioCardGroups.length > 0) {
      bioBody = bioCardGroups.map(([title, rows]) => `
        <dl class="ov-kv">
          <dt class="ov-bio-section">${escapeHtml(title)}</dt><dd></dd>
          ${rows.map(r => `<dt>${escapeHtml(r.label)}</dt><dd>${escapeHtml(r.value)}</dd>`).join('')}
        </dl>
      `).join('');
    } else if (bioFallbackText) {
      bioBody = `<div style="margin-bottom:8px;font-size:12px;color:#e2e8f0;white-space:pre-wrap">${escapeHtml(bioFallbackText)}</div>`;
    } else if (subscriberRows.length > 0) {
      // Subscriber info already routed to Account card — Bio card has nothing distinct.
      bioBody = '<div class="ov-empty">Subscriber information shown in Account card.</div>';
    } else {
      bioBody = '<div class="ov-empty">No bio data in this return.</div>';
    }
    const bioCard = `
      <section class="ov-card">
        <header class="ov-card-header"><span class="ov-card-icon">\u{1F464}</span><h3>Bio</h3></header>
        ${bioBody}
      </section>`;

    const summaryTiles = sectionsSorted.map(s => `
      <div class="ov-tile" onclick="window._jumpToSection('${escapeJs(s)}')">
        <div class="ov-tile-icon">${SECTION_ICONS[s] || '\u2022'}</div>
        <div class="ov-tile-count">${itemsBySection[s]}</div>
        <div class="ov-tile-label">${escapeHtml(SECTION_LABELS[s] || s)}</div>
      </div>
    `).join('');
    const summaryCard = `
      <section class="ov-card ov-card-wide">
        <header class="ov-card-header">
          <span class="ov-card-icon">\u{1F5C2}</span>
          <h3>Data Summary</h3>
          <span class="ov-card-subtle">Click a category to view items</span>
        </header>
        <div class="ov-tiles">${summaryTiles}</div>
      </section>`;

    const analystBucketChips = DATA.buckets.length
      ? `<div class="ov-bucket-chips">${DATA.buckets.map(b => `
          <span class="ov-bchip" onclick="window._jumpToBucket('${escapeJs(b.id)}')">
            <span class="dot" style="background:${escapeAttr(b.color)}"></span>
            ${escapeHtml(b.name)}
            <span class="ct">${itemsByBucket[b.id] || 0}</span>
          </span>`).join('')}</div>`
      : '';
    const triageCard = `
      <section class="ov-card">
        <header class="ov-card-header">
          <span class="ov-card-icon">\u{1F3AF}</span><h3>Analyst Triage</h3>
        </header>
        <div class="ov-stats">
          <div class="ov-stat" onclick="window._jumpToBucket('flagged')">
            <div class="ov-stat-num flag">${analystFlagged}</div>
            <div class="ov-stat-label">Flagged</div>
          </div>
          <div class="ov-stat" onclick="window._goAllItems()">
            <div class="ov-stat-num good">${totalBucketed}</div>
            <div class="ov-stat-label">Bucketed</div>
          </div>
          <div class="ov-stat" onclick="window._jumpToBucket('unbucketed')">
            <div class="ov-stat-num warn">${itemsByBucket.unbucketed}</div>
            <div class="ov-stat-label">Unbucketed</div>
          </div>
        </div>
        ${analystBucketChips}
        ${noRecordsRows.length ? `
          <div class="ov-no-records">
            <div class="ov-card-subtle ov-no-records-title">Categories With No Records Returned</div>
            <div class="ov-no-records-chips">
              ${noRecordsRows.map(r => `<span class="ov-no-records-chip" title="${escapeAttr(r.value || r.label)}">${escapeHtml(r.label)}</span>`).join('')}
            </div>
          </div>` : ''}
      </section>`;

    const myBucketChips = state.reviewer.buckets.length
      ? `<div class="ov-bucket-chips" style="margin-top:8px">${state.reviewer.buckets.map(b => {
          const ct = myBucketedIds.filter(id => myFlags[id].bucket === b.id).length;
          return `<span class="ov-bchip" onclick="window._jumpToBucket('${escapeJs(b.id)}')">
            <span class="dot" style="background:${escapeAttr(b.color)}"></span>
            ${escapeHtml(b.name)}
            <span class="ct">${ct}</span>
          </span>`;
        }).join('')}</div>`
      : '<div class="ov-empty" style="margin-top:8px">No personal buckets created yet. Open an item and use the bucket dropdown.</div>';

    const recentFlagged = myFlaggedIds.slice(-5).reverse().map(id => {
      const it = DATA.items.find(x => x.id === id);
      if (!it) return '';
      const label = SECTION_LABELS[it.section] || it.section;
      const txt = (it.summary || it.bodyText || '\u2014').slice(0, 70);
      return `<div class="ov-myflag-row" onclick="window._openItem('${escapeJs(id)}')">
        <span class="icon">\u{2B50}</span>
        <span class="text">${escapeHtml(txt)}</span>
        <span class="meta">${escapeHtml(label)}</span>
      </div>`;
    }).join('');

    const myFlagsCard = `
      <section class="ov-card ov-card-wide">
        <header class="ov-card-header">
          <span class="ov-card-icon">\u{2B50}</span>
          <h3>My Flags</h3>
          <span class="ov-card-subtle">Saved in this browser \u00B7 use Export My Flags to keep them</span>
        </header>
        <div class="ov-stats">
          <div class="ov-stat" onclick="window._jumpToBucket('my-flagged')">
            <div class="ov-stat-num cyan">${myFlaggedIds.length}</div>
            <div class="ov-stat-label">My Flags</div>
          </div>
          <div class="ov-stat">
            <div class="ov-stat-num cyan">${myBucketedIds.length}</div>
            <div class="ov-stat-label">In My Buckets</div>
          </div>
          <div class="ov-stat">
            <div class="ov-stat-num cyan">${myNoteIds.length}</div>
            <div class="ov-stat-label">My Notes</div>
          </div>
        </div>
        ${myBucketChips}
        ${recentFlagged ? `<div style="margin-top:10px"><div class="ov-card-subtle" style="margin-bottom:6px">Recent flags</div><div class="ov-myflag-list">${recentFlagged}</div></div>` : ''}
      </section>`;

    const reqRows = reqParamsItems.length
      ? Object.entries(reqParamsItems[0].rawFields || {}).slice(0, 12)
          .map(([k,v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v).slice(0, 200))}</dd>`).join('')
      : '';
    const sourceCard = `
      <section class="ov-card ov-card-wide">
        <header class="ov-card-header"><span class="ov-card-icon">\u{1F4E6}</span><h3>Source File</h3></header>
        <dl class="ov-kv">
          <dt>Filename</dt><dd class="mono">${escapeHtml(c.sourceFilename || '\u2014')}</dd>
          ${reqRows}
        </dl>
      </section>`;

    // Hash scan card
    const sr = (DATA && DATA.scanResults) || {};
    const hs = sr.hashScan || null;
    const hashScanCard = hs
      ? (() => {
          const recent = (hs.hits || []).slice(0, 10).map(h => `
            <div class="ov-myflag-row" title="${escapeAttr(h.sha1)}">
              <span class="icon">\u{1F517}</span>
              <span class="text">${escapeHtml(h.filename)}</span>
              <span class="meta">${escapeHtml(h.listName || '')}${h.category ? ' \u00B7 ' + escapeHtml(h.category) : ''}</span>
            </div>`).join('');
          return `
            <section class="ov-card">
              <header class="ov-card-header">
                <span class="ov-card-icon">\u{1F9EC}</span>
                <h3>Hash Scan</h3>
                <span class="ov-card-subtle">${fmtDate(hs.ranAt)}</span>
              </header>
              <div class="ov-stats">
                <div class="ov-stat"><div class="ov-stat-num flag">${(hs.hits || []).length}</div><div class="ov-stat-label">Hits</div></div>
                <div class="ov-stat"><div class="ov-stat-num cyan">${hs.filesScanned || 0}</div><div class="ov-stat-label">Scanned</div></div>
                <div class="ov-stat"><div class="ov-stat-num cyan">${hs.filesTotal || 0}</div><div class="ov-stat-label">Files</div></div>
              </div>
              ${recent ? `<div style="margin-top:10px"><div class="ov-card-subtle" style="margin-bottom:6px">Top hits</div><div class="ov-myflag-list">${recent}</div></div>` : '<div class="ov-empty" style="margin-top:6px">No hash matches \u2014 nothing in the loaded databases matched these media files.</div>'}
            </section>`;
        })()
      : `<section class="ov-card">
          <header class="ov-card-header"><span class="ov-card-icon">\u{1F9EC}</span><h3>Hash Scan</h3></header>
          <div class="ov-empty">No scan conducted before report export.</div>
        </section>`;

    // Keyword scan card
    const ks = sr.keywordScan || null;
    const keywordScanCard = ks
      ? (() => {
          const recent = (ks.hits || []).slice(0, 10).map(h => `
            <div class="ov-myflag-row" onclick="window._openItem('${escapeJs(h.itemId)}')">
              <span class="icon">\u{1F50D}</span>
              <span class="text"><strong style="color:#5dcfff">${escapeHtml(h.keyword)}</strong> \u00B7 ${escapeHtml(h.snippet)}</span>
              <span class="meta">${escapeHtml(SECTION_LABELS[h.section] || h.section)}</span>
            </div>`).join('');
          return `
            <section class="ov-card">
              <header class="ov-card-header">
                <span class="ov-card-icon">\u{1F50D}</span>
                <h3>Keyword Scan</h3>
                <span class="ov-card-subtle">${fmtDate(ks.ranAt)}</span>
              </header>
              <div class="ov-stats">
                <div class="ov-stat"><div class="ov-stat-num flag">${(ks.hits || []).length}</div><div class="ov-stat-label">Hits</div></div>
                <div class="ov-stat"><div class="ov-stat-num cyan">${ks.keywordCount || 0}</div><div class="ov-stat-label">Keywords</div></div>
                <div class="ov-stat"><div class="ov-stat-num cyan">${ks.itemsScanned || 0}</div><div class="ov-stat-label">Items</div></div>
              </div>
              <div class="ov-card-subtle" style="margin-top:6px">Lists: ${(ks.listsUsed || []).map(escapeHtml).join(', ') || '\u2014'}</div>
              ${recent ? `<div style="margin-top:10px"><div class="ov-card-subtle" style="margin-bottom:6px">Top hits</div><div class="ov-myflag-list">${recent}</div></div>` : '<div class="ov-empty" style="margin-top:6px">No keyword matches.</div>'}
            </section>`;
        })()
      : `<section class="ov-card">
          <header class="ov-card-header"><span class="ov-card-icon">\u{1F50D}</span><h3>Keyword Scan</h3></header>
          <div class="ov-empty">No scan conducted before report export.</div>
        </section>`;

    document.getElementById('overview-scroll').innerHTML = `
      <div class="ov-grid">
        ${accountCard}
        ${bioCard}
        ${summaryCard}
        ${triageCard}
        ${myFlagsCard}
        ${hashScanCard}
        ${keywordScanCard}
        ${sourceCard}
      </div>
    `;
  }
  window._jumpToSection = function(s) { state.view='items'; state.sectionFilter=s; state.bucketFilter=null; state.selectedId=null; rerender(); };
  window._jumpToBucket  = function(id){ state.view='items'; state.sectionFilter=null; state.bucketFilter=id; state.selectedId=null; rerender(); };
  window._goAllItems    = function() { state.view='items'; state.sectionFilter=null; state.bucketFilter=null; state.selectedId=null; rerender(); };
  window._openItem      = function(id){ state.view='items'; state.sectionFilter=null; state.bucketFilter=null; state.selectedId=id; rerender(); };

  window.openLightbox = function(filename) {
    const img = document.getElementById('lightbox-img');
    const meta = document.getElementById('lightbox-meta');
    img.src = `media/${encodeURIComponent(filename)}`;
    img.alt = filename;
    meta.textContent = filename;
    document.getElementById('lightbox').classList.remove('hidden');
  };
  window.closeLightbox = function(e) {
    if (e.target.tagName === 'IMG') return;
    document.getElementById('lightbox').classList.add('hidden');
  };
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      document.getElementById('lightbox').classList.add('hidden');
      closeModal({target: document.getElementById('modal')});
    }
  });

  window.closeModal = function(e) {
    if (!e || e.target === document.getElementById('modal') || e.forced) {
      document.getElementById('modal').classList.add('hidden');
    }
  };
  document.getElementById('modal').addEventListener('click', (e) => {
    if (e.target.id === 'modal') document.getElementById('modal').classList.add('hidden');
  });
  document.getElementById('modal-x-btn').addEventListener('click', () => {
    document.getElementById('modal').classList.add('hidden');
  });
  function openModal(title, contentHtml) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-content').innerHTML = contentHtml;
    document.getElementById('modal').classList.remove('hidden');
  }
  function openNewBucketModal(cb) {
    const defaultColor = REVIEWER_PALETTE[state.reviewer.buckets.length % REVIEWER_PALETTE.length];
    openModal('Create personal bucket', `
      <label>Name</label>
      <input type="text" id="rb-name" placeholder="e.g. Suspect Conversations" maxlength="40">
      <label>Color</label>
      <input type="color" id="rb-color" value="${defaultColor}">
      <div class="modal-actions">
        <button class="btn" id="rb-cancel">Cancel</button>
        <button class="btn btn-primary" id="rb-save">Create</button>
      </div>
    `);
    setTimeout(() => document.getElementById('rb-name').focus(), 50);
    document.getElementById('rb-cancel').onclick = () => { closeModal({forced:true}); cb && cb(null); };
    document.getElementById('rb-save').onclick = () => {
      const name = document.getElementById('rb-name').value.trim();
      const color = document.getElementById('rb-color').value;
      if (!name) { toast('Name is required.', 'error'); return; }
      const id = newRBucket(name, color);
      closeModal({forced:true});
      toast('Bucket created.', 'success');
      cb && cb(id);
    };
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast' + (kind ? ' ' + kind : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), 3000);
  }

  function exportFlags() {
    const payload = {
      format: 'scout-warrant-reviewer-flags',
      version: STATE_VERSION,
      caseId: CASE_ID,
      provider: (DATA.case && DATA.case.provider) || null,
      target: (DATA.case && DATA.case.targetAccount) || null,
      exportedAt: new Date().toISOString(),
      reviewer: state.reviewer,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeTarget = (payload.target || 'case').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 40);
    a.download = `${CASE_ID}_${safeTarget}_reviewer_flags.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
    const total = Object.keys(state.reviewer.flags).length + state.reviewer.buckets.length;
    toast(`Exported ${total} reviewer entries.`, 'success');
  }

  function importFlags(file) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const obj = JSON.parse(reader.result);
        if (!obj || obj.format !== 'scout-warrant-reviewer-flags') {
          toast('Not a valid reviewer-flags file.', 'error'); return;
        }
        if (obj.caseId && obj.caseId !== CASE_ID) {
          if (!confirm(`This flags file is for case ${obj.caseId}, but you're viewing ${CASE_ID}. Import anyway?`)) return;
        }
        const incoming = obj.reviewer || {};
        const merge = confirm('OK = merge with your existing flags.  Cancel = replace.');
        if (merge) {
          state.reviewer.flags = Object.assign({}, state.reviewer.flags, incoming.flags || {});
          const existingIds = new Set(state.reviewer.buckets.map(b => b.id));
          for (const b of (incoming.buckets || [])) {
            if (!existingIds.has(b.id)) state.reviewer.buckets.push(b);
          }
        } else {
          state.reviewer.flags = incoming.flags || {};
          state.reviewer.buckets = incoming.buckets || [];
          state.reviewer.reviewerName = incoming.reviewerName || '';
        }
        saveReviewer();
        rerender();
        toast('Reviewer flags imported.', 'success');
      } catch (e) {
        toast('Import failed: ' + e.message, 'error');
      }
    };
    reader.readAsText(file);
  }

  function clearFlags() {
    if (!confirm('Erase ALL reviewer flags, notes, and personal buckets for this case? This only affects this browser.')) return;
    state.reviewer = defaultReviewer();
    saveReviewer();
    rerender();
    toast('Reviewer annotations cleared.', 'success');
  }

  document.getElementById('search').addEventListener('input', e => {
    state.search = e.target.value;
    if (state.view !== 'items') state.view = 'items';
    rerender();
  });
  document.getElementById('clear-filters').addEventListener('click', () => {
    state.sectionFilter = null; state.bucketFilter = null; state.search = '';
    document.getElementById('search').value = '';
    rerender();
  });
  document.getElementById('btn-toggle-sidebar').addEventListener('click', () => {
    const sb = document.getElementById('sidebar');
    sb.style.display = sb.style.display === 'none' ? '' : 'none';
  });
  document.getElementById('btn-export-flags').addEventListener('click', exportFlags);
  document.getElementById('btn-clear-flags').addEventListener('click', clearFlags);
  document.getElementById('btn-import-flags').addEventListener('click', () => {
    document.getElementById('file-import').click();
  });
  document.getElementById('file-import').addEventListener('change', e => {
    if (e.target.files && e.target.files[0]) importFlags(e.target.files[0]);
    e.target.value = '';
  });
  document.getElementById('btn-new-rbucket').addEventListener('click', () => openNewBucketModal(() => rerender()));

  function rerender() {
    if (state.view === 'overview') {
      document.getElementById('overview-view').classList.remove('hidden');
      document.getElementById('itemlist-view').classList.add('hidden');
      renderSidebar();
      renderOverview();
      renderDetail();
    } else {
      document.getElementById('overview-view').classList.add('hidden');
      document.getElementById('itemlist-view').classList.remove('hidden');
      if (!state.selectedId) {
        const f = getFilteredItems();
        if (f.length) state.selectedId = f[0].id;
      }
      renderSidebar();
      renderItemList();
      renderDetail();
    }
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function escapeAttr(s) { return escapeHtml(s); }
  function escapeJs(s) { return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }

  renderTopbar();
  rerender();
})();
"#;
