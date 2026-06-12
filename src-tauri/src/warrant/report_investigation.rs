//! Investigation-level HTML report exporter.
//!
//! Builds the combined "detective receives one folder" deliverable for
//! a multi-return investigation:
//!
//! ```text
//! <dest>/Scout_Investigation_<NAME>_<YYYYMMDD_HHMMSS>/
//! ├── index.html                          # cover + roll-up + roster
//! └── returns/
//!     ├── 01_<label>_<provider>/index.html + media/   (single-return report)
//!     ├── 02_...
//!     └── NN_...
//! ```
//!
//! Each per-return subfolder is the existing single-return report
//! ([`super::report::export_report_to_folder`]) — the detective can open
//! either the top-level `index.html` (for the case-wide view) or any of
//! the per-return `index.html` files directly.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::investigation::{self, Investigation, ReturnDetail};
use super::report::{self, ReportError};
use super::triage_state;

/// Progress events emitted to the frontend during an investigation
/// export.  Stages, in order:
/// 1. `started`  — total returns known, nothing written yet
/// 2. `return`   — repeated, once per return; `index` is 1-based
/// 3. `rollup`   — building flagged-items roll-up table
/// 4. `cover`    — rendering the top-level index.html
/// 5. `done`     — emitted by the command after `export_investigation_report` returns
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportProgress {
    pub stage: String,
    pub index: usize,
    pub total: usize,
    pub label: String,
}

/// Callback used by the exporter to push progress upstream.  Boxed so
/// the function signature stays a single concrete type.
pub type ProgressEmitter<'a> = &'a dyn Fn(ExportProgress);

/// No-op emitter for callers (e.g. tests) that don't care.
pub fn noop_emitter(_: ExportProgress) {}

/// Top-level entry.  Reads the investigation, generates per-return
/// reports into numbered subfolders, then writes the cover-page
/// `index.html`.  Returns the path to the new investigation folder.
pub fn export_investigation_report(
    investigation_id: &str,
    dest_dir: &Path,
    emit: ProgressEmitter,
) -> Result<PathBuf, ReportError> {
    if !dest_dir.exists() {
        return Err(ReportError::Other(format!(
            "destination does not exist: {}",
            dest_dir.display()
        )));
    }

    let detail = investigation::load_detail(investigation_id)
        .map_err(ReportError::State)?;

    // ─── Build unique top-level folder name ────────────────────────────
    let name_slug = sanitize_slug(&detail.investigation.name);
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let folder_name = format!("Scout_Investigation_{}_{}", name_slug, ts);
    let root = dest_dir.join(folder_name);
    fs::create_dir_all(&root)?;

    let returns_root = root.join("returns");
    fs::create_dir_all(&returns_root)?;

    let total = detail.returns.len();
    emit(ExportProgress {
        stage: "started".to_string(),
        index: 0,
        total,
        label: detail.investigation.name.clone(),
    });

    // ─── Per-return reports ────────────────────────────────────────────
    // Each subfolder is numbered for stable ordering when the OS lists
    // them alphabetically.  We preserve roster order (= investigation
    // returns order).
    let mut roster: Vec<RosterRow> = Vec::with_capacity(detail.returns.len());
    for (idx, ret) in detail.returns.iter().enumerate() {
        let n = idx + 1;
        emit(ExportProgress {
            stage: "return".to_string(),
            index: n,
            total,
            label: ret.label.clone(),
        });
        let label_slug = sanitize_slug(&ret.label);
        let provider_slug = sanitize_slug(&ret.summary.provider_display);
        let sub_name = format!("{:02}_{}_{}", n, label_slug, provider_slug);
        let sub_folder = returns_root.join(&sub_name);

        // If the return data has gone missing, skip gracefully.
        if report::export_report_to_folder(&ret.summary.case_id, &sub_folder).is_err() {
            continue;
        }

        roster.push(RosterRow {
            index: n,
            label: ret.label.clone(),
            subfolder: sub_name,
            ret_detail: ret.clone(),
        });
    }

    // ─── Pull flagged items across all returns for the roll-up table ───
    emit(ExportProgress {
        stage: "rollup".to_string(),
        index: total,
        total,
        label: String::new(),
    });
    let mut flagged: Vec<FlaggedRow> = Vec::new();
    for row in &roster {
        if let Ok(cd) = triage_state::load_case_detail(&row.ret_detail.summary.case_id) {
            let bucket_lookup: std::collections::HashMap<&str, &str> = cd
                .buckets
                .iter()
                .map(|b| (b.id.as_str(), b.name.as_str()))
                .collect();
            for item in cd.items.iter().filter(|i| i.is_flagged) {
                let bucket_name = item
                    .bucket
                    .as_deref()
                    .and_then(|id| bucket_lookup.get(id).copied())
                    .unwrap_or("")
                    .to_string();
                flagged.push(FlaggedRow {
                    return_index: row.index,
                    return_label: row.label.clone(),
                    return_subfolder: row.subfolder.clone(),
                    item_id: item.id.clone(),
                    section: item.section_display.clone(),
                    timestamp: item.timestamp.clone().unwrap_or_default(),
                    author: item.author.clone().unwrap_or_default(),
                    summary: item
                        .summary
                        .clone()
                        .or_else(|| item.body_text.clone())
                        .unwrap_or_default(),
                    bucket: bucket_name,
                    note: item.note.clone().unwrap_or_default(),
                });
            }
        }
    }

    // ─── Write cover-page index.html ───────────────────────────────────
    emit(ExportProgress {
        stage: "cover".to_string(),
        index: total,
        total,
        label: String::new(),
    });
    let html = render_cover_html(&detail.investigation, &roster, &flagged);
    fs::write(root.join("index.html"), html)?;

    Ok(root)
}

// ─── Helpers ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RosterRow {
    index: usize,
    label: String,
    subfolder: String,
    ret_detail: ReturnDetail,
}

struct FlaggedRow {
    return_index: usize,
    return_label: String,
    return_subfolder: String,
    item_id: String,
    section: String,
    timestamp: String,
    author: String,
    summary: String,
    bucket: String,
    note: String,
}

/// Strict slugifier — alphanum + `_`, max 40 chars.  Mirrors the rule
/// used by the single-return report so folders look consistent.
fn sanitize_slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_us = true;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_us = false;
        } else if !prev_us {
            out.push('_');
            prev_us = true;
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

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Truncate for table cells — keeps the HTML compact when summaries are
/// long paragraphs.
fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn render_cover_html(
    inv: &Investigation,
    roster: &[RosterRow],
    flagged: &[FlaggedRow],
) -> String {
    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Aggregate counts.
    let total_items: usize = roster.iter().map(|r| r.ret_detail.summary.item_count).sum();
    let total_flagged: usize = roster.iter().map(|r| r.ret_detail.summary.flagged_count).sum();
    let total_bucketed: usize = roster.iter().map(|r| r.ret_detail.summary.bucketed_count).sum();

    // Provider breakdown.
    let mut by_provider: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for row in roster {
        let e = by_provider
            .entry(row.ret_detail.summary.provider_display.clone())
            .or_insert((0, 0));
        e.0 += 1;
        e.1 += row.ret_detail.summary.item_count;
    }

    // ─── Roster rows HTML ─────────────────────────────────────────────
    let mut roster_html = String::new();
    if roster.is_empty() {
        roster_html.push_str(
            r#"<tr><td colspan="7" class="empty">No returns in this investigation yet.</td></tr>"#,
        );
    } else {
        for row in roster {
            let s = &row.ret_detail.summary;
            roster_html.push_str(&format!(
                r#"<tr>
                    <td class="num">{n:02}</td>
                    <td class="label"><a href="returns/{sub}/index.html">{label}</a></td>
                    <td>{prov}</td>
                    <td>{target}</td>
                    <td class="num">{items}</td>
                    <td class="num flag-cell">{flagged}</td>
                    <td class="num">{bucketed}</td>
                </tr>"#,
                n = row.index,
                sub = esc(&row.subfolder),
                label = esc(&row.label),
                prov = esc(&s.provider_display),
                target = esc(s.target_account.as_deref().unwrap_or("—")),
                items = s.item_count,
                flagged = s.flagged_count,
                bucketed = s.bucketed_count,
            ));
        }
    }

    // ─── Provider breakdown HTML ──────────────────────────────────────
    let mut providers_html = String::new();
    for (name, (count, items)) in &by_provider {
        providers_html.push_str(&format!(
            r#"<div class="provider-row"><span class="provider-name">{name}</span><span class="provider-count">{count} return{plural} · {items} items</span></div>"#,
            name = esc(name),
            count = count,
            plural = if *count == 1 { "" } else { "s" },
            items = items,
        ));
    }
    if providers_html.is_empty() {
        providers_html.push_str(r#"<div class="empty">No returns.</div>"#);
    }

    // ─── Flagged roll-up HTML ─────────────────────────────────────────
    let mut flagged_html = String::new();
    if flagged.is_empty() {
        flagged_html.push_str(
            r#"<tr><td colspan="7" class="empty">No flagged items across this investigation.</td></tr>"#,
        );
    } else {
        for f in flagged {
            // The deep link uses #item-<id> — the per-return report
            // already renders rows with that anchor.
            flagged_html.push_str(&format!(
                r#"<tr>
                    <td><a href="returns/{sub}/index.html#item-{item}">{label}</a></td>
                    <td>{section}</td>
                    <td>{ts}</td>
                    <td>{author}</td>
                    <td>{summary}</td>
                    <td><span class="bucket-pill">{bucket}</span></td>
                    <td class="note">{note}</td>
                </tr>"#,
                sub = esc(&f.return_subfolder),
                item = esc(&f.item_id),
                label = esc(&format!("#{:02} {}", f.return_index, f.return_label)),
                section = esc(&f.section),
                ts = esc(&f.timestamp),
                author = esc(&f.author),
                summary = esc(&short(&f.summary, 140)),
                bucket = esc(&f.bucket),
                note = esc(&short(&f.note, 80)),
            ));
        }
    }

    // ─── Optional fields ──────────────────────────────────────────────
    let agency_html = inv
        .agency_case_number
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!(r#"<div class="meta-row"><span class="k">Agency case #</span><span class="v">{}</span></div>"#, esc(s)))
        .unwrap_or_default();
    let notes_html = inv
        .notes
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!(r#"<div class="notes-block"><div class="notes-label">Notes</div><div class="notes-body">{}</div></div>"#, esc(s)))
        .unwrap_or_default();

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} — Scout Investigation Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #0b1322;
    --panel: #111c34;
    --panel-2: #182542;
    --border: #243a64;
    --text: #e6ecf8;
    --muted: #8b9bbf;
    --accent: #5dcfff;
    --accent-2: #4a7aff;
    --flag: #ff5e6b;
    --bucket: #f1c40f;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width: 1180px; margin: 0 auto; padding: 32px 28px 64px; }}
  header.cover {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }}
  .brand {{ font-size: 12px; letter-spacing: 0.18em; color: var(--accent); text-transform: uppercase; margin-bottom: 6px; }}
  h1 {{ margin: 0 0 6px; font-size: 30px; font-weight: 700; letter-spacing: -0.01em; }}
  .meta-row {{ display: flex; gap: 14px; align-items: baseline; margin-top: 6px; font-size: 14px; }}
  .meta-row .k {{ color: var(--muted); min-width: 120px; }}
  .meta-row .v {{ color: var(--text); }}
  .notes-block {{ margin-top: 14px; padding: 12px 14px; background: var(--panel); border-radius: 6px; border: 1px solid var(--border); }}
  .notes-label {{ font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }}
  .notes-body {{ white-space: pre-wrap; font-size: 14px; line-height: 1.5; }}

  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0 26px; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }}
  .stat .num {{ font-size: 26px; font-weight: 700; letter-spacing: -0.01em; }}
  .stat .lbl {{ color: var(--muted); font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; margin-top: 2px; }}
  .stat.flag .num {{ color: var(--flag); }}
  .stat.acc .num {{ color: var(--accent); }}

  section.block {{ margin: 28px 0; }}
  section.block h2 {{ font-size: 16px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); margin: 0 0 12px; font-weight: 600; }}
  .provider-row {{ display: flex; justify-content: space-between; padding: 8px 12px; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; }}
  .provider-row .provider-count {{ color: var(--muted); font-size: 13px; }}

  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: var(--panel-2); color: var(--muted); text-align: left; padding: 10px 12px; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 600; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 12px; font-size: 13px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  td a {{ color: var(--accent); text-decoration: none; }}
  td a:hover {{ text-decoration: underline; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
  td.flag-cell {{ color: var(--flag); font-weight: 600; }}
  td.empty {{ text-align: center; color: var(--muted); padding: 18px; }}
  td.label a {{ font-weight: 600; }}
  td.note {{ color: var(--muted); }}
  .bucket-pill {{ display: inline-block; padding: 2px 8px; background: rgba(241,196,15,0.12); color: var(--bucket); border-radius: 12px; font-size: 11px; letter-spacing: 0.06em; }}
  .bucket-pill:empty {{ display: none; }}

  footer {{ margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
  <div class="wrap">
    <header class="cover">
      <div class="brand">Datapilot Scout — Investigation Report</div>
      <h1>{title}</h1>
      {agency_html}
      <div class="meta-row"><span class="k">Generated</span><span class="v">{generated}</span></div>
      <div class="meta-row"><span class="k">Returns</span><span class="v">{ret_count}</span></div>
      {notes_html}
    </header>

    <div class="stat-grid">
      <div class="stat"><div class="num">{ret_count}</div><div class="lbl">Returns</div></div>
      <div class="stat acc"><div class="num">{total_items}</div><div class="lbl">Total items</div></div>
      <div class="stat flag"><div class="num">{total_flagged}</div><div class="lbl">Flagged</div></div>
      <div class="stat"><div class="num">{total_bucketed}</div><div class="lbl">Bucketed</div></div>
    </div>

    <section class="block">
      <h2>Returns roster</h2>
      <table>
        <thead><tr>
          <th>#</th><th>Label</th><th>Provider</th><th>Target account</th>
          <th class="num">Items</th><th class="num">Flagged</th><th class="num">Bucketed</th>
        </tr></thead>
        <tbody>
          {roster_html}
        </tbody>
      </table>
    </section>

    <section class="block">
      <h2>By provider</h2>
      {providers_html}
    </section>

    <section class="block">
      <h2>Flagged items across all returns</h2>
      <table>
        <thead><tr>
          <th>Source</th><th>Section</th><th>Timestamp</th><th>Author</th>
          <th>Summary</th><th>Bucket</th><th>Note</th>
        </tr></thead>
        <tbody>
          {flagged_html}
        </tbody>
      </table>
    </section>

    <footer>
      Each return has its own self-contained report under <code>returns/</code>.
      Open this <code>index.html</code> for the case-wide view, or any per-return
      <code>index.html</code> for full triage detail and full-res media.
    </footer>
  </div>
</body>
</html>
"##,
        title = esc(&inv.name),
        agency_html = agency_html,
        notes_html = notes_html,
        generated = generated,
        ret_count = roster.len(),
        total_items = total_items,
        total_flagged = total_flagged,
        total_bucketed = total_bucketed,
        roster_html = roster_html,
        providers_html = providers_html,
        flagged_html = flagged_html,
    )
}
