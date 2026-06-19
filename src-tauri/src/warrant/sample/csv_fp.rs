//! CSV / TSV structural fingerprint.
//!
//! Captures:
//! - Column headers (verbatim — user picked minimal redaction)
//! - Row count
//! - Per-column value-format inference (computed from up to N sample rows,
//!   then the sample strings are dropped — only the inferred tag survives)
//! - Per-column length range
//!
//! **Never captured**: row data, individual cell values.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::format_infer::infer_tag_from_samples;

const MAX_SAMPLE_ROWS: usize = 256;
const MAX_COLS: usize = 128;
const MAX_CELL_LEN_FOR_SAMPLING: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CsvFingerprint {
    pub delimiter: String,
    pub headers: Vec<String>,
    pub columns: Vec<ColumnInfo>,
    pub row_count: usize,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ColumnInfo {
    pub name: String,
    pub min_len: usize,
    pub max_len: usize,
    pub null_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inferred: Option<String>,
}

pub fn inspect(bytes: &[u8], delimiter: u8) -> Value {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            let mut fp = CsvFingerprint::default();
            fp.parse_error = Some("non-utf8 csv".into());
            return serde_json::to_value(fp).unwrap_or(Value::Null);
        }
    };
    let mut fp = CsvFingerprint {
        delimiter: (delimiter as char).to_string(),
        ..Default::default()
    };

    // Minimal CSV parser: supports quoted fields with "" escape.
    let rows = parse_csv(text, delimiter as char);
    if rows.is_empty() {
        fp.parse_error = Some("empty".into());
        return serde_json::to_value(fp).unwrap_or(Value::Null);
    }

    fp.headers = rows[0].iter().take(MAX_COLS).cloned().collect();
    let n_cols = fp.headers.len();

    // Per-column sample bags
    let mut col_samples: Vec<Vec<String>> = vec![Vec::new(); n_cols];
    let mut col_min_len: Vec<usize> = vec![usize::MAX; n_cols];
    let mut col_max_len: Vec<usize> = vec![0; n_cols];
    let mut col_null: Vec<usize> = vec![0; n_cols];

    let data_rows = &rows[1..];
    fp.row_count = data_rows.len();
    if data_rows.len() > MAX_SAMPLE_ROWS {
        fp.truncated = true;
    }

    for row in data_rows.iter().take(MAX_SAMPLE_ROWS) {
        for (i, cell) in row.iter().enumerate().take(n_cols) {
            let len = cell.len();
            if cell.is_empty() {
                col_null[i] += 1;
                continue;
            }
            if len < col_min_len[i] { col_min_len[i] = len; }
            if len > col_max_len[i] { col_max_len[i] = len; }
            if len <= MAX_CELL_LEN_FOR_SAMPLING
                && col_samples[i].len() < 32
            {
                col_samples[i].push(cell.clone());
            }
        }
    }

    for (i, h) in fp.headers.iter().enumerate() {
        let refs: Vec<&str> = col_samples[i].iter().map(|s| s.as_str()).collect();
        let inferred = infer_tag_from_samples(&refs);
        fp.columns.push(ColumnInfo {
            name: h.clone(),
            min_len: if col_min_len[i] == usize::MAX { 0 } else { col_min_len[i] },
            max_len: col_max_len[i],
            null_count: col_null[i],
            inferred,
        });
    }

    // Samples are now dropped — they go out of scope here, so nothing
    // value-side leaks into the serialized output.
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

// ─── Tiny CSV/TSV parser ─────────────────────────────────────────────────

fn parse_csv(text: &str, delim: char) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                cell.push(c);
            }
        } else {
            if c == '"' && cell.is_empty() {
                in_quotes = true;
            } else if c == delim {
                row.push(std::mem::take(&mut cell));
            } else if c == '\n' {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            } else if c == '\r' {
                // skip; will be terminated by next \n
            } else {
                cell.push(c);
            }
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build(content: &str, delim: u8) -> CsvFingerprint {
        let raw = inspect(content.as_bytes(), delim);
        serde_json::from_value(raw).unwrap()
    }

    #[test]
    fn basic_headers_and_rows() {
        let csv = "id,name,ts\n1,alice,1781883803\n2,bob,1781883900\n3,carol,1781884000\n";
        let fp = build(csv, b',');
        assert_eq!(fp.headers, vec!["id", "name", "ts"]);
        assert_eq!(fp.row_count, 3);
        // ts column should be inferred as unix_seconds
        let ts_col = fp.columns.iter().find(|c| c.name == "ts").unwrap();
        assert_eq!(ts_col.inferred.as_deref(), Some("unix_seconds"));
    }

    #[test]
    fn no_cell_values_in_output() {
        let csv = "name,case_note\nAlice Doe,CASE-12345-VICTIM-STATEMENT\nBob Smith,CASE-67890\n";
        let raw = inspect(csv.as_bytes(), b',');
        let s = serde_json::to_string(&raw).unwrap();
        assert!(!s.contains("Alice"), "leaked value: {}", s);
        assert!(!s.contains("CASE-12345"), "leaked value: {}", s);
        // But headers must be present
        assert!(s.contains("case_note"));
    }

    #[test]
    fn handles_quoted_fields() {
        let csv = "a,b\n\"hello, world\",\"with \"\"quotes\"\"\"\n";
        let fp = build(csv, b',');
        assert_eq!(fp.headers, vec!["a", "b"]);
        assert_eq!(fp.row_count, 1);
    }

    #[test]
    fn tab_delimited() {
        let tsv = "x\ty\tz\n1\t2\t3\n";
        let fp = build(tsv, b'\t');
        assert_eq!(fp.headers, vec!["x", "y", "z"]);
        assert_eq!(fp.delimiter, "\t");
    }

    #[test]
    fn email_column_inferred() {
        let csv = "user,email\na,a@x.com\nb,b@x.com\nc,c@x.com\nd,d@x.com\n";
        let fp = build(csv, b',');
        let e = fp.columns.iter().find(|c| c.name == "email").unwrap();
        assert_eq!(e.inferred.as_deref(), Some("email"));
    }
}
