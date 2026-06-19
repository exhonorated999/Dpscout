//! JSON structural fingerprint.
//!
//! Walks an arbitrary JSON document and produces a schema-only summary:
//! every key path, the value type observed at it, array lengths, and (for
//! strings) an inferred semantic tag via [`super::format_infer`].  No
//! values themselves are recorded.
//!
//! The schema is keyed by **canonical JSON-pointer-like paths**:
//!   `"messages[].body"`, `"user.id"`, etc.
//! Arrays collapse — `users[0]`, `users[1]`, … all merge under `users[]`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::format_infer::{infer_tag_from_samples, StringStats};
use super::{MAX_NODES_PER_FILE, MAX_STRUCTURE_DEPTH};

const SAMPLES_PER_FIELD: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JsonFingerprint {
    pub root_type: String,
    /// Map of `canonical_path -> FieldStats`.
    pub fields: BTreeMap<String, FieldStats>,
    /// Total nodes walked (caps at [`MAX_NODES_PER_FILE`]).
    pub nodes_walked: usize,
    /// Maximum depth observed.
    pub max_depth: usize,
    /// True if the walk hit a cap (depth/node limit).
    pub truncated: bool,
    /// Parse error if the document isn't valid JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FieldStats {
    /// Number of times this path was encountered.
    pub occurrences: usize,
    /// Bag of observed value types: `{"string": 412, "null": 3}`.
    pub types: BTreeMap<String, usize>,
    /// For arrays: distribution of lengths observed.
    #[serde(default, skip_serializing_if = "ArrayLengthStats::is_zero")]
    pub array_lengths: ArrayLengthStats,
    /// For strings: length range + inferred semantic tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string: Option<StringStats>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArrayLengthStats {
    pub min: usize,
    pub max: usize,
    pub sum: usize,
    pub n: usize,
}

impl ArrayLengthStats {
    pub fn is_zero(&self) -> bool { self.n == 0 }
    pub fn record(&mut self, len: usize) {
        if self.n == 0 || len < self.min { self.min = len; }
        if len > self.max { self.max = len; }
        self.sum += len;
        self.n += 1;
    }
}

// ─── Walker state ────────────────────────────────────────────────────────

struct Walker {
    fields: BTreeMap<String, FieldStats>,
    /// Per-field collected sample strings (for inference at finalize).
    /// Kept tiny (`SAMPLES_PER_FIELD`).
    samples: BTreeMap<String, Vec<String>>,
    nodes_walked: usize,
    max_depth: usize,
    truncated: bool,
}

impl Walker {
    fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
            samples: BTreeMap::new(),
            nodes_walked: 0,
            max_depth: 0,
            truncated: false,
        }
    }

    fn type_name(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() { "integer" } else { "float" }
            }
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    fn record(&mut self, path: &str, v: &Value) {
        let entry = self.fields.entry(path.to_string()).or_default();
        entry.occurrences += 1;
        *entry.types.entry(Self::type_name(v).to_string()).or_insert(0) += 1;

        match v {
            Value::Array(arr) => entry.array_lengths.record(arr.len()),
            Value::String(s) => {
                let ss = entry.string.get_or_insert_with(StringStats::default);
                ss.record(s);
                // collect up to SAMPLES_PER_FIELD samples — they're used
                // only for inference and never serialized
                let bag = self.samples.entry(path.to_string()).or_default();
                if bag.len() < SAMPLES_PER_FIELD {
                    bag.push(s.clone());
                }
            }
            _ => {}
        }
    }

    fn walk(&mut self, path: &str, v: &Value, depth: usize) {
        if depth > self.max_depth { self.max_depth = depth; }
        if self.nodes_walked >= MAX_NODES_PER_FILE {
            self.truncated = true;
            return;
        }
        if depth >= MAX_STRUCTURE_DEPTH {
            self.truncated = true;
            return;
        }
        self.nodes_walked += 1;
        self.record(path, v);

        match v {
            Value::Object(map) => {
                for (k, child) in map.iter() {
                    let next = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", path, k)
                    };
                    self.walk(&next, child, depth + 1);
                }
            }
            Value::Array(arr) => {
                let next = format!("{}[]", path);
                for child in arr.iter() {
                    self.walk(&next, child, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn finalize(mut self) -> (BTreeMap<String, FieldStats>, usize, usize, bool) {
        // Run value-format inference per field using collected samples.
        for (path, samples) in self.samples.iter() {
            if let Some(field) = self.fields.get_mut(path) {
                if let Some(ss) = field.string.as_mut() {
                    let refs: Vec<&str> = samples.iter().map(|s| s.as_str()).collect();
                    ss.inferred = infer_tag_from_samples(&refs);
                }
            }
        }
        (self.fields, self.nodes_walked, self.max_depth, self.truncated)
    }
}

// ─── Public entry ────────────────────────────────────────────────────────

pub fn inspect(bytes: &[u8]) -> Value {
    let parsed: Result<Value, _> = serde_json::from_slice(bytes);
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) => {
            let mut fp = JsonFingerprint::default();
            fp.root_type = "invalid".into();
            fp.parse_error = Some(e.to_string());
            return serde_json::to_value(fp).unwrap_or(Value::Null);
        }
    };

    let root_type = Walker::type_name(&parsed).to_string();
    let mut w = Walker::new();
    w.walk("", &parsed, 0);
    let (fields, nodes_walked, max_depth, truncated) = w.finalize();

    let fp = JsonFingerprint {
        root_type,
        fields,
        nodes_walked,
        max_depth,
        truncated,
        parse_error: None,
    };
    serde_json::to_value(fp).unwrap_or(Value::Null)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(v: Value) -> JsonFingerprint {
        let bytes = serde_json::to_vec(&v).unwrap();
        let raw = inspect(&bytes);
        serde_json::from_value::<JsonFingerprint>(raw).unwrap()
    }

    #[test]
    fn simple_object() {
        let fp = build(json!({"id": "abc", "n": 42, "active": true}));
        assert_eq!(fp.root_type, "object");
        assert!(fp.fields.contains_key("id"));
        assert!(fp.fields.contains_key("n"));
        assert!(fp.fields.contains_key("active"));
        assert_eq!(fp.fields["id"].types.get("string").copied(), Some(1));
        assert_eq!(fp.fields["n"].types.get("integer").copied(), Some(1));
        assert_eq!(fp.fields["active"].types.get("bool").copied(), Some(1));
    }

    #[test]
    fn arrays_collapse_under_brackets() {
        let fp = build(json!({
            "messages": [
                {"id": "m1", "body": "hi"},
                {"id": "m2", "body": "yo"},
                {"id": "m3", "body": "hey"}
            ]
        }));
        // Each message contributes "messages[].id", "messages[].body"
        assert_eq!(fp.fields["messages[].id"].occurrences, 3);
        assert_eq!(fp.fields["messages[].body"].occurrences, 3);
        assert_eq!(fp.fields["messages"].array_lengths.min, 3);
        assert_eq!(fp.fields["messages"].array_lengths.max, 3);
    }

    #[test]
    fn no_values_leak_into_fingerprint() {
        let secret = "alice.victim+sensitive@example.com";
        let v = json!({"email": secret, "msg": "DO NOT LEAK"});
        let bytes = serde_json::to_vec(&v).unwrap();
        let raw = inspect(&bytes);
        let raw_str = serde_json::to_string(&raw).unwrap();
        assert!(!raw_str.contains(secret), "leaked email into fingerprint!");
        assert!(!raw_str.contains("DO NOT LEAK"), "leaked message body!");
    }

    #[test]
    fn detects_email_format() {
        let v = json!({
            "u": [
                {"e": "a@x.com"}, {"e": "b@x.com"},
                {"e": "c@x.com"}, {"e": "d@x.com"}
            ]
        });
        let fp = build(v);
        let stats = fp.fields["u[].e"].string.as_ref().unwrap();
        assert_eq!(stats.inferred.as_deref(), Some("email"));
    }

    #[test]
    fn detects_unix_ms_in_string_field() {
        // Some warrants give ms timestamps as strings
        let v = json!({
            "msgs": [
                {"ts": "1781883803123"},
                {"ts": "1781883803456"},
                {"ts": "1781883803789"}
            ]
        });
        let fp = build(v);
        let stats = fp.fields["msgs[].ts"].string.as_ref().unwrap();
        assert_eq!(stats.inferred.as_deref(), Some("unix_ms"));
    }

    #[test]
    fn invalid_json_returns_error() {
        let raw = inspect(b"{ not json");
        let fp: JsonFingerprint = serde_json::from_value(raw).unwrap();
        assert!(fp.parse_error.is_some());
        assert_eq!(fp.root_type, "invalid");
    }

    #[test]
    fn depth_limit_truncates() {
        // Deeply nested object
        let mut v = json!("leaf");
        for _ in 0..(MAX_STRUCTURE_DEPTH + 5) {
            v = json!({"x": v});
        }
        let bytes = serde_json::to_vec(&v).unwrap();
        let raw = inspect(&bytes);
        let fp: JsonFingerprint = serde_json::from_value(raw).unwrap();
        assert!(fp.truncated, "expected truncation at depth cap");
    }
}
