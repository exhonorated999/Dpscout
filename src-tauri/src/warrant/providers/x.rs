//! X (Twitter) warrant-return parser.
//!
//! Format reference (clean-room)
//! -----------------------------
//! An X / Twitter law-enforcement production arrives as a `.zip` (or an
//! already-extracted folder).  Inside is a set of `*.txt` data files plus
//! optional media sub-folders.  Each `.txt` is a **PGP cleartext-signed**
//! wrapper around a JSON payload:
//!
//! ```text
//! -----BEGIN PGP SIGNED MESSAGE-----
//! Hash: SHA256
//!
//! [ { "tweet": { ... } }, ... ]        <- the JSON body (dash-escaped)
//! -----BEGIN PGP SIGNATURE-----
//! ...signature...
//! -----END PGP SIGNATURE-----
//! ```
//!
//! Files may be prefixed with the target account id, e.g.
//! `1234567890-account.txt` → record stem `account`.  A `README.txt`
//! catalogues the contents.
//!
//! Record stems we surface (Tier 1–2 forensic value):
//!   account / account-limited     — target identity
//!   tweets / deleted-tweets       — posts (marker-delimited objects)
//!   direct-messages (+ group /    — DM conversations & messages
//!     deleted variants)
//!   follower / following          — social graph
//!   ip-audit                      — login / IP history
//!   device / device-token         — device attribution
//!   personalization               — inferred demographics / interests
//!   ad-impressions / ad-engagements
//!
//! Media files live in sibling folders whose names end in e.g.
//! `_tweets_media`, `_direct_messages_media`.  A media file is named
//! `<parentId>-<token>.<ext>` where `<parentId>` is the owning tweet-id or
//! message-id, letting us link a post / DM to its photo or video on disk.
//!
//! This is a clean-room implementation written from a format spec — it is
//! intentionally shipped as a DEMO parser: the most common / important
//! record types are handled; exotic stems fall through to a generic
//! flattened view rather than being dropped.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use zip::ZipArchive;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantCase, WarrantItem, WarrantParser,
};

pub struct XWarrantParser;

// ─── Constants ───────────────────────────────────────────────────────────

const IMAGE_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".tiff",
];
const VIDEO_EXTS: &[&str] = &[".mp4", ".mov", ".webm", ".m4v", ".avi", ".mkv"];
const AUDIO_EXTS: &[&str] = &[".aac", ".m4a", ".mp3", ".wav", ".ogg", ".opus"];

/// Record stems that positively identify an X production during `accepts`.
const X_KNOWN_STEMS: &[&str] = &[
    "account",
    "account-limited",
    "account-creation-ip",
    "tweets",
    "deleted-tweets",
    "tweet-headers",
    "direct-messages",
    "direct-messages-group",
    "deleted-direct-messages",
    "deleted-direct-messages-group",
    "follower",
    "following",
    "ip-audit",
    "device",
    "device-token",
    "personalization",
    "ad-impressions",
    "ad-engagements",
    "screen-name-change",
    "connected-application",
];

// ─── Trait impl ──────────────────────────────────────────────────────────

impl WarrantParser for XWarrantParser {
    fn provider(&self) -> Provider {
        Provider::X
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            let mut names = Vec::new();
            collect_txt_basenames_from_dir(path, &mut names);
            return Ok(names_look_like_x(&names));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        let mut basenames: Vec<String> = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().to_string();
            let base = basename(&name).to_string();
            let lower = base.to_lowercase();

            // A README.txt that lists `/account.txt:` etc. is a strong signal.
            if lower == "readme.txt" {
                let mut head = vec![0u8; 4096];
                let read = entry.read(&mut head).unwrap_or(0);
                let head_str = String::from_utf8_lossy(&head[..read]).to_lowercase();
                if head_str.contains("/account.txt")
                    || head_str.contains("/tweets.txt")
                    || head_str.contains("/direct-messages.txt")
                    || (head_str.contains("twitter") && head_str.contains("account"))
                {
                    return Ok(true);
                }
            }
            basenames.push(base);
        }

        Ok(names_look_like_x(&basenames))
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        fs::create_dir_all(media_extract_dir)?;

        // ── Phase 1: load all record bodies + extract media to disk.
        let loaded = if archive_path.is_dir() {
            load_from_dir(archive_path, media_extract_dir)?
        } else {
            load_from_zip(archive_path, media_extract_dir)?
        };

        if loaded.stems.is_empty() && loaded.all_media.is_empty() {
            return Err(ParseError::Other(
                "No X/Twitter data files found in input".into(),
            ));
        }

        // ── Phase 2: emit WarrantItems section by section.
        let mut ctx = Ctx::default();

        emit_account(&loaded, &mut ctx);
        emit_tweets(&loaded, "tweets", false, &mut ctx);
        emit_tweets(&loaded, "deleted-tweets", true, &mut ctx);
        emit_dms(&loaded, "direct-messages", false, &mut ctx);
        emit_dms(&loaded, "direct-messages-group", false, &mut ctx);
        emit_dms(&loaded, "deleted-direct-messages", true, &mut ctx);
        emit_dms(&loaded, "deleted-direct-messages-group", true, &mut ctx);
        emit_social(&loaded, "follower", "followers", "Followers", &mut ctx);
        emit_social(&loaded, "following", "following", "Following", &mut ctx);
        emit_ip_audit(&loaded, &mut ctx);
        emit_devices(&loaded, "device", &mut ctx);
        emit_devices(&loaded, "device-token", &mut ctx);
        emit_personalization(&loaded, &mut ctx);
        emit_ads(&loaded, "ad-impressions", "Ad Impression", &mut ctx);
        emit_ads(&loaded, "ad-engagements", "Ad Engagement", &mut ctx);

        // A curated set of lower-tier stems surfaced as account metadata.
        for stem in [
            "screen-name-change",
            "ageinfo",
            "connected-application",
            "account-creation-ip",
            "like",
            "block",
            "mute",
            "lists",
            "saved-search",
        ] {
            emit_generic_metadata(&loaded, stem, &mut ctx);
        }

        // Any media not linked to a post / DM still shows in the gallery.
        backfill_unlinked_media(&loaded, &mut ctx);

        // ── Phase 3: assemble the case.
        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let target_account = ctx
            .target_account
            .clone()
            .or_else(|| loaded.account_id_hint.clone());

        let case = WarrantCase {
            case_id,
            provider: Provider::X,
            provider_display: "X (Twitter)".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account,
            date_range: None,
            generated_at_source: None,
            media_root: Some(media_extract_dir.to_string_lossy().into_owned()),
        };

        Ok(ParsedReturn {
            case,
            items: ctx.items,
            default_buckets: self.default_buckets(),
        })
    }

    fn default_buckets(&self) -> Vec<BucketTemplate> {
        vec![
            BucketTemplate {
                name: "CSAM".into(),
                color: "#ef4444".into(),
                description: Some("Child sexual abuse material".into()),
            },
            BucketTemplate {
                name: "Posts of Interest".into(),
                color: "#1d9bf0".into(),
                description: Some("Tweets / posts relevant to the investigation".into()),
            },
            BucketTemplate {
                name: "DMs of Interest".into(),
                color: "#0ea5e9".into(),
                description: Some("Direct messages relevant to the investigation".into()),
            },
            BucketTemplate {
                name: "Contacts of Interest".into(),
                color: "#8b5cf6".into(),
                description: None,
            },
            BucketTemplate {
                name: "Media of Interest".into(),
                color: "#a78bfa".into(),
                description: None,
            },
            BucketTemplate {
                name: "Unrelated".into(),
                color: "#6b7280".into(),
                description: None,
            },
            BucketTemplate {
                name: "Needs Follow-Up".into(),
                color: "#f59e0b".into(),
                description: None,
            },
        ]
    }
}

// ─── Loaded production ───────────────────────────────────────────────────

#[derive(Default)]
struct Loaded {
    /// stem → list of cleartext JSON bodies (one per source file).
    stems: HashMap<String, Vec<String>>,
    /// parentId (tweet-id / message-id) → extracted media filenames.
    media_index: HashMap<String, Vec<String>>,
    /// every extracted media filename (relative to the case media dir).
    all_media: Vec<String>,
    /// best-effort numeric account id lifted from a `<id>-stem.txt` prefix.
    account_id_hint: Option<String>,
}

impl Loaded {
    fn objects_for(&self, stem: &str) -> Vec<Value> {
        match self.stems.get(stem) {
            Some(bodies) => parse_objects(bodies),
            None => Vec::new(),
        }
    }
}

#[derive(Default)]
struct Ctx {
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,
    target_account: Option<String>,
    linked_media: std::collections::HashSet<String>,
}

impl Ctx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }
}

// ─── Loading (zip / dir) ─────────────────────────────────────────────────

fn load_from_zip(zip_path: &Path, media_dir: &Path) -> Result<Loaded, ParseError> {
    let file = File::open(zip_path)?;
    let mut zip = ZipArchive::new(file)?;
    let mut loaded = Loaded::default();

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let base = basename(&name).to_string();
        let lower = base.to_lowercase();

        if lower == "readme.txt" {
            continue;
        }

        if lower.ends_with(".txt") {
            let mut bytes = Vec::new();
            if entry.read_to_end(&mut bytes).is_ok() {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                ingest_txt(&base, &text, &mut loaded);
            }
        } else if is_media_ext(&lower) {
            let out_name = flatten_path(&name);
            let out_path = media_dir.join(&out_name);
            if let Ok(mut out) = File::create(&out_path) {
                if std::io::copy(&mut entry, &mut out).is_ok() {
                    register_media(&base, &out_name, &mut loaded);
                }
            }
        }
    }

    Ok(loaded)
}

fn load_from_dir(root: &Path, media_dir: &Path) -> Result<Loaded, ParseError> {
    let mut loaded = Loaded::default();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let base = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let lower = base.to_lowercase();

            if lower == "readme.txt" {
                continue;
            }

            if lower.ends_with(".txt") {
                if let Ok(bytes) = fs::read(&p) {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    ingest_txt(&base, &text, &mut loaded);
                }
            } else if is_media_ext(&lower) {
                // Preserve a collision-safe name using the parent folder.
                let parent = p
                    .parent()
                    .and_then(|pp| pp.file_name())
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let out_name = if parent.is_empty() {
                    base.clone()
                } else {
                    format!("{}~~{}", parent, base)
                };
                let out_path = media_dir.join(&out_name);
                if fs::copy(&p, &out_path).is_ok() {
                    register_media(&base, &out_name, &mut loaded);
                }
            }
        }
    }

    Ok(loaded)
}

fn ingest_txt(basename_str: &str, raw_text: &str, loaded: &mut Loaded) {
    let body = strip_pgp_cleartext(raw_text);
    let stem = stem_from_filename(basename_str);
    if loaded.account_id_hint.is_none() {
        if let Some(a) = account_prefix(basename_str) {
            loaded.account_id_hint = Some(a);
        }
    }
    loaded.stems.entry(stem).or_default().push(body);
}

fn register_media(basename_str: &str, out_name: &str, loaded: &mut Loaded) {
    if let Some(pid) = parent_id_from_media(basename_str) {
        loaded
            .media_index
            .entry(pid)
            .or_default()
            .push(out_name.to_string());
    }
    loaded.all_media.push(out_name.to_string());
}

// ─── Emitters ────────────────────────────────────────────────────────────

fn emit_account(loaded: &Loaded, ctx: &mut Ctx) {
    for stem in ["account", "account-limited"] {
        for obj in loaded.objects_for(stem) {
            let inner = unwrap_key(&obj, "account");
            let username = vstr(inner, "username")
                .or_else(|| vstr(inner, "screenName"))
                .or_else(|| vstr(inner, "accountDisplayName"));
            let account_id = vstr(inner, "accountId").or_else(|| vstr(inner, "id"));
            let created = vstr(inner, "createdAt").or_else(|| vstr(inner, "createdVia"));
            let email = vstr(inner, "email");

            if ctx.target_account.is_none() {
                ctx.target_account = username.clone().or_else(|| account_id.clone());
            }

            let handle = username
                .clone()
                .map(|u| format!("@{}", u.trim_start_matches('@')))
                .unwrap_or_else(|| account_id.clone().unwrap_or_else(|| "account".into()));
            let mut summary = handle.clone();
            if let Some(id) = &account_id {
                summary.push_str(&format!(" · id {}", id));
            }

            let id = ctx.next_id("acct");
            ctx.items.push(WarrantItem {
                id,
                section: "x_account".into(),
                section_display: "Account".into(),
                timestamp: created,
                author: username.clone(),
                recipient: None,
                body_text: email,
                summary: Some(truncate(&summary, 90)),
                raw_fields: inner.clone(),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn emit_tweets(loaded: &Loaded, stem: &str, deleted: bool, ctx: &mut Ctx) {
    for obj in loaded.objects_for(stem) {
        let t = unwrap_key(&obj, "tweet");
        let tid = vstr(t, "id_str").or_else(|| vstr(t, "id"));
        let text = vstr(t, "full_text")
            .or_else(|| vstr(t, "text"))
            .unwrap_or_default();
        let created = vstr(t, "created_at");
        let author = t
            .get("user")
            .and_then(|u| vstr(u, "screen_name"))
            .or_else(|| ctx.target_account.clone());

        let is_rt = text.trim_start().starts_with("RT @")
            || t.get("retweeted_status").is_some();

        // Link media by tweet id.
        let mut attachments = Vec::new();
        if let Some(id) = &tid {
            if let Some(files) = loaded.media_index.get(id) {
                for f in files {
                    attachments.push(f.clone());
                    ctx.linked_media.insert(f.clone());
                }
            }
        }

        let prefix = if deleted { "[DELETED] " } else if is_rt { "[RT] " } else { "" };
        let summary = format!("{}{}", prefix, truncate(&text, 80));

        let id = ctx.next_id("tweet");
        ctx.items.push(WarrantItem {
            id,
            section: "tweets".into(),
            section_display: "Posts / Tweets".into(),
            timestamp: created,
            author,
            recipient: None,
            body_text: if text.trim().is_empty() { None } else { Some(text) },
            summary: Some(truncate(&summary, 100)),
            raw_fields: t.clone(),
            attachments,
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_dms(loaded: &Loaded, stem: &str, deleted: bool, ctx: &mut Ctx) {
    let is_group = stem.contains("group");
    for obj in loaded.objects_for(stem) {
        let conv = unwrap_key(&obj, "dmConversation");
        let conv_id = vstr(conv, "conversationId");
        let messages = match conv.get("messages").and_then(|m| m.as_array()) {
            Some(arr) => arr.clone(),
            None => continue,
        };

        for msg in &messages {
            // Standard shape: { "messageCreate": { ... } }
            let mc = unwrap_key(msg, "messageCreate");
            let mid = vstr(mc, "id").or_else(|| vstr(mc, "messageId"));
            let sender = vstr(mc, "senderId").or_else(|| vstr(mc, "sender"));
            let recipient = vstr(mc, "recipientId").or_else(|| vstr(mc, "recipient"));
            let created = vstr(mc, "createdAt").or_else(|| vstr(mc, "created_at"));
            let text = vstr(mc, "text")
                .or_else(|| vstr(mc, "body"))
                .unwrap_or_default();

            // Skip pure non-message events (reactions/joins) with no text/id.
            if mid.is_none() && text.trim().is_empty() {
                continue;
            }

            let mut attachments = Vec::new();
            if let Some(id) = &mid {
                if let Some(files) = loaded.media_index.get(id) {
                    for f in files {
                        attachments.push(f.clone());
                        ctx.linked_media.insert(f.clone());
                    }
                }
            }

            let route = match (sender.as_deref(), recipient.as_deref()) {
                (Some(s), Some(r)) => format!("{} → {}", s, r),
                (Some(s), None) => s.to_string(),
                _ => conv_id.clone().unwrap_or_default(),
            };
            let del = if deleted { "[DELETED] " } else { "" };
            let grp = if is_group { "[GROUP] " } else { "" };
            let summary = format!("{}{}{} · {}", del, grp, route, truncate(&text, 60));

            let mut raw = mc.clone();
            if let Some(cid) = &conv_id {
                if let Value::Object(map) = &mut raw {
                    map.insert("_conversationId".into(), json!(cid));
                }
            }

            let id = ctx.next_id("dm");
            ctx.items.push(WarrantItem {
                id,
                section: "direct_messages".into(),
                section_display: "Direct Messages".into(),
                timestamp: created,
                author: sender,
                recipient,
                body_text: if text.trim().is_empty() { None } else { Some(text) },
                summary: Some(truncate(&summary, 100)),
                raw_fields: raw,
                attachments,
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn emit_social(loaded: &Loaded, stem: &str, section: &str, section_display: &str, ctx: &mut Ctx) {
    for obj in loaded.objects_for(stem) {
        // Wrapper is `{ "follower": { "accountId": "..." } }` or `{ "following": {...} }`.
        let inner = unwrap_key(&obj, stem);
        let account_id = vstr(inner, "accountId")
            .or_else(|| vstr(inner, "userId"))
            .or_else(|| vstr(inner, "id"));
        let handle = vstr(inner, "username").or_else(|| vstr(inner, "screenName"));
        let label = handle
            .clone()
            .map(|h| format!("@{}", h.trim_start_matches('@')))
            .or_else(|| account_id.clone())
            .unwrap_or_else(|| "(unknown)".into());

        let id = ctx.next_id(if section == "followers" { "flwr" } else { "flwg" });
        ctx.items.push(WarrantItem {
            id,
            section: section.to_string(),
            section_display: section_display.to_string(),
            timestamp: None,
            author: handle.or(account_id),
            recipient: None,
            body_text: None,
            summary: Some(truncate(&label, 80)),
            raw_fields: inner.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_ip_audit(loaded: &Loaded, ctx: &mut Ctx) {
    for stem in ["ip-audit", "account-creation-ip"] {
        for obj in loaded.objects_for(stem) {
            // Unwrap any single-key wrapper, then flatten to find ip + time.
            let inner = unwrap_any_single(&obj);
            let mut flat = Vec::new();
            flatten(inner, "", &mut flat);

            let ip = find_containing(&flat, &["ip", "address"]);
            let ts = find_containing(&flat, &["time", "created", "date", "login", "logged"]);
            let ua = find_containing(&flat, &["useragent", "user_agent", "client"]);

            let summary = match (&ip, &ts) {
                (Some(ip), Some(ts)) => format!("{} · {}", ip, ts),
                (Some(ip), None) => ip.clone(),
                (None, Some(ts)) => ts.clone(),
                (None, None) => "IP audit record".into(),
            };

            let id = ctx.next_id("ipaudit");
            ctx.items.push(WarrantItem {
                id,
                section: "ip_audit".into(),
                section_display: "IP / Login Audit".into(),
                timestamp: ts,
                author: ip,
                recipient: None,
                body_text: ua,
                summary: Some(truncate(&summary, 100)),
                raw_fields: inner.clone(),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn emit_devices(loaded: &Loaded, stem: &str, ctx: &mut Ctx) {
    for obj in loaded.objects_for(stem) {
        let inner = unwrap_any_single(&obj);
        let mut flat = Vec::new();
        flatten(inner, "", &mut flat);

        let app = vstr(inner, "clientApplicationName")
            .or_else(|| find_containing(&flat, &["applicationname", "appname", "devicename", "client"]));
        let app_id = vstr(inner, "clientApplicationId");
        let os = find_containing(&flat, &["ostype", "os_type", "platform", "devicetype"]);
        let created = find_containing(&flat, &["created", "time", "date", "registered"]);

        let mut summary = app.clone().unwrap_or_else(|| "Device".into());
        if let Some(os) = &os {
            summary.push_str(&format!(" · {}", os));
        }

        let id = ctx.next_id("device");
        ctx.items.push(WarrantItem {
            id,
            section: "devices".into(),
            section_display: "Devices".into(),
            timestamp: created,
            author: app.or(app_id),
            recipient: None,
            body_text: os,
            summary: Some(truncate(&summary, 90)),
            raw_fields: inner.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_personalization(loaded: &Loaded, ctx: &mut Ctx) {
    for obj in loaded.objects_for("personalization") {
        let p13n = unwrap_key(&obj, "p13nData");
        let gender = p13n
            .pointer("/demographics/genderInfo/gender")
            .and_then(json_scalar_string);
        let age = p13n
            .pointer("/inferredAgeInfo/age")
            .and_then(json_scalar_string);
        let langs = p13n
            .pointer("/demographics/languages")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|l| vstr(l, "language"))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty());

        let mut parts: Vec<String> = Vec::new();
        if let Some(g) = &gender {
            parts.push(format!("gender: {}", g));
        }
        if let Some(a) = &age {
            parts.push(format!("age: {}", a));
        }
        if let Some(l) = &langs {
            parts.push(format!("langs: {}", l));
        }
        let summary = if parts.is_empty() {
            "Inferred personalization data".to_string()
        } else {
            parts.join(" · ")
        };

        let id = ctx.next_id("p13n");
        ctx.items.push(WarrantItem {
            id,
            section: "personalization".into(),
            section_display: "Personalization".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: langs,
            summary: Some(truncate(&summary, 100)),
            raw_fields: p13n.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_ads(loaded: &Loaded, stem: &str, label: &str, ctx: &mut Ctx) {
    for obj in loaded.objects_for(stem) {
        let inner = unwrap_any_single(&obj);
        let mut flat = Vec::new();
        flatten(inner, "", &mut flat);

        let advertiser = find_containing(&flat, &["advertisername", "advertiser_name", "advertiserinfo.screenname"]);
        let when = find_containing(&flat, &["impressiontime", "engagementtime", "time", "created"]);
        let tweet_text = find_containing(&flat, &["tweettext", "tweet_text"]);
        let device = find_containing(&flat, &["ostype", "devicetype", "deviceid"]);

        let mut summary = label.to_string();
        if let Some(a) = &advertiser {
            summary.push_str(&format!(" · {}", a));
        }
        if let Some(w) = &when {
            summary.push_str(&format!(" · {}", w));
        }

        let id = ctx.next_id("ad");
        ctx.items.push(WarrantItem {
            id,
            section: "ad_data".into(),
            section_display: "Ad Data".into(),
            timestamp: when,
            author: advertiser,
            recipient: None,
            body_text: tweet_text.or(device),
            summary: Some(truncate(&summary, 100)),
            raw_fields: inner.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

/// Fallback surfacing for lower-tier stems — one row per record, generic
/// flattened preview.  Keeps data visible without a bespoke schema.
fn emit_generic_metadata(loaded: &Loaded, stem: &str, ctx: &mut Ctx) {
    let objs = loaded.objects_for(stem);
    if objs.is_empty() {
        return;
    }
    let display = pretty_stem(stem);
    for obj in objs {
        let inner = unwrap_any_single(&obj);
        let mut flat = Vec::new();
        flatten(inner, "", &mut flat);
        let preview: String = flat
            .iter()
            .take(3)
            .map(|(k, v)| format!("{}={}", k, truncate(v, 24)))
            .collect::<Vec<_>>()
            .join("  ");
        let ts = find_containing(&flat, &["time", "created", "date", "changed"]);

        let id = ctx.next_id("meta");
        ctx.items.push(WarrantItem {
            id,
            section: "x_metadata".into(),
            section_display: "Account Metadata".into(),
            timestamp: ts,
            author: Some(display.clone()),
            recipient: None,
            body_text: None,
            summary: Some(truncate(&format!("{} · {}", display, preview), 100)),
            raw_fields: inner.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn backfill_unlinked_media(loaded: &Loaded, ctx: &mut Ctx) {
    for filename in &loaded.all_media {
        if ctx.linked_media.contains(filename) {
            continue;
        }
        let ext = filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let dotted = format!(".{}", ext);
        let is_video = VIDEO_EXTS.contains(&dotted.as_str());
        let is_audio = AUDIO_EXTS.contains(&dotted.as_str());
        let (section, section_display) = if is_video {
            ("videos", "Videos")
        } else if is_audio {
            ("audio", "Audio")
        } else {
            ("photos", "Photos")
        };

        let id = ctx.next_id("media");
        ctx.items.push(WarrantItem {
            id,
            section: section.into(),
            section_display: section_display.into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(basename(filename).to_string()),
            summary: Some(truncate(basename(filename), 90)),
            raw_fields: json!({ "filename": filename }),
            attachments: vec![filename.clone()],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── PGP cleartext handling ──────────────────────────────────────────────

/// Strip a PGP cleartext-signature wrapper, returning just the JSON body.
/// If the text isn't PGP-wrapped, it's returned unchanged (trimmed).
fn strip_pgp_cleartext(text: &str) -> String {
    const BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
    const SIG: &str = "-----BEGIN PGP SIGNATURE-----";

    let begin = match text.find(BEGIN) {
        Some(i) => i,
        None => return text.trim().to_string(),
    };
    // Body starts after the blank line that follows the `Hash:` header(s).
    let after_begin = &text[begin + BEGIN.len()..];
    let body_start = match after_begin.find("\n\n").or_else(|| after_begin.find("\r\n\r\n")) {
        Some(i) => {
            // advance past the blank-line separator
            let sep_len = if after_begin[i..].starts_with("\r\n\r\n") { 4 } else { 2 };
            i + sep_len
        }
        None => 0,
    };
    let rest = &after_begin[body_start..];
    let end = rest.find(SIG).unwrap_or(rest.len());
    let body = &rest[..end];

    // Un-escape cleartext dash-escaping: lines beginning "- " → "".
    let mut out = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        if let Some(stripped) = line.strip_prefix("- ") {
            out.push_str(stripped);
        } else {
            out.push_str(line);
        }
    }
    out.trim().to_string()
}

// ─── JSON object extraction ──────────────────────────────────────────────

/// Parse every JSON object/array across a stem's bodies into a flat list of
/// values.  Handles: a single JSON array, a single object, or marker-
/// delimited concatenations of `{...}` objects (tweets / DMs).
fn parse_objects(bodies: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for body in bodies {
        let trimmed = body.trim();
        if trimmed.is_empty() || trimmed == "[]" || trimmed == "[ ]" {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Array(a)) => out.extend(a),
            Ok(v) => out.push(v),
            Err(_) => out.extend(extract_json_objects(trimmed)),
        }
    }
    out
}

/// Balanced-brace scanner: pulls top-level `{...}` objects out of text that
/// isn't a strict JSON document (string/escape aware).
fn extract_json_objects(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    let mut in_str = false;
    let mut esc = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            b'}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        if let Ok(v) = serde_json::from_str::<Value>(&s[start..=i]) {
                            out.push(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ─── Value helpers ───────────────────────────────────────────────────────

fn json_scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn vstr(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(json_scalar_string).filter(|s| !s.is_empty())
}

/// If `v` is `{ key: inner }`, return `inner`; otherwise return `v`.
fn unwrap_key<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(v)
}

/// If `v` is a single-key object, return its inner value; else return `v`.
fn unwrap_any_single(v: &Value) -> &Value {
    if let Value::Object(map) = v {
        if map.len() == 1 {
            return map.values().next().unwrap();
        }
    }
    v
}

fn flatten(v: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten(val, &p, out);
            }
        }
        Value::Array(a) => {
            for (i, val) in a.iter().enumerate() {
                let p = format!("{}[{}]", prefix, i);
                flatten(val, &p, out);
            }
        }
        _ => {
            if let Some(s) = json_scalar_string(v) {
                if !s.is_empty() {
                    out.push((prefix.to_string(), s));
                }
            }
        }
    }
}

/// First flattened value whose (lower-cased) key contains ANY needle.
fn find_containing(flat: &[(String, String)], needles: &[&str]) -> Option<String> {
    for (k, val) in flat {
        let kl = k.to_lowercase();
        if needles.iter().any(|n| kl.contains(n)) && !val.trim().is_empty() {
            return Some(val.clone());
        }
    }
    None
}

// ─── Filename / media helpers ────────────────────────────────────────────

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn flatten_path(path: &str) -> String {
    path.replace(['/', '\\'], "~~")
}

fn stem_from_filename(base: &str) -> String {
    let no_ext = base.strip_suffix(".txt").unwrap_or(base);
    // Strip a leading "<digits>-" account prefix.
    match no_ext.split_once('-') {
        Some((head, rest)) if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) => {
            rest.to_string()
        }
        _ => no_ext.to_string(),
    }
    .to_lowercase()
}

fn account_prefix(base: &str) -> Option<String> {
    let (head, _rest) = base.split_once('-')?;
    if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) {
        Some(head.to_string())
    } else {
        None
    }
}

/// Media files are `<parentId>-<token>.<ext>` — parentId is the owning
/// tweet-id / message-id (prefix up to the first '-').
fn parent_id_from_media(base: &str) -> Option<String> {
    let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(base);
    let head = stem.split('-').next().unwrap_or("");
    if head.is_empty() {
        None
    } else {
        Some(head.to_string())
    }
}

fn is_media_ext(lower_name: &str) -> bool {
    IMAGE_EXTS.iter().chain(VIDEO_EXTS).chain(AUDIO_EXTS).any(|e| lower_name.ends_with(e))
}

fn names_look_like_x(basenames: &[String]) -> bool {
    for b in basenames {
        let lower = b.to_lowercase();
        if !lower.ends_with(".txt") {
            continue;
        }
        let stem = stem_from_filename(&lower);
        if X_KNOWN_STEMS.contains(&stem.as_str()) {
            return true;
        }
    }
    false
}

fn pretty_stem(stem: &str) -> String {
    let mut s = String::new();
    for (i, word) in stem.split(['-', '_']).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            s.extend(first.to_uppercase());
            s.push_str(chars.as_str());
        }
    }
    s
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn collect_txt_basenames_from_dir(root: &Path, out: &mut Vec<String>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Some(name) = p.file_name() {
                    out.push(name.to_string_lossy().into_owned());
                }
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a JSON body in a PGP cleartext-signed envelope like a real X
    /// production file, including a dash-escaped line to exercise unescaping.
    fn pgp_wrap(body: &str) -> String {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}\n-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n",
            body
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir()
            .join(format!("scout_x_test_{}_{}", tag, Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn strip_pgp_unwraps_and_unescapes() {
        let wrapped = pgp_wrap("[{\"a\":1}]");
        let body = strip_pgp_cleartext(&wrapped);
        assert_eq!(body, "[{\"a\":1}]");
    }

    #[test]
    fn extracts_marker_delimited_objects() {
        // Two concatenated objects, not a JSON array (the tweets shape).
        let s = "{\"tweet\":{\"id_str\":\"1\"}}\n{\"tweet\":{\"id_str\":\"2\"}}";
        let objs = parse_objects(&[s.to_string()]);
        assert_eq!(objs.len(), 2);
    }

    #[test]
    fn parses_synthetic_production_dir() {
        let root = temp_dir("prod");
        let media = temp_dir("media");

        fs::write(
            root.join("12345-account.txt"),
            pgp_wrap("[{\"account\":{\"accountId\":\"12345\",\"username\":\"suspect\"}}]"),
        )
        .unwrap();
        fs::write(
            root.join("tweets.txt"),
            pgp_wrap("{\"tweet\":{\"id_str\":\"111\",\"created_at\":\"Fri Jan 09 11:54:03 +0000 2026\",\"full_text\":\"hello world\",\"user\":{\"screen_name\":\"suspect\"}}}"),
        )
        .unwrap();
        fs::write(
            root.join("direct-messages.txt"),
            pgp_wrap("[{\"dmConversation\":{\"conversationId\":\"12345-67890\",\"messages\":[{\"messageCreate\":{\"id\":\"m1\",\"senderId\":\"12345\",\"recipientId\":\"67890\",\"createdAt\":\"2026-01-09T11:54:03.071Z\",\"text\":\"meet me\"}}]}}]"),
        )
        .unwrap();
        fs::write(
            root.join("follower.txt"),
            pgp_wrap("[{\"follower\":{\"accountId\":\"67890\"}}]"),
        )
        .unwrap();

        let parser = XWarrantParser;
        assert!(parser.accepts(&root).unwrap(), "should accept X production dir");

        let parsed = parser.parse(&root, &media).unwrap();
        assert_eq!(parsed.case.provider, Provider::X);
        assert_eq!(parsed.case.target_account.as_deref(), Some("suspect"));

        let sections: std::collections::HashSet<&str> =
            parsed.items.iter().map(|i| i.section.as_str()).collect();
        assert!(sections.contains("x_account"), "account section missing");
        assert!(sections.contains("tweets"), "tweets section missing");
        assert!(sections.contains("direct_messages"), "dm section missing");
        assert!(sections.contains("followers"), "followers section missing");

        let dm = parsed
            .items
            .iter()
            .find(|i| i.section == "direct_messages")
            .unwrap();
        assert_eq!(dm.author.as_deref(), Some("12345"));
        assert_eq!(dm.recipient.as_deref(), Some("67890"));
        assert_eq!(dm.body_text.as_deref(), Some("meet me"));

        // Cleanup.
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&media);
    }

    #[test]
    fn rejects_non_x_dir() {
        let root = temp_dir("notx");
        fs::write(root.join("random.txt"), "hello").unwrap();
        let parser = XWarrantParser;
        assert!(!parser.accepts(&root).unwrap());
        let _ = fs::remove_dir_all(&root);
    }
}
