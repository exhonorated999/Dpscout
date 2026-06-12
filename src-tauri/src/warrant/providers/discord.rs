//! Discord warrant-return parser.
//!
//! Format reference
//! ----------------
//! Discord serves search-warrant returns as Discord Data Packages — same
//! format as a user's "Request All My Data" export.  Layout:
//!
//! ```text
//!   README.txt
//!   Account/
//!     user.json                — subscriber info (id, email, phone, ip, sessions, …)
//!     avatar.{jpeg,png}        — current avatar
//!     recent_avatars/*.jpeg    — historical avatars
//!     user_data_exports/
//!       discord_billing/{billing_profile,payment_sources,payments,entitlements}.json
//!       discord_promotions/{quests_reward_codes,drops_reward_codes}.json
//!       discord_store/wishlist_items.json
//!       discord_virtual_currency/{coin_accounts,coin_transactions}.json
//!       discord_harvests/data_subject_access_requests.json
//!   Messages/
//!     index.json               — { channelId: "channel · server" }
//!     c{channelId}/
//!       channel.json           — { id, type, name, guild: { id, name } }
//!       messages.json          — [ { ID, Timestamp, Contents, Attachments } ]
//!   Servers/
//!     index.json               — { guildId: "ServerName" }
//!     {guildId}/
//!       guild.json             — { id, name }
//!       audit-log.json         — array (often empty)
//!   Activity/
//!     {analytics,tns,reporting,modeling}/events-*.json
//!         — JSON Lines telemetry; tns is the high-value one (auth events, IPs)
//! ```
//!
//! Attachments inside `Messages/c*/messages.json` are HTTPS URLs to
//! `cdn.discordapp.com/attachments/…` with signed expirations.  We do NOT
//! download them (often expired by the time investigators import) but we
//! preserve the URL list in `rawFields.attachmentUrls` and surface a `📎`
//! count on the chat bubble.  Avatars (`avatar.jpeg`, `recent_avatars/*`)
//! ARE extracted to the case media dir so the Photos tab has something
//! tangible to triage.
//!
//! This implementation is a port of the JS reference parser at
//! `C:\Users\JUSTI\Workspace\VIPER\modules\discord-warrant\discord-warrant-parser.js`.

use std::collections::{HashMap, HashSet};
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

pub struct DiscordWarrantParser;

// ─── WarrantParser impl ─────────────────────────────────────────────────

impl WarrantParser for DiscordWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Discord
    }

    fn accepts(&self, path: &Path) -> Result<bool, ParseError> {
        if path.is_dir() {
            return Ok(dir_has_discord_format(path));
        }

        let file = File::open(path)?;
        let mut zip = match ZipArchive::new(file) {
            Ok(z) => z,
            Err(_) => return Ok(false),
        };

        let mut has_user_json = false;
        let mut has_messages_index = false;
        let mut has_activity = false;
        let mut readme_matches = false;

        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let raw_name = entry.name().to_string();
            let lower = raw_name.to_lowercase();
            // Tolerate top-level wrapper folder.
            if lower.ends_with("account/user.json") {
                has_user_json = true;
            }
            if lower.ends_with("messages/index.json") {
                has_messages_index = true;
            }
            if lower.contains("/activity/") || lower.starts_with("activity/") {
                has_activity = true;
            }
            if lower.ends_with("readme.txt") && !readme_matches {
                let mut buf = String::new();
                let _ = entry.read_to_string(&mut buf);
                if buf.to_lowercase().contains("discord data package") {
                    readme_matches = true;
                }
            }
        }

        Ok(readme_matches || (has_user_json && (has_messages_index || has_activity)))
    }

    fn parse(
        &self,
        archive_path: &Path,
        media_extract_dir: &Path,
    ) -> Result<ParsedReturn, ParseError> {
        if !self.accepts(archive_path)? {
            return Err(ParseError::WrongFormat);
        }

        fs::create_dir_all(media_extract_dir)?;

        // ── Phase 1: slurp every relevant file into memory; extract avatars to disk.
        let mut sources = DiscordSources::default();
        if archive_path.is_dir() {
            collect_from_dir(archive_path, media_extract_dir, &mut sources)?;
        } else {
            let file = File::open(archive_path)?;
            let mut zip = ZipArchive::new(file)?;
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                let raw_name = entry.name().to_string();
                if raw_name.ends_with('/') {
                    continue;
                }
                let rel = strip_zip_wrapper(&raw_name);
                let lower = rel.to_lowercase();
                let basename = lower
                    .rsplit('/')
                    .next()
                    .unwrap_or(&lower)
                    .to_string();

                // Avatar / recent avatar extraction
                if rel == "Account/avatar.jpeg"
                    || rel == "Account/avatar.png"
                    || rel == "Account/avatar.gif"
                    || rel == "Account/avatar.webp"
                {
                    let out_name = basename.clone();
                    let out_path = media_extract_dir.join(&out_name);
                    let mut out = File::create(&out_path)?;
                    std::io::copy(&mut entry, &mut out)?;
                    sources.avatar_files.push(out_name);
                    continue;
                }
                if rel.starts_with("Account/recent_avatars/") && is_image_basename(&basename) {
                    // Prefix to avoid clashing with current avatar filename.
                    let out_name = format!("recent_{}", basename);
                    let out_path = media_extract_dir.join(&out_name);
                    let mut out = File::create(&out_path)?;
                    std::io::copy(&mut entry, &mut out)?;
                    sources.recent_avatar_files.push(out_name);
                    continue;
                }

                // Text JSON / JSONL files we care about
                if basename.ends_with(".json") || basename.ends_with(".txt") {
                    // Avoid pulling enormous activity files into memory unnecessarily —
                    // but they're typically only a few hundred KB.
                    let mut buf = String::new();
                    if entry.read_to_string(&mut buf).is_ok() {
                        sources.texts.insert(rel.clone(), buf);
                    }
                }
            }
        }

        let case_id = Uuid::new_v4().to_string();
        let source_filename = archive_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        let mut ctx = ParseCtx::default();

        // ── Phase 2: subscriber bio.
        let subscriber = parse_user_json(sources.read("Account/user.json"));
        emit_bio(&subscriber, &mut ctx);

        // Pull the target account label from username / global_name / id.
        if let Some(s) = &subscriber {
            ctx.target_account = s.username
                .clone()
                .or_else(|| s.global_name.clone())
                .or_else(|| s.id.clone());
        }

        // ── Phase 3: avatars → photos
        emit_avatars(
            &sources.avatar_files,
            &sources.recent_avatar_files,
            &mut ctx,
        );

        // ── Phase 4: messages
        emit_messages(&sources, &mut ctx, media_extract_dir);

        // ── Phase 5: servers
        emit_servers(&sources, &mut ctx);

        // ── Phase 6: billing / store / virtual currency / promotions
        emit_billing(&sources, &mut ctx);

        // ── Phase 7: activity events (JSONL); aggregate IP + device
        let activity = parse_activity(&sources);
        let (ip_rows, device_rows) = aggregate_ip_and_devices(&subscriber, &activity);
        emit_ip_addresses(&ip_rows, &mut ctx);
        emit_devices(&device_rows, &mut ctx);

        // ── Phase 8: friends / connections
        emit_friends(&subscriber, &mut ctx);

        // ── Phase 9: backfill any orphan media files (none expected for
        //              Discord, but keeps parity with Meta).
        backfill_media_as_photos(media_extract_dir, &mut ctx);

        let case = WarrantCase {
            case_id,
            provider: Provider::Discord,
            provider_display: "Discord".to_string(),
            source_filename,
            imported_at: Utc::now().to_rfc3339(),
            target_account: ctx.target_account.clone(),
            date_range: ctx.date_range.clone(),
            generated_at_source: ctx.generated_at_source.clone(),
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
                name: "DMs of Interest".into(),
                color: "#5865F2".into(),
                description: Some("Direct messages flagged for review".into()),
            },
            BucketTemplate {
                name: "Server Activity".into(),
                color: "#6c8aed".into(),
                description: None,
            },
            BucketTemplate {
                name: "Contacts of Interest".into(),
                color: "#8b5cf6".into(),
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

// ─── Internal helpers ────────────────────────────────────────────────────

#[derive(Default)]
struct DiscordSources {
    /// rel-path → text contents (UTF-8). Keys are normalised, no leading
    /// wrapper folder, forward slashes.
    texts: HashMap<String, String>,
    /// Avatar basenames extracted to media dir.
    avatar_files: Vec<String>,
    recent_avatar_files: Vec<String>,
}

impl DiscordSources {
    fn read(&self, rel: &str) -> Option<&str> {
        self.texts.get(rel).map(|s| s.as_str())
    }
}

#[derive(Default)]
struct ParseCtx {
    items: Vec<WarrantItem>,
    id_seq: HashMap<&'static str, usize>,
    target_account: Option<String>,
    date_range: Option<String>,
    generated_at_source: Option<String>,
}

impl ParseCtx {
    fn next_id(&mut self, prefix: &'static str) -> String {
        let n = self.id_seq.entry(prefix).or_insert(0);
        *n += 1;
        format!("{}-{:04}", prefix, *n)
    }
}

#[derive(Default, Clone)]
struct Subscriber {
    id: Option<String>,
    username: Option<String>,
    global_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ip: Option<String>,
    verified: bool,
    has_mobile: bool,
    premium_until: Option<String>,
    avatar_hash: Option<String>,
    flags: Vec<String>,
    sessions: Vec<SessionRow>,
    connections: Vec<Value>,
    external_friends_lists: Vec<Value>,
    raw: Option<Value>,
}

#[derive(Default, Clone)]
#[allow(dead_code)]
struct SessionRow {
    ip: Option<String>,
    os: Option<String>,
    platform: Option<String>,
    creation_time: Option<String>,
    last_used: Option<String>,
    expiration_time: Option<String>,
    is_mfa: bool,
    is_bot: bool,
    is_soft_deleted: bool,
    binding_token: Option<String>,
}

fn parse_user_json(txt: Option<&str>) -> Option<Subscriber> {
    let txt = txt?;
    let v: Value = serde_json::from_str(txt).ok()?;

    let mut sub = Subscriber::default();
    sub.id = v.get("id").and_then(|s| s.as_str().map(String::from));
    sub.username = v.get("username").and_then(|s| s.as_str().map(String::from));
    sub.global_name = v.get("global_name").and_then(|s| s.as_str().map(String::from));
    sub.email = v.get("email").and_then(|s| s.as_str().map(String::from));
    sub.phone = v.get("phone").and_then(|s| s.as_str().map(String::from));
    sub.ip = v.get("ip").and_then(|s| s.as_str().map(String::from));
    sub.verified = v.get("verified").and_then(|b| b.as_bool()).unwrap_or(false);
    sub.has_mobile = v.get("has_mobile").and_then(|b| b.as_bool()).unwrap_or(false);
    sub.premium_until = v.get("premium_until").and_then(|s| s.as_str().map(String::from));
    sub.avatar_hash = v.get("avatar_hash").and_then(|s| s.as_str().map(String::from));
    sub.flags = v
        .get("flags")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    sub.connections = v
        .get("connections")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    sub.external_friends_lists = v
        .get("external_friends_lists")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    if let Some(arr) = v.get("user_sessions").and_then(|x| x.as_array()) {
        for s in arr {
            let ud = s.get("user_data").cloned().unwrap_or(s.clone());
            let ci = ud.get("client_info").cloned().unwrap_or(Value::Null);
            let row = SessionRow {
                ip: ci.get("ip").and_then(|x| x.as_str().map(String::from)),
                os: ci.get("os").and_then(|x| x.as_str().map(String::from)),
                platform: ci.get("platform").and_then(|x| x.as_str().map(String::from)),
                creation_time: ud
                    .get("creation_time")
                    .and_then(|x| x.as_str().map(String::from)),
                last_used: ud
                    .get("approx_last_used_time")
                    .and_then(|x| x.as_str().map(String::from)),
                expiration_time: ud
                    .get("expiration_time")
                    .and_then(|x| x.as_str().map(String::from)),
                is_mfa: ud.get("is_mfa").and_then(|b| b.as_bool()).unwrap_or(false),
                is_bot: ud.get("is_bot").and_then(|b| b.as_bool()).unwrap_or(false),
                is_soft_deleted: s
                    .get("is_soft_deleted")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false),
                binding_token: ud
                    .get("extra_tokens")
                    .and_then(|t| t.get("binding_token"))
                    .and_then(|t| t.get("binding_token"))
                    .and_then(|x| x.as_str().map(String::from)),
            };
            sub.sessions.push(row);
        }
    }

    sub.raw = Some(v);
    Some(sub)
}

fn emit_bio(sub: &Option<Subscriber>, ctx: &mut ParseCtx) {
    let Some(s) = sub else { return };

    // Emit ONE consolidated bio item with all fields in `raw_fields.fields`
    // as an ordered array of {label, value} pairs.  The Bio overview card
    // and the BIO row in the detail pane both consume this structure, so
    // we only show a single "BIO" row in the section list (instead of a
    // dozen separate rows that clutter the list).
    let mut fields: Vec<Value> = Vec::new();
    let mut push = |label: &str, value: Option<&str>| {
        if let Some(v) = value.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            fields.push(json!({ "label": label, "value": v }));
        }
    };

    push("User ID", s.id.as_deref());
    push("Username", s.username.as_deref());
    push("Display Name", s.global_name.as_deref());
    push("Email", s.email.as_deref());
    push("Phone", s.phone.as_deref());
    push("Account IP", s.ip.as_deref());
    push("Verified", Some(if s.verified { "Yes" } else { "No" }));
    push("Has Mobile", Some(if s.has_mobile { "Yes" } else { "No" }));
    push("Premium Until", s.premium_until.as_deref());

    let flags_str: String;
    if !s.flags.is_empty() {
        flags_str = s.flags.join(", ");
        push("Flags", Some(&flags_str));
    }
    let sessions_str: String;
    if !s.sessions.is_empty() {
        sessions_str = s.sessions.len().to_string();
        push("Sessions", Some(&sessions_str));
    }
    let conn_str: String;
    if !s.connections.is_empty() {
        conn_str = s.connections.len().to_string();
        push("Connections", Some(&conn_str));
    }

    if fields.is_empty() {
        return;
    }

    // Build a short summary line: "Username · Email · User ID"
    let summary_bits: Vec<String> = ["Username", "Email", "User ID"]
        .iter()
        .filter_map(|label| {
            fields.iter().find_map(|f| {
                let l = f.get("label").and_then(|v| v.as_str())?;
                let v = f.get("value").and_then(|v| v.as_str())?;
                if l == *label { Some(v.to_string()) } else { None }
            })
        })
        .collect();
    let summary = if summary_bits.is_empty() {
        format!("Account · {} fields", fields.len())
    } else {
        summary_bits.join(" · ")
    };

    // Build body_text as a multi-line "Label: Value" listing so the list
    // pane shows useful context even when collapsed.
    let body_lines: Vec<String> = fields
        .iter()
        .filter_map(|f| {
            let l = f.get("label").and_then(|v| v.as_str())?;
            let v = f.get("value").and_then(|v| v.as_str())?;
            Some(format!("{}: {}", l, v))
        })
        .collect();
    let body_text = body_lines.join("\n");

    let id = ctx.next_id("bio");
    ctx.items.push(WarrantItem {
        id,
        section: "bio".into(),
        section_display: "Account".into(),
        timestamp: None,
        author: None,
        recipient: None,
        body_text: Some(body_text),
        summary: Some(summary),
        raw_fields: json!({
            "fields": fields,
            "source": "Account/user.json",
        }),
        attachments: Vec::new(),
        bucket: None,
        note: None,
        is_flagged: false,
    });
}

fn emit_avatars(current: &[String], recent: &[String], ctx: &mut ParseCtx) {
    // current avatar first
    for name in current {
        let id = ctx.next_id("photo");
        ctx.items.push(WarrantItem {
            id,
            section: "profile_photos".into(),
            section_display: "Avatars".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some("Current avatar".into()),
            summary: Some(format!("Current avatar · {}", name)),
            raw_fields: json!({ "filename": name, "kind": "current_avatar" }),
            attachments: vec![name.clone()],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
    for name in recent {
        let id = ctx.next_id("photo");
        ctx.items.push(WarrantItem {
            id,
            section: "profile_photos".into(),
            section_display: "Avatars".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some("Recent avatar".into()),
            summary: Some(format!("Historical avatar · {}", name)),
            raw_fields: json!({ "filename": name, "kind": "recent_avatar" }),
            attachments: vec![name.clone()],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_messages(sources: &DiscordSources, ctx: &mut ParseCtx, media_extract_dir: &Path) {
    // Build messages_index map
    let index: HashMap<String, String> = sources
        .read("Messages/index.json")
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .and_then(|v| v.as_object().cloned())
        .map(|m| {
            m.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Discover channel folders Messages/c{id}/...
    let mut channel_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for key in sources.texts.keys() {
        if let Some(rest) = key.strip_prefix("Messages/c") {
            if let Some(slash) = rest.find('/') {
                let cid = &rest[..slash];
                if !cid.is_empty() && cid.chars().all(|c| c.is_ascii_digit()) && seen.insert(cid.to_string()) {
                    channel_ids.push(cid.to_string());
                }
            }
        }
    }
    channel_ids.sort();

    for cid in &channel_ids {
        let channel_meta_v: Value = sources
            .read(&format!("Messages/c{}/channel.json", cid))
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or(Value::Null);

        let channel_id = channel_meta_v
            .get("id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| cid.clone());
        let channel_name = channel_meta_v
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| index.get(cid).cloned())
            .unwrap_or_else(|| format!("c{}", cid));
        let channel_type = channel_meta_v
            .get("type")
            .and_then(|v| v.as_str())
            .map(String::from);
        let guild_id = channel_meta_v
            .get("guild")
            .and_then(|g| g.get("id"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let guild_name = channel_meta_v
            .get("guild")
            .and_then(|g| g.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let recipients = channel_meta_v
            .get("recipients")
            .cloned()
            .unwrap_or(Value::Null);

        let label_for_thread = match (&guild_name, &channel_type) {
            (Some(g), _) => format!("#{} · {}", channel_name, g),
            (None, Some(t)) if t == "DM" || t == "GROUP_DM" => {
                format!("{} ({})", channel_name, t)
            }
            _ => channel_name.clone(),
        };

        // Read messages
        let msgs_v: Value = sources
            .read(&format!("Messages/c{}/messages.json", cid))
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or(Value::Array(Vec::new()));
        let msgs = msgs_v.as_array().cloned().unwrap_or_default();

        // Sort by timestamp ascending so chat view reads top-to-bottom.
        let mut indexed: Vec<(usize, &Value)> = msgs.iter().enumerate().collect();
        indexed.sort_by(|a, b| {
            let ta = a
                .1
                .get("Timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tb = b
                .1
                .get("Timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            ta.cmp(tb).then_with(|| a.0.cmp(&b.0))
        });

        for (_, m) in indexed {
            let msg_id = m
                .get("ID")
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                })
                .unwrap_or_default();
            let timestamp = m
                .get("Timestamp")
                .and_then(|v| v.as_str())
                .map(String::from);
            let contents = m
                .get("Contents")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default();
            let raw_atts = m
                .get("Attachments")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default();

            let attachment_urls: Vec<String> = if raw_atts.trim().is_empty() {
                Vec::new()
            } else {
                raw_atts
                    .split_whitespace()
                    .map(|s| s.trim_end_matches(',').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };

            // Skip totally empty messages.
            if contents.is_empty() && attachment_urls.is_empty() {
                continue;
            }

            // ── Try to download each attachment URL.
            //
            // Discord CDN URLs are signed and may be expired by the time
            // the warrant return is imported.  We attempt a short-timeout
            // GET; on success, the file is saved into `media_extract_dir`
            // with a deterministic name and added to `attachments` so the
            // photos gallery + chat bubble can render it.  On failure we
            // still record the URL + filename in
            // `raw_fields.attachmentLinks` so investigators can see what
            // was attached even when the file is unrecoverable.
            let mut downloaded_atts: Vec<String> = Vec::new();
            let mut attachment_links: Vec<Value> = Vec::new();
            for (n, url) in attachment_urls.iter().enumerate() {
                let original_name = filename_from_url(url);
                let safe_orig = sanitize_filename(&original_name);
                let local_name = format!(
                    "discord_{}_{:02}_{}",
                    if msg_id.is_empty() { "msg".to_string() } else { msg_id.clone() },
                    n + 1,
                    safe_orig
                );
                let out_path = media_extract_dir.join(&local_name);

                let mut status = "url_only";
                let mut saved_as: Option<String> = None;

                // Skip download attempt if URL looks structurally expired
                // (Discord signs with `?ex={hex_unix_ts}`).
                let already_expired = url_signed_expired(url);

                if !already_expired {
                    if let Ok(resp) = ureq::get(url)
                        .timeout(std::time::Duration::from_secs(8))
                        .call()
                    {
                        if resp.status() >= 200 && resp.status() < 300 {
                            if let Ok(mut file) = File::create(&out_path) {
                                let mut reader = resp.into_reader();
                                if std::io::copy(&mut reader, &mut file).is_ok() {
                                    downloaded_atts.push(local_name.clone());
                                    saved_as = Some(local_name.clone());
                                    status = "downloaded";
                                }
                            }
                        }
                    }
                } else {
                    status = "expired";
                }

                attachment_links.push(json!({
                    "url": url,
                    "filename": original_name,
                    "savedAs": saved_as,
                    "status": status,
                }));
            }

            let body_for_summary = if !contents.is_empty() {
                contents.clone()
            } else if !attachment_urls.is_empty() {
                // Prefer filename in summary if we have one
                let names: Vec<String> = attachment_links
                    .iter()
                    .filter_map(|l| l.get("filename").and_then(|v| v.as_str()).map(String::from))
                    .collect();
                if !names.is_empty() {
                    format!("📎 {}", names.join(", "))
                } else {
                    format!("📎 {} attachment(s)", attachment_urls.len())
                }
            } else {
                String::new()
            };

            let id = ctx.next_id("msg");

            // Author defaults to the subscriber — Discord messages.json
            // only contains messages SENT by the warrant subject.
            let author = ctx.target_account.clone();
            // Recipient: derive from channel context.
            let recipient = if matches!(channel_type.as_deref(), Some("DM"))
                && recipients.is_array()
            {
                recipients
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|x| x.as_str())
                    .map(String::from)
                    .or_else(|| Some(channel_name.clone()))
            } else {
                Some(label_for_thread.clone())
            };

            let attachment_url_value: Vec<Value> = attachment_urls
                .iter()
                .cloned()
                .map(Value::String)
                .collect();

            ctx.items.push(WarrantItem {
                id,
                section: "unified_messages".into(),
                section_display: "Messages".into(),
                timestamp: timestamp.clone(),
                author: author.clone(),
                recipient,
                body_text: if contents.is_empty() { None } else { Some(contents.clone()) },
                summary: Some(truncate(&body_for_summary, 80)),
                raw_fields: json!({
                    "messageId": msg_id,
                    "threadId": channel_id,
                    "channelName": channel_name,
                    "channelType": channel_type,
                    "guildId": guild_id,
                    "guildName": guild_name,
                    "participants": [author.clone().unwrap_or_default(), label_for_thread.clone()],
                    "sent": timestamp,
                    "body": contents,
                    "attachmentUrls": attachment_url_value,
                    "attachmentLinks": attachment_links,
                    "source": "messages.json",
                }),
                attachments: downloaded_atts,
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

fn emit_servers(sources: &DiscordSources, ctx: &mut ParseCtx) {
    let index: HashMap<String, String> = sources
        .read("Servers/index.json")
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .and_then(|v| v.as_object().cloned())
        .map(|m| {
            m.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut guild_ids: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for key in sources.texts.keys() {
        if let Some(rest) = key.strip_prefix("Servers/") {
            if let Some(slash) = rest.find('/') {
                let gid = &rest[..slash];
                if !gid.is_empty() && gid.chars().all(|c| c.is_ascii_digit()) && seen.insert(gid.to_string()) {
                    guild_ids.push(gid.to_string());
                }
            }
        }
    }
    guild_ids.sort();

    for gid in &guild_ids {
        let guild_v: Value = sources
            .read(&format!("Servers/{}/guild.json", gid))
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or(Value::Null);
        let audit_v: Value = sources
            .read(&format!("Servers/{}/audit-log.json", gid))
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or(Value::Array(Vec::new()));

        let name = guild_v
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| index.get(gid).cloned())
            .unwrap_or_else(|| format!("Server {}", gid));
        let audit_count = audit_v.as_array().map(|a| a.len()).unwrap_or(0);

        let id = ctx.next_id("server");
        ctx.items.push(WarrantItem {
            id,
            section: "servers".into(),
            section_display: "Servers".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(name.clone()),
            summary: Some(format!("{} · {} audit entries", name, audit_count)),
            raw_fields: json!({
                "guildId": gid,
                "name": name,
                "auditLog": audit_v,
                "source": format!("Servers/{}/guild.json", gid),
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_billing(sources: &DiscordSources, ctx: &mut ParseCtx) {
    let billing_files = [
        ("Account/user_data_exports/discord_billing/billing_profile.json", "Billing Profile"),
        ("Account/user_data_exports/discord_billing/payment_sources.json", "Payment Sources"),
        ("Account/user_data_exports/discord_billing/payments.json", "Payments"),
        ("Account/user_data_exports/discord_billing/entitlements.json", "Entitlements"),
        ("Account/user_data_exports/discord_store/wishlist_items.json", "Wishlist"),
        ("Account/user_data_exports/discord_virtual_currency/coin_accounts.json", "Coin Accounts"),
        ("Account/user_data_exports/discord_virtual_currency/coin_transactions.json", "Coin Transactions"),
        ("Account/user_data_exports/discord_promotions/quests_reward_codes.json", "Quest Rewards"),
        ("Account/user_data_exports/discord_promotions/drops_reward_codes.json", "Drop Rewards"),
    ];
    for (path, label) in billing_files {
        let Some(txt) = sources.read(path) else { continue };
        let v: Value = match serde_json::from_str(txt) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let records = v
            .get("records")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            continue;
        }
        for r in &records {
            let id = ctx.next_id("billing");
            let summary = format!("{} record", label);
            ctx.items.push(WarrantItem {
                id,
                section: "payment_methods".into(),
                section_display: "Billing & Store".into(),
                timestamp: r
                    .get("Created At")
                    .and_then(|x| x.as_str())
                    .map(String::from)
                    .or_else(|| {
                        r.get("timestamp")
                            .and_then(|x| x.as_str())
                            .map(String::from)
                    }),
                author: None,
                recipient: None,
                body_text: Some(label.to_string()),
                summary: Some(summary),
                raw_fields: json!({
                    "label": label,
                    "source": path,
                    "record": r,
                }),
                attachments: Vec::new(),
                bucket: None,
                note: None,
                is_flagged: false,
            });
        }
    }
}

#[derive(Default, Clone, Debug)]
#[allow(dead_code)]
struct IpEventRow {
    category: String,
    event_type: String,
    timestamp: Option<String>,
    ip: Option<String>,
    city: Option<String>,
    region_code: Option<String>,
    country_code: Option<String>,
    time_zone: Option<String>,
    isp: Option<String>,
    browser: Option<String>,
    browser_user_agent: Option<String>,
    device: Option<String>,
    device_vendor_id: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    client_version: Option<String>,
    user_id: Option<String>,
    event_id: Option<String>,
}

#[derive(Default)]
struct ParsedActivity {
    events: Vec<IpEventRow>,
    total_event_count: u64,
    event_counts: HashMap<String, u64>,
}

const IP_EVENT_TYPES: &[&str] = &[
    "session_start_success",
    "session_start",
    "session_end",
    "app_opened",
    "login_attempted",
    "login_succeeded",
    "login_successful",
    "login_failed",
    "register",
    "register_succeeded",
    "register_attempted",
    "logout",
];

fn parse_activity(sources: &DiscordSources) -> ParsedActivity {
    let mut out = ParsedActivity::default();
    let categories = ["analytics", "tns", "reporting", "modeling"];
    for cat in categories {
        for (rel, txt) in &sources.texts {
            let prefix = format!("Activity/{}/", cat);
            if !rel.starts_with(&prefix) {
                continue;
            }
            if !rel.ends_with(".json") {
                continue;
            }
            for line in txt.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let ev: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                out.total_event_count += 1;
                let t = ev
                    .get("event_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                *out.event_counts.entry(format!("{}/{}", cat, t)).or_insert(0) += 1;

                if !IP_EVENT_TYPES.contains(&t.as_str()) {
                    continue;
                }

                let row = IpEventRow {
                    category: cat.to_string(),
                    event_type: t,
                    timestamp: ev
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim_matches('"').to_string()),
                    ip: ev.get("ip").and_then(|v| v.as_str().map(String::from)),
                    city: ev.get("city").and_then(|v| v.as_str().map(String::from)),
                    region_code: ev
                        .get("region_code")
                        .and_then(|v| v.as_str().map(String::from)),
                    country_code: ev
                        .get("country_code")
                        .and_then(|v| v.as_str().map(String::from)),
                    time_zone: ev
                        .get("time_zone")
                        .and_then(|v| v.as_str().map(String::from)),
                    isp: ev.get("isp").and_then(|v| v.as_str().map(String::from)),
                    browser: ev.get("browser").and_then(|v| v.as_str().map(String::from)),
                    browser_user_agent: ev
                        .get("browser_user_agent")
                        .and_then(|v| v.as_str().map(String::from)),
                    device: ev.get("device").and_then(|v| v.as_str().map(String::from)),
                    device_vendor_id: ev
                        .get("device_vendor_id")
                        .and_then(|v| v.as_str().map(String::from)),
                    os: ev.get("os").and_then(|v| v.as_str().map(String::from)),
                    os_version: ev
                        .get("os_version")
                        .and_then(|v| v.as_str().map(String::from)),
                    client_version: ev
                        .get("client_version")
                        .and_then(|v| v.as_str().map(String::from)),
                    user_id: ev.get("user_id").and_then(|v| v.as_str().map(String::from)),
                    event_id: ev.get("event_id").and_then(|v| v.as_str().map(String::from)),
                };
                out.events.push(row);
            }
        }
    }
    out
}

#[derive(Default)]
struct IpAggregate {
    ip: String,
    count: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
    locations: HashSet<String>,
    browsers: HashSet<String>,
    oses: HashSet<String>,
    devices: HashSet<String>,
    isps: HashSet<String>,
    sources: HashSet<String>,
}

#[derive(Default)]
struct DeviceAggregate {
    key: String,
    device_vendor_id: Option<String>,
    device: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    browser: Option<String>,
    browser_user_agent: Option<String>,
    client_version: Option<String>,
    count: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
    ips: HashSet<String>,
}

fn aggregate_ip_and_devices(
    subscriber: &Option<Subscriber>,
    activity: &ParsedActivity,
) -> (Vec<IpAggregate>, Vec<DeviceAggregate>) {
    let mut ip_map: HashMap<String, IpAggregate> = HashMap::new();
    let mut dev_map: HashMap<String, DeviceAggregate> = HashMap::new();

    let mut track_ip = |ip: &Option<String>, ts: &Option<String>, fields: &TrackFields, source: &str| {
        let Some(ip) = ip.as_ref().filter(|s| !s.is_empty()) else { return };
        let row = ip_map.entry(ip.clone()).or_insert_with(|| IpAggregate {
            ip: ip.clone(),
            ..Default::default()
        });
        row.count += 1;
        update_first_last(&mut row.first_seen, &mut row.last_seen, ts);
        let mut loc_parts: Vec<String> = Vec::new();
        if let Some(c) = &fields.city { loc_parts.push(c.clone()); }
        if let Some(r) = &fields.region_code { loc_parts.push(r.clone()); }
        if let Some(c) = &fields.country_code { loc_parts.push(c.clone()); }
        if !loc_parts.is_empty() {
            row.locations.insert(loc_parts.join(", "));
        }
        if let Some(b) = &fields.browser { row.browsers.insert(b.clone()); }
        if let Some(os) = &fields.os {
            row.oses.insert(match &fields.os_version {
                Some(v) => format!("{} {}", os, v),
                None => os.clone(),
            });
        }
        if let Some(d) = &fields.device { row.devices.insert(d.clone()); }
        if let Some(i) = &fields.isp { row.isps.insert(i.clone()); }
        if !source.is_empty() { row.sources.insert(source.to_string()); }
    };

    let mut track_device = |key: &str, ts: &Option<String>, fields: &TrackFields| {
        if key.is_empty() { return; }
        let row = dev_map.entry(key.to_string()).or_insert_with(|| DeviceAggregate {
            key: key.to_string(),
            ..Default::default()
        });
        row.count += 1;
        update_first_last(&mut row.first_seen, &mut row.last_seen, ts);
        if let Some(ip) = &fields.ip { row.ips.insert(ip.clone()); }
        promote(&mut row.device_vendor_id, &fields.device_vendor_id);
        promote(&mut row.device, &fields.device);
        promote(&mut row.os, &fields.os);
        promote(&mut row.os_version, &fields.os_version);
        promote(&mut row.browser, &fields.browser);
        promote(&mut row.browser_user_agent, &fields.browser_user_agent);
        promote(&mut row.client_version, &fields.client_version);
    };

    // From subscriber sessions
    if let Some(sub) = subscriber {
        for s in &sub.sessions {
            let ts = s.last_used.clone().or_else(|| s.creation_time.clone());
            let f = TrackFields {
                ip: s.ip.clone(),
                os: s.os.clone(),
                browser: s.platform.clone(),
                ..Default::default()
            };
            track_ip(&s.ip, &ts, &f, "user_sessions");
            let key = format!(
                "{}|{}",
                s.os.as_deref().unwrap_or("?"),
                s.platform.as_deref().unwrap_or("?")
            );
            track_device(&key, &ts, &f);
        }
        if let Some(ip) = &sub.ip {
            let f = TrackFields::default();
            track_ip(&Some(ip.clone()), &None, &f, "account");
        }
    }

    // From activity events
    for ev in &activity.events {
        let f = TrackFields {
            ip: ev.ip.clone(),
            city: ev.city.clone(),
            region_code: ev.region_code.clone(),
            country_code: ev.country_code.clone(),
            isp: ev.isp.clone(),
            browser: ev.browser.clone(),
            browser_user_agent: ev.browser_user_agent.clone(),
            device: ev.device.clone(),
            device_vendor_id: ev.device_vendor_id.clone(),
            os: ev.os.clone(),
            os_version: ev.os_version.clone(),
            client_version: ev.client_version.clone(),
        };
        track_ip(&ev.ip, &ev.timestamp, &f, &ev.event_type);
        let key = ev
            .device_vendor_id
            .clone()
            .or_else(|| {
                ev.device.as_ref().map(|d| {
                    format!(
                        "{}|{}",
                        d,
                        ev.os.as_deref().unwrap_or("?")
                    )
                })
            })
            .or_else(|| {
                ev.browser.as_ref().map(|b| {
                    format!(
                        "{}|{}",
                        b,
                        ev.os.as_deref().unwrap_or("?")
                    )
                })
            })
            .unwrap_or_default();
        if !key.is_empty() {
            track_device(&key, &ev.timestamp, &f);
        }
    }

    let mut ips: Vec<IpAggregate> = ip_map.into_values().collect();
    ips.sort_by(|a, b| b.count.cmp(&a.count));
    let mut devs: Vec<DeviceAggregate> = dev_map.into_values().collect();
    devs.sort_by(|a, b| b.count.cmp(&a.count));
    (ips, devs)
}

#[derive(Default, Clone)]
struct TrackFields {
    ip: Option<String>,
    city: Option<String>,
    region_code: Option<String>,
    country_code: Option<String>,
    isp: Option<String>,
    browser: Option<String>,
    browser_user_agent: Option<String>,
    device: Option<String>,
    device_vendor_id: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    client_version: Option<String>,
}

fn update_first_last(
    first: &mut Option<String>,
    last: &mut Option<String>,
    ts: &Option<String>,
) {
    let Some(ts) = ts.as_ref().filter(|s| !s.is_empty()) else { return };
    if first.as_ref().map_or(true, |f| ts.as_str() < f.as_str()) {
        *first = Some(ts.clone());
    }
    if last.as_ref().map_or(true, |l| ts.as_str() > l.as_str()) {
        *last = Some(ts.clone());
    }
}

fn promote(slot: &mut Option<String>, new_val: &Option<String>) {
    if slot.is_none() {
        if let Some(v) = new_val {
            *slot = Some(v.clone());
        }
    }
}

fn emit_ip_addresses(rows: &[IpAggregate], ctx: &mut ParseCtx) {
    for r in rows {
        let id = ctx.next_id("ip");
        let mut locs: Vec<&String> = r.locations.iter().collect();
        locs.sort();
        let loc_str = locs
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" / ");
        let summary = if !loc_str.is_empty() {
            format!("{} · {} hits · {}", r.ip, r.count, loc_str)
        } else {
            format!("{} · {} hits", r.ip, r.count)
        };

        let to_arr = |s: &HashSet<String>| -> Vec<Value> {
            let mut v: Vec<&String> = s.iter().collect();
            v.sort();
            v.into_iter().cloned().map(Value::String).collect()
        };

        ctx.items.push(WarrantItem {
            id,
            section: "ip_addresses".into(),
            section_display: "IP Addresses".into(),
            timestamp: r.last_seen.clone(),
            author: None,
            recipient: None,
            body_text: Some(r.ip.clone()),
            summary: Some(summary),
            raw_fields: json!({
                "ip": r.ip,
                "count": r.count,
                "firstSeen": r.first_seen,
                "lastSeen": r.last_seen,
                "locations": to_arr(&r.locations),
                "browsers": to_arr(&r.browsers),
                "oses": to_arr(&r.oses),
                "devices": to_arr(&r.devices),
                "isps": to_arr(&r.isps),
                "sources": to_arr(&r.sources),
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_devices(rows: &[DeviceAggregate], ctx: &mut ParseCtx) {
    for r in rows {
        let id = ctx.next_id("device");
        let label = r
            .device
            .clone()
            .or_else(|| r.browser.clone())
            .unwrap_or_else(|| r.key.clone());
        let summary = format!(
            "{} · {} · {} hits",
            label,
            r.os.as_deref().unwrap_or("?"),
            r.count
        );
        let ips: Vec<Value> = {
            let mut v: Vec<&String> = r.ips.iter().collect();
            v.sort();
            v.into_iter().cloned().map(Value::String).collect()
        };
        ctx.items.push(WarrantItem {
            id,
            section: "device_info".into(),
            section_display: "Devices".into(),
            timestamp: r.last_seen.clone(),
            author: None,
            recipient: None,
            body_text: Some(label),
            summary: Some(summary),
            raw_fields: json!({
                "key": r.key,
                "deviceVendorId": r.device_vendor_id,
                "device": r.device,
                "os": r.os,
                "osVersion": r.os_version,
                "browser": r.browser,
                "browserUserAgent": r.browser_user_agent,
                "clientVersion": r.client_version,
                "count": r.count,
                "firstSeen": r.first_seen,
                "lastSeen": r.last_seen,
                "ips": ips,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn emit_friends(sub: &Option<Subscriber>, ctx: &mut ParseCtx) {
    let Some(s) = sub else { return };
    // External friends lists (contacts sync, etc.)
    for fl in &s.external_friends_lists {
        let id = ctx.next_id("friends");
        let platform = fl
            .get("platform_type")
            .and_then(|v| v.as_str())
            .unwrap_or("contacts");
        let name = fl
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(no name)");
        let count = fl
            .get("friend_id_hashes")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        ctx.items.push(WarrantItem {
            id,
            section: "friends".into(),
            section_display: "Friends".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(format!("{} on {}", name, platform)),
            summary: Some(format!("{} ({}) · {} contacts", name, platform, count)),
            raw_fields: json!({
                "platform": platform,
                "name": name,
                "friendCount": count,
                "data": fl,
            }),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
    // Connections (linked accounts: Twitch, YouTube, etc.)
    for c in &s.connections {
        let id = ctx.next_id("conn");
        let typ = c.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        let name = c
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| c.get("id").and_then(|v| v.as_str()))
            .unwrap_or("(unknown)");
        ctx.items.push(WarrantItem {
            id,
            section: "social_connections".into(),
            section_display: "Connections".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: Some(format!("{} ({})", name, typ)),
            summary: Some(format!("{} · {}", typ, name)),
            raw_fields: c.clone(),
            attachments: Vec::new(),
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

fn backfill_media_as_photos(media_dir: &Path, ctx: &mut ParseCtx) {
    let mut already: HashSet<String> = HashSet::new();
    for item in &ctx.items {
        for a in &item.attachments {
            already.insert(a.to_ascii_lowercase());
        }
    }
    let entries = match fs::read_dir(media_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    files.sort();
    for path in files {
        let Some(filename) = path.file_name().and_then(|s| s.to_str()) else { continue };
        let lower = filename.to_ascii_lowercase();
        if already.contains(&lower) {
            continue;
        }
        if !is_image_basename(&lower) && !is_media_basename(&lower) {
            continue;
        }
        let id = ctx.next_id("photo");
        ctx.items.push(WarrantItem {
            id,
            section: "photos".into(),
            section_display: "Photos".into(),
            timestamp: None,
            author: None,
            recipient: None,
            body_text: None,
            summary: Some(format!("Unreferenced media · {}", filename)),
            raw_fields: json!({
                "filename": filename,
                "note": "Discovered in case media directory, not referenced by any record",
            }),
            attachments: vec![filename.to_string()],
            bucket: None,
            note: None,
            is_flagged: false,
        });
    }
}

// ─── File-system helpers ────────────────────────────────────────────────

fn collect_from_dir(
    root: &Path,
    media_extract_dir: &Path,
    out: &mut DiscordSources,
) -> Result<(), ParseError> {
    walk_dir(root, root, media_extract_dir, out)?;
    Ok(())
}

fn walk_dir(
    base: &Path,
    dir: &Path,
    media_extract_dir: &Path,
    out: &mut DiscordSources,
) -> Result<(), ParseError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_dir(base, &p, media_extract_dir, out)?;
            continue;
        }
        let rel = match p.strip_prefix(base) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        let rel_norm = strip_wrapper_dir(&rel);
        let lower = rel_norm.to_lowercase();
        let basename = lower
            .rsplit('/')
            .next()
            .unwrap_or(&lower)
            .to_string();

        if rel_norm == "Account/avatar.jpeg"
            || rel_norm == "Account/avatar.png"
            || rel_norm == "Account/avatar.gif"
            || rel_norm == "Account/avatar.webp"
        {
            let out_name = basename.clone();
            let out_path = media_extract_dir.join(&out_name);
            fs::copy(&p, &out_path)?;
            out.avatar_files.push(out_name);
            continue;
        }
        if rel_norm.starts_with("Account/recent_avatars/") && is_image_basename(&basename) {
            let out_name = format!("recent_{}", basename);
            let out_path = media_extract_dir.join(&out_name);
            fs::copy(&p, &out_path)?;
            out.recent_avatar_files.push(out_name);
            continue;
        }
        if basename.ends_with(".json") || basename.ends_with(".txt") {
            if let Ok(txt) = fs::read_to_string(&p) {
                out.texts.insert(rel_norm, txt);
            }
        }
    }
    Ok(())
}

fn dir_has_discord_format(dir: &Path) -> bool {
    // Cheap check: look for Account/user.json with optional wrapper folder.
    fn has_user_json(d: &Path, depth: u8) -> bool {
        if depth > 2 {
            return false;
        }
        let candidate = d.join("Account").join("user.json");
        if candidate.is_file() {
            return true;
        }
        // Recurse into one level of subdirs.
        if let Ok(entries) = fs::read_dir(d) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() && has_user_json(&p, depth + 1) {
                    return true;
                }
            }
        }
        false
    }
    has_user_json(dir, 0)
}

fn strip_zip_wrapper(raw: &str) -> String {
    let cleaned = raw.replace('\\', "/");
    let parts: Vec<&str> = cleaned.split('/').collect();
    // If first segment doesn't match Discord's top-level dirs, treat it as
    // a wrapper folder and drop it.  Discord's TLDs are deterministic.
    const TLDS: &[&str] = &[
        "Account",
        "Activities",
        "Activity",
        "Ads",
        "Messages",
        "Servers",
        "Support_Tickets",
    ];
    if parts.len() > 1 {
        let first = parts[0];
        let second = parts[1];
        if !TLDS.contains(&first)
            && first != "README.txt"
            && (TLDS.contains(&second) || second == "README.txt")
        {
            return parts[1..].join("/");
        }
    }
    cleaned
}

fn strip_wrapper_dir(rel: &str) -> String {
    strip_zip_wrapper(rel)
}

fn is_image_basename(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".heif"]
        .iter()
        .any(|ext| l.ends_with(ext))
}
fn is_media_basename(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [".mp4", ".mov", ".webm", ".avi", ".mkv", ".m4v"]
        .iter()
        .any(|ext| l.ends_with(ext))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Extract the basename portion from a CDN URL like
/// `https://cdn.discordapp.com/attachments/12/34/foo.jpg?ex=…`.
fn filename_from_url(url: &str) -> String {
    let before_query = url.split('?').next().unwrap_or(url);
    let last = before_query.rsplit('/').next().unwrap_or(before_query);
    if last.is_empty() {
        "attachment.bin".to_string()
    } else {
        last.to_string()
    }
}

/// Remove characters that can't appear in a Windows filename.
fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => out.push('_'),
            c if (c as u32) < 32 => out.push('_'),
            c => out.push(c),
        }
    }
    let trimmed: String = out.trim_matches(|c: char| c == '.' || c.is_whitespace()).into();
    if trimmed.is_empty() { "attachment.bin".to_string() } else { trimmed }
}

/// Discord CDN URLs encode their expiration as `ex={hex_unix_timestamp}`.
/// Returns true when that timestamp is in the past (or `ex=0` which marks
/// already-redacted URLs in some warrant returns).
fn url_signed_expired(url: &str) -> bool {
    let q = match url.split_once('?') {
        Some((_, q)) => q,
        None => return false,
    };
    for pair in q.split('&') {
        if let Some(val) = pair.strip_prefix("ex=") {
            if val == "0" {
                return true;
            }
            if let Ok(ts) = i64::from_str_radix(val, 16) {
                if ts == 0 {
                    return true;
                }
                let now = Utc::now().timestamp();
                return ts < now;
            }
            return false;
        }
    }
    false
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_zip() -> Option<PathBuf> {
        let p = PathBuf::from(
            r"C:\Users\JUSTI\Desktop\New VIPER Evidence Support Files\package.zip",
        );
        if p.exists() { Some(p) } else { None }
    }

    #[test]
    fn discord_accepts_sample_zip() {
        let Some(zip) = sample_zip() else {
            eprintln!("skip — sample zip not present");
            return;
        };
        let parser = DiscordWarrantParser;
        let accepted = parser.accepts(&zip).unwrap();
        assert!(accepted, "parser should accept Discord package.zip");
    }

    #[test]
    fn discord_parses_sample_zip() {
        let Some(zip) = sample_zip() else {
            eprintln!("skip — sample zip not present");
            return;
        };
        let parser = DiscordWarrantParser;
        let tmp = std::env::temp_dir().join("scout_discord_test_media");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let res = parser.parse(&zip, &tmp).expect("parse should succeed");

        // Should have at least: 1 bio + 1 server + multiple messages.
        let bio_count = res.items.iter().filter(|i| i.section == "bio").count();
        let msg_count = res
            .items
            .iter()
            .filter(|i| i.section == "unified_messages")
            .count();
        let server_count = res.items.iter().filter(|i| i.section == "servers").count();
        let photo_count = res
            .items
            .iter()
            .filter(|i| i.section == "profile_photos" || i.section == "photos")
            .count();

        eprintln!(
            "bios={} msgs={} servers={} photos={} totalItems={}",
            bio_count,
            msg_count,
            server_count,
            photo_count,
            res.items.len()
        );

        assert!(bio_count >= 1, "expected at least one bio item");
        assert!(msg_count >= 1, "expected at least one message item");
        assert!(server_count >= 1, "expected at least one server item");
        assert!(photo_count >= 1, "expected at least one avatar/photo item");
        assert_eq!(res.case.provider_display, "Discord");

        // Bio should be a SINGLE consolidated item with `fields` array.
        let bio = res
            .items
            .iter()
            .find(|i| i.section == "bio")
            .expect("bio item");
        let fields = bio
            .raw_fields
            .get("fields")
            .and_then(|v| v.as_array())
            .expect("bio.raw_fields.fields should be an array");
        assert!(fields.len() >= 5, "expected multiple bio fields");
    }
}
