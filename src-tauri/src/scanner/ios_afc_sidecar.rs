//! Long-lived Python sidecar that owns an AFC connection to one iOS
//! device and serves JSON-RPC commands over stdin/stdout.
//!
//! The actual protocol and AFC work live in `scripts/ios_afc_daemon.py`.
//! This Rust module is a thin transport: it spawns the daemon, classifies
//! incoming events into streaming vs response, and exposes a small trait
//! (`IosAfcBackend`) so a future native Rust impl can drop in without
//! changing call sites.
//!
//! Threading model
//! ---------------
//! * One reader thread loops over the daemon's stdout, JSON-decodes each
//!   line, and either pushes the event onto a request/response channel
//!   (for short ack-style events like `pong`, `opened`, `list_result`,
//!   `stat_result`, `pulled`, `devices`, `error`, `bye`) OR forwards it
//!   to the registered streaming sink (for `file_hash`, `progress`,
//!   `walk_warn`, `complete`, `stopped`).
//! * Caller threads write one JSON line to stdin per command.
//! * `IosAfcSidecar` is `Send + Sync`; stdin and the streaming sink are
//!   each guarded by a `Mutex`.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AfcEntry {
    pub name: String,
    pub path: String,
    pub size: u64,
    /// One of "file", "dir", "link", "other".
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub mtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AfcWalkRequest {
    /// Absolute AFC paths to walk, e.g. `["/DCIM", "/Downloads"]`.
    pub roots: Vec<String>,
    /// Hash algorithms in lowercase: `sha256`, `sha1`, `md5`.
    pub algos: Vec<String>,
    /// Skip files smaller than this number of bytes.
    #[serde(default)]
    pub min_bytes: u64,
    /// Optional lowercase extension filter (e.g. `[".heic", ".jpg"]`).
    #[serde(default)]
    pub extensions: Option<Vec<String>>,
}

/// Trait so we can swap the Python sidecar for a native Rust AFC client
/// later without touching the Tauri command layer.
pub trait IosAfcBackend: Send + Sync {
    fn open(&self, udid: Option<&str>) -> Result<String, String>;
    fn list_dir(&self, path: &str) -> Result<Vec<AfcEntry>, String>;
    fn stat(&self, path: &str) -> Result<AfcEntry, String>;
    /// Start a walk. Streaming events (`file_hash`, `progress`,
    /// `walk_warn`, `complete`, `stopped`) flow through the sink
    /// registered with [`set_event_sink`]. Returns immediately after
    /// the daemon ack'd receipt of the command — the walk runs in the
    /// daemon process and is observed via the sink.
    fn start_walk_hash(&self, req: &AfcWalkRequest) -> Result<(), String>;
    fn stop_walk(&self) -> Result<(), String>;
    fn pull(&self, path: &str, dest: &str) -> Result<u64, String>;
    /// Stream `path` bytes via AFC and return a small JPEG data URL.
    /// Returns `(data_url, src_bytes)`. Never persists source bytes.
    fn thumbnail(&self, path: &str, max_dim: u32) -> Result<(String, u64), String>;
    /// Stream `path` bytes via AFC into ffmpeg's stdin, extract one
    /// frame near the start, and return it as a JPEG data URL.
    /// `(data_url, src_bytes)`. Never writes the source bytes to disk.
    fn video_thumbnail(&self, path: &str, max_dim: u32) -> Result<(String, u64), String>;
    /// Read `[offset, offset+length)` bytes of `path` via AFC seek
    /// and return the raw bytes (already base64-decoded by the
    /// sidecar). Returns shorter than requested at EOF.
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Vec<u8>, String>;
    fn set_event_sink(&self, sink: Box<dyn Fn(Value) + Send + Sync>);
    fn clear_event_sink(&self);
    fn shutdown(&self) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// PythonSidecar implementation
// ---------------------------------------------------------------------------

pub struct PythonSidecar {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    /// Streaming events from `walk_hash` go here.
    event_sink: Arc<Mutex<Option<Box<dyn Fn(Value) + Send + Sync>>>>,
    /// Serializes ack-style RPCs that NEED single-flight semantics
    /// (open / shutdown). Thumbnail RPCs intentionally DO NOT take
    /// this lock — they rely on `pending` routing instead so image
    /// thumbs can run concurrently with in-flight video thumbs.
    request_lock: Mutex<()>,
    /// Single shared inbox for ALL ack-style events (thumbnail_result,
    /// video_thumbnail_result, read_range_result, pulled, stat_result,
    /// list_result, opened, ready, bye, error). The stdout reader pushes
    /// every non-streaming event here and notifies the Condvar. Each
    /// waiter holds the mutex, scans for an event matching its
    /// (event_name, optional path) tuple, removes it, and returns. If
    /// none match, the waiter `wait_timeout`s on the Condvar — when a
    /// new event arrives or another waiter consumes one, all waiters
    /// re-scan. This avoids the deadlock the old crossbeam-channel
    /// design had: in that design, an event for path X received by a
    /// waiter for path Y would be stashed but its real recipient was
    /// blocked in `recv` and never re-checked the stash.
    pending: Arc<(Mutex<VecDeque<Value>>, Condvar)>,
    /// Cached UDID of the currently-open device. Used to short-circuit
    /// redundant `open` round-trips that would otherwise re-pair the
    /// device on every thumbnail / range request and risk triggering
    /// the iOS Trust dialog mid-session.
    opened_udid: Mutex<Option<String>>,
}

impl PythonSidecar {
    /// Spawn the daemon and wait for its initial `ready` event.
    pub fn spawn() -> Result<Self, String> {
        let scripts_dir = get_scripts_dir();
        let script = scripts_dir.join("ios_afc_daemon.py");
        if !script.exists() {
            return Err(format!(
                "ios_afc_daemon.py not found at {}",
                script.display()
            ));
        }

        let python = get_python_cmd();
        eprintln!(
            "[iOS AFC] Spawning {} {}",
            python,
            script.display()
        );

        // Locate ffmpeg the same way the existing image-thumbnail
        // command does and pass it as SCOUT_FFMPEG so the daemon's
        // video_thumbnail handler can find it without rediscovering.
        let ffmpeg_path = resolve_ffmpeg_path();
        if let Some(p) = ffmpeg_path.as_ref() {
            eprintln!("[iOS AFC] ffmpeg for video thumbs: {}", p.display());
        } else {
            eprintln!(
                "[iOS AFC] WARNING: ffmpeg not found; video thumbnails will fail"
            );
        }

        // Unbuffered I/O on the daemon side so we get lines as they're
        // emitted. `-u` flag works for both `py.exe` and `python.exe`.
        let mut cmd = Command::new(&python);
        cmd.arg("-u")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(p) = ffmpeg_path {
            cmd.env("SCOUT_FFMPEG", p);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn python sidecar: {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "no stdin on python sidecar".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "no stdout on python sidecar".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "no stderr on python sidecar".to_string())?;

        let pending: Arc<(Mutex<VecDeque<Value>>, Condvar)> =
            Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let pending_for_reader = Arc::clone(&pending);
        let event_sink: Arc<Mutex<Option<Box<dyn Fn(Value) + Send + Sync>>>> =
            Arc::new(Mutex::new(None));
        let sink_for_reader = Arc::clone(&event_sink);

        // Stdout reader thread — classifies each line.
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let raw = match line {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("[iOS AFC] stdout read error: {e}");
                        break;
                    }
                };
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let value: Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "[iOS AFC] non-JSON line from daemon: {} ({e})",
                            trimmed
                        );
                        continue;
                    }
                };
                if is_streaming_event(&value) {
                    if let Some(sink) = sink_for_reader.lock().unwrap().as_ref()
                    {
                        sink(value);
                    }
                } else {
                    // Ack-style → shared inbox + notify all waiters.
                    let (mtx, cvar) = &*pending_for_reader;
                    mtx.lock().unwrap().push_back(value);
                    cvar.notify_all();
                }
            }
            eprintln!("[iOS AFC] stdout reader thread exiting");
            // Wake any blocked waiters so they can fail fast.
            let (_mtx, cvar) = &*pending_for_reader;
            cvar.notify_all();
        });

        // Stderr drain — just log so we can see Python tracebacks.
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().flatten() {
                eprintln!("[iOS AFC stderr] {line}");
            }
        });

        let sidecar = PythonSidecar {
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            event_sink,
            request_lock: Mutex::new(()),
            pending,
            opened_udid: Mutex::new(None),
        };

        // Wait for the daemon's initial `ready`.
        let ready = sidecar
            .wait_for("ready", Duration::from_secs(10))
            .map_err(|e| format!("waiting for daemon ready: {e}"))?;
        if event_name(&ready) != "ready" {
            return Err(format!(
                "expected 'ready' from daemon, got {}",
                ready
            ));
        }
        Ok(sidecar)
    }

    fn send_cmd(&self, cmd: Value) -> Result<(), String> {
        let line = serde_json::to_string(&cmd)
            .map_err(|e| format!("encode cmd: {e}"))?;
        let mut guard = self.stdin.lock().unwrap();
        let stdin = guard
            .as_mut()
            .ok_or_else(|| "sidecar stdin closed".to_string())?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|e| format!("write cmd: {e}"))?;
        Ok(())
    }

    fn wait_for(&self, expected: &str, timeout: Duration) -> Result<Value, String> {
        self.wait_for_with_path(expected, None, timeout)
    }

    /// Block until an event matching `(expected, expected_path)` lands
    /// in the shared inbox, or the timeout elapses.
    ///
    /// `expected_path = None` matches any event with the given name
    /// (used for events that don't carry a path: ready / opened / bye).
    /// `expected_path = Some(p)` matches only events whose top-level
    /// `path` field equals `p` (used for thumbnail_result,
    /// video_thumbnail_result, read_range_result, pulled, stat_result —
    /// any of which can have multiple concurrent in-flight requests).
    /// Events whose name matches but path differs are LEFT in the
    /// inbox for the right waiter; they are not consumed. This is the
    /// critical fix vs. the old crossbeam-channel design where a
    /// wrong-path event would be received-and-stashed by an unrelated
    /// waiter and then sit until something else nudged the system.
    fn wait_for_with_path(
        &self,
        expected: &str,
        expected_path: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let (mtx, cvar) = &*self.pending;
        let mut q = mtx.lock().unwrap();
        loop {
            // 1. Scan for our event.
            if let Some(pos) = q.iter().position(|v| {
                event_name(v) == expected && path_matches(v, expected_path)
            }) {
                return Ok(q.remove(pos).unwrap());
            }

            // 2. Scan for an `error` event addressed to us. Errors
            //    carrying a path get routed by path; errors without one
            //    are claimed by ANY waiter (legacy behaviour).
            if let Some(pos) = q.iter().position(|v| {
                if event_name(v) != "error" {
                    return false;
                }
                match (expected_path, v.get("path").and_then(|p| p.as_str())) {
                    (None, _) => true,
                    (Some(_), None) => true, // legacy/no-path errors
                    (Some(want), Some(got)) => want == got,
                }
            }) {
                let v = q.remove(pos).unwrap();
                return Err(format!(
                    "daemon error while waiting for '{expected}': {}",
                    v.get("msg").and_then(|m| m.as_str()).unwrap_or("?")
                ));
            }

            // 3. Wait until something new arrives (or timeout).
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "timed out waiting for '{expected}' event"
                ));
            }
            let remaining = deadline - now;
            let (new_q, wt) = cvar.wait_timeout(q, remaining).unwrap();
            q = new_q;
            if wt.timed_out() {
                // Re-check the queue once more in case another waiter
                // pushed something in just as we timed out.
                if let Some(pos) = q.iter().position(|v| {
                    event_name(v) == expected && path_matches(v, expected_path)
                }) {
                    return Ok(q.remove(pos).unwrap());
                }
                return Err(format!(
                    "timed out waiting for '{expected}' event"
                ));
            }
            // Wake — loop and re-scan. The notify is shared with all
            // waiters so anyone consuming an event will also wake us
            // (because notify_all is used). Spurious wakeups are
            // tolerated by the loop.
        }
    }
}

impl IosAfcBackend for PythonSidecar {
    fn open(&self, udid: Option<&str>) -> Result<String, String> {
        // Short-circuit: if we already opened this UDID, don't re-pair
        // the device. The daemon-side `open` rebuilds lockdown+AFC,
        // which on a real iPhone can trigger the iOS Trust dialog and
        // leaves any in-flight requests stuck behind the rebuild.
        {
            let cached = self.opened_udid.lock().unwrap();
            if let Some(ref open_udid) = *cached {
                if udid.is_none() || udid == Some(open_udid.as_str()) {
                    return Ok(open_udid.clone());
                }
            }
        }
        // Serialize with other ack RPCs so we don't race a thumbnail's
        // wait_for and steal its `opened` event.
        let _g = self.request_lock.lock().unwrap();
        // Double-check inside the lock — another caller may have just
        // opened the same UDID while we were waiting on the mutex.
        {
            let cached = self.opened_udid.lock().unwrap();
            if let Some(ref open_udid) = *cached {
                if udid.is_none() || udid == Some(open_udid.as_str()) {
                    return Ok(open_udid.clone());
                }
            }
        }
        let cmd = match udid {
            Some(u) => json!({"cmd": "open", "udid": u}),
            None => json!({"cmd": "open"}),
        };
        self.send_cmd(cmd)?;
        let ev = self.wait_for("opened", Duration::from_secs(30))?;
        let opened = ev
            .get("udid")
            .and_then(|u| u.as_str())
            .ok_or_else(|| "opened event missing udid".to_string())?
            .to_string();
        *self.opened_udid.lock().unwrap() = Some(opened.clone());
        Ok(opened)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<AfcEntry>, String> {
        self.send_cmd(json!({"cmd": "list", "path": path}))?;
        let ev = self.wait_for("list_result", Duration::from_secs(30))?;
        let entries = ev
            .get("entries")
            .ok_or_else(|| "list_result missing entries".to_string())?
            .clone();
        serde_json::from_value::<Vec<AfcEntry>>(entries)
            .map_err(|e| format!("decode list entries: {e}"))
    }

    fn stat(&self, path: &str) -> Result<AfcEntry, String> {
        self.send_cmd(json!({"cmd": "stat", "path": path}))?;
        let ev = self.wait_for_with_path(
            "stat_result",
            Some(path),
            Duration::from_secs(30),
        )?;
        let data = ev
            .get("data")
            .ok_or_else(|| "stat_result missing data".to_string())?
            .clone();
        // The daemon's `stat` shape carries `raw` we don't need.
        let entry = AfcEntry {
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            path: data
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or(path)
                .to_string(),
            size: data.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
            kind: data
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("other")
                .to_string(),
            mtime: data
                .get("mtime")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string()),
        };
        Ok(entry)
    }

    fn start_walk_hash(&self, req: &AfcWalkRequest) -> Result<(), String> {
        let mut cmd = json!({
            "cmd": "walk_hash",
            "roots": req.roots,
            "algos": req.algos,
            "min_bytes": req.min_bytes,
        });
        if let Some(exts) = &req.extensions {
            cmd["extensions"] = json!(exts);
        }
        self.send_cmd(cmd)
        // We deliberately do NOT wait_for `complete` here. The walk
        // can take many minutes; events flow through the sink and the
        // caller observes `complete`/`stopped` via that path.
    }

    fn stop_walk(&self) -> Result<(), String> {
        self.send_cmd(json!({"cmd": "stop_walk"}))?;
        // Daemon emits {"event":"stop_requested"} immediately. Drain it
        // with a short timeout so it doesn't pollute later wait_for calls.
        match self.wait_for("stop_requested", Duration::from_secs(2)) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // Best-effort.
        }
    }

    fn pull(&self, path: &str, dest: &str) -> Result<u64, String> {
        self.send_cmd(json!({"cmd": "pull", "path": path, "dest": dest}))?;
        let ev = self.wait_for_with_path(
            "pulled",
            Some(path),
            Duration::from_secs(60 * 10),
        )?;
        Ok(ev.get("size").and_then(|s| s.as_u64()).unwrap_or(0))
    }

    fn thumbnail(&self, path: &str, max_dim: u32) -> Result<(String, u64), String> {
        // NO request_lock here — thumbnails route their responses via
        // `pending_events` so multiple concurrent thumbnail RPCs (one
        // video + N images on the Flagged tab) can be in flight at
        // once. Without this, image thumbs on the Flagged tab would
        // block behind every video thumb (which can take 30+ s each
        // while the full file streams off AFC).
        eprintln!("[iOS AFC] thumbnail request: {} (max_dim={})", path, max_dim);
        self.send_cmd(json!({
            "cmd": "thumbnail",
            "path": path,
            "max_dim": max_dim,
            "quality": 70,
        }))?;
        let ev = match self.wait_for_with_path(
            "thumbnail_result",
            Some(path),
            Duration::from_secs(60),
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[iOS AFC] thumbnail FAILED for {}: {}", path, e);
                return Err(e);
            }
        };
        let data_url = ev
            .get("data_url")
            .and_then(|d| d.as_str())
            .ok_or_else(|| "thumbnail_result missing data_url".to_string())?
            .to_string();
        let src_bytes = ev
            .get("src_bytes")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        eprintln!(
            "[iOS AFC] thumbnail OK: {} ({} src bytes, {} b64 bytes)",
            path,
            src_bytes,
            data_url.len()
        );
        Ok((data_url, src_bytes))
    }

    fn set_event_sink(&self, sink: Box<dyn Fn(Value) + Send + Sync>) {
        *self.event_sink.lock().unwrap() = Some(sink);
    }

    fn clear_event_sink(&self) {
        *self.event_sink.lock().unwrap() = None;
    }

    fn video_thumbnail(
        &self,
        path: &str,
        max_dim: u32,
    ) -> Result<(String, u64), String> {
        // NO request_lock — see comment in `thumbnail` above. Concurrent
        // ack RPCs are routed via `pending_events`.
        eprintln!(
            "[iOS AFC] video_thumbnail request: {} (max_dim={})",
            path, max_dim
        );
        self.send_cmd(json!({
            "cmd": "video_thumbnail",
            "path": path,
            "max_dim": max_dim,
        }))?;
        // Video decode + AFC streaming is slower than image decode.
        // We now stream the WHOLE file to a local temp file before
        // ffmpeg runs (needed because iOS MOV moov atom is at end of
        // file and ffmpeg needs to seek). At ~5–10 MB/s over USB-2,
        // a 500 MB recording can take ~1 minute just to copy. 300 s
        // leaves headroom for the biggest realistic iPhone videos
        // plus a slow ffmpeg pass.
        let ev = match self.wait_for_with_path(
            "video_thumbnail_result",
            Some(path),
            Duration::from_secs(300),
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[iOS AFC] video_thumbnail FAILED for {}: {}", path, e);
                return Err(e);
            }
        };
        let data_url = ev
            .get("data_url")
            .and_then(|d| d.as_str())
            .ok_or_else(|| "video_thumbnail_result missing data_url".to_string())?
            .to_string();
        let src_bytes = ev
            .get("src_bytes")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        eprintln!(
            "[iOS AFC] video_thumbnail OK: {} ({} src bytes, {} b64 bytes)",
            path,
            src_bytes,
            data_url.len()
        );
        Ok((data_url, src_bytes))
    }

    fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, String> {
        let _g = self.request_lock.lock().unwrap();
        self.send_cmd(json!({
            "cmd": "read_range",
            "path": path,
            "offset": offset,
            "length": length,
        }))?;
        // 60s per range is generous; even slow USB cables push
        // ~10 MB/s, and we cap a single range at a few MB.
        let ev = self.wait_for_with_path(
            "read_range_result",
            Some(path),
            Duration::from_secs(60),
        )?;
        let b64 = ev
            .get("data_b64")
            .and_then(|d| d.as_str())
            .ok_or_else(|| "read_range_result missing data_b64".to_string())?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("decode b64 range: {e}"))?;
        Ok(bytes)
    }

    fn shutdown(&self) -> Result<(), String> {
        // Try a clean quit first. Ignore errors — child may already be dead.
        let _ = self.send_cmd(json!({"cmd": "quit"}));
        let _ = self.wait_for("bye", Duration::from_secs(2));
        // Drop stdin so the daemon's stdin loop exits if it didn't already.
        *self.stdin.lock().unwrap() = None;
        if let Some(mut child) = self.child.lock().unwrap().take() {
            // Give it a moment, then kill.
            for _ in 0..10 {
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                    Err(e) => return Err(format!("child wait: {e}")),
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}

impl Drop for PythonSidecar {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn event_name(v: &Value) -> &str {
    v.get("event").and_then(|e| e.as_str()).unwrap_or("")
}

/// Path correlation for ack events that carry a `"path"` field.
/// If `expected` is `None`, any event matches (legacy behavior).
/// If `expected` is `Some` but the event has no `path` field, we
/// accept it — fallback for daemon emits that might omit `path`
/// (defensive, shouldn't happen for thumbnail/range/pull).
fn path_matches(v: &Value, expected: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(want) => match v.get("path").and_then(|p| p.as_str()) {
            None => true, // be lenient
            Some(got) => got == want,
        },
    }
}

fn is_streaming_event(v: &Value) -> bool {
    matches!(
        event_name(v),
        "file_hash"
            | "progress"
            | "walk_warn"
            | "complete"
            | "stopped"
            | "phase_started"
            | "phase_complete"
            | "afc_reconnect"
            | "afc_reconnected"
    )
}

/// Locate `scripts/` relative to the executable.
/// (Mirror of the resolver used by `scanner::ios_python`.)
fn get_scripts_dir() -> PathBuf {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let candidates = [
        exe_dir.join("..").join("..").join("..").join("scripts"),
        exe_dir.join("..").join("..").join("scripts"),
        exe_dir.join("scripts"),
        PathBuf::from("scripts"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.canonicalize().unwrap_or_else(|_| c.clone());
        }
    }
    exe_dir.join("scripts")
}

/// Locate the ffmpeg binary so the daemon can use it for video
/// thumbnails. Mirrors the search performed by
/// `thumbnail_generator::generate_video_thumbnail`.
fn resolve_ffmpeg_path() -> Option<PathBuf> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let mut candidates: Vec<PathBuf> = Vec::new();

    if cfg!(target_os = "windows") {
        candidates.push(PathBuf::from("ffmpeg.exe"));
        candidates.push(PathBuf::from("C:\\ProgramData\\chocolatey\\bin\\ffmpeg.exe"));
        candidates.push(PathBuf::from("C:\\ffmpeg\\bin\\ffmpeg.exe"));
        if let Some(ref dir) = exe_dir {
            candidates.push(dir.join("external/ffmpeg.exe"));
            candidates.push(dir.join("external/ffmpeg/ffmpeg.exe"));
            candidates.push(dir.join("external/ffmpeg/bin/ffmpeg.exe"));
            if let Some(project_root) = dir
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
            {
                candidates.push(project_root.join("external/ffmpeg/ffmpeg.exe"));
                candidates.push(project_root.join("external/ffmpeg/bin/ffmpeg.exe"));
                // Dev tree layout: src-tauri/external/ffmpeg/ffmpeg-X.Y.Z-essentials_build/bin/ffmpeg.exe.
                // Glob the versioned directory at runtime rather than hard-coding 8.0.1.
                // Search BOTH project_root/external/ffmpeg AND
                // project_root/src-tauri/external/ffmpeg — the latter
                // is the real dev-tree location.
                for base in [
                    project_root.join("external/ffmpeg"),
                    project_root.join("src-tauri/external/ffmpeg"),
                ] {
                    // Also try the un-nested ffmpeg.exe right under src-tauri/external/ffmpeg.
                    let direct = base.join("ffmpeg.exe");
                    if direct.exists() {
                        candidates.push(direct);
                    }
                    let direct_bin = base.join("bin/ffmpeg.exe");
                    if direct_bin.exists() {
                        candidates.push(direct_bin);
                    }
                    if let Ok(rd) = std::fs::read_dir(&base) {
                        for entry in rd.flatten() {
                            let p = entry.path();
                            if p.is_dir() {
                                let candidate = p.join("bin/ffmpeg.exe");
                                if candidate.exists() {
                                    candidates.push(candidate);
                                }
                            }
                        }
                    }
                }
                candidates.push(project_root.join(
                    "dist-demo/external/ffmpeg/ffmpeg-8.0.1-essentials_build/bin/ffmpeg.exe",
                ));
                // Also check the sibling repo root (dist-demo lives one level above src-tauri).
                if let Some(repo_root) = project_root.parent() {
                    candidates.push(repo_root.join(
                        "dist-demo/external/ffmpeg/ffmpeg-8.0.1-essentials_build/bin/ffmpeg.exe",
                    ));
                }
            }
        }
    } else {
        candidates.push(PathBuf::from("ffmpeg"));
        candidates.push(PathBuf::from("/usr/local/bin/ffmpeg"));
        candidates.push(PathBuf::from("/usr/bin/ffmpeg"));
        candidates.push(PathBuf::from("/opt/homebrew/bin/ffmpeg"));
    }

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
        // Bare names like "ffmpeg.exe" should be left as-is so the OS
        // PATH resolves them at exec time.
        if c.components().count() == 1 {
            // Probe PATH by trying to run `ffmpeg -version`.
            if Command::new(c)
                .arg("-version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Find a working Python executable.
fn get_python_cmd() -> String {
    let candidates = if cfg!(target_os = "windows") {
        vec!["py", "python3", "python"]
    } else {
        vec!["python3", "python", "py"]
    };
    for c in candidates {
        if Command::new(c)
            .arg("-c")
            .arg("print('OK')")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout).trim() == "OK"
            })
            .unwrap_or(false)
        {
            return c.to_string();
        }
    }
    "py".to_string()
}

// ---------------------------------------------------------------------------
// Process-wide singleton
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static SIDECAR: OnceLock<Mutex<Option<Arc<dyn IosAfcBackend>>>> =
    OnceLock::new();

fn sidecar_slot() -> &'static Mutex<Option<Arc<dyn IosAfcBackend>>> {
    SIDECAR.get_or_init(|| Mutex::new(None))
}

/// Get or spawn the singleton backend. Subsequent calls reuse the
/// same long-lived process.
pub fn get_or_spawn_backend() -> Result<Arc<dyn IosAfcBackend>, String> {
    let mut slot = sidecar_slot().lock().unwrap();
    if let Some(b) = slot.as_ref() {
        return Ok(Arc::clone(b));
    }
    let new = Arc::new(PythonSidecar::spawn()?) as Arc<dyn IosAfcBackend>;
    *slot = Some(Arc::clone(&new));
    Ok(new)
}

/// Tear the singleton down (e.g. on disconnect or app shutdown).
pub fn shutdown_backend() {
    if let Some(b) = sidecar_slot().lock().unwrap().take() {
        let _ = b.shutdown();
    }
}
