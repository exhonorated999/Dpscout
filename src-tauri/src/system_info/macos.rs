//! macOS host identification for the portable Mac scan (Device Info tab).
//!
//! Same `SystemInfo` shape as Windows.  Sources are read-only, unprivileged
//! commands — `scutil`, `sw_vers`, `ioreg`, `df`, `diskutil info`, `ifconfig`,
//! `dscl .` — plus the shared email/BitLocker collectors (which report
//! nothing applicable on a Mac).  No network: the portable Mac build stays
//! offline, so `public_ip` is always `None`.
//!
//! Parsers are pure and platform-neutral so they are tested on Windows; only
//! [`collect`] runs commands.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use super::{DriveInfo, UserAccount};

/// `sw_vers` → `macOS 14.5 (Build 23F79)`.
pub fn parse_sw_vers(text: &str) -> String {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.split_once(':').filter(|(a, _)| a.trim() == k).map(|(_, b)| b.trim().to_string()))
            .unwrap_or_default()
    };
    let name = get("ProductName");
    let name = if name.is_empty() || name == "Mac OS X" { "macOS".to_string() } else { name };
    let version = get("ProductVersion");
    let build = get("BuildVersion");
    match (version.is_empty(), build.is_empty()) {
        (true, _) => name,
        (false, true) => format!("{} {}", name, version),
        (false, false) => format!("{} {} (Build {})", name, version, build),
    }
}

/// `ioreg -rd1 -c IOPlatformExpertDevice` → (serial number, hardware UUID).
pub fn parse_ioreg_platform(text: &str) -> (Option<String>, Option<String>) {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim().trim_matches('"') == key).then(|| v.trim().trim_matches('"').to_string())
        })
    };
    (
        get("IOPlatformSerialNumber").filter(|s| !s.is_empty()),
        get("IOPlatformUUID").filter(|s| !s.is_empty()),
    )
}

/// `df -kP` → mount points of real volumes (`/` and `/Volumes/*`), with
/// (total, free) bytes as a fallback when `diskutil` has no answer.
pub fn parse_df(text: &str) -> Vec<(String, u64, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() < 6 || !t[0].starts_with("/dev/") {
                return None;
            }
            let mount = t[5..].join(" ");
            if mount != "/" && !mount.starts_with("/Volumes/") {
                return None;
            }
            let kb = |s: &str| s.parse::<u64>().unwrap_or(0) * 1024;
            Some((mount, kb(t[1]), kb(t[3])))
        })
        .collect()
}

/// `diskutil info -plist <mount>` → a `DriveInfo` for `mount`.
pub fn parse_diskutil_info(xml: &[u8], mount: &str, df_total: u64, df_free: u64) -> DriveInfo {
    let v = plist::Value::from_reader_xml(xml).ok();
    let d = v.as_ref().and_then(|v| v.as_dictionary());
    let s = |k: &str| {
        d.and_then(|d| d.get(k))
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string()
    };
    let n = |k: &str| {
        d.and_then(|d| d.get(k)).and_then(|v| match v {
            plist::Value::Integer(i) => i.as_unsigned(),
            _ => None,
        })
    };
    let label = match s("VolumeName") {
        x if x.is_empty() => mount.rsplit('/').find(|p| !p.is_empty()).unwrap_or("/").to_string(),
        x => x,
    };
    let filesystem = match (s("FilesystemName"), s("FilesystemType")) {
        (a, _) if !a.is_empty() => a,
        (_, b) => b,
    };
    DriveInfo {
        letter: mount.to_string(),
        label,
        serial_number: s("VolumeUUID"),
        filesystem,
        total_space: n("TotalSize").unwrap_or(df_total),
        free_space: n("APFSContainerFree").or_else(|| n("FreeSpace")).unwrap_or(df_free),
    }
}

/// `ifconfig` → (MAC addresses, non-loopback IPv4 addresses), deduplicated.
pub fn parse_ifconfig(text: &str) -> (Vec<String>, Vec<String>) {
    let mut macs: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    for l in text.lines().map(str::trim) {
        let mut it = l.split_whitespace();
        match (it.next(), it.next()) {
            (Some("ether"), Some(m)) => {
                let m = m.to_uppercase();
                if m != "00:00:00:00:00:00" && !macs.contains(&m) {
                    macs.push(m);
                }
            }
            (Some("inet"), Some(ip)) => {
                if !ip.starts_with("127.") && !ip.starts_with("169.254.") && !ips.iter().any(|x| x == ip) {
                    ips.push(ip.to_string());
                }
            }
            _ => {}
        }
    }
    (macs, ips)
}

/// `dscl . -list /Users UniqueID` → real (UID ≥ 500, non-`_`) accounts.
pub fn parse_dscl_uids(text: &str) -> Vec<(String, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let uid: u32 = it.next()?.parse().ok()?;
            (uid >= 500 && !name.starts_with('_')).then(|| (name.to_string(), uid))
        })
        .collect()
}

/// `dscl . -read <path> <Attr>` → value; handles the single-line
/// (`Attr: value`) and the wrapped (`Attr:\n value`) forms.
pub fn parse_dscl_attr(text: &str, attr: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if let Some(rest) = l.strip_prefix(attr).and_then(|r| r.strip_prefix(':')) {
            let v = rest.trim();
            let v = if v.is_empty() { lines.next().unwrap_or("").trim() } else { v };
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

pub fn build_accounts(
    uids: &[(String, u32)],
    admins: &[String],
    real_name: impl Fn(&str) -> Option<String>,
    home: impl Fn(&str) -> Option<String>,
) -> Vec<UserAccount> {
    uids.iter()
        .map(|(name, _)| UserAccount {
            username: name.clone(),
            full_name: real_name(name),
            profile_path: home(name).unwrap_or_else(|| format!("/Users/{}", name)),
            last_login: None,
            account_type: if admins.iter().any(|a| a == name) { "Admin" } else { "Standard" }.to_string(),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "macos")]
pub fn mounted_volumes() -> Vec<DriveInfo> {
    run("/bin/df", &["-kP"])
        .map(|t| parse_df(&t))
        .unwrap_or_default()
        .into_iter()
        .map(|(mount, total, free)| {
            let xml = std::process::Command::new("/usr/sbin/diskutil")
                .args(["info", "-plist", &mount])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default();
            parse_diskutil_info(&xml, &mount, total, free)
        })
        .collect()
}

#[cfg(target_os = "macos")]
pub fn collect() -> Result<super::SystemInfo, String> {
    use super::{HardwareInfo, NetworkInfo, SystemInfo};

    let scutil = |k: &str| run("/usr/sbin/scutil", &["--get", k]).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let computer_name = scutil("ComputerName")
        .or_else(|| run("/bin/hostname", &[]).map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "Unknown Mac".to_string());
    let hostname = scutil("LocalHostName").unwrap_or_else(|| computer_name.clone());
    let os_version = run("/usr/bin/sw_vers", &[]).map(|t| parse_sw_vers(&t)).unwrap_or_else(|| "macOS".to_string());

    let (serial, uuid) = run("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])
        .map(|t| parse_ioreg_platform(&t))
        .unwrap_or((None, None));
    let drives = mounted_volumes();

    let uids = run("/usr/bin/dscl", &[".", "-list", "/Users", "UniqueID"])
        .map(|t| parse_dscl_uids(&t))
        .unwrap_or_default();
    let admins: Vec<String> = run("/usr/bin/dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])
        .and_then(|t| parse_dscl_attr(&t, "GroupMembership"))
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let read_attr = |user: &str, attr: &str| {
        run("/usr/bin/dscl", &[".", "-read", &format!("/Users/{}", user), attr]).and_then(|t| parse_dscl_attr(&t, attr))
    };
    let user_accounts = build_accounts(&uids, &admins, |u| read_attr(u, "RealName"), |u| read_attr(u, "NFSHomeDirectory"));

    let (mac_addresses, ip_addresses) = run("/sbin/ifconfig", &[]).map(|t| parse_ifconfig(&t)).unwrap_or_default();

    let bitlocker = super::bitlocker::collect(super::bitlocker::SweepScope::Targeted);

    Ok(SystemInfo {
        scan_id: uuid::Uuid::new_v4().to_string(),
        scan_timestamp: chrono::Utc::now().to_rfc3339(),
        scan_duration_secs: None,
        computer_name,
        os_version,
        registered_owner: None,
        registered_organization: None,
        product_id: None,
        domain: None,
        user_accounts,
        emails: super::discover_emails().unwrap_or_default(),
        hardware: HardwareInfo {
            drives,
            motherboard_serial: None,
            bios_serial: serial,
            system_uuid: uuid,
        },
        network: NetworkInfo {
            mac_addresses,
            hostname,
            ip_addresses,
            public_ip: None,
        },
        usb_history: Vec::new(),
        bitlocker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sw_vers_formats() {
        let t = "ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n";
        assert_eq!(parse_sw_vers(t), "macOS 14.5 (Build 23F79)");
        assert_eq!(parse_sw_vers("ProductName: Mac OS X\nProductVersion: 10.15.7\n"), "macOS 10.15.7");
        assert_eq!(parse_sw_vers(""), "macOS");
    }

    #[test]
    fn ioreg_platform_fields() {
        let t = r#"+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000243>
    {
      "IOPlatformUUID" = "1A2B3C4D-0000-1111-2222-333344445555"
      "IOPlatformSerialNumber" = "C02XK1ABCDEF"
      "model" = <"MacBookPro18,3">
    }"#;
        assert_eq!(
            parse_ioreg_platform(t),
            (Some("C02XK1ABCDEF".to_string()), Some("1A2B3C4D-0000-1111-2222-333344445555".to_string()))
        );
        assert_eq!(parse_ioreg_platform(""), (None, None));
    }

    #[test]
    fn df_keeps_root_and_volumes_only() {
        let t = "Filesystem     1024-blocks      Used Available Capacity  Mounted on\n\
/dev/disk3s1s1   482797652  10541344 199093552     6%    /\n\
devfs                  204       204         0   100%    /dev\n\
/dev/disk3s6     482797652   2097172 199093552     2%    /System/Volumes/VM\n\
/dev/disk3s5     482797652 268907120 199093552    58%    /System/Volumes/Data\n\
map auto_home            0         0         0   100%    /System/Volumes/Data/home\n\
/dev/disk4s1      62513152   1048576  61464576     2%    /Volumes/SCOUT USB\n";
        assert_eq!(
            parse_df(t),
            vec![
                ("/".to_string(), 482797652 * 1024, 199093552 * 1024),
                ("/Volumes/SCOUT USB".to_string(), 62513152 * 1024, 61464576 * 1024),
            ]
        );
    }

    #[test]
    fn diskutil_plist_maps_to_drive_info() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>VolumeName</key><string>Macintosh HD</string>
<key>FilesystemName</key><string>APFS</string>
<key>VolumeUUID</key><string>ABCD-1234</string>
<key>TotalSize</key><integer>494384795648</integer>
<key>APFSContainerFree</key><integer>203871797248</integer>
<key>FreeSpace</key><integer>1</integer>
</dict></plist>"#;
        let d = parse_diskutil_info(xml, "/", 7, 8);
        assert_eq!(d.letter, "/");
        assert_eq!(d.label, "Macintosh HD");
        assert_eq!(d.filesystem, "APFS");
        assert_eq!(d.serial_number, "ABCD-1234");
        assert_eq!(d.total_space, 494384795648);
        assert_eq!(d.free_space, 203871797248);

        let fallback = parse_diskutil_info(b"garbage", "/Volumes/SCOUT USB", 7, 8);
        assert_eq!(fallback.label, "SCOUT USB");
        assert_eq!((fallback.total_space, fallback.free_space), (7, 8));
    }

    #[test]
    fn ifconfig_macs_and_ips() {
        let t = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
\tinet 127.0.0.1 netmask 0xff000000\n\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
\tether a4:83:e7:12:34:56\n\
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255\n\
en1: flags=8863<UP> mtu 1500\n\
\tether 00:00:00:00:00:00\n\
\tinet 169.254.10.2 netmask 0xffff0000\n\
bridge0: flags=8863<UP> mtu 1500\n\
\tether a4:83:e7:12:34:56\n";
        assert_eq!(
            parse_ifconfig(t),
            (vec!["A4:83:E7:12:34:56".to_string()], vec!["192.168.1.23".to_string()])
        );
    }

    #[test]
    fn dscl_accounts() {
        let uids = parse_dscl_uids("_mbsetupuser 248\nalice 501\nbob 502\nnobody -2\n_hidden 600\ndaemon 1\n");
        assert_eq!(uids, vec![("alice".to_string(), 501), ("bob".to_string(), 502)]);
        assert_eq!(parse_dscl_attr("RealName:\n Alice Smith\n", "RealName"), Some("Alice Smith".to_string()));
        assert_eq!(parse_dscl_attr("RealName: bob\n", "RealName"), Some("bob".to_string()));
        assert_eq!(
            parse_dscl_attr("GroupMembership: root alice\n", "GroupMembership"),
            Some("root alice".to_string())
        );
        assert_eq!(parse_dscl_attr("No such key: RealName\n", "RealName"), None);

        let admins = vec!["root".to_string(), "alice".to_string()];
        let acc = build_accounts(
            &uids,
            &admins,
            |u| (u == "alice").then(|| "Alice Smith".to_string()),
            |_| None,
        );
        assert_eq!(acc[0].account_type, "Admin");
        assert_eq!(acc[0].full_name.as_deref(), Some("Alice Smith"));
        assert_eq!(acc[1].account_type, "Standard");
        assert_eq!(acc[1].profile_path, "/Users/bob");
    }
}
