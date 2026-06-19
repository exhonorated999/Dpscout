use super::{AppCategory, QuestionableApp};
use super::simple_categorizer::CategoryMappings;
use std::collections::HashMap;
use winreg::enums::*;
use winreg::RegKey;
use std::process::Command;

/// Get artifact paths for a given application name
fn get_artifact_paths(app_name: &str) -> Vec<String> {
    let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    
    match app_name {
        // I. Global Dominant Messengers (1-10)
        "WhatsApp Desktop" => vec![
            format!("{}\\WhatsApp", localappdata),
            format!("{}\\WhatsApp", appdata),
            format!("{}\\WhatsApp\\Cache", appdata),
        ],
        "Telegram Desktop" => vec![
            format!("{}\\Telegram Desktop\\tdata", appdata),
        ],
        "Discord" => vec![
            format!("{}\\Discord\\Local Storage\\leveldb", appdata),
            format!("{}\\Discord\\Cache", appdata),
        ],
        "Signal Desktop" => vec![
            format!("{}\\Signal\\sql\\db.sqlite", appdata),
        ],
        "Skype" => vec![
            format!("{}\\Microsoft\\Skype for Desktop\\db", appdata),
            format!("{}\\Packages\\Microsoft.SkypeApp_*\\LocalState", localappdata),
        ],
        "Viber" => vec![
            format!("{}\\ViberPC\\*\\viber.db", appdata),
        ],
        "Facebook Messenger" => vec![
            format!("{}\\Packages\\Facebook.Facebook._*\\LocalState", localappdata),
        ],
        "LINE" => vec![
            format!("{}\\LINE\\Data", localappdata),
        ],
        "WeChat" => vec![
            format!("{}\\Documents\\WeChat Files\\*", userprofile),
        ],
        "KakaoTalk" => vec![
            format!("{}\\Kakao\\KakaoTalk", localappdata),
        ],
        
        // II. Enterprise/Collaboration Tools (11-20)
        "Microsoft Teams" => vec![
            format!("{}\\Microsoft\\Teams\\Cache", appdata),
            format!("{}\\Microsoft\\Teams\\Local Storage\\IndexedDB", appdata),
        ],
        "Slack" => vec![
            format!("{}\\Slack\\Cache", appdata),
            format!("{}\\Slack\\Local Storage", appdata),
        ],
        "Zoom" => vec![
            format!("{}\\Zoom\\data", appdata),
        ],
        "Cisco Webex" => vec![
            format!("{}\\CiscoSpark\\CiscoSpark\\Local Storage", localappdata),
        ],
        "Rocket.Chat" => vec![
            format!("{}\\Rocket.Chat", appdata),
        ],
        "Mattermost" => vec![
            format!("{}\\Mattermost", appdata),
        ],
        "Google Chat" => vec![
            format!("{}\\Google\\Chrome\\User Data\\Default\\Local Storage", localappdata),
        ],
        "Cisco Jabber" => vec![
            format!("{}\\Cisco\\Unified Communications\\Jabber\\CSF\\History", appdata),
        ],
        "Citrix Workspace" => vec![
            format!("{}\\Citrix", localappdata),
        ],
        "ICQ New" => vec![
            format!("{}\\ICQ", appdata),
        ],
        
        // III. Niche, Security, & Regional Clients (21-35)
        "Threema" => vec![
            format!("{}\\Threema\\data", appdata),
        ],
        "Wire" => vec![
            format!("{}\\Wire", appdata),
        ],
        "Wickr Me" => vec![
            format!("{}\\Wickr_Me", appdata),
        ],
        "Keybase" => vec![
            format!("{}\\Keybase", appdata),
        ],
        "AOL Instant Messenger" => vec![
            format!("{}\\AIM\\logs", appdata),
        ],
        "Trillian" => vec![
            format!("{}\\Trillian\\users\\*\\database.dat", appdata),
        ],
        "Pidgin" => vec![
            format!("{}\\.\\.purple\\logs", appdata),
        ],
        "Gadu-Gadu" => vec![
            format!("{}\\Gadu-Gadu\\gg*", appdata),
        ],
        "VK Messenger" => vec![
            format!("{}\\vk-messenger", appdata),
        ],
        "Zalo" => vec![
            format!("{}\\ZaloPC\\*", appdata),
        ],
        "BBM" => vec![
            format!("{}\\BBM", appdata),
        ],
        "YY" => vec![
            format!("{}\\Documents\\YY", userprofile),
        ],
        "QQ" => vec![
            format!("{}\\Documents\\Tencent Files\\*", userprofile),
        ],
        
        // Default: no artifact paths
        _ => vec![],
    }
}

/// OLD: This database is no longer used - we now scan ALL apps and categorize them
/// Kept for reference only
#[allow(dead_code)]
fn get_questionable_apps_database_DEPRECATED() -> HashMap<&'static str, (AppCategory, Vec<&'static str>)> {
    let mut db = HashMap::new();

    // ===== CATEGORY 1: SOCIAL MEDIA & MESSAGING (TOP 50) =====
    // I. Global Dominant Messengers (1-10)
    db.insert("WhatsApp Desktop", (AppCategory::SocialMedia, vec!["whatsapp"]));
    db.insert("Telegram Desktop", (AppCategory::SocialMedia, vec!["telegram"]));
    db.insert("Discord", (AppCategory::SocialMedia, vec!["discord"]));
    db.insert("Signal Desktop", (AppCategory::SocialMedia, vec!["signal"]));
    db.insert("Skype", (AppCategory::SocialMedia, vec!["skype"]));
    db.insert("Viber", (AppCategory::SocialMedia, vec!["viber", "rakuten viber"]));
    db.insert("Facebook Messenger", (AppCategory::SocialMedia, vec!["messenger", "facebook messenger", "facebook.facebook"]));
    db.insert("LINE", (AppCategory::SocialMedia, vec!["line messenger", "line"]));
    db.insert("WeChat", (AppCategory::SocialMedia, vec!["wechat", "weixin", "tencent wechat"]));
    db.insert("KakaoTalk", (AppCategory::SocialMedia, vec!["kakaotalk", "kakao"]));
    
    // II. Enterprise/Collaboration Tools (11-20)
    db.insert("Microsoft Teams", (AppCategory::SocialMedia, vec!["microsoft teams", "teams"]));
    db.insert("Slack", (AppCategory::SocialMedia, vec!["slack"]));
    db.insert("Zoom", (AppCategory::SocialMedia, vec!["zoom"]));
    db.insert("Cisco Webex", (AppCategory::SocialMedia, vec!["webex", "cisco webex"]));
    db.insert("Rocket.Chat", (AppCategory::SocialMedia, vec!["rocket.chat", "rocketchat"]));
    db.insert("Mattermost", (AppCategory::SocialMedia, vec!["mattermost"]));
    db.insert("Google Chat", (AppCategory::SocialMedia, vec!["google chat", "hangouts"]));
    db.insert("Cisco Jabber", (AppCategory::SocialMedia, vec!["jabber", "cisco jabber"]));
    db.insert("Citrix Workspace", (AppCategory::SocialMedia, vec!["citrix workspace", "gotomeeting", "goto"]));
    db.insert("ICQ New", (AppCategory::SocialMedia, vec!["icq"]));
    
    // III. Niche, Security, & Regional Clients (21-35)
    db.insert("Threema", (AppCategory::SocialMedia, vec!["threema"]));
    db.insert("Wire", (AppCategory::SocialMedia, vec!["wire"]));
    db.insert("Wickr Me", (AppCategory::SocialMedia, vec!["wickr"]));
    db.insert("Keybase", (AppCategory::SocialMedia, vec!["keybase"]));
    db.insert("AOL Instant Messenger", (AppCategory::SocialMedia, vec!["aim", "aol instant messenger"]));
    db.insert("Trillian", (AppCategory::SocialMedia, vec!["trillian"]));
    db.insert("Pidgin", (AppCategory::SocialMedia, vec!["pidgin"]));
    db.insert("Gadu-Gadu", (AppCategory::SocialMedia, vec!["gadu-gadu", "gg"]));
    db.insert("VK Messenger", (AppCategory::SocialMedia, vec!["vk messenger", "vk-messenger", "vkontakte"]));
    db.insert("Zalo", (AppCategory::SocialMedia, vec!["zalo"]));
    db.insert("BBM", (AppCategory::SocialMedia, vec!["bbm", "blackberry messenger"]));
    db.insert("YY", (AppCategory::SocialMedia, vec!["yy voice"]));
    db.insert("Mixer", (AppCategory::SocialMedia, vec!["mixer"]));
    db.insert("GroupMe", (AppCategory::SocialMedia, vec!["groupme"]));
    db.insert("QQ", (AppCategory::SocialMedia, vec!["tencent qq", "qq"]));
    
    // IV. Additional Social Media Platforms (36-50)
    db.insert("Snapchat", (AppCategory::SocialMedia, vec!["snapchat"]));
    db.insert("Instagram", (AppCategory::SocialMedia, vec!["instagram", "metaplatforms.instagram"]));
    db.insert("Twitter/X", (AppCategory::SocialMedia, vec!["twitter", "x corp"]));
    db.insert("TikTok", (AppCategory::SocialMedia, vec!["tiktok"]));
    db.insert("Reddit", (AppCategory::SocialMedia, vec!["reddit"]));
    db.insert("Threads", (AppCategory::SocialMedia, vec!["threads"]));
    db.insert("Kik Messenger", (AppCategory::SocialMedia, vec!["kik messenger", "kik"]));
    db.insert("MeWe", (AppCategory::SocialMedia, vec!["mewe"]));
    db.insert("Jitsi Meet", (AppCategory::SocialMedia, vec!["jitsi meet", "jitsi"]));
    db.insert("Steam Chat", (AppCategory::SocialMedia, vec!["steam"]));
    db.insert("Facebook", (AppCategory::SocialMedia, vec!["facebook"]));
    db.insert("Google Voice", (AppCategory::SocialMedia, vec!["google voice"]));
    db.insert("Google Meet", (AppCategory::SocialMedia, vec!["google meet"]));
    db.insert("Element", (AppCategory::SocialMedia, vec!["element", "riot.im"]));
    db.insert("Session", (AppCategory::SocialMedia, vec!["session messenger", "session"]));

    // ===== CATEGORY 2: PEER-TO-PEER / FILE SHARING =====
    db.insert("BitTorrent", (AppCategory::PeerToPeer, vec!["bittorrent"]));
    db.insert("uTorrent", (AppCategory::PeerToPeer, vec!["utorrent", "µtorrent"]));
    db.insert("qBittorrent", (AppCategory::PeerToPeer, vec!["qbittorrent"]));
    db.insert("Transmission", (AppCategory::PeerToPeer, vec!["transmission"]));
    db.insert("Deluge", (AppCategory::PeerToPeer, vec!["deluge"]));
    db.insert("Vuze", (AppCategory::PeerToPeer, vec!["vuze", "azureus"]));
    db.insert("libtorrent", (AppCategory::PeerToPeer, vec!["libtorrent"]));
    db.insert("eMule", (AppCategory::PeerToPeer, vec!["emule"]));
    db.insert("eDonkey", (AppCategory::PeerToPeer, vec!["edonkey"]));
    db.insert("Ares Galaxy", (AppCategory::PeerToPeer, vec!["ares galaxy", "ares"]));
    db.insert("FrostWire", (AppCategory::PeerToPeer, vec!["frostwire"]));
    db.insert("LimeWire", (AppCategory::PeerToPeer, vec!["limewire"]));
    db.insert("Shareaza", (AppCategory::PeerToPeer, vec!["shareaza"]));
    db.insert("BearShare", (AppCategory::PeerToPeer, vec!["bearshare"]));
    db.insert("Gnutella", (AppCategory::PeerToPeer, vec!["gnutella"]));
    db.insert("Gnutella2", (AppCategory::PeerToPeer, vec!["gnutella2", "g2"]));
    db.insert("Freenet", (AppCategory::PeerToPeer, vec!["freenet"]));
    db.insert("Tor Browser", (AppCategory::PeerToPeer, vec!["tor browser", "tor"]));
    db.insert("I2P", (AppCategory::PeerToPeer, vec!["i2p"]));
    db.insert("Tribler", (AppCategory::PeerToPeer, vec!["tribler"]));
    db.insert("DC++", (AppCategory::PeerToPeer, vec!["dc++", "dcplusplus"]));
    db.insert("Soulseek", (AppCategory::PeerToPeer, vec!["soulseek"]));
    db.insert("BitComet", (AppCategory::PeerToPeer, vec!["bitcomet"]));
    db.insert("Tixati", (AppCategory::PeerToPeer, vec!["tixati"]));
    db.insert("MLDonkey", (AppCategory::PeerToPeer, vec!["mldonkey"]));
    db.insert("eDonkey2000", (AppCategory::PeerToPeer, vec!["edonkey2000", "metamachine"]));
    db.insert("KTorrent", (AppCategory::PeerToPeer, vec!["ktorrent"]));
    db.insert("rTorrent", (AppCategory::PeerToPeer, vec!["rtorrent"]));
    db.insert("Halite", (AppCategory::PeerToPeer, vec!["halite"]));
    db.insert("BiglyBT", (AppCategory::PeerToPeer, vec!["biglybt"]));
    db.insert("WebTorrent", (AppCategory::PeerToPeer, vec!["webtorrent"]));
    db.insert("PicoTorrent", (AppCategory::PeerToPeer, vec!["picotorrent"]));
    db.insert("BitTornado", (AppCategory::PeerToPeer, vec!["bittornado"]));
    db.insert("BitLord", (AppCategory::PeerToPeer, vec!["bitlord"]));
    db.insert("BitSpirit", (AppCategory::PeerToPeer, vec!["bitspirit"]));
    db.insert("Acquisition", (AppCategory::PeerToPeer, vec!["acquisition"]));
    db.insert("Cabos", (AppCategory::PeerToPeer, vec!["cabos"]));
    db.insert("Phex", (AppCategory::PeerToPeer, vec!["phex"]));
    db.insert("gtk-gnutella", (AppCategory::PeerToPeer, vec!["gtk-gnutella"]));
    db.insert("Morpheus", (AppCategory::PeerToPeer, vec!["morpheus"]));
    db.insert("iMesh", (AppCategory::PeerToPeer, vec!["imesh"]));
    db.insert("Kazaa", (AppCategory::PeerToPeer, vec!["kazaa"]));
    db.insert("WinMX", (AppCategory::PeerToPeer, vec!["winmx"]));
    db.insert("Napster", (AppCategory::PeerToPeer, vec!["napster"]));
    db.insert("Perfect Dark", (AppCategory::PeerToPeer, vec!["perfect dark"]));
    db.insert("Share", (AppCategory::PeerToPeer, vec!["share p2p"]));
    db.insert("Winny", (AppCategory::PeerToPeer, vec!["winny"]));
    db.insert("StealthNet", (AppCategory::PeerToPeer, vec!["stealthnet"]));
    db.insert("RetroShare", (AppCategory::PeerToPeer, vec!["retroshare"]));
    db.insert("GNUnet", (AppCategory::PeerToPeer, vec!["gnunet"]));
    db.insert("Invisible IRC Project", (AppCategory::PeerToPeer, vec!["iip"]));
    db.insert("Lokinet", (AppCategory::PeerToPeer, vec!["lokinet"]));
    db.insert("ZeroNet", (AppCategory::PeerToPeer, vec!["zeronet"]));
    db.insert("IPFS Desktop", (AppCategory::PeerToPeer, vec!["ipfs"]));
    db.insert("Resilio Sync", (AppCategory::PeerToPeer, vec!["resilio", "bittorrent sync"]));
    db.insert("Syncthing", (AppCategory::PeerToPeer, vec!["syncthing"]));

    // ===== CATEGORY 3: VPN APPLICATIONS =====
    db.insert("NordVPN", (AppCategory::VPN, vec!["nordvpn", "nord vpn"]));
    db.insert("ExpressVPN", (AppCategory::VPN, vec!["expressvpn", "express vpn"]));
    db.insert("ProtonVPN", (AppCategory::VPN, vec!["protonvpn", "proton vpn"]));
    db.insert("CyberGhost", (AppCategory::VPN, vec!["cyberghost"]));
    db.insert("Surfshark", (AppCategory::VPN, vec!["surfshark"]));
    db.insert("Private Internet Access", (AppCategory::VPN, vec!["private internet access", "pia vpn", "pia"]));
    db.insert("TunnelBear", (AppCategory::VPN, vec!["tunnelbear"]));
    db.insert("IPVanish", (AppCategory::VPN, vec!["ipvanish"]));
    db.insert("Windscribe", (AppCategory::VPN, vec!["windscribe"]));
    db.insert("OpenVPN", (AppCategory::VPN, vec!["openvpn"]));
    db.insert("WireGuard", (AppCategory::VPN, vec!["wireguard"]));
    db.insert("Mullvad", (AppCategory::VPN, vec!["mullvad"]));
    db.insert("IVPN", (AppCategory::VPN, vec!["ivpn"]));
    db.insert("Hide.me", (AppCategory::VPN, vec!["hide.me", "hideme"]));
    db.insert("VyprVPN", (AppCategory::VPN, vec!["vyprvpn"]));
    db.insert("HotSpot Shield", (AppCategory::VPN, vec!["hotspot shield", "hotspotshield"]));
    db.insert("TorGuard", (AppCategory::VPN, vec!["torguard"]));
    db.insert("PureVPN", (AppCategory::VPN, vec!["purevpn"]));
    db.insert("ZenMate", (AppCategory::VPN, vec!["zenmate"]));
    db.insert("Hola VPN", (AppCategory::VPN, vec!["hola vpn", "hola"]));
    db.insert("ProXPN", (AppCategory::VPN, vec!["proxpn"]));
    db.insert("StrongVPN", (AppCategory::VPN, vec!["strongvpn"]));
    db.insert("VPN Unlimited", (AppCategory::VPN, vec!["vpn unlimited", "keepsolid"]));
    db.insert("Cisco AnyConnect", (AppCategory::VPN, vec!["cisco anyconnect", "anyconnect"]));
    db.insert("Fortinet VPN", (AppCategory::VPN, vec!["forticlient", "fortinet"]));
    db.insert("SoftEther VPN", (AppCategory::VPN, vec!["softether"]));
    db.insert("Psiphon", (AppCategory::VPN, vec!["psiphon"]));
    db.insert("Betternet", (AppCategory::VPN, vec!["betternet"]));

    // ===== CATEGORY 4: VIRTUAL MACHINES =====
    db.insert("VMware Workstation", (AppCategory::VirtualMachine, vec!["vmware workstation", "vmware"]));
    db.insert("VMware Player", (AppCategory::VirtualMachine, vec!["vmware player"]));
    db.insert("VirtualBox", (AppCategory::VirtualMachine, vec!["virtualbox", "oracle vm virtualbox"]));
    db.insert("Parallels Desktop", (AppCategory::VirtualMachine, vec!["parallels desktop", "parallels"]));
    db.insert("Hyper-V", (AppCategory::VirtualMachine, vec!["hyper-v", "hyperv"]));
    db.insert("QEMU", (AppCategory::VirtualMachine, vec!["qemu"]));
    db.insert("Xen", (AppCategory::VirtualMachine, vec!["xen", "citrix hypervisor"]));
    db.insert("Proxmox", (AppCategory::VirtualMachine, vec!["proxmox"]));
    db.insert("KVM", (AppCategory::VirtualMachine, vec!["kvm", "kernel virtual machine"]));
    db.insert("Vagrant", (AppCategory::VirtualMachine, vec!["vagrant"]));
    db.insert("Docker Desktop", (AppCategory::VirtualMachine, vec!["docker desktop", "docker"]));
    db.insert("Sandboxie", (AppCategory::VirtualMachine, vec!["sandboxie"]));
    db.insert("Windows Sandbox", (AppCategory::VirtualMachine, vec!["windows sandbox"]));

    // ===== CATEGORY 5: WEB BROWSERS =====
    db.insert("Brave Browser", (AppCategory::WebBrowser, vec!["brave browser", "brave"]));
    db.insert("Tor Browser", (AppCategory::WebBrowser, vec!["tor browser"]));
    db.insert("Opera", (AppCategory::WebBrowser, vec!["opera"]));
    db.insert("Opera GX", (AppCategory::WebBrowser, vec!["opera gx"]));
    db.insert("Vivaldi", (AppCategory::WebBrowser, vec!["vivaldi"]));
    db.insert("Epic Privacy Browser", (AppCategory::WebBrowser, vec!["epic privacy browser", "epic browser"]));
    db.insert("Waterfox", (AppCategory::WebBrowser, vec!["waterfox"]));
    db.insert("Pale Moon", (AppCategory::WebBrowser, vec!["pale moon", "palemoon"]));
    db.insert("Comodo Dragon", (AppCategory::WebBrowser, vec!["comodo dragon"]));
    db.insert("Maxthon", (AppCategory::WebBrowser, vec!["maxthon"]));
    db.insert("Ungoogled Chromium", (AppCategory::WebBrowser, vec!["ungoogled chromium"]));
    db.insert("Firefox", (AppCategory::WebBrowser, vec!["firefox", "mozilla firefox"]));
    db.insert("Chrome", (AppCategory::WebBrowser, vec!["google chrome", "chrome"]));
    db.insert("Edge", (AppCategory::WebBrowser, vec!["microsoft edge", "edge"]));
    db.insert("Safari", (AppCategory::WebBrowser, vec!["safari"]));
    db.insert("Chromium", (AppCategory::WebBrowser, vec!["chromium"]));

    // ===== CATEGORY 6: CLEANERS AND SHREDDERS =====
    db.insert("CCleaner", (AppCategory::Cleaner, vec!["ccleaner"]));
    db.insert("Eraser", (AppCategory::Cleaner, vec!["eraser"]));
    db.insert("BCWipe", (AppCategory::Cleaner, vec!["bcwipe"]));
    db.insert("File Shredder", (AppCategory::Cleaner, vec!["file shredder", "fileshredder"]));
    db.insert("Secure Eraser", (AppCategory::Cleaner, vec!["secure eraser"]));
    db.insert("Permanent Eraser", (AppCategory::Cleaner, vec!["permanent eraser"]));
    db.insert("BleachBit", (AppCategory::Cleaner, vec!["bleachbit"]));
    db.insert("Hardwipe", (AppCategory::Cleaner, vec!["hardwipe"]));
    db.insert("Freeraser", (AppCategory::Cleaner, vec!["freeraser"]));
    db.insert("Privacy Eraser", (AppCategory::Cleaner, vec!["privacy eraser"]));
    db.insert("Wipe", (AppCategory::Cleaner, vec!["wipe"]));
    db.insert("East-Tec Eraser", (AppCategory::Cleaner, vec!["east-tec eraser", "easttec"]));
    db.insert("Shred", (AppCategory::Cleaner, vec!["shred"]));
    db.insert("DeleteOnClick", (AppCategory::Cleaner, vec!["deleteonclick"]));
    db.insert("Moo0 File Shredder", (AppCategory::Cleaner, vec!["moo0 file shredder", "moo0"]));
    db.insert("WipeFile", (AppCategory::Cleaner, vec!["wipefile"]));
    db.insert("Privazer", (AppCategory::Cleaner, vec!["privazer"]));
    db.insert("System Mechanic", (AppCategory::Cleaner, vec!["system mechanic"]));
    db.insert("Glary Utilities", (AppCategory::Cleaner, vec!["glary utilities", "glarysoft"]));
    db.insert("Wise Disk Cleaner", (AppCategory::Cleaner, vec!["wise disk cleaner", "wisecleaner"]));
    db.insert("CleanMyPC", (AppCategory::Cleaner, vec!["cleanmypc"]));

    // ===== DISK ENCRYPTION (Keeping existing) =====
    db.insert("VeraCrypt", (AppCategory::Encryption, vec!["veracrypt"]));
    db.insert("TrueCrypt", (AppCategory::Encryption, vec!["truecrypt"]));
    db.insert("BitLocker", (AppCategory::Encryption, vec!["bitlocker"]));
    db.insert("DiskCryptor", (AppCategory::Encryption, vec!["diskcryptor"]));
    db.insert("AxCrypt", (AppCategory::Encryption, vec!["axcrypt"]));
    db.insert("Cryptomator", (AppCategory::Encryption, vec!["cryptomator"]));
    db.insert("7-Zip", (AppCategory::Encryption, vec!["7-zip"]));
    db.insert("WinRAR", (AppCategory::Encryption, vec!["winrar"]));

    // ===== ANTI-FORENSICS =====
    db.insert("Metasploit", (AppCategory::AntiForensics, vec!["metasploit"]));
    db.insert("Timestomp", (AppCategory::AntiForensics, vec!["timestomp"]));
    db.insert("Anti-Forensics Tool", (AppCategory::AntiForensics, vec!["anti-forensics", "antiforensics"]));

    db
}

/// Scan Windows registry for ALL installed applications
pub fn scan_installed_apps() -> Result<Vec<QuestionableApp>, Box<dyn std::error::Error>> {
    let mut found_apps = Vec::new();

    // Load category mappings
    eprintln!("Loading category mappings...");
    let mappings = CategoryMappings::load()?;
    eprintln!("✓ Category mappings loaded");

    // Registry paths to check for installed applications
    let registry_paths = vec![
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];

    for (hkey, path) in registry_paths {
        if let Ok(uninstall_key) = RegKey::predef(hkey).open_subkey(path) {
            for subkey_name in uninstall_key.enum_keys().filter_map(Result::ok) {
                if let Ok(app_key) = uninstall_key.open_subkey(&subkey_name) {
                    // Get ALL applications, not just "questionable" ones
                    if let Some(app) = parse_application_from_registry(&app_key, &mappings) {
                        found_apps.push(app);
                    }
                }
            }
        }
    }

    // Scan Windows Store apps - DISABLED for stability
    // Windows Store apps are not typically used in forensic investigations
    // and the PowerShell command can cause crashes on some systems
    // eprintln!("Scanning Windows Store apps...");
    // match scan_windows_store_apps(&mappings) {
    //     Ok(mut store_apps) => {
    //         eprintln!("Found {} Windows Store apps", store_apps.len());
    //         found_apps.append(&mut store_apps);
    //     }
    //     Err(e) => eprintln!("Warning: Could not scan Store apps: {}", e),
    // }

    // Remove duplicates based on name and install path
    found_apps.sort_by(|a, b| a.name.cmp(&b.name));
    found_apps.dedup_by(|a, b| a.name == b.name && a.install_path == b.install_path);

    Ok(found_apps)
}

/// Scan Windows Store (UWP) apps using PowerShell
fn scan_windows_store_apps(mappings: &CategoryMappings) -> Result<Vec<QuestionableApp>, Box<dyn std::error::Error>> {
    let mut cmd = Command::new("powershell");
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    
    let output = cmd
        .args(&[
            "-Command",
            "Get-AppxPackage | Select-Object Name,Publisher,InstallLocation | ConvertTo-Json"
        ])
        .output()?;
    
    if !output.status.success() {
        return Ok(Vec::new());
    }
    
    let json_str = String::from_utf8_lossy(&output.stdout);
    
    // Try parsing as array first, if that fails try as single object
    let apps_array: Vec<serde_json::Value> = match serde_json::from_str(&json_str) {
        Ok(arr) => arr,
        Err(_) => {
            // Try parsing as single object
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(obj) => vec![obj],
                Err(e) => {
                    eprintln!("Failed to parse Store apps JSON: {}", e);
                    return Ok(Vec::new());
                }
            }
        }
    };
    
    let mut found_apps = Vec::new();
    
    for app in &apps_array {
        if let (Some(name), Some(publisher), Some(location)) = (
            app.get("Name").and_then(|n| n.as_str()),
            app.get("Publisher").and_then(|p| p.as_str()),
            app.get("InstallLocation").and_then(|l| l.as_str())
        ) {
            // Skip system packages
            if name.starts_with("Microsoft.Windows") || 
               name.starts_with("Microsoft.VCLibs") ||
               name.starts_with("Microsoft.UI") {
                continue;
            }
            
            // Clean up the name for display
            let display_name = name.replace(".", " ")
                                  .replace("_", " ");
            
            let (investigative_category, confidence) = mappings.categorize(
                &display_name,
                &Some(publisher.to_string()),
                location
            );
            
            let legacy_category = categorize_application(&display_name, &Some(publisher.to_string()));
            
            found_apps.push(QuestionableApp {
                name: display_name,
                category: legacy_category,
                install_path: location.to_string(),
                version: "Store App".to_string(),
                install_date: None,
                publisher: Some(publisher.to_string()),
                artifact_paths: vec![],
                investigative_category: investigative_category.clone(),
                function_category: investigative_category,
                confidence,
            });
        }
    }
    
    Ok(found_apps)
}

/// Parse an application from registry and categorize it
fn parse_application_from_registry(app_key: &RegKey, mappings: &CategoryMappings) -> Option<QuestionableApp> {
    let display_name: String = app_key.get_value("DisplayName").ok()?;
    
    // Skip system components and updates
    let display_name_lower = display_name.to_lowercase();
    if display_name_lower.contains("security update") 
        || display_name_lower.contains("hotfix")
        || display_name_lower.starts_with("kb")
        || display_name_lower.contains("update for")
        || display_name.starts_with("Microsoft Visual C++")
        || display_name.starts_with("Microsoft .NET")
        || display_name_lower == "windows"
        || display_name.len() < 3 {
        return None;
    }

    let install_location: String = app_key
        .get_value("InstallLocation")
        .unwrap_or_else(|_| String::from("Unknown"));

    let version: String = app_key
        .get_value("DisplayVersion")
        .unwrap_or_else(|_| String::from("Unknown"));

    let publisher: Option<String> = app_key.get_value("Publisher").ok();
    let install_date: Option<String> = app_key.get_value("InstallDate").ok();
    
    // Use simple categorizer - checks if keywords appear anywhere
    let (investigative_category, confidence) = mappings.categorize(
        &display_name,
        &publisher,
        &install_location
    );
    
    // Also use legacy categorization for backward compatibility with UI
    let legacy_category = categorize_application(&display_name, &publisher);
    let artifact_paths = get_artifact_paths(&display_name);

    Some(QuestionableApp {
        name: display_name,
        category: legacy_category,
        install_path: install_location,
        version,
        install_date,
        publisher,
        artifact_paths,
        investigative_category: investigative_category.clone(),
        function_category: investigative_category, // Same for now
        confidence,
    })
}



/// Categorize an application based on its name and publisher
fn categorize_application(name: &str, publisher: &Option<String>) -> AppCategory {
    let name_lower = name.to_lowercase();
    let publisher_lower = publisher.as_ref().map(|p| p.to_lowercase()).unwrap_or_default();
    
    // Debug logging for first 10 apps
    static mut DEBUG_COUNT: usize = 0;
    unsafe {
        if DEBUG_COUNT < 10 {
            eprintln!("DEBUG: Categorizing '{}' (Publisher: '{}')", name, publisher_lower);
            DEBUG_COUNT += 1;
        }
    }
    
    // DARK WEB / ANONYMITY TOOLS (Check first - highest priority)
    if name_lower.contains("tor browser") || name_lower.contains("torbrowser")
        || name_lower.contains("i2p") && !name_lower.contains("zip")
        || name_lower.contains("freenet")
        || name_lower.contains("onion")  && publisher_lower.contains("tor")
        || name_lower.contains("tails")
        || name_lower.contains("whonix")
    {
        return AppCategory::DarkWeb;
    }
    
    // ANTI-FORENSICS / CLEANERS (High priority)
    if name_lower.contains("ccleaner")
        || name_lower.contains("bleachbit")
        || name_lower.contains("eraser") && (name_lower.contains("secure") || publisher_lower.contains("heidi"))
        || name_lower.contains("file shredder")
        || name_lower.contains("wipe") && name_lower.contains("file")
        || name_lower.contains("secure delete")
        || name_lower.contains("privacy eraser")
        || name_lower.contains("east-tec")
        || name_lower.contains("cyberscrub")
        || name_lower.contains("windows washer")
    {
        return AppCategory::AntiForensics;
    }
    
    // MESSAGING APPS (Dedicated messaging)
    if name_lower.contains("whatsapp") 
        || name_lower.contains("telegram")
        || name_lower.contains("discord") 
        || name_lower.contains("signal")
        || name_lower.contains("skype")
        || name_lower.contains("viber")
        || name_lower.contains("messenger")
        || name_lower.contains("facebook")
        || name_lower.contains("line")
        || name_lower.contains("wechat") || name_lower.contains("weixin")
        || name_lower.contains("kakaotalk") || name_lower.contains("kakao")
        || name_lower.contains("slack")
        || name_lower.contains("zoom")
        || name_lower.contains("teams") || publisher_lower.contains("microsoft teams")
        || name_lower.contains("webex")
        || name_lower.contains("rocket.chat") || name_lower.contains("rocketchat")
        || name_lower.contains("mattermost")
        || name_lower.contains("google chat")
        || name_lower.contains("jabber")
        || name_lower.contains("icq")
        || name_lower.contains("threema")
        || name_lower.contains("wire")
        || name_lower.contains("wickr")
        || name_lower.contains("keybase")
        || name_lower.contains("aim") || name_lower.contains("aol instant")
        || name_lower.contains("trillian")
        || name_lower.contains("pidgin")
        || name_lower.contains("gadu-gadu")
        || name_lower.contains("vk messenger") || name_lower.contains("vkontakte")
        || name_lower.contains("zalo")
        || name_lower.contains("bbm") || name_lower.contains("blackberry messenger")
        || name_lower.contains("snapchat")
        || name_lower.contains("instagram")
        || name_lower.contains("twitter") || name_lower.contains("x corp")
        || name_lower.contains("tiktok")
        || name_lower.contains("reddit")
        || name_lower.contains("kik")
        || name_lower.contains("jitsi")
        || name_lower.contains("element")
        || name_lower.contains("session")
        || name_lower.contains("qq") && (publisher_lower.contains("tencent") || name_lower.contains("tencent"))
    {
        return AppCategory::Messaging;
    }
    
    // SOCIAL MEDIA PLATFORMS
    if name_lower.contains("snapchat")
        || name_lower.contains("instagram")
        || name_lower.contains("twitter") || name_lower.contains("x corp")
        || name_lower.contains("tiktok")
        || name_lower.contains("reddit")
        || name_lower.contains("facebook") && !name_lower.contains("messenger")
        || name_lower.contains("pinterest")
        || name_lower.contains("linkedin")
        || name_lower.contains("tumblr")
        || name_lower.contains("mastodon")
    {
        return AppCategory::SocialMedia;
    }
    
    // GAMING
    if name_lower.contains("steam")
        || name_lower.contains("epic games")
        || name_lower.contains("origin") && (publisher_lower.contains("electronic arts") || publisher_lower.contains("ea"))
        || name_lower.contains("blizzard") || name_lower.contains("battle.net")
        || name_lower.contains("gog galaxy")
        || name_lower.contains("ubisoft connect") || name_lower.contains("uplay")
        || name_lower.contains("xbox") && name_lower.contains("game")
        || name_lower.contains("playstation")
        || name_lower.contains("riot") && name_lower.contains("games")
        || name_lower.contains("minecraft")
        || name_lower.contains("roblox")
        || name_lower.contains("fortnite")
        || name_lower.contains("league of legends")
        || name_lower.contains("valorant")
        || name_lower.contains("overwatch")
        || name_lower.contains("world of warcraft")
    {
        return AppCategory::Gaming;
    }
    
    // CLOUD STORAGE
    if name_lower.contains("dropbox")
        || name_lower.contains("google drive") || name_lower.contains("googledrive")
        || name_lower.contains("onedrive") || (name_lower.contains("microsoft") && name_lower.contains("onedrive"))
        || name_lower.contains("box") && (publisher_lower.contains("box") || name_lower.contains("sync"))
        || name_lower.contains("mega") && (publisher_lower.contains("mega") || name_lower.contains("sync"))
        || name_lower.contains("tresorit")
        || name_lower.contains("sync.com") || name_lower.contains("synccom")
        || name_lower.contains("pcloud")
        || name_lower.contains("icedrive")
        || name_lower.contains("nextcloud")
        || name_lower.contains("owncloud")
        || name_lower.contains("seafile")
    {
        return AppCategory::CloudStorage;
    }
    
    // CRYPTO / PAYMENT
    if name_lower.contains("bitcoin")
        || name_lower.contains("ethereum") || name_lower.contains("eth wallet")
        || name_lower.contains("electrum")
        || name_lower.contains("exodus")
        || name_lower.contains("coinbase")
        || name_lower.contains("binance")
        || name_lower.contains("metamask")
        || name_lower.contains("ledger live")
        || name_lower.contains("trezor")
        || name_lower.contains("crypto") && name_lower.contains("wallet")
        || name_lower.contains("monero")
        || name_lower.contains("litecoin")
        || name_lower.contains("dogecoin")
    {
        return AppCategory::CryptoPayment;
    }
    
    // ENCRYPTION
    if name_lower.contains("veracrypt")
        || name_lower.contains("bitlocker")
        || name_lower.contains("7-zip") && name_lower.contains("aes")
        || name_lower.contains("axcrypt")
        || name_lower.contains("gpg") || name_lower.contains("gnupg")
        || name_lower.contains("kleopatra")
        || name_lower.contains("cryptomator")
        || name_lower.contains("boxcryptor")
        || name_lower.contains("diskcryptor")
    {
        return AppCategory::Encryption;
    }
    
    // REMOTE ACCESS
    if name_lower.contains("teamviewer")
        || name_lower.contains("anydesk")
        || name_lower.contains("remote desktop") || name_lower.contains("remotedesktop")
        || name_lower.contains("vnc") && !name_lower.contains("service")
        || name_lower.contains("logmein")
        || name_lower.contains("splashtop")
        || name_lower.contains("chrome remote desktop")
        || name_lower.contains("parsec")
        || name_lower.contains("rustdesk")
    {
        return AppCategory::RemoteAccess;
    }
    
    // DEVELOPMENT TOOLS
    if name_lower.contains("visual studio") && !name_lower.contains("redistrib")
        || name_lower.contains("vscode") || name_lower.contains("vs code")
        || name_lower.contains("intellij")
        || name_lower.contains("pycharm")
        || name_lower.contains("android studio")
        || name_lower.contains("eclipse")
        || name_lower.contains("netbeans")
        || name_lower.contains("sublime text")
        || name_lower.contains("atom editor")
        || name_lower.contains("git") && (name_lower.contains("github") || name_lower.contains("desktop"))
        || name_lower.contains("docker desktop")
        || name_lower.contains("postman")
    {
        return AppCategory::Development;
    }
    
    // PRODUCTIVITY
    if name_lower.contains("microsoft office") || name_lower.contains("ms office")
        || name_lower.contains("word") && publisher_lower.contains("microsoft")
        || name_lower.contains("excel") && publisher_lower.contains("microsoft")
        || name_lower.contains("powerpoint") && publisher_lower.contains("microsoft")
        || name_lower.contains("outlook") && publisher_lower.contains("microsoft")
        || name_lower.contains("onenote") && publisher_lower.contains("microsoft")
        || name_lower.contains("libreoffice")
        || name_lower.contains("openoffice")
        || name_lower.contains("adobe acrobat") || name_lower.contains("adobe reader")
        || name_lower.contains("foxit") && name_lower.contains("reader")
        || name_lower.contains("pdf") && (name_lower.contains("reader") || name_lower.contains("viewer"))
        || name_lower.contains("notion")
        || name_lower.contains("evernote")
        || name_lower.contains("obsidian")
        || name_lower.contains("notepad++")
        || name_lower.contains("sublime text")
        || name_lower.contains("atom")
        || name_lower.contains("brackets")
    {
        return AppCategory::Productivity;
    }
    
    // MULTIMEDIA
    if name_lower.contains("vlc")
        || name_lower.contains("spotify")
        || name_lower.contains("itunes")
        || name_lower.contains("audacity")
        || name_lower.contains("obs studio") || name_lower.contains("obs-studio")
        || name_lower.contains("handbrake")
        || name_lower.contains("plex")
        || name_lower.contains("kodi")
        || name_lower.contains("gimp")
        || name_lower.contains("inkscape")
        || name_lower.contains("blender")
        || name_lower.contains("davinci resolve")
        || name_lower.contains("adobe") && (name_lower.contains("photoshop") || name_lower.contains("premiere") || name_lower.contains("after effects"))
    {
        return AppCategory::Multimedia;
    }
    
    // WEB BROWSERS
    if (name_lower.contains("chrome") && !name_lower.contains("remote"))
        || (name_lower.contains("firefox") && !name_lower.contains("tor"))
        || (name_lower.contains("edge") && !name_lower.contains("edgeupdate"))
        || name_lower.contains("opera")
        || name_lower.contains("brave")
        || name_lower.contains("vivaldi")
        || name_lower == "safari"
        || name_lower.contains("internet explorer")
        || name_lower.contains("waterfox")
        || name_lower.contains("pale moon")
    {
        return AppCategory::WebBrowser;
    }
    
    // PEER-TO-PEER / FILE SHARING
    if name_lower.contains("torrent") 
        || name_lower.contains("emule")
        || name_lower.contains("ares")
        || name_lower.contains("frostwire")
        || name_lower.contains("limewire")
        || name_lower.contains("shareaza")
        || name_lower.contains("bearshare")
        || name_lower.contains("gnutella")
        || name_lower.contains("freenet")
        || name_lower.contains("tribler")
        || name_lower.contains("dc++")
        || name_lower.contains("soulseek")
        || name_lower.contains("bitcomet")
        || name_lower.contains("tixati")
        || name_lower.contains("mldonkey")
        || name_lower.contains("edonkey")
        || name_lower.contains("ktorrent")
        || name_lower.contains("rtorrent")
        || name_lower.contains("halite")
        || name_lower.contains("biglybt")
        || name_lower.contains("webtorrent")
        || name_lower.contains("picotorrent")
        || name_lower.contains("vuze") || name_lower.contains("azureus")
        || name_lower.contains("deluge")
        || name_lower.contains("transmission")
        || name_lower.contains("i2p")
        || name_lower.contains("ipfs")
        || name_lower.contains("resilio") || name_lower.contains("bittorrent sync")
        || name_lower.contains("syncthing")
    {
        return AppCategory::PeerToPeer;
    }
    
    // VPN CLIENTS
    if name_lower.contains("vpn") 
        || name_lower.contains("nordvpn")
        || name_lower.contains("expressvpn")
        || name_lower.contains("protonvpn")
        || name_lower.contains("cyberghost")
        || name_lower.contains("surfshark")
        || name_lower.contains("tunnelbear")
        || name_lower.contains("ipvanish")
        || name_lower.contains("private internet access")
    {
        return AppCategory::VPN;
    }
    
    // VIRTUAL MACHINES
    if name_lower.contains("virtualbox")
        || name_lower.contains("vmware")
        || name_lower.contains("hyper-v")
        || name_lower.contains("parallels")
        || name_lower.contains("qemu")
    {
        return AppCategory::VirtualMachine;
    }
    
    // UTILITIES (System tools, compression, etc.)
    if name_lower.contains("7-zip") || name_lower.contains("7zip")
        || name_lower.contains("winrar") || name_lower.contains("winzip") || name_lower.contains("winace")
        || name_lower.contains("notepad++") || name_lower.contains("notepadplusplus")
        || name_lower.contains("everything") && publisher_lower.contains("voidtools")
        || name_lower.contains("process explorer") || name_lower.contains("sysinternals")
        || name_lower.contains("autoruns") && publisher_lower.contains("microsoft")
        || name_lower.contains("wireshark")
        || name_lower.contains("putty")
        || name_lower.contains("winscp")
        || name_lower.contains("filezilla")
        || name_lower.contains("cpu-z")
        || name_lower.contains("gpu-z")
        || name_lower.contains("hwinfo")
        || name_lower.contains("speccy")
        || name_lower.contains("crystaldisk")
        || name_lower.contains("rufus")
        || name_lower.contains("balenaetcher")
        || name_lower.contains("windirstat")
        || name_lower.contains("treesize")
    {
        return AppCategory::Utilities;
    }
    
    // If we got here and it still contains certain keywords, categorize as cleaner/anti-forensic
    if name_lower.contains("cleaner") || name_lower.contains("clean")
        || name_lower.contains("wipe") || name_lower.contains("shred")
        || name_lower.contains("erase") && name_lower.contains("secure")
    {
        return AppCategory::Cleaner;
    }
    
    // Catch remaining encryption tools not already categorized
    if name_lower.contains("crypt") || name_lower.contains("encrypt")
    {
        return AppCategory::Encryption;
    }
    
    // ANTI-FORENSICS TOOLS
    if name_lower.contains("metasploit")
        || name_lower.contains("timestomp")
        || name_lower.contains("anti-forensic")
    {
        return AppCategory::AntiForensics;
    }
    
    // Broad categorization for remaining apps based on publisher or common patterns
    
    // MANUFACTURER-SPECIFIC UTILITIES (Dell, HP, Lenovo, ASUS, etc.)
    if publisher_lower.contains("dell") || name_lower.contains("dell")
        || publisher_lower.contains("hewlett") || publisher_lower.contains("hp inc") || name_lower.starts_with("hp ")
        || publisher_lower.contains("lenovo") || name_lower.contains("lenovo")
        || publisher_lower.contains("asus") || name_lower.contains("asus")
        || publisher_lower.contains("acer") || name_lower.contains("acer")
        || publisher_lower.contains("toshiba") || name_lower.contains("toshiba")
        || publisher_lower.contains("samsung") || name_lower.contains("samsung")
    {
        return AppCategory::Utilities;
    }
    
    // APPLE APPS
    if publisher_lower.contains("apple") || name_lower.contains("apple")
        || name_lower.contains("itunes") || name_lower.contains("icloud")
        || name_lower.contains("bonjour")
    {
        return AppCategory::Utilities;
    }
    
    // System/Microsoft apps
    if publisher_lower.contains("microsoft") || name_lower.starts_with("microsoft")
    {
        return AppCategory::Productivity;
    }
    
    // Intel/AMD/NVIDIA drivers and tools
    if publisher_lower.contains("intel") || publisher_lower.contains("amd") || publisher_lower.contains("nvidia")
        || name_lower.contains("intel") && (name_lower.contains("driver") || name_lower.contains("graphics"))
        || name_lower.contains("nvidia") && (name_lower.contains("driver") || name_lower.contains("geforce"))
        || name_lower.contains("amd") && (name_lower.contains("driver") || name_lower.contains("radeon"))
        || name_lower.contains("realtek") || publisher_lower.contains("realtek")
    {
        return AppCategory::Utilities;
    }
    
    // Google apps (not already categorized)
    if publisher_lower.contains("google") || name_lower.starts_with("google")
    {
        return AppCategory::Productivity;
    }
    
    // Common utility patterns
    if name_lower.contains("driver") || name_lower.contains("update")
        || name_lower.contains("support") || name_lower.contains("assistant")
        || name_lower.contains("utility") || name_lower.contains("tool")
        || name_lower.contains("launcher") || name_lower.contains("manager")
    {
        return AppCategory::Utilities;
    }
    
    // Runtime libraries and redistributables
    if name_lower.contains("runtime") || name_lower.contains("redistributable")
        || name_lower.contains("framework") || name_lower.contains("library")
    {
        return AppCategory::Utilities;
    }
    
    // Default to Unknown
    unsafe {
        if DEBUG_COUNT < 10 {
            eprintln!("DEBUG: '{}' -> Unknown (no matches)", name);
        }
    }
    AppCategory::Unknown
}

/// Scan common installation directories for additional apps not in registry
/// This is kept for legacy/portable apps but registry should catch most
pub fn scan_common_directories() -> Result<Vec<QuestionableApp>, Box<dyn std::error::Error>> {
    // Registry scanning should catch everything, this is now optional
    // Could be used for portable apps in the future
    Ok(Vec::new())
}



/// Scan for portable/non-registered apps in user directories
/// Most apps should be found in registry, this catches portable ones
pub fn scan_p2p_artifacts() -> Result<Vec<QuestionableApp>, Box<dyn std::error::Error>> {
    let mut found_apps = Vec::new();
    
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let user_path = std::path::Path::new(&user_profile);
        
        // Check for Tor Browser (portable)
        let tor_paths = vec![
            user_path.join("Desktop\\Tor Browser"),
            user_path.join("Downloads\\Tor Browser"),
            user_path.join("Documents\\Tor Browser"),
        ];
        
        for tor_path in tor_paths {
            if tor_path.exists() {
                let name = "Tor Browser".to_string();
                let publisher = Some("The Tor Project".to_string());
                found_apps.push(QuestionableApp {
                    name: name.clone(),
                    category: categorize_application(&name, &publisher),
                    install_path: tor_path.to_string_lossy().to_string(),
                    version: "Portable".to_string(),
                    install_date: None,
                    publisher,
                    artifact_paths: get_artifact_paths(&name),
                    investigative_category: "ANONYMITY_ANTI_FORENSICS".to_string(),
                    function_category: "Browser".to_string(),
                    confidence: 1.0,
                });
            }
        }
        
        // Check for I2P
        if let Ok(appdata) = std::env::var("APPDATA") {
            let i2p_path = std::path::Path::new(&appdata).join("I2P");
            if i2p_path.exists() {
                let name = "I2P".to_string();
                let publisher = Some("I2P Project".to_string());
                found_apps.push(QuestionableApp {
                    name: name.clone(),
                    category: categorize_application(&name, &publisher),
                    install_path: i2p_path.to_string_lossy().to_string(),
                    version: "Unknown".to_string(),
                    install_date: None,
                    publisher,
                    artifact_paths: get_artifact_paths(&name),
                    investigative_category: "ANONYMITY_ANTI_FORENSICS".to_string(),
                    function_category: "AnonymityTool".to_string(),
                    confidence: 1.0,
                });
            }
        }
    }
    
    Ok(found_apps)
}

pub fn scan_questionable_apps() -> Result<Vec<QuestionableApp>, Box<dyn std::error::Error>> {
    let mut all_apps = Vec::new();

    if crate::scanner::hash_scan::is_scan_cancelled() {
        eprintln!("[Questionable Apps] ⛔ Cancelled before start");
        return Ok(all_apps);
    }

    // Scan registry
    match scan_installed_apps() {
        Ok(mut apps) => all_apps.append(&mut apps),
        Err(e) => eprintln!("Error scanning registry: {}", e),
    }

    if crate::scanner::hash_scan::is_scan_cancelled() {
        eprintln!("[Questionable Apps] ⛔ Cancelled after registry");
        return Ok(all_apps);
    }

    // Scan directories
    match scan_common_directories() {
        Ok(mut apps) => all_apps.append(&mut apps),
        Err(e) => eprintln!("Error scanning directories: {}", e),
    }

    if crate::scanner::hash_scan::is_scan_cancelled() {
        eprintln!("[Questionable Apps] ⛔ Cancelled after directories");
        return Ok(all_apps);
    }

    // Windows Store apps are now scanned in scan_installed_apps()
    // No need to scan them separately here
    
    // Scan for P2P artifacts in user directories
    match scan_p2p_artifacts() {
        Ok(mut apps) => all_apps.append(&mut apps),
        Err(e) => eprintln!("Error scanning P2P artifacts: {}", e),
    }

    // Remove duplicates
    all_apps.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.install_path.cmp(&b.install_path))
    });
    all_apps.dedup_by(|a, b| a.name == b.name && a.install_path == b.install_path);

    // **CRITICAL FIX: Filter out apps with UNKNOWN category and low confidence**
    // Only keep apps that are actually "questionable" based on category or confidence
    eprintln!("Before filtering: {} apps", all_apps.len());
    let filtered_apps: Vec<QuestionableApp> = all_apps
        .into_iter()
        .filter(|app| {
            // Keep app if:
            // 1. It has a non-UNKNOWN investigative category, OR
            // 2. It has confidence > 0.3 (meaning categorizer detected keywords), OR
            // 3. It has a non-Unknown legacy category
            let keep = app.investigative_category != "UNKNOWN" 
                || app.confidence > 0.3
                || !matches!(app.category, AppCategory::Unknown);
            
            if !keep {
                eprintln!("Filtering out: {} (category: {}, confidence: {})", 
                    app.name, app.investigative_category, app.confidence);
            }
            keep
        })
        .collect();
    
    eprintln!("After filtering: {} questionable apps", filtered_apps.len());
    
    Ok(filtered_apps)
}
