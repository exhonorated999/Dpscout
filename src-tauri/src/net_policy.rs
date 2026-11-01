//! G9 — network egress policy.
//!
//! The macOS build is portable-only and runs on a host that is usually the
//! *subject* of the examination. Any outbound connection from it would leave
//! traces on that host (DNS cache, firewall/Little Snitch logs, the unified
//! log, proxy logs) and can tip off a remote party. So on macOS Scout makes
//! **no network calls at all**:
//!
//! - **Licensing:** the stick is activated on Windows, where the licence cache lives in `ScoutData`. That cache is shared with the Mac through the same `USB-VOL-%08X` machine id. On a Mac, status is computed from the cache only, and register/activate are refused.
//! - **Updates, bug reports, telemetry, public IP, warrant parser submissions and Discord CDN media fetches** are all refused or skipped.
//!
//! Windows behaviour is unchanged: `network_allowed()` is `true` there.
//!
//! Every egress site calls [`network_allowed`] (or [`require_network`])
//! instead of matching on `target_os` itself, so the policy lives in one place
//! and grep for `net_policy::` lists every gate.

/// True when this build may open outbound connections.
#[inline]
pub fn network_allowed() -> bool {
    !cfg!(target_os = "macos")
}

/// `Err` with a user-facing explanation when the network is off-limits.
pub fn require_network(what: &str) -> Result<(), String> {
    if network_allowed() {
        Ok(())
    } else {
        Err(offline_message(what))
    }
}

/// The message shown when `what` is refused by the offline policy.
pub fn offline_message(what: &str) -> String {
    format!(
        "{} is unavailable on macOS: the Mac edition of Scout runs fully offline so it leaves \
         no network traces on the examined computer. Do this from Scout on Windows instead.",
        what
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_matches_target() {
        assert_eq!(network_allowed(), !cfg!(target_os = "macos"));
        assert_eq!(require_network("Update check").is_ok(), network_allowed());
    }

    #[test]
    fn message_names_the_action() {
        let m = offline_message("Licence activation");
        assert!(m.starts_with("Licence activation is unavailable on macOS"));
        assert!(m.contains("Windows"));
    }
}
