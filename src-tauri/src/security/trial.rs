use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

/// Trial status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialStatus {
    pub is_trial: bool,
    pub is_expired: bool,
    pub registered_at: Option<String>,
    pub expires_at: Option<String>,
    pub days_remaining: i64,
}

const TRIAL_DAYS: i64 = 60;

/// Check if this is a demo/trial build
pub fn is_trial_build() -> bool {
    // Check if the build is configured as demo
    // This will be set via compile-time feature flag
    #[cfg(feature = "demo")]
    {
        true
    }
    #[cfg(not(feature = "demo"))]
    {
        false
    }
}

/// Get trial status
pub fn get_trial_status() -> Result<TrialStatus, String> {
    // If not a trial build, return non-trial status
    if !is_trial_build() {
        return Ok(TrialStatus {
            is_trial: false,
            is_expired: false,
            registered_at: None,
            expires_at: None,
            days_remaining: -1,
        });
    }

    // For demo builds, check the local license cache first (instant — no network call).
    // Cache is refreshed whenever the user visits Settings, activates a key, or App.tsx
    // calls get_license_status() on startup.
    if let Ok(Some(license)) = crate::licensing::load_cached_license() {
        if license.registered {
            if let Some(ref plan) = license.plan {
                let plan_lower = plan.to_lowercase();
                if plan_lower != "trial" {
                    // Paid license active (annual, perpetual, etc.) — not a trial
                    return Ok(TrialStatus {
                        is_trial: false,
                        is_expired: false,
                        registered_at: None,
                        expires_at: license.expires_at,
                        days_remaining: license.days_remaining,
                    });
                }

                // Trial plan: prefer the cached `expires_at` so the badge stays in
                // sync with the bottom-right license window (and the server's view).
                // We recompute days_remaining locally from expires_at so the count
                // ticks down between cache refreshes instead of staying static.
                if let Some(ref expires_at) = license.expires_at {
                    if let Ok(exp) = DateTime::parse_from_rfc3339(expires_at) {
                        let exp_utc = exp.with_timezone(&Utc);
                        let now = Utc::now();
                        let days_remaining = (exp_utc - now).num_days();
                        let is_expired = now > exp_utc;
                        return Ok(TrialStatus {
                            is_trial: true,
                            is_expired,
                            registered_at: None,
                            expires_at: Some(exp_utc.to_rfc3339()),
                            days_remaining: days_remaining.max(0),
                        });
                    }
                }

                // Cached trial but no parseable expires_at — fall back to cached count.
                return Ok(TrialStatus {
                    is_trial: true,
                    is_expired: license.is_expired,
                    registered_at: None,
                    expires_at: license.expires_at,
                    days_remaining: license.days_remaining.max(0),
                });
            }
        }
    }

    // No cached license — fall through to local users table (USB/portable auth path)
    let db_path = super::init_security_db()?;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // Get registration date
    let registered_at: Result<String, _> = conn.query_row(
        "SELECT created_at FROM users ORDER BY id ASC LIMIT 1",
        [],
        |row| row.get(0),
    );

    match registered_at {
        Ok(reg_date) => {
            let registered = DateTime::parse_from_rfc3339(&reg_date)
                .map_err(|e| format!("Failed to parse registration date: {}", e))?
                .with_timezone(&Utc);

            let expiration = registered + Duration::days(TRIAL_DAYS);
            let now = Utc::now();
            let days_remaining = (expiration - now).num_days();
            let is_expired = now > expiration;

            Ok(TrialStatus {
                is_trial: true,
                is_expired,
                registered_at: Some(reg_date),
                expires_at: Some(expiration.to_rfc3339()),
                days_remaining: days_remaining.max(0),
            })
        }
        Err(_) => {
            // Not registered yet - trial hasn't started
            Ok(TrialStatus {
                is_trial: true,
                is_expired: false,
                registered_at: None,
                expires_at: None,
                days_remaining: TRIAL_DAYS,
            })
        }
    }
}

/// Check if trial is expired and prevent access
pub fn check_trial_access() -> Result<(), String> {
    let status = get_trial_status()?;

    if status.is_trial && status.is_expired {
        Err(format!(
            "TRIAL EXPIRED\n\n\
            Your 60-day trial period has ended.\n\n\
            Trial started: {}\n\
            Expired on: {}\n\n\
            To continue using Hindsight, please contact us for the full version:\n\
            Email: scout@datapilot.com\n\
            Website: https://datapilot.com",
            status.registered_at.unwrap_or_default(),
            status.expires_at.unwrap_or_default()
        ))
    } else {
        Ok(())
    }
}

/// Format trial status as user-friendly message
pub fn format_trial_message(status: &TrialStatus) -> String {
    if !status.is_trial {
        return "Full Version".to_string();
    }

    if status.is_expired {
        return "TRIAL EXPIRED - Contact us for full version".to_string();
    }

    if status.registered_at.is_none() {
        return format!("Demo Version - {} days available after registration", TRIAL_DAYS);
    }

    format!(
        "Demo Version - {} days remaining (expires {})",
        status.days_remaining,
        status.expires_at.as_ref()
            .and_then(|e| DateTime::parse_from_rfc3339(e).ok())
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trial_status_logic() {
        // Test calculations (assuming demo feature is enabled)
        let status = TrialStatus {
            is_trial: true,
            is_expired: false,
            registered_at: Some(Utc::now().to_rfc3339()),
            expires_at: Some((Utc::now() + Duration::days(60)).to_rfc3339()),
            days_remaining: 60,
        };

        assert!(!status.is_expired);
        assert_eq!(status.days_remaining, 60);
    }
}
