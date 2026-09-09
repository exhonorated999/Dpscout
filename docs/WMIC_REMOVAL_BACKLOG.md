# `wmic` removal backlog

## Why this exists

`wmic.exe` was deprecated in Windows 10 21H1 and is **absent** on Windows 11
24H2 (build 26100) and later — it was demoted to a disabled-by-default
Feature-on-Demand. `std::process::Command::new("wmic")` does not return a
non-zero exit code there; the process **spawn itself fails** with
`FileNotFoundError / WinError 2`.

Verified on this dev machine (build 26100):

```
shutil.which("wmic")          -> None
subprocess.run(["wmic", ...]) -> FileNotFoundError [WinError 2]
```

Every one of our call sites wraps the call in `if let Ok(output) = ...` or
`.output().ok()?`, so on 24H2 they all **silently return nothing**. No error,
no log line, no user-visible failure — just missing data in reports.

## Fixed

| File | Line | What it fed | Status |
|---|---|---|---|
| `src/licensing.rs` | 94 | machine ID (motherboard serial) | **FIXED** — now reads `Win32_BaseBoard.SerialNumber` via the `wmi` crate, with the `wmic` path kept as a fallback. See `baseboard_serial()`. |

This one was urgent because dropping the serial *changes the machine ID*, which
presents to the user as "Machine not registered" on a machine that registered
fine before they took the 24H2 update. The other sites only lose report data.

### Migration: deliberately manual

An automatic client-side fallback was written and then **reverted**. The idea
was to try the degraded `SHA256(COMPUTERNAME|USERNAME)` ID when the current one
came back unregistered, so nobody who registered during the degraded window got
stranded. It is not safe:

- The server authorizes on the client-supplied `machine_id` hash alone — no
  signature, no per-install secret, no challenge/response.
- `SHA256(COMPUTERNAME|USERNAME)` is guessable. `DESK-PD01` + `jsmith` is not a
  secret the way a motherboard serial is.
- So accepting the legacy hash means anyone who sets those two environment
  variables to a licensed agency's values is served that agency's license.

Gating it on local state (e.g. a non-empty `registration_info` table) does not
help: an attacker can edit the SQLite file, patch the client, or just call the
API directly with the computed hash. A client-side condition is a UX hint, not
an authorization boundary.

What ships instead: `licensing::get_license_diagnostics()` (Tauri command
`get_license_diagnostics`, surfaced as **Settings → License → Machine
Identity**) reports the current ID, the legacy ID when it differs, and a
warning if no serial is readable at all. Affected users copy those values to
support, and support repoints the server record.

**Open follow-up — the admin dashboard cannot do this yet.**
`agency_detail.html:79-80` only renders a ✓/✗ for whether a desktop machine ID
exists; there is no way to view or reset it. A rebind UI (show `machine_id`,
allow replacing it, audit the change) is required for this workflow to work at
all. It must *replace* the old ID, never keep it as an accepted alias.

Longer term the real fix is not a better fingerprint: issue a random
per-install credential at activation, store it DPAPI-backed, and prove
possession on later requests. Fingerprints then become a risk signal rather
than the sole authenticator.

## Remaining — 11 sites, degrade quietly

| File | Lines | Query | Data lost on 24H2 |
|---|---|---|---|
| `src/system_info/hardware.rs` | 51 | `volume where ... get Label,FileSystem,Capacity,FreeSpace` | Storage drive details in Device Info + PDF |
| `src/system_info/hardware.rs` | 138 | `baseboard get manufacturer,product,serialnumber` | Motherboard make/model/serial |
| `src/system_info/hardware.rs` | 170 | `bios get serialnumber` | BIOS serial |
| `src/system_info/hardware.rs` | 202 | `csproduct get uuid` | Hardware UUID |
| `src/scanner/usb_device.rs` | 153, 202, 249, 321 | USB / disk drive enumeration | USB device identification |
| `src/platform/windows.rs` | 68, 118 | installed-product enumeration | Installed apps (WMI path) |
| `src/system_info/accounts.rs` | 97 | `useraccount get ...` | Local user account details |

## How to fix each

Mirror `licensing.rs::baseboard_serial()`. The `wmi` crate (0.14) is already a
top-level dependency and `security/usb_fingerprint.rs` already establishes the
COM-init pattern:

```rust
use wmi::{COMLibrary, WMIConnection, Variant};
use std::collections::HashMap;

let com = COMLibrary::new().ok()?;
let conn = WMIConnection::new(com).ok()?;
let rows: Vec<HashMap<String, Variant>> =
    conn.raw_query("SELECT SerialNumber FROM Win32_BaseBoard").ok()?;
```

Notes:

- `wmic <alias> get <prop>` is just printing a WMI property, so reading the
  same property via the `wmi` crate returns a **byte-identical** string. That
  is what makes the licensing swap hash-stable.
- Alias → class mapping: `baseboard` → `Win32_BaseBoard`, `bios` →
  `Win32_BIOS`, `csproduct` → `Win32_ComputerSystemProduct`, `volume` →
  `Win32_Volume`, `useraccount` → `Win32_UserAccount`, `diskdrive` →
  `Win32_DiskDrive`.
- `COMLibrary::new()` is per-thread. Do not hold a `WMIConnection` across
  threads; create one where you use it.
- Prefer `SELECT <specific props>` over `SELECT *` — `SELECT *` on
  `Win32_Volume` is noticeably slow.
- **Do not** add new `wmic` callers. If a fallback is wanted for very old
  Windows, keep it behind `.or_else(...)` like `baseboard_serial_via_wmic()`.
- Always pass `CREATE_NO_WINDOW` (`0x08000000`) to any surviving
  `Command::new` so no console flashes during a scan.

## Detection

To confirm nothing new creeps in:

```
rg 'Command::new\("wmic"\)' src-tauri/src
```

Expected result after this backlog is cleared: exactly one hit, the deliberate
fallback in `licensing.rs`.
