#!/usr/bin/env bash
# Build the macOS portable edition of Datapilot Scout (.app), sign it, and
# (when Apple credentials are present) notarize + staple it.
#
# UNTESTED until run on a real Mac — see RFD 0001 / plans/…macos-portable-m0b.
#
# Usage:
#   scripts/build-macos-portable.sh                # universal (Apple Silicon + Intel)
#   ARCH=aarch64 scripts/build-macos-portable.sh   # or x86_64
#
# Signing / notarization is driven entirely by environment variables, which
# the Tauri CLI reads itself:
#   APPLE_SIGNING_IDENTITY   "Developer ID Application: … (TEAMID)".
#                            Unset → ad-hoc signature ("-"): runs on THIS Mac
#                            only after a right-click → Open, never on an
#                            offline examined Mac. Fine for local testing.
#   Notarization, either:
#     APPLE_API_ISSUER + APPLE_API_KEY + APPLE_API_KEY_PATH   (App Store Connect key), or
#     APPLE_ID + APPLE_PASSWORD (app-specific) + APPLE_TEAM_ID
#   With a Developer ID identity and notarization credentials Tauri submits to
#   notarytool, waits, and staples the ticket. Stapling is REQUIRED: examined
#   Macs are offline, and Gatekeeper can only check a stapled ticket offline.
#
# Output: dist-macos/Datapilot-Scout-Portable-<version>-<arch>.zip (+ .sha256)
# Stage onto a stick with scripts/stage-stick-macos.sh.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (codesign, notarytool, ditto)."

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(node -p "require('./package.json').version")"
ARCH="${ARCH:-universal}"
case "$ARCH" in
  universal) TRIPLE="universal-apple-darwin"; RUST_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin) ;;
  aarch64)   TRIPLE="aarch64-apple-darwin";   RUST_TARGETS=(aarch64-apple-darwin) ;;
  x86_64)    TRIPLE="x86_64-apple-darwin";    RUST_TARGETS=(x86_64-apple-darwin) ;;
  *) die "ARCH must be universal, aarch64 or x86_64 (got '$ARCH')." ;;
esac

# --- Signing mode -----------------------------------------------------------
NOTARIZE=0
if [[ -n "${APPLE_API_ISSUER:-}" && -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_KEY_PATH:-}" ]]; then
  NOTARIZE=1
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
  NOTARIZE=1
fi

if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  export APPLE_SIGNING_IDENTITY="-"
  note "No APPLE_SIGNING_IDENTITY: ad-hoc signing (local testing only)."
  if [[ "$NOTARIZE" == 1 ]]; then
    die "Notarization credentials are set but there is no Developer ID identity; ad-hoc builds cannot be notarized."
  fi
elif [[ "$NOTARIZE" == 0 ]]; then
  echo "WARNING: signing with '$APPLE_SIGNING_IDENTITY' but NOT notarizing." >&2
  echo "         Gatekeeper will block this build on an offline examined Mac." >&2
fi

# The updater is disabled on Mac (offline policy, createUpdaterArtifacts=false
# in the overlay); make sure a stray Windows key does not get used here.
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD || true

# --- Toolchain --------------------------------------------------------------
command -v cargo >/dev/null || die "Rust (cargo) not found — install via rustup."
command -v npm   >/dev/null || die "npm not found."
for t in "${RUST_TARGETS[@]}"; do
  rustup target list --installed | grep -qx "$t" || { note "rustup target add $t"; rustup target add "$t"; }
done
[[ -d node_modules ]] || { note "npm ci"; npm ci; }

# --- Build ------------------------------------------------------------------
# Config merge order (later wins): tauri.conf.json → tauri.conf.portable.json
# (name, identifier, portable frontend build) → tauri.conf.macos-portable.json
# (.app target, incognito webview, asset scope, Info.plist, entitlements).
#
# src-tauri/macos/entitlements.plist is deliberately an EMPTY dict (hardened
# runtime, not sandboxed): no App Sandbox (Scout reads arbitrary folders and
# /Volumes, and a sandbox container under ~/Library/Containers would break the
# zero-host-writes rule) and no com.apple.security.cs.* exceptions (no unsigned
# code, no JIT in our process, no DYLD vars). Only add an exception after a
# signed build demonstrably fails without it.
# codesign parses entitlements with AMFIUnserializeXML, which rejects XML
# comments and CRLF ("syntax error near line 1") — keep the file bare and LF.
ENT="src-tauri/macos/entitlements.plist"
if grep -q '<!--' "$ENT" || grep -q $'\r' "$ENT"; then
  die "$ENT must have no XML comments and LF line endings (codesign's AMFI parser rejects them)."
fi
plutil -lint "$ENT" >/dev/null || die "$ENT is not a valid plist."

note "Building Datapilot Scout Portable $VERSION for $TRIPLE"
npx tauri build \
  --target "$TRIPLE" \
  --features demo,portable \
  --config src-tauri/tauri.conf.portable.json \
  --config src-tauri/tauri.conf.macos-portable.json \
  --bundles app

APP_DIR="src-tauri/target/$TRIPLE/release/bundle/macos"
APP="$(find "$APP_DIR" -maxdepth 1 -name '*.app' -print -quit)"
[[ -n "$APP" && -d "$APP" ]] || die "No .app produced under $APP_DIR."
note "Built: $APP"

# --- Guards -----------------------------------------------------------------
# The dev-only Mac UI preview must never reach a shipped bundle.
if grep -rqE 'VITE_MAC_PREVIEW|PREVIEW_MAC_DRIVES|Mac UI preview' dist/; then
  die "Mac UI preview code found in dist/ — rebuild without VITE_MAC_PREVIEW."
fi

PLIST="$APP/Contents/Info.plist"
for key in NSDesktopFolderUsageDescription NSDocumentsFolderUsageDescription \
           NSDownloadsFolderUsageDescription NSRemovableVolumesUsageDescription \
           NSNetworkVolumesUsageDescription; do
  /usr/libexec/PlistBuddy -c "Print :$key" "$PLIST" >/dev/null 2>&1 \
    || die "Info.plist is missing $key (macos/Info.plist was not merged)."
done
MIN_OS="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$PLIST" 2>/dev/null || true)"
note "LSMinimumSystemVersion=$MIN_OS"

BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$PLIST")"
note "Architectures: $(lipo -archs "$BIN")"

# --- Signature checks -------------------------------------------------------
note "codesign --verify"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dv --verbose=4 "$APP" 2>&1 | grep -E '^(Authority|TeamIdentifier|Runtime Version|flags)=' || true

if [[ "$NOTARIZE" == 1 ]]; then
  note "Stapler / Gatekeeper"
  xcrun stapler validate "$APP" || die "No stapled notarization ticket — offline Macs will refuse this build."
  spctl --assess --type execute --verbose=2 "$APP" || die "Gatekeeper rejects the app."
fi

# --- Package ----------------------------------------------------------------
OUT="$ROOT/dist-macos"
mkdir -p "$OUT"
ZIP="$OUT/Datapilot-Scout-Portable-$VERSION-$ARCH.zip"
rm -f "$ZIP" "$ZIP.sha256"
# ditto keeps the code signature and bundle structure intact (plain zip does not).
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
( cd "$OUT" && shasum -a 256 "$(basename "$ZIP")" > "$(basename "$ZIP").sha256" )

note "Done: $ZIP"
cat "$ZIP.sha256"
if [[ "$APPLE_SIGNING_IDENTITY" == "-" ]]; then
  echo "NOTE: ad-hoc signed. Full Disk Access grants will not survive a rebuild." >&2
fi
