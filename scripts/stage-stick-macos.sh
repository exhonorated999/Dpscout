#!/usr/bin/env bash
# Put the macOS portable .app onto a Scout USB stick, beside the Windows
# portable install, so both editions share one ScoutData folder (hash lists,
# keyword lists, settings, cases).
#
# UNTESTED until run on a real Mac.
#
# Usage:
#   scripts/stage-stick-macos.sh <Datapilot-Scout-Portable-….zip | ….app> /Volumes/<STICK>
#
# Layout it produces (Windows install at the stick root or in one sub-folder):
#   /Volumes/STICK/[folder/]datapilot-scout.exe
#   /Volumes/STICK/[folder/]ScoutData/
#   /Volumes/STICK/[folder/]Datapilot Scout Portable.app     <- added here
#   /Volumes/STICK/.metadata_never_index                     <- no Spotlight on the stick
#   /Volumes/STICK/.fseventsd/no_log                         <- no FSEvents log on the stick
#
# Everything is written to the STICK only; nothing on this Mac is modified
# except the scratch unzip folder, which is removed on exit.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only."
[[ $# -eq 2 ]] || die "usage: $0 <app.zip|App.app> /Volumes/<STICK>"

SRC="$1"
STICK="${2%/}"

[[ "$STICK" == /Volumes/* && -d "$STICK" ]] || die "'$STICK' is not a mounted volume under /Volumes."
[[ -w "$STICK" ]] || die "'$STICK' is not writable (locked or read-only)."

FS="$(diskutil info -plist "$STICK" | plutil -extract FilesystemType raw -o - - 2>/dev/null || echo unknown)"
note "Stick $STICK ($FS)"

# --- Locate the .app --------------------------------------------------------
WORK=""
cleanup() { [[ -n "$WORK" && -d "$WORK" ]] && rm -r "$WORK"; }
trap cleanup EXIT

if [[ "$SRC" == *.zip ]]; then
  [[ -f "$SRC" ]] || die "No such file: $SRC"
  if [[ -f "$SRC.sha256" ]]; then
    ( cd "$(dirname "$SRC")" && shasum -a 256 -c "$(basename "$SRC").sha256" ) || die "Checksum mismatch."
  fi
  WORK="$(mktemp -d)"
  ditto -x -k "$SRC" "$WORK"
  APP="$(find "$WORK" -maxdepth 1 -name '*.app' -print -quit)"
else
  APP="${SRC%/}"
fi
[[ -n "$APP" && -d "$APP" && "$APP" == *.app ]] || die "No .app found in $SRC."
codesign --verify --deep --strict "$APP" || die "Source app's signature is not intact."

# --- Find the Windows install on the stick -----------------------------------
DEST=""
if [[ -f "$STICK/datapilot-scout.exe" ]]; then
  DEST="$STICK"
else
  while IFS= read -r -d '' exe; do
    DEST="$(dirname "$exe")"; break
  done < <(find "$STICK" -mindepth 2 -maxdepth 2 -name datapilot-scout.exe -not -path '*/.*' -print0 | sort -z)
fi
if [[ -z "$DEST" ]]; then
  echo "WARNING: no Windows portable install (datapilot-scout.exe) on the stick." >&2
  echo "         Installing at the stick root; the Mac edition will create its own ScoutData." >&2
  DEST="$STICK"
fi
[[ -d "$DEST/ScoutData" ]] || echo "NOTE: $DEST/ScoutData does not exist yet; Scout creates it on first run." >&2

TARGET="$DEST/$(basename "$APP")"
note "Installing to $TARGET"

# --- Copy -------------------------------------------------------------------
# exFAT/FAT cannot hold extended attributes, so macOS would scatter AppleDouble
# "._*" files through the bundle, and those break the code-signature seal
# ("a sealed resource is missing or invalid"). Copy without xattrs/resource
# forks/quarantine and strip any "._*" files afterwards.
if [[ -e "$TARGET" ]]; then
  OLD="$TARGET.old-$(date +%Y%m%d%H%M%S)"
  note "Moving the existing copy aside to $(basename "$OLD")"
  mv "$TARGET" "$OLD"
fi
ditto --norsrc --noextattr --noqtn "$APP" "$TARGET"
dot_clean -m "$TARGET" 2>/dev/null || true
find "$TARGET" -name '._*' -type f -delete

codesign --verify --deep --strict --verbose=2 "$TARGET" \
  || die "Signature broken after copying to the stick ($FS). Re-run; if it persists, report it."

# --- Stick hygiene (written to the stick only) --------------------------------
touch "$STICK/.metadata_never_index"
mkdir -p "$STICK/.fseventsd" && touch "$STICK/.fseventsd/no_log"

if [[ -n "${OLD:-}" ]]; then
  note "Previous copy kept at: $OLD (delete it once the new one is verified)."
fi
note "Done. Eject the stick with: diskutil eject \"$STICK\""
