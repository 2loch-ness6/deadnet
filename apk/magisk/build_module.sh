#!/usr/bin/env bash
# Assemble a flashable Magisk module zip for the arm64 device from the app's
# prebuilt native engines. Association tools (wpa_supplicant/udhcpc) are included
# only if present in extra_bin/ — otherwise the app detects their absence via the
# ToolBroker and stubs the associate action.
#
# Usage:  ./build_module.sh [arch]   (arch default: arm64)
# Output: dist/deadnet-magisk-<arch>.zip
set -euo pipefail
ARCH="${1:-arm64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
APK="$(cd "$HERE/.." && pwd)"
ASSETS="$APK/assets"
STAGE="$(mktemp -d)"
OUT="$HERE/dist"
mkdir -p "$OUT"

# --- module tree ---
mkdir -p "$STAGE/system/bin" "$STAGE/META-INF/com/google/android"
cp "$HERE/module.prop" "$STAGE/"
cp "$HERE/customize.sh" "$STAGE/"

# our engines, renamed onto PATH as deadnet-<tool>
map_tool() { # <srcname> <dstname>
  local src="$ASSETS/$1.$ARCH" dst="$STAGE/system/bin/$2"
  if [ -f "$src" ]; then install -m0755 "$src" "$dst"; echo "  + $2"; else echo "  ! missing $src (skipped)"; fi
}
echo "[*] staging engines for $ARCH"
map_tool emit    deadnet-emit
map_tool sniff   deadnet-sniff
map_tool synscan deadnet-synscan
map_tool arp     deadnet-arp
map_tool nra     deadnet-nra

# optional association tools dropped in by the owner
if [ -d "$HERE/extra_bin/$ARCH" ]; then
  echo "[*] adding extra_bin tools"
  for f in "$HERE/extra_bin/$ARCH"/*; do [ -e "$f" ] && install -m0755 "$f" "$STAGE/system/bin/$(basename "$f")" && echo "  + $(basename "$f")"; done
fi

# --- standard Magisk flashable boilerplate ---
cat > "$STAGE/META-INF/com/google/android/update-binary" <<'EOF'
#!/sbin/sh
#################
# Magisk Module Installer boilerplate
#################
umask 022
OUTFD=$2
ZIPFILE=$3
mount /data 2>/dev/null
[ -f /data/adb/magisk/util_functions.sh ] && . /data/adb/magisk/util_functions.sh || { echo "! Magisk not installed"; exit 1; }
install_module
exit 0
EOF
echo "#MAGISK" > "$STAGE/META-INF/com/google/android/updater-script"

ZIP="$OUT/deadnet-magisk-$ARCH.zip"
( cd "$STAGE" && zip -qr9 "$ZIP" . )
rm -rf "$STAGE"
echo "[*] built $ZIP"
ls -lh "$ZIP"
