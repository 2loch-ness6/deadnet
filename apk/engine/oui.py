"""
MAC OUI (IEEE MA-L) vendor lookup.

Loads the compact vendor table shipped at ../assets/oui.csv (relative to this
file) and resolves a MAC address's first 3 octets (24-bit OUI) to a vendor
name. Handles locally-administered / randomized MACs (common on modern
phones doing MAC randomization) by detecting the "locally administered" bit
rather than returning a bogus vendor match.

Stdlib only. Safe to import off-device (no Kivy requirement).
"""
from __future__ import annotations

import csv
import os
import re
from typing import Dict, Optional

try:
    from kivy.logger import Logger
except Exception:  # pragma: no cover - off-device / bare test env
    Logger = None


def _log(level: str, msg: str) -> None:
    if Logger is not None:
        getattr(Logger, level, Logger.info)(msg)


_DEFAULT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "oui.csv")

# Module-level cache: loaded once, reused by lookup()/classify().
_TABLE: Optional[Dict[str, str]] = None
_TABLE_PATH: Optional[str] = None

_HEX6_RE = re.compile(r"^[0-9A-F]{6}$")
_MAC_STRIP_RE = re.compile(r"[^0-9A-Fa-f]")


def load(path: Optional[str] = None) -> Dict[str, str]:
    """Load the OUI->vendor CSV into a dict, caching module-level.

    `path` defaults to the sibling `../assets/oui.csv` resolved relative to
    this file. Re-calling with the same (or no) path returns the cached
    table without re-reading the file. Passing a different path reloads.
    """
    global _TABLE, _TABLE_PATH

    resolved = os.path.abspath(path) if path else _DEFAULT_CSV

    if _TABLE is not None and _TABLE_PATH == resolved:
        return _TABLE

    table: Dict[str, str] = {}
    try:
        with open(resolved, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                first = row[0].strip()
                if not first or first.startswith("#"):
                    continue
                if first.upper() == "OUI_HEX":
                    continue  # header row
                if len(row) < 2:
                    continue
                oui_hex = first.upper()
                if not _HEX6_RE.match(oui_hex):
                    continue
                vendor = row[1].strip()
                if vendor:
                    table[oui_hex] = vendor
    except OSError as exc:
        _log("warning", f"oui: failed to load {resolved}: {exc}")
        table = {}

    _TABLE = table
    _TABLE_PATH = resolved
    return table


def _normalize_oui(mac: str) -> Optional[str]:
    """Strip separators, uppercase, and take the first 6 hex chars."""
    if not mac:
        return None
    stripped = _MAC_STRIP_RE.sub("", mac).upper()
    if len(stripped) < 6:
        return None
    oui = stripped[:6]
    if not _HEX6_RE.match(oui):
        return None
    return oui


def _is_randomized(mac: str) -> bool:
    """True if the MAC's first octet has the locally-administered bit set
    (bit 0x02) — the standard signal for a randomized/private MAC."""
    stripped = _MAC_STRIP_RE.sub("", mac).upper()
    if len(stripped) < 2:
        return False
    try:
        first_octet = int(stripped[0:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def lookup(mac: str, table: Optional[Dict[str, str]] = None) -> str:
    """Return the vendor for `mac`, "" if unknown.

    Randomized/locally-administered MACs return "(randomized)" instead of
    whatever the (meaningless) OUI bits happen to collide with.
    """
    if _is_randomized(mac):
        return "(randomized)"

    oui = _normalize_oui(mac)
    if oui is None:
        return ""

    tbl = table if table is not None else load()
    return tbl.get(oui, "")


def classify(mac: str) -> str:
    """Convenience: vendor name, or "(randomized)" / "(unknown)"."""
    vendor = lookup(mac)
    if vendor == "(randomized)":
        return vendor
    return vendor if vendor else "(unknown)"


if __name__ == "__main__":
    table = load()
    print(f"oui table size: {len(table)} entries")

    apple_mac = "00:17:F2:11:22:33"
    apple_vendor = lookup(apple_mac)
    if apple_vendor:
        assert "Apple" in apple_vendor, f"expected Apple in vendor, got {apple_vendor!r}"
        print(f"lookup({apple_mac}) -> {apple_vendor!r} (checked)")
    else:
        print(f"note: 0017F2 not present in built table ({_TABLE_PATH}); skipping Apple assertion")

    rand_mac = "02:00:00:11:22:33"
    rand_result = lookup(rand_mac)
    assert rand_result == "(randomized)", f"expected (randomized), got {rand_result!r}"
    print(f"lookup({rand_mac}) -> {rand_result!r}")

    unknown_mac = "FD:FF:FF:FF:FF:FF"
    unknown_result = lookup(unknown_mac)
    assert unknown_result == "", f"expected '', got {unknown_result!r}"
    print(f"lookup({unknown_mac}) -> {unknown_result!r}")

    print(f"table size: {len(table)}")
    print("U3 PASS")
