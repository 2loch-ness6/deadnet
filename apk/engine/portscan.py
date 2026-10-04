"""
DeadNet engine — P2 port scan + fingerprint (engine/portscan.py)

Thin Python wrapper around the native ``synscan.<arch>`` TCP SYN scanner (Android's
Python can't open raw sockets, so the heavy lifting is in src/synscan.cpp). This
module:

  * resolves the arch-specific synscan binary and runs it under ``su`` (device/root
    only), parsing its ``PORT=.. STATE=..`` lines -> ``{port: "open"/"closed"}``;
  * offers a cheap, pure-Python ``fingerprint()`` role guess from an open-port set;
  * reserves ``smart_x_scan()`` as the P3 stub the owner drops their code into.

It imports cleanly off-device (no Kivy, no android, no su required) so the pure
functions stay unit-testable on the x86_64 build box.

Thematic note (contracts.py): a scanned electronic is a "scent"; this is P2
enrichment (ScanPhase.P2_FINGERPRINT) layered on top of the P1 OUI inventory.
"""
from __future__ import annotations

import os
import platform as _pt
import subprocess
from typing import Dict, Iterable, Optional

# --- logging: guarded so the module imports in a bare test env (CONTRACTS.md rule 6) ---
try:
    from kivy.logger import Logger  # type: ignore
except Exception:  # pragma: no cover - exercised only off-device
    import logging

    Logger = logging.getLogger("deadnet.portscan")

_PREF = "DeadNet/portscan"

# Arch -> binary suffix. Mirrors DeadNetAPK._BINARY_MAP in deadnet_apk.py so the
# same asset naming convention (synscan.<arch>) is used everywhere.
_BINARY_MAP = {
    "x86_64": "x86_64",
    "arm": "arm",
    "aarch64": "arm64",
    "i386": "i386",
    "i686": "i386",
}

_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "assets")

# Default port set: the usual suspects the fingerprint heuristic keys off.
DEFAULT_PORTS = (22, 80, 443, 8080, 53, 23, 445, 139, 3389, 5555)


def _arch_suffix() -> Optional[str]:
    """Device arch -> synscan binary suffix, or None if unsupported."""
    return _BINARY_MAP.get(_pt.machine())


def _resolve_binary(arch_suffix: str) -> str:
    """Absolute path to the bundled synscan binary for this arch (in assets/)."""
    return os.path.abspath(os.path.join(_ASSETS_DIR, f"synscan.{arch_suffix}"))


def _prepare_binary(arch_suffix: str, dest_dir: Optional[str] = None) -> str:
    """Copy synscan.<arch> into an exec-friendly dir and mark it root-runnable.

    Mirrors DeadNetAPK._prepare_binaries: copy under su, chmod 777, chown root.
    Returns the destination path. Device/root only.
    """
    src = _resolve_binary(arch_suffix)
    if dest_dir is None:
        # Lazy import: android helper is unavailable (and unneeded) off-device.
        from utils.android_utils import get_app_data_dir  # type: ignore

        dest_dir = get_app_data_dir()
    dest = os.path.join(dest_dir, f"synscan.{arch_suffix}")
    subprocess.run(f"su -c 'cp -rf {src} {dest}'", shell=True, check=True)
    subprocess.run(f"su -c 'chmod 777 {dest}'", shell=True, check=True)
    subprocess.run(f"su -c 'chown root {dest}'", shell=True, check=True)
    return dest


def _parse_lines(text: str, scanned: Iterable[int]) -> Dict[int, str]:
    """Parse ``PORT=<n> STATE=<open|closed>`` lines into {port: state}.

    Only ports we actually asked about are kept; unanswered ports are absent
    (filtered), exactly as synscan omits them.
    """
    wanted = set(int(p) for p in scanned)
    out: Dict[int, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "PORT=" not in line:
            continue
        fields = {}
        for tok in line.split():
            k, _, v = tok.partition("=")
            if k and v:
                fields[k] = v
        try:
            port = int(fields.get("PORT", ""))
        except ValueError:
            continue
        state = fields.get("STATE", "")
        if port in wanted and state in ("open", "closed"):
            out[port] = state
    return out


def syn_scan(iface: str,
             ip: str,
             ports: Iterable[int] = DEFAULT_PORTS,
             timeout_ms: int = 800) -> Dict[int, str]:
    """Native TCP SYN scan of ``ip`` over ``iface``. Device/root only.

    Runs ``synscan.<arch> <iface> <ip> <ports_csv> <timeout_ms>`` under ``su`` and
    parses the result. Returns ``{port: "open"/"closed"}``; ports that never answered
    within the timeout are simply absent (filtered). Raises if the device arch is
    unsupported; returns {} on an exec/timeout failure (logged).
    """
    arch = _arch_suffix()
    if not arch:
        raise RuntimeError(f"Unsupported device machine architecture -> {_pt.machine()}")

    port_list = [int(p) for p in ports]
    if not port_list:
        return {}
    ports_csv = ",".join(str(p) for p in port_list)

    try:
        bin_path = _prepare_binary(arch)
    except Exception as e:
        Logger.error(f"{_PREF}: failed to stage synscan binary - {e}")
        return {}

    cmd = f"{bin_path} {iface} {ip} {ports_csv} {timeout_ms}"
    # Generous subprocess ceiling above the native listen window so we always reap it.
    proc_timeout = max(5.0, (timeout_ms / 1000.0) + 5.0)
    try:
        res = subprocess.run(
            ["su", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=proc_timeout,
        )
    except subprocess.TimeoutExpired:
        Logger.warning(f"{_PREF}: synscan timed out for {ip} on {iface}")
        return {}
    except Exception as e:
        Logger.error(f"{_PREF}: synscan exec error for {ip} - {e}")
        return {}

    return _parse_lines(res.stdout or "", port_list)


# --------------------------------------------------------------------------------
# Cheap service/role fingerprint — pure, unit-testable, no I/O.
# --------------------------------------------------------------------------------
def fingerprint(open_ports: Iterable[int]) -> str:
    """Heuristic service/role guess from a set of open ports.

    Pure function: order-independent, side-effect free. Returns a short human string
    (possibly a few hints joined by '; '). Empty / unknown -> "unknown".
    """
    ports = set(int(p) for p in open_ports)
    if not ports:
        return "unknown"

    hints = []
    # Most specific role signatures first.
    if {5555} & ports:
        hints.append("adb/android")
    if {445, 139} & ports and ({445, 139} <= ports or 445 in ports):
        hints.append("smb/windows")
    elif 139 in ports:
        hints.append("smb/windows")
    if {80, 443} & ports:
        hints.append("web/router")
    if 9100 in ports:
        hints.append("printer")
    if 53 in ports:
        hints.append("dns/gateway")
    if 3389 in ports:
        hints.append("rdp/windows")
    if 23 in ports:
        hints.append("telnet/iot")
    if 22 in ports:
        hints.append("ssh host")

    if not hints:
        # Something is open but none of the known signatures matched.
        return "generic host (ports: " + ",".join(str(p) for p in sorted(ports)) + ")"
    # De-dupe while preserving first-seen order.
    seen = []
    for h in hints:
        if h not in seen:
            seen.append(h)
    return "; ".join(seen)


# --------------------------------------------------------------------------------
# P3 — owner's "smart X scan". STUB: the owner drops their implementation here.
# --------------------------------------------------------------------------------
def smart_x_scan(*args, **kwargs):
    """P3 ScanPhase.P3_SMART_X — owner-supplied "smart X scan".

    This is a deliberate stub. The owner will replace this body with their own
    scanning logic (hence *args/**kwargs: the real signature is theirs to define).
    Until then it raises so nothing silently treats a no-op as a completed scan.
    """
    raise NotImplementedError("smart-X scan is owner-supplied; stub")


# --------------------------------------------------------------------------------
# Self-test — runs on the x86_64 build box, no device, no root (CONTRACTS.md rule 3).
# --------------------------------------------------------------------------------
if __name__ == "__main__":
    # fingerprint() heuristics
    assert "web" in fingerprint({80, 443}), fingerprint({80, 443})
    assert "ssh" in fingerprint({22}), fingerprint({22})
    assert "smb" in fingerprint({445, 139}), fingerprint({445, 139})
    assert "adb" in fingerprint({5555}), fingerprint({5555})
    assert "dns" in fingerprint({53}), fingerprint({53})
    assert "printer" in fingerprint({9100}), fingerprint({9100})
    assert fingerprint(set()) == "unknown"
    # a mixed host still surfaces the relevant roles
    mixed = fingerprint({22, 80, 443})
    assert "ssh" in mixed and "web" in mixed, mixed

    # _parse_lines() contract: only asked-about, well-formed, open/closed lines survive
    parsed = _parse_lines(
        "PORT=22 STATE=open\nPORT=23 STATE=closed\nPORT=9999 STATE=open\njunk\nPORT=80 STATE=weird\n",
        [22, 23, 80],
    )
    assert parsed == {22: "open", 23: "closed"}, parsed

    # smart_x_scan is a recognizable stub
    _stub_ok = False
    try:
        smart_x_scan()
    except NotImplementedError as e:
        _stub_ok = "stub" in str(e).lower()
    assert _stub_ok, "smart_x_scan must raise NotImplementedError mentioning 'stub'"

    # Report the 4 ELF `file` results if the binaries are present.
    import subprocess as _sp

    for suffix in ("arm64", "arm", "x86", "x86_64"):
        path = os.path.abspath(os.path.join(_ASSETS_DIR, f"synscan.{suffix}"))
        if os.path.exists(path):
            try:
                out = _sp.run(["file", path], stdout=_sp.PIPE, text=True).stdout.strip()
                print(out)
            except Exception as e:
                print(f"{path}: (file failed: {e})")
        else:
            print(f"{path}: MISSING")

    print("U10 PASS")
